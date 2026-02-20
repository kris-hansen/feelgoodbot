// Package mdscanner detects potential prompt injection attacks in markdown.
package mdscanner

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
)

// Severity levels for findings
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

// FindingType categorizes the type of potential injection
type FindingType string

const (
	TypeHiddenInstruction FindingType = "hidden_instruction"
	TypeUnicodeTrick      FindingType = "unicode_trick"
	TypeHiddenText        FindingType = "hidden_text"
	TypeBase64Payload     FindingType = "base64_payload"
	TypeInstructionLike   FindingType = "instruction_pattern"
	TypeLinkMismatch      FindingType = "link_mismatch"
	TypeSuspiciousAltText FindingType = "suspicious_alt_text"
)

// Finding represents a potential prompt injection
type Finding struct {
	Line     int         `json:"line"`
	Column   int         `json:"column,omitempty"`
	Type     FindingType `json:"type"`
	Severity Severity    `json:"severity"`
	Message  string      `json:"message"`
	Content  string      `json:"content,omitempty"` // Excerpt of suspicious content
}

// ScanResult contains all findings from a scan
type ScanResult struct {
	Findings   []Finding `json:"findings"`
	LinesTotal int       `json:"lines_total"`
	Clean      bool      `json:"clean"`
}

// Scanner configuration
type Config struct {
	// MaxLineLength limits line scanning (performance)
	MaxLineLength int
	// CheckBase64 enables base64 content analysis
	CheckBase64 bool
	// CustomPatterns adds additional instruction patterns to detect
	CustomPatterns []string
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	return &Config{
		MaxLineLength: 10000,
		CheckBase64:   true,
	}
}

// Scanner detects prompt injection in markdown
type Scanner struct {
	config   *Config
	patterns []*regexp.Regexp
}

// New creates a scanner with the given config
func New(cfg *Config) *Scanner {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	s := &Scanner{config: cfg}
	s.compilePatterns()
	return s
}

// compilePatterns pre-compiles regex patterns for performance
func (s *Scanner) compilePatterns() {
	// Instruction-like patterns (case insensitive)
	patterns := []string{
		// Direct instruction patterns
		`(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?|context)`,
		`(?i)\bdisregard\s+(all\s+)?(previous|prior|above)`,
		`(?i)\bforget\s+(everything|all|what)\s+(you|i)\s+(said|told|know)`,
		`(?i)\byou\s+are\s+now\s+(a|an)\b`,
		`(?i)\bact\s+as\s+(if\s+)?(you\s+are|a|an)\b`,
		`(?i)\bpretend\s+(you\s+are|to\s+be)\b`,
		`(?i)\bnew\s+instructions?:`,
		`(?i)\bsystem\s*:\s*`,
		`(?i)\b(assistant|user|human)\s*:\s*`,
		`(?i)\boverride\s+(previous|prior|all)\s+(instructions?|rules?)`,
		`(?i)\bdo\s+not\s+follow\s+(previous|prior|the)\s+(instructions?|rules?)`,
		`(?i)\bignore\s+(the\s+)?(system\s+)?(prompt|message)`,
		`(?i)\bfrom\s+now\s+on\b.*\bact\b`,
		`(?i)\byour\s+new\s+(role|task|purpose|goal)\s+is\b`,
		// Jailbreak attempts
		`(?i)\bDAN\s+mode\b`,
		`(?i)\bdeveloper\s+mode\b`,
		`(?i)\bjailbreak\b`,
		`(?i)\bunlock\b.*\bfull\s+potential\b`,
	}

	// Add custom patterns
	patterns = append(patterns, s.config.CustomPatterns...)

	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			s.patterns = append(s.patterns, re)
		}
	}
}

// ScanReader scans markdown from an io.Reader
func (s *Scanner) ScanReader(r io.Reader) (*ScanResult, error) {
	result := &ScanResult{
		Findings: []Finding{},
	}

	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Truncate very long lines for performance
		if len(line) > s.config.MaxLineLength {
			line = line[:s.config.MaxLineLength]
		}

		// Run all checks on this line
		s.checkLine(line, lineNum, result)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan error: %w", err)
	}

	result.LinesTotal = lineNum
	result.Clean = len(result.Findings) == 0
	return result, nil
}

// ScanString scans markdown content from a string
func (s *Scanner) ScanString(content string) (*ScanResult, error) {
	return s.ScanReader(strings.NewReader(content))
}

// checkLine runs all detection checks on a single line
func (s *Scanner) checkLine(line string, lineNum int, result *ScanResult) {
	// 1. Check for HTML comments with hidden instructions
	s.checkHTMLComments(line, lineNum, result)

	// 2. Check for Unicode tricks
	s.checkUnicode(line, lineNum, result)

	// 3. Check for hidden text (CSS)
	s.checkHiddenText(line, lineNum, result)

	// 4. Check for instruction-like patterns
	s.checkInstructionPatterns(line, lineNum, result)

	// 5. Check for suspicious link mismatches
	s.checkLinks(line, lineNum, result)

	// 6. Check for suspicious image alt/title text
	s.checkImageText(line, lineNum, result)

	// 7. Check for base64 content
	if s.config.CheckBase64 {
		s.checkBase64(line, lineNum, result)
	}
}

// checkHTMLComments detects hidden instructions in HTML comments
func (s *Scanner) checkHTMLComments(line string, lineNum int, result *ScanResult) {
	re := regexp.MustCompile(`<!--(.+?)-->`)
	matches := re.FindAllStringSubmatch(line, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		comment := match[1]

		// Check if comment contains instruction-like content
		for _, pattern := range s.patterns {
			if pattern.MatchString(comment) {
				result.Findings = append(result.Findings, Finding{
					Line:     lineNum,
					Type:     TypeHiddenInstruction,
					Severity: SeverityHigh,
					Message:  "HTML comment contains instruction-like content",
					Content:  truncate(comment, 100),
				})
				return // One finding per comment
			}
		}
	}
}

// checkUnicode detects suspicious Unicode characters
func (s *Scanner) checkUnicode(line string, lineNum int, result *ScanResult) {
	for i, r := range line {
		// Right-to-left override
		if r == '\u202E' || r == '\u202D' || r == '\u202C' {
			result.Findings = append(result.Findings, Finding{
				Line:     lineNum,
				Column:   i + 1,
				Type:     TypeUnicodeTrick,
				Severity: SeverityHigh,
				Message:  "Right-to-left override character detected",
			})
		}

		// Zero-width characters
		if r == '\u200B' || r == '\u200C' || r == '\u200D' || r == '\uFEFF' {
			result.Findings = append(result.Findings, Finding{
				Line:     lineNum,
				Column:   i + 1,
				Type:     TypeUnicodeTrick,
				Severity: SeverityMedium,
				Message:  "Zero-width character detected",
			})
		}

		// Homoglyph detection (Cyrillic/Greek lookalikes for Latin)
		if isHomoglyph(r) {
			result.Findings = append(result.Findings, Finding{
				Line:     lineNum,
				Column:   i + 1,
				Type:     TypeUnicodeTrick,
				Severity: SeverityMedium,
				Message:  fmt.Sprintf("Potential homoglyph character: U+%04X", r),
			})
		}
	}
}

// checkHiddenText detects CSS-based text hiding
func (s *Scanner) checkHiddenText(line string, lineNum int, result *ScanResult) {
	hiddenPatterns := []struct {
		pattern *regexp.Regexp
		message string
	}{
		{regexp.MustCompile(`(?i)display\s*:\s*none`), "CSS display:none detected"},
		{regexp.MustCompile(`(?i)visibility\s*:\s*hidden`), "CSS visibility:hidden detected"},
		{regexp.MustCompile(`(?i)font-size\s*:\s*0`), "CSS font-size:0 detected"},
		{regexp.MustCompile(`(?i)color\s*:\s*(white|#fff|#ffffff|rgba?\([^)]*,\s*0\s*\))`), "CSS color hiding detected"},
		{regexp.MustCompile(`(?i)opacity\s*:\s*0[^.]`), "CSS opacity:0 detected"},
		{regexp.MustCompile(`(?i)position\s*:\s*absolute.*left\s*:\s*-\d{4,}`), "CSS off-screen positioning detected"},
	}

	for _, hp := range hiddenPatterns {
		if hp.pattern.MatchString(line) {
			result.Findings = append(result.Findings, Finding{
				Line:     lineNum,
				Type:     TypeHiddenText,
				Severity: SeverityHigh,
				Message:  hp.message,
				Content:  truncate(line, 100),
			})
		}
	}
}

// checkInstructionPatterns detects instruction-like text
func (s *Scanner) checkInstructionPatterns(line string, lineNum int, result *ScanResult) {
	for _, pattern := range s.patterns {
		if loc := pattern.FindStringIndex(line); loc != nil {
			// Skip if inside HTML comment (already handled)
			if strings.Contains(line[:loc[0]], "<!--") {
				continue
			}

			result.Findings = append(result.Findings, Finding{
				Line:     lineNum,
				Column:   loc[0] + 1,
				Type:     TypeInstructionLike,
				Severity: SeverityMedium,
				Message:  "Instruction-like pattern detected",
				Content:  truncate(line[loc[0]:], 80),
			})
		}
	}
}

// checkLinks detects suspicious link mismatches
func (s *Scanner) checkLinks(line string, lineNum int, result *ScanResult) {
	// Match markdown links: [text](url "title")
	re := regexp.MustCompile(`\[([^\]]+)\]\(([^)\s]+)(?:\s+"([^"]*)")?\)`)
	matches := re.FindAllStringSubmatch(line, -1)

	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		text := strings.ToLower(match[1])
		url := strings.ToLower(match[2])

		// Check for javascript: URLs
		if strings.HasPrefix(url, "javascript:") {
			result.Findings = append(result.Findings, Finding{
				Line:     lineNum,
				Type:     TypeLinkMismatch,
				Severity: SeverityHigh,
				Message:  "JavaScript URL in markdown link",
				Content:  truncate(match[0], 100),
			})
		}

		// Check for data: URLs
		if strings.HasPrefix(url, "data:") {
			result.Findings = append(result.Findings, Finding{
				Line:     lineNum,
				Type:     TypeLinkMismatch,
				Severity: SeverityMedium,
				Message:  "Data URL in markdown link",
				Content:  truncate(match[0], 100),
			})
		}

		// Check for text/URL mismatch (text looks like URL but points elsewhere)
		if (strings.Contains(text, "http") || strings.Contains(text, "www.")) &&
			!strings.Contains(url, extractDomain(text)) {
			result.Findings = append(result.Findings, Finding{
				Line:     lineNum,
				Type:     TypeLinkMismatch,
				Severity: SeverityMedium,
				Message:  "Link text suggests different URL than target",
				Content:  truncate(match[0], 100),
			})
		}
	}
}

// checkImageText detects suspicious alt text or titles
func (s *Scanner) checkImageText(line string, lineNum int, result *ScanResult) {
	// Match markdown images: ![alt](url "title")
	re := regexp.MustCompile(`!\[([^\]]*)\]\([^)]+(?:\s+"([^"]*)")?\)`)
	matches := re.FindAllStringSubmatch(line, -1)

	for _, match := range matches {
		textToCheck := ""
		if len(match) > 1 {
			textToCheck += match[1] // alt text
		}
		if len(match) > 2 {
			textToCheck += " " + match[2] // title
		}

		// Check for instruction patterns in alt/title
		for _, pattern := range s.patterns {
			if pattern.MatchString(textToCheck) {
				result.Findings = append(result.Findings, Finding{
					Line:     lineNum,
					Type:     TypeSuspiciousAltText,
					Severity: SeverityHigh,
					Message:  "Instruction-like content in image alt/title",
					Content:  truncate(textToCheck, 100),
				})
				break
			}
		}
	}
}

// checkBase64 detects and analyzes base64 content
func (s *Scanner) checkBase64(line string, lineNum int, result *ScanResult) {
	// Match potential base64 strings (at least 20 chars)
	re := regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	matches := re.FindAllString(line, -1)

	for _, match := range matches {
		// Try to decode
		decoded, err := base64.StdEncoding.DecodeString(match)
		if err != nil {
			continue
		}

		// Check if decoded content looks suspicious
		decodedStr := string(decoded)
		if !isPrintable(decodedStr) {
			continue
		}

		// Check for instruction patterns in decoded content
		for _, pattern := range s.patterns {
			if pattern.MatchString(decodedStr) {
				result.Findings = append(result.Findings, Finding{
					Line:     lineNum,
					Type:     TypeBase64Payload,
					Severity: SeverityHigh,
					Message:  "Base64-encoded instruction-like content",
					Content:  truncate(decodedStr, 80),
				})
				break
			}
		}
	}
}

// Helper functions

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func isHomoglyph(r rune) bool {
	// Common Cyrillic/Greek lookalikes for Latin letters
	// This is a subset - full homoglyph detection would need a comprehensive table
	homoglyphs := map[rune]bool{
		'а': true, 'е': true, 'о': true, 'р': true, 'с': true, 'у': true, 'х': true, // Cyrillic
		'Α': true, 'Β': true, 'Ε': true, 'Η': true, 'Ι': true, 'Κ': true, 'Μ': true, // Greek
		'Ν': true, 'Ο': true, 'Ρ': true, 'Τ': true, 'Υ': true, 'Χ': true, 'Ζ': true,
	}
	return homoglyphs[r]
}

func isPrintable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func extractDomain(text string) string {
	// Simple domain extraction
	text = strings.TrimPrefix(text, "http://")
	text = strings.TrimPrefix(text, "https://")
	text = strings.TrimPrefix(text, "www.")
	if idx := strings.Index(text, "/"); idx > 0 {
		text = text[:idx]
	}
	return text
}
