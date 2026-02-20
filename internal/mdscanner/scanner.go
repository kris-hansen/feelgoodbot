// Package mdscanner detects potential prompt injection and supply chain attacks in markdown.
package mdscanner

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"unicode"
)

// Severity levels for findings
type Severity string

const (
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityCritical Severity = "critical"
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
	TypeShellInjection    FindingType = "shell_injection"
	TypeCredentialAccess  FindingType = "credential_access"
	TypeSecurityBypass    FindingType = "security_bypass"
	TypeStagedDelivery    FindingType = "staged_delivery"
	TypeSuspiciousURL     FindingType = "suspicious_url"
	TypeDataExfiltration  FindingType = "data_exfiltration"
	TypeKillChain         FindingType = "kill_chain"
	TypeCodeBlockThreat   FindingType = "code_block_threat"
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
	// CheckShellCommands enables shell injection detection
	CheckShellCommands bool
	// CheckCredentials enables credential access pattern detection
	CheckCredentials bool
	// CheckURLs enables suspicious URL detection
	CheckURLs bool
	// CustomPatterns adds additional instruction patterns to detect
	CustomPatterns []string
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	return &Config{
		MaxLineLength:      10000,
		CheckBase64:        true,
		CheckShellCommands: true,
		CheckCredentials:   true,
		CheckURLs:          true,
	}
}

// Scanner detects prompt injection in markdown
type Scanner struct {
	config              *Config
	patterns            []*regexp.Regexp
	shellPatterns       []*shellPattern
	credentialPatterns  []*credentialPattern
	securityBypass      []*regexp.Regexp
	stagedDelivery      []*regexp.Regexp
	exfiltrationPattern []*regexp.Regexp
	killChainPatterns   []*regexp.Regexp
	suspiciousTLDs      map[string]bool
	inCodeBlock         bool
	codeBlockLang       string
	codeBlockStart      int
	codeBlockContent    strings.Builder
}

type shellPattern struct {
	pattern *regexp.Regexp
	message string
}

type credentialPattern struct {
	pattern *regexp.Regexp
	message string
}

// New creates a scanner with the given config
func New(cfg *Config) *Scanner {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	s := &Scanner{
		config: cfg,
		suspiciousTLDs: map[string]bool{
			".tk": true, ".ml": true, ".ga": true, ".cf": true, ".gq": true,
			".top": true, ".xyz": true, ".pw": true, ".cc": true, ".su": true,
		},
	}
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

	// Shell injection patterns
	s.shellPatterns = []*shellPattern{
		// Pipe to shell
		{regexp.MustCompile(`(?i)curl\s+[^|]*\|\s*(sh|bash|zsh|dash|ksh)`), "curl piped to shell"},
		{regexp.MustCompile(`(?i)wget\s+[^|]*\|\s*(sh|bash|zsh|dash|ksh)`), "wget piped to shell"},
		{regexp.MustCompile(`(?i)curl\s+[^|]*\|\s*sudo\s+(sh|bash)`), "curl piped to sudo shell"},
		// Download and execute
		{regexp.MustCompile(`(?i)wget\s+.*&&\s*chmod\s+\+x`), "wget with chmod +x"},
		{regexp.MustCompile(`(?i)curl\s+.*-o\s+\S+.*&&\s*chmod`), "curl download with chmod"},
		{regexp.MustCompile(`(?i)curl\s+.*>\s*\S+\.sh.*&&`), "curl redirect to script"},
		// Eval patterns
		{regexp.MustCompile(`(?i)eval\s*["\']?\$\(`), "eval with command substitution"},
		{regexp.MustCompile(`(?i)eval\s*["\']?\` + "`"), "eval with backticks"},
		{regexp.MustCompile(`(?i)\$\(\s*curl`), "command substitution with curl"},
		// Base64 decode to shell
		{regexp.MustCompile(`(?i)base64\s+(-d|--decode)\s*\|`), "base64 decode piped"},
		{regexp.MustCompile(`(?i)echo\s+.*\|\s*base64\s+(-d|--decode)\s*\|\s*(sh|bash)`), "echo base64 decode to shell"},
		// Bash networking
		{regexp.MustCompile(`/dev/tcp/`), "bash /dev/tcp networking"},
		{regexp.MustCompile(`/dev/udp/`), "bash /dev/udp networking"},
		// Reverse shells
		{regexp.MustCompile(`(?i)nc\s+(-e|-c)\s`), "netcat with execute flag"},
		{regexp.MustCompile(`(?i)ncat\s+(-e|-c)\s`), "ncat with execute flag"},
		{regexp.MustCompile(`(?i)bash\s+-i\s+>&`), "bash interactive redirect (reverse shell)"},
		{regexp.MustCompile(`(?i)python[23]?\s+-c\s*['"]\s*import\s+(socket|subprocess|os)`), "python inline with dangerous imports"},
		{regexp.MustCompile(`(?i)perl\s+-e\s*['"].*socket`), "perl inline socket"},
		{regexp.MustCompile(`(?i)ruby\s+-rsocket\s+-e`), "ruby socket inline"},
		// Process manipulation
		{regexp.MustCompile(`(?i)pkill\s+(-9\s+)?`), "process kill command"},
		{regexp.MustCompile(`(?i)killall\s+`), "killall command"},
		// Disk operations
		{regexp.MustCompile(`(?i)rm\s+(-rf?|--recursive)\s+[/~]`), "recursive delete from root or home"},
		{regexp.MustCompile(`(?i)dd\s+if=.*of=/dev/`), "dd to device"},
		{regexp.MustCompile(`(?i)mkfs\s`), "filesystem format command"},
		// Cron/persistence
		{regexp.MustCompile(`(?i)crontab\s+(-e|-r|-)?\s*<<`), "crontab heredoc"},
		{regexp.MustCompile(`(?i)echo\s+.*>>\s*/etc/cron`), "append to cron"},
		// Password/sudo tricks
		{regexp.MustCompile(`(?i)echo\s+.*\|\s*sudo\s+-S`), "echo password to sudo"},
		{regexp.MustCompile(`(?i)sudo\s+.*<<<`), "sudo with herestring"},
	}

	// Credential access patterns
	s.credentialPatterns = []*credentialPattern{
		// SSH keys
		{regexp.MustCompile(`(?i)(cat|less|more|head|tail|cp|scp|rsync)\s+.*~?/?\.ssh/(id_|authorized_keys|known_hosts)`), "SSH key access"},
		{regexp.MustCompile(`(?i)~/.ssh/id_(rsa|dsa|ecdsa|ed25519)`), "reference to SSH private key"},
		// Environment files
		{regexp.MustCompile(`(?i)(cat|source|\.)\s+.*\.env\b`), ".env file access"},
		{regexp.MustCompile(`(?i)export\s+.*=.*\$\(cat.*\.env`), ".env export pattern"},
		// API keys and tokens
		{regexp.MustCompile(`(?i)\$\{?(OPENAI|ANTHROPIC|CLAUDE|GITHUB|AWS|GCP|AZURE|STRIPE|TWILIO|SENDGRID)_?(API)?_?(KEY|TOKEN|SECRET)\}?`), "API key environment variable"},
		{regexp.MustCompile(`(?i)echo\s+\$\{?(API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIALS)\}?`), "echoing sensitive env var"},
		{regexp.MustCompile(`(?i)printenv\s+(API|SECRET|TOKEN|KEY|PASSWORD|CRED)`), "printenv sensitive variable"},
		// Config files
		{regexp.MustCompile(`(?i)(cat|less|more)\s+.*(\.aws/credentials|\.npmrc|\.pypirc|\.netrc|\.docker/config)`), "credential config file access"},
		{regexp.MustCompile(`(?i)~/.aws/(credentials|config)`), "AWS credentials reference"},
		{regexp.MustCompile(`(?i)~/.kube/config`), "Kubernetes config reference"},
		{regexp.MustCompile(`(?i)/etc/(passwd|shadow|sudoers)`), "system auth file reference"},
		// Keychain
		{regexp.MustCompile(`(?i)security\s+(find|dump|delete)-(generic|internet)-password`), "macOS keychain access"},
		{regexp.MustCompile(`(?i)keychain|KeyChain`), "keychain reference"},
		// Git credentials
		{regexp.MustCompile(`(?i)git\s+config\s+.*credential`), "git credential config"},
		{regexp.MustCompile(`(?i)\.git-credentials`), "git credentials file"},
		// Browser data
		{regexp.MustCompile(`(?i)(Chrome|Firefox|Safari).*Cookies`), "browser cookies reference"},
		{regexp.MustCompile(`(?i)Login\s*Data|logins\.json`), "browser login data"},
	}

	// Security bypass patterns
	s.securityBypass = []*regexp.Regexp{
		regexp.MustCompile(`(?i)xattr\s+(-[rd]|--remove)\s*.*quarantine`),
		regexp.MustCompile(`(?i)xattr\s+-c\s`),
		regexp.MustCompile(`(?i)spctl\s+--master-disable`),
		regexp.MustCompile(`(?i)csrutil\s+disable`),
		regexp.MustCompile(`(?i)SIP.*disable`),
		regexp.MustCompile(`(?i)setenforce\s+0`),
		regexp.MustCompile(`(?i)iptables\s+-F`),
		regexp.MustCompile(`(?i)ufw\s+disable`),
		regexp.MustCompile(`(?i)systemctl\s+(stop|disable)\s+(firewalld|apparmor|selinux)`),
		regexp.MustCompile(`(?i)Set-MpPreference\s+-DisableRealtimeMonitoring`),
		regexp.MustCompile(`(?i)powershell.*-ExecutionPolicy\s+Bypass`),
		regexp.MustCompile(`(?i)--no-sandbox`),
		regexp.MustCompile(`(?i)TCC.*reset`),
	}

	// Staged delivery patterns
	s.stagedDelivery = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(install|download)\s+(the\s+)?(required\s+)?prerequisite`),
		regexp.MustCompile(`(?i)first\s*,?\s*(install|download|run)\s+`),
		regexp.MustCompile(`(?i)required\s+dependency.*http`),
		regexp.MustCompile(`(?i)(click|go\s+to)\s+(here|this\s+link)\s+to\s+(install|download)`),
		regexp.MustCompile(`(?i)download\s+and\s+(run|execute|install)`),
		regexp.MustCompile(`(?i)run\s+this\s+(command|script)\s+first`),
		regexp.MustCompile(`(?i)paste\s+(this\s+)?(in|into)\s+(your\s+)?(terminal|shell|command)`),
	}

	// Data exfiltration patterns
	s.exfiltrationPattern = []*regexp.Regexp{
		regexp.MustCompile(`(?i)curl\s+.*(-X\s*POST|-d\s|--data)`),
		regexp.MustCompile(`(?i)curl\s+.*-F\s`),
		regexp.MustCompile(`(?i)wget\s+--post`),
		regexp.MustCompile(`(?i)nc\s+.*<\s*`),
		regexp.MustCompile(`(?i)requests\.(post|put)\s*\(`),
		regexp.MustCompile(`(?i)fetch\s*\([^)]*method:\s*['"]POST`),
		regexp.MustCompile(`(?i)http\.request.*POST`),
		regexp.MustCompile(`(?i)upload.*curl|curl.*upload`),
		regexp.MustCompile(`(?i)webhook\.site|requestbin\.com|hookbin\.com|pipedream\.net`),
		regexp.MustCompile(`(?i)ngrok\.io|localtunnel\.me`),
		regexp.MustCompile(`(?i)discord\.com/api/webhooks`),
		regexp.MustCompile(`(?i)api\.telegram\.org/bot`),
	}

	// Kill chain patterns (download -> make executable -> run)
	s.killChainPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(curl|wget).*&&.*chmod.*&&.*(\.\/|sh|bash)`),
		regexp.MustCompile(`(?i)(curl|wget).*;.*chmod.*;.*(\.\/|sh|bash)`),
		regexp.MustCompile(`(?i)download.*install.*run`),
	}
}

// ScanReader scans markdown from an io.Reader
func (s *Scanner) ScanReader(r io.Reader) (*ScanResult, error) {
	result := &ScanResult{
		Findings: []Finding{},
	}

	scanner := bufio.NewScanner(r)
	lineNum := 0

	// Reset code block state
	s.inCodeBlock = false
	s.codeBlockContent.Reset()

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Truncate very long lines for performance
		if len(line) > s.config.MaxLineLength {
			line = line[:s.config.MaxLineLength]
		}

		// Handle code block boundaries
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			s.handleCodeBlockBoundary(line, lineNum, result)
			continue
		}

		// If inside code block, accumulate content
		if s.inCodeBlock {
			s.codeBlockContent.WriteString(line)
			s.codeBlockContent.WriteString("\n")
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

// handleCodeBlockBoundary processes code block start/end markers
func (s *Scanner) handleCodeBlockBoundary(line string, lineNum int, result *ScanResult) {
	trimmed := strings.TrimSpace(line)

	if !s.inCodeBlock {
		// Starting a code block
		s.inCodeBlock = true
		s.codeBlockStart = lineNum
		s.codeBlockContent.Reset()

		// Extract language
		lang := strings.TrimPrefix(trimmed, "```")
		s.codeBlockLang = strings.ToLower(strings.TrimSpace(lang))
	} else {
		// Ending a code block - analyze accumulated content
		s.analyzeCodeBlock(lineNum, result)
		s.inCodeBlock = false
		s.codeBlockLang = ""
		s.codeBlockContent.Reset()
	}
}

// analyzeCodeBlock performs deep analysis on completed code blocks
func (s *Scanner) analyzeCodeBlock(_ int, result *ScanResult) {
	content := s.codeBlockContent.String()

	// Check for shell-like code blocks
	isShell := s.codeBlockLang == "sh" || s.codeBlockLang == "bash" ||
		s.codeBlockLang == "zsh" || s.codeBlockLang == "shell" ||
		s.codeBlockLang == "" // Unmarked blocks are suspicious too

	if isShell || s.codeBlockLang == "" {
		// Check for kill chain patterns (multi-line sequences)
		for _, pattern := range s.killChainPatterns {
			if pattern.MatchString(content) {
				result.Findings = append(result.Findings, Finding{
					Line:     s.codeBlockStart,
					Type:     TypeKillChain,
					Severity: SeverityCritical,
					Message:  "Kill chain detected: download → chmod → execute sequence",
					Content:  truncate(content, 150),
				})
			}
		}

		// Check for multiple dangerous operations in same block
		dangerCount := 0
		var dangerOps []string

		for _, sp := range s.shellPatterns {
			if sp.pattern.MatchString(content) {
				dangerCount++
				dangerOps = append(dangerOps, sp.message)
			}
		}

		if dangerCount >= 2 {
			result.Findings = append(result.Findings, Finding{
				Line:     s.codeBlockStart,
				Type:     TypeCodeBlockThreat,
				Severity: SeverityHigh,
				Message:  fmt.Sprintf("Code block contains %d dangerous operations: %s", dangerCount, strings.Join(dangerOps, ", ")),
				Content:  truncate(content, 150),
			})
		}
	}
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

	// 8. Check for shell injection patterns
	if s.config.CheckShellCommands {
		s.checkShellPatterns(line, lineNum, result)
	}

	// 9. Check for credential access patterns
	if s.config.CheckCredentials {
		s.checkCredentialPatterns(line, lineNum, result)
	}

	// 10. Check for security bypass patterns
	s.checkSecurityBypass(line, lineNum, result)

	// 11. Check for staged delivery patterns
	s.checkStagedDelivery(line, lineNum, result)

	// 12. Check for data exfiltration patterns
	s.checkExfiltration(line, lineNum, result)

	// 13. Check for suspicious URLs
	if s.config.CheckURLs {
		s.checkSuspiciousURLs(line, lineNum, result)
	}
}

// checkShellPatterns detects dangerous shell command patterns
func (s *Scanner) checkShellPatterns(line string, lineNum int, result *ScanResult) {
	for _, sp := range s.shellPatterns {
		if sp.pattern.MatchString(line) {
			severity := SeverityHigh
			// Escalate certain patterns to critical
			if strings.Contains(sp.message, "reverse shell") ||
				strings.Contains(sp.message, "piped to shell") ||
				strings.Contains(sp.message, "piped to sudo") {
				severity = SeverityCritical
			}

			result.Findings = append(result.Findings, Finding{
				Line:     lineNum,
				Type:     TypeShellInjection,
				Severity: severity,
				Message:  sp.message,
				Content:  truncate(line, 100),
			})
		}
	}
}

// checkCredentialPatterns detects credential access patterns
func (s *Scanner) checkCredentialPatterns(line string, lineNum int, result *ScanResult) {
	for _, cp := range s.credentialPatterns {
		if cp.pattern.MatchString(line) {
			result.Findings = append(result.Findings, Finding{
				Line:     lineNum,
				Type:     TypeCredentialAccess,
				Severity: SeverityHigh,
				Message:  cp.message,
				Content:  truncate(line, 100),
			})
		}
	}
}

// checkSecurityBypass detects attempts to disable security controls
func (s *Scanner) checkSecurityBypass(line string, lineNum int, result *ScanResult) {
	for _, pattern := range s.securityBypass {
		if pattern.MatchString(line) {
			result.Findings = append(result.Findings, Finding{
				Line:     lineNum,
				Type:     TypeSecurityBypass,
				Severity: SeverityCritical,
				Message:  "Security control bypass detected",
				Content:  truncate(line, 100),
			})
		}
	}
}

// checkStagedDelivery detects social engineering patterns for staged attacks
func (s *Scanner) checkStagedDelivery(line string, lineNum int, result *ScanResult) {
	for _, pattern := range s.stagedDelivery {
		if pattern.MatchString(line) {
			result.Findings = append(result.Findings, Finding{
				Line:     lineNum,
				Type:     TypeStagedDelivery,
				Severity: SeverityMedium,
				Message:  "Staged delivery pattern detected (social engineering)",
				Content:  truncate(line, 100),
			})
		}
	}
}

// checkExfiltration detects data exfiltration patterns
func (s *Scanner) checkExfiltration(line string, lineNum int, result *ScanResult) {
	for _, pattern := range s.exfiltrationPattern {
		if pattern.MatchString(line) {
			result.Findings = append(result.Findings, Finding{
				Line:     lineNum,
				Type:     TypeDataExfiltration,
				Severity: SeverityHigh,
				Message:  "Potential data exfiltration pattern",
				Content:  truncate(line, 100),
			})
		}
	}
}

// checkSuspiciousURLs detects risky URLs
func (s *Scanner) checkSuspiciousURLs(line string, lineNum int, result *ScanResult) {
	// Match URLs
	urlPattern := regexp.MustCompile(`https?://[^\s"'\)>\]]+`)
	urls := urlPattern.FindAllString(line, -1)

	for _, url := range urls {
		urlLower := strings.ToLower(url)

		// Check for raw IP addresses
		ipPattern := regexp.MustCompile(`https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
		if ipMatch := ipPattern.FindStringSubmatch(urlLower); len(ipMatch) > 1 {
			// Verify it's a valid IP
			if ip := net.ParseIP(ipMatch[1]); ip != nil {
				// Allow localhost/private ranges with lower severity
				if ip.IsLoopback() || ip.IsPrivate() {
					result.Findings = append(result.Findings, Finding{
						Line:     lineNum,
						Type:     TypeSuspiciousURL,
						Severity: SeverityLow,
						Message:  "URL uses raw IP address (local/private)",
						Content:  truncate(url, 80),
					})
				} else {
					result.Findings = append(result.Findings, Finding{
						Line:     lineNum,
						Type:     TypeSuspiciousURL,
						Severity: SeverityHigh,
						Message:  "URL uses raw IP address (public)",
						Content:  truncate(url, 80),
					})
				}
			}
		}

		// Check for suspicious TLDs
		for tld := range s.suspiciousTLDs {
			if strings.Contains(urlLower, tld+"/") || strings.HasSuffix(urlLower, tld) {
				result.Findings = append(result.Findings, Finding{
					Line:     lineNum,
					Type:     TypeSuspiciousURL,
					Severity: SeverityMedium,
					Message:  fmt.Sprintf("URL uses suspicious TLD: %s", tld),
					Content:  truncate(url, 80),
				})
				break
			}
		}

		// Check for URL shorteners
		shorteners := []string{
			"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
			"cli.gs", "pic.gd", "short.to", "shorturl.at", "cutt.ly",
		}
		for _, shortener := range shorteners {
			if strings.Contains(urlLower, shortener) {
				result.Findings = append(result.Findings, Finding{
					Line:     lineNum,
					Type:     TypeSuspiciousURL,
					Severity: SeverityMedium,
					Message:  "URL shortener detected (obscures destination)",
					Content:  truncate(url, 80),
				})
				break
			}
		}

		// Check for discord CDN (commonly abused)
		if strings.Contains(urlLower, "cdn.discordapp.com/attachments") {
			result.Findings = append(result.Findings, Finding{
				Line:     lineNum,
				Type:     TypeSuspiciousURL,
				Severity: SeverityMedium,
				Message:  "Discord CDN URL (commonly used for malware hosting)",
				Content:  truncate(url, 80),
			})
		}
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

		// Also check for shell patterns in decoded content
		for _, sp := range s.shellPatterns {
			if sp.pattern.MatchString(decodedStr) {
				result.Findings = append(result.Findings, Finding{
					Line:     lineNum,
					Type:     TypeBase64Payload,
					Severity: SeverityCritical,
					Message:  "Base64-encoded shell command: " + sp.message,
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
