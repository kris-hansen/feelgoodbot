// Package mdscanner provides skill directory scanning capabilities.
package mdscanner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// SkillScanResult contains findings from scanning an entire skill directory
type SkillScanResult struct {
	SkillPath   string                 `json:"skill_path"`
	Files       map[string]*ScanResult `json:"files"`
	TotalFiles  int                    `json:"total_files"`
	CleanFiles  int                    `json:"clean_files"`
	TotalIssues int                    `json:"total_issues"`
	Clean       bool                   `json:"clean"`
	Critical    int                    `json:"critical"`
	High        int                    `json:"high"`
	Medium      int                    `json:"medium"`
	Low         int                    `json:"low"`
}

// SupportedExtensions defines which file types to scan
var SupportedExtensions = map[string]bool{
	".md":   true,
	".sh":   true,
	".bash": true,
	".zsh":  true,
	".py":   true,
	".js":   true,
	".ts":   true,
	".rb":   true,
	".pl":   true,
	".ps1":  true,
	".bat":  true,
	".cmd":  true,
}

// ScanSkillDirectory scans an entire skill directory for threats
func (s *Scanner) ScanSkillDirectory(skillPath string) (*SkillScanResult, error) {
	result := &SkillScanResult{
		SkillPath: skillPath,
		Files:     make(map[string]*ScanResult),
	}

	// Verify directory exists
	info, err := os.Stat(skillPath)
	if err != nil {
		return nil, fmt.Errorf("cannot access skill path: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("skill path is not a directory: %s", skillPath)
	}

	// Walk the directory
	err = filepath.WalkDir(skillPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if d.IsDir() {
			// Skip hidden directories and common non-code dirs
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "node_modules" || name == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}

		// Check if we should scan this file
		ext := strings.ToLower(filepath.Ext(path))
		name := strings.ToLower(d.Name())

		// Always scan SKILL.md and similar
		shouldScan := SupportedExtensions[ext] ||
			name == "skill.md" ||
			name == "readme.md" ||
			name == "install.md" ||
			name == "setup.md"

		if !shouldScan {
			return nil
		}

		// Scan the file
		fileResult, scanErr := s.ScanFile(path)
		if scanErr != nil {
			// Log but don't fail on individual file errors
			result.Files[path] = &ScanResult{
				Findings: []Finding{{
					Line:     0,
					Type:     "scan_error",
					Severity: SeverityLow,
					Message:  fmt.Sprintf("Failed to scan: %v", scanErr),
				}},
				Clean: false,
			}
			return nil
		}

		result.Files[path] = fileResult
		result.TotalFiles++
		if fileResult.Clean {
			result.CleanFiles++
		}

		// Aggregate findings
		for _, f := range fileResult.Findings {
			result.TotalIssues++
			switch f.Severity {
			case SeverityCritical:
				result.Critical++
			case SeverityHigh:
				result.High++
			case SeverityMedium:
				result.Medium++
			case SeverityLow:
				result.Low++
			}
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking skill directory: %w", err)
	}

	result.Clean = result.TotalIssues == 0
	return result, nil
}

// ScanFile scans a single file for threats
func (s *Scanner) ScanFile(path string) (*ScanResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open file: %w", err)
	}
	defer f.Close()

	// Check file size - skip very large files
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot stat file: %w", err)
	}
	if info.Size() > 1<<20 { // 1MB limit
		return &ScanResult{
			Findings: []Finding{{
				Line:     0,
				Type:     "file_too_large",
				Severity: SeverityLow,
				Message:  fmt.Sprintf("File too large to scan: %d bytes", info.Size()),
			}},
			Clean: true, // Don't fail on large files
		}, nil
	}

	return s.ScanReader(f)
}

// FormatSkillResult returns a human-readable summary of skill scan results
func FormatSkillResult(r *SkillScanResult) string {
	var sb strings.Builder

	if r.Clean {
		sb.WriteString(fmt.Sprintf("✅ Skill scan clean: %s\n", r.SkillPath))
		sb.WriteString(fmt.Sprintf("   Scanned %d files, no issues found.\n", r.TotalFiles))
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("⚠️  Skill scan found issues: %s\n", r.SkillPath))
	sb.WriteString(fmt.Sprintf("   Scanned: %d files\n", r.TotalFiles))
	sb.WriteString(fmt.Sprintf("   Issues:  %d total", r.TotalIssues))

	if r.Critical > 0 {
		sb.WriteString(fmt.Sprintf(" (🚨 %d critical", r.Critical))
	}
	if r.High > 0 {
		if r.Critical > 0 {
			sb.WriteString(", ")
		} else {
			sb.WriteString(" (")
		}
		sb.WriteString(fmt.Sprintf("🔴 %d high", r.High))
	}
	if r.Medium > 0 {
		if r.Critical > 0 || r.High > 0 {
			sb.WriteString(", ")
		} else {
			sb.WriteString(" (")
		}
		sb.WriteString(fmt.Sprintf("🟡 %d medium", r.Medium))
	}
	if r.Low > 0 {
		if r.Critical > 0 || r.High > 0 || r.Medium > 0 {
			sb.WriteString(", ")
		} else {
			sb.WriteString(" (")
		}
		sb.WriteString(fmt.Sprintf("🟢 %d low", r.Low))
	}
	if r.Critical > 0 || r.High > 0 || r.Medium > 0 || r.Low > 0 {
		sb.WriteString(")")
	}
	sb.WriteString("\n\n")

	// List findings by file
	for path, fileResult := range r.Files {
		if fileResult.Clean {
			continue
		}

		relPath := path
		if strings.HasPrefix(path, r.SkillPath) {
			relPath = strings.TrimPrefix(path, r.SkillPath)
			relPath = strings.TrimPrefix(relPath, "/")
		}

		sb.WriteString(fmt.Sprintf("📄 %s:\n", relPath))
		for _, f := range fileResult.Findings {
			emoji := "❓"
			switch f.Severity {
			case SeverityCritical:
				emoji = "🚨"
			case SeverityHigh:
				emoji = "🔴"
			case SeverityMedium:
				emoji = "🟡"
			case SeverityLow:
				emoji = "🟢"
			}
			sb.WriteString(fmt.Sprintf("   %s Line %d: %s\n", emoji, f.Line, f.Message))
			if f.Content != "" {
				sb.WriteString(fmt.Sprintf("      → %s\n", f.Content))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
