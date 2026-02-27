// Package scanner provides file integrity scanning functionality
package scanner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kris-hansen/feelgoodbot/pkg/indicators"
)

// FileInfo represents metadata and hash of a monitored file
type FileInfo struct {
	Path        string      `json:"path"`
	Hash        string      `json:"hash"`
	Size        int64       `json:"size"`
	Mode        os.FileMode `json:"mode"`
	ModTime     time.Time   `json:"mod_time"`
	Owner       uint32      `json:"owner"`
	Group       uint32      `json:"group"`
	Codesigned  bool        `json:"codesigned,omitempty"`
	SignedBy    string      `json:"signed_by,omitempty"`
	IsSymlink   bool        `json:"is_symlink,omitempty"`
	SymlinkDest string      `json:"symlink_dest,omitempty"`
}

// Severity levels for detected changes
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityWarning
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityWarning:
		return "WARNING"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) Emoji() string {
	switch s {
	case SeverityInfo:
		return "ℹ️"
	case SeverityWarning:
		return "⚠️"
	case SeverityCritical:
		return "🚨"
	default:
		return "❓"
	}
}

// Change represents a detected file change
type Change struct {
	Path        string    `json:"path"`
	Type        string    `json:"type"` // "added", "removed", "modified"
	Severity    Severity  `json:"severity"`
	Category    string    `json:"category"`
	Before      *FileInfo `json:"before,omitempty"`
	After       *FileInfo `json:"after,omitempty"`
	Details     string    `json:"details,omitempty"`
	Description string    `json:"description,omitempty"`
}

// ScanResult contains the results of a scan
type ScanResult struct {
	StartTime    time.Time            `json:"start_time"`
	EndTime      time.Time            `json:"end_time"`
	FilesScanned int                  `json:"files_scanned"`
	Changes      []Change             `json:"changes"`
	Files        map[string]*FileInfo `json:"files"`
	Errors       []string             `json:"errors,omitempty"`
}

// Scanner scans files for changes
type Scanner struct {
	indicators []indicators.Indicator
	verbose    bool
}

// Option configures the scanner
type Option func(*Scanner)

// WithVerbose enables verbose output
func WithVerbose(v bool) Option {
	return func(s *Scanner) {
		s.verbose = v
	}
}

// WithIndicators sets custom indicators
func WithIndicators(inds []indicators.Indicator) Option {
	return func(s *Scanner) {
		s.indicators = inds
	}
}

// New creates a new Scanner with default indicators
func New(opts ...Option) *Scanner {
	s := &Scanner{
		indicators: indicators.DefaultIndicators(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// HashFile computes SHA-256 hash of a file
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// CheckCodesign verifies if a binary is properly code-signed
func CheckCodesign(path string) (signed bool, signer string) {
	cmd := exec.Command("codesign", "-dv", "--verbose=2", path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return false, ""
	}

	output := stderr.String()
	if strings.Contains(output, "Authority=") {
		// Extract signer
		for _, line := range strings.Split(output, "\n") {
			if strings.HasPrefix(line, "Authority=") {
				signer = strings.TrimPrefix(line, "Authority=")
				break
			}
		}
		return true, signer
	}

	return false, ""
}

// ScanFile gathers info about a single file
func ScanFile(path string, checkCodesign bool) (*FileInfo, error) {
	// Check for symlink first
	linfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}

	fi := &FileInfo{
		Path:    path,
		Size:    linfo.Size(),
		Mode:    linfo.Mode(),
		ModTime: linfo.ModTime(),
	}

	// Handle symlinks
	if linfo.Mode()&os.ModeSymlink != 0 {
		fi.IsSymlink = true
		dest, err := os.Readlink(path)
		if err == nil {
			fi.SymlinkDest = dest
		}
		// Hash the destination, not the link
		realPath, err := filepath.EvalSymlinks(path)
		if err == nil {
			path = realPath
			info, err := os.Stat(path)
			if err == nil {
				fi.Size = info.Size()
			}
		}
	}

	// Get owner/group (Unix)
	if stat, ok := linfo.Sys().(*syscall.Stat_t); ok {
		fi.Owner = stat.Uid
		fi.Group = stat.Gid
	}

	// Only hash regular files
	if linfo.Mode().IsRegular() || fi.IsSymlink {
		hash, err := HashFile(path)
		if err != nil {
			// Non-fatal, some files may be unreadable
			fi.Hash = "UNREADABLE"
		} else {
			fi.Hash = hash
		}
	}

	// Check code signature for executables
	if checkCodesign && isExecutable(path) {
		fi.Codesigned, fi.SignedBy = CheckCodesign(path)
	}

	return fi, nil
}

// isExecutable checks if a file looks like an executable
func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	// Check if it has execute permission
	if info.Mode()&0111 != 0 {
		return true
	}

	// Check for common executable extensions/patterns
	ext := strings.ToLower(filepath.Ext(path))
	return ext == "" || ext == ".app" || ext == ".dylib" || ext == ".so"
}

// ScanDirectory recursively scans a directory
func (s *Scanner) ScanDirectory(root string, checkCodesign bool) (map[string]*FileInfo, []string) {
	files := make(map[string]*FileInfo)
	var errors []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Log but continue on permission errors
			if os.IsPermission(err) {
				errors = append(errors, fmt.Sprintf("permission denied: %s", path))
				return nil
			}
			return nil // Skip other errors too
		}

		// Skip directories themselves, just scan files
		if info.IsDir() {
			return nil
		}

		fileInfo, err := ScanFile(path, checkCodesign)
		if err != nil {
			errors = append(errors, fmt.Sprintf("scan error: %s: %v", path, err))
			return nil
		}

		files[path] = fileInfo
		return nil
	})

	if err != nil {
		errors = append(errors, fmt.Sprintf("walk error: %s: %v", root, err))
	}

	return files, errors
}

// Scan performs a full scan of all indicators
func (s *Scanner) Scan() *ScanResult {
	result := &ScanResult{
		StartTime: time.Now(),
		Files:     make(map[string]*FileInfo),
	}

	for _, ind := range s.indicators {
		info, err := os.Stat(ind.Path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", ind.Path, err))
			continue
		}

		// Check if we should verify codesign (only for binaries)
		checkCodesign := ind.Category == "system_binaries" || ind.Category == "apps"

		switch {
		case info.IsDir() && ind.Recursive:
			files, errs := s.ScanDirectory(ind.Path, checkCodesign)
			result.Errors = append(result.Errors, errs...)
			for path, fileInfo := range files {
				result.Files[path] = fileInfo
			}
		case !info.IsDir():
			fileInfo, err := ScanFile(ind.Path, checkCodesign)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", ind.Path, err))
				continue
			}
			result.Files[ind.Path] = fileInfo
		case info.IsDir() && !ind.Recursive:
			// Non-recursive directory - just list top level
			entries, err := os.ReadDir(ind.Path)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", ind.Path, err))
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				fullPath := filepath.Join(ind.Path, entry.Name())
				fileInfo, err := ScanFile(fullPath, checkCodesign)
				if err != nil {
					continue
				}
				result.Files[fullPath] = fileInfo
			}
		}
	}

	result.EndTime = time.Now()
	result.FilesScanned = len(result.Files)
	return result
}

// Compare compares current scan to baseline and returns changes
func Compare(baseline, current map[string]*FileInfo) []Change {
	var changes []Change

	// Build indicator lookup for severity classification
	indLookup := make(map[string]indicators.Indicator)
	for _, ind := range indicators.DefaultIndicators() {
		indLookup[ind.Path] = ind
	}

	// Check for removed and modified files
	for path, baseInfo := range baseline {
		curInfo, exists := current[path]
		if !exists {
			changes = append(changes, Change{
				Path:        path,
				Type:        "removed",
				Severity:    classifySeverity(path, "removed"),
				Category:    classifyCategory(path),
				Before:      baseInfo,
				Details:     "file removed",
				Description: fmt.Sprintf("File removed: %s", path),
			})
			continue
		}

		// Check for modifications
		switch {
		case baseInfo.Hash != curInfo.Hash && baseInfo.Hash != "" && curInfo.Hash != "":
			changes = append(changes, Change{
				Path:        path,
				Type:        "modified",
				Severity:    classifySeverity(path, "modified"),
				Category:    classifyCategory(path),
				Before:      baseInfo,
				After:       curInfo,
				Details:     "content changed (hash mismatch)",
				Description: fmt.Sprintf("File modified: %s", path),
			})
		case baseInfo.Mode != curInfo.Mode:
			changes = append(changes, Change{
				Path:        path,
				Type:        "modified",
				Severity:    SeverityWarning,
				Category:    classifyCategory(path),
				Before:      baseInfo,
				After:       curInfo,
				Details:     fmt.Sprintf("permissions changed: %o -> %o", baseInfo.Mode, curInfo.Mode),
				Description: fmt.Sprintf("Permissions changed: %s", path),
			})
		case baseInfo.Owner != curInfo.Owner || baseInfo.Group != curInfo.Group:
			changes = append(changes, Change{
				Path:        path,
				Type:        "modified",
				Severity:    SeverityWarning,
				Category:    classifyCategory(path),
				Before:      baseInfo,
				After:       curInfo,
				Details:     fmt.Sprintf("ownership changed: %d:%d -> %d:%d", baseInfo.Owner, baseInfo.Group, curInfo.Owner, curInfo.Group),
				Description: fmt.Sprintf("Ownership changed: %s", path),
			})
		}
	}

	// Check for new files
	for path, curInfo := range current {
		if _, exists := baseline[path]; !exists {
			changes = append(changes, Change{
				Path:        path,
				Type:        "added",
				Severity:    classifySeverity(path, "added"),
				Category:    classifyCategory(path),
				After:       curInfo,
				Details:     "new file detected",
				Description: fmt.Sprintf("New file: %s", path),
			})
		}
	}

	return changes
}

// classifySeverity determines severity based on path and change type
func classifySeverity(path string, changeType string) Severity {
	// LaunchDaemons and LaunchAgents are always critical
	if strings.Contains(path, "LaunchDaemons") || strings.Contains(path, "LaunchAgents") {
		return SeverityCritical
	}

	// System binaries modifications are critical
	if strings.HasPrefix(path, "/usr/bin") ||
		strings.HasPrefix(path, "/usr/sbin") ||
		strings.HasPrefix(path, "/bin/") ||
		strings.HasPrefix(path, "/sbin/") {
		if changeType == "modified" || changeType == "removed" {
			return SeverityCritical
		}
		return SeverityWarning
	}

	// Kernel extensions are critical
	if strings.Contains(path, "/Extensions/") {
		return SeverityCritical
	}

	// sudoers and PAM are critical
	if strings.Contains(path, "sudoers") || strings.Contains(path, "pam.d") {
		return SeverityCritical
	}

	// SSH authorized_keys changes are critical
	if strings.Contains(path, "authorized_keys") {
		return SeverityCritical
	}

	// SSH config changes are warning
	if strings.Contains(path, ".ssh/") || strings.Contains(path, "/ssh/") {
		return SeverityWarning
	}

	// Shell configs are warning (could be injected)
	if strings.HasSuffix(path, "rc") || strings.HasSuffix(path, "profile") {
		return SeverityWarning
	}

	// Git hooks are warning
	if strings.Contains(path, "hooks/") {
		return SeverityWarning
	}

	// Browser extensions are warnings
	if strings.Contains(path, "Extensions") {
		return SeverityWarning
	}

	// AI agent configs - Clawdbot core files are critical
	if strings.Contains(path, "clawdbot") || strings.Contains(path, "/clawd/") {
		// Critical: personality, config, skills
		if strings.Contains(path, "SOUL.md") ||
			strings.Contains(path, "AGENTS.md") ||
			strings.Contains(path, "config.yaml") ||
			strings.Contains(path, "/skills/") {
			return SeverityCritical
		}
		return SeverityWarning
	}

	// Other AI agent configs are warnings
	if strings.Contains(path, "claude") || strings.Contains(path, "cursor") {
		return SeverityWarning
	}

	return SeverityInfo
}

// classifyCategory determines the category of a path
func classifyCategory(path string) string {
	switch {
	case strings.HasPrefix(path, "/usr/bin") || strings.HasPrefix(path, "/usr/sbin") ||
		strings.HasPrefix(path, "/bin/") || strings.HasPrefix(path, "/sbin/"):
		return "system_binaries"
	case strings.Contains(path, "LaunchDaemons") || strings.Contains(path, "LaunchAgents"):
		return "persistence"
	case strings.Contains(path, "sudoers") || strings.Contains(path, "pam.d"):
		return "privilege_escalation"
	case strings.Contains(path, ".ssh/") || strings.Contains(path, "/ssh/"):
		return "ssh"
	case strings.HasSuffix(path, "rc") || strings.HasSuffix(path, "profile"):
		return "shell_config"
	case strings.Contains(path, "homebrew"):
		return "package_managers"
	case strings.Contains(path, "node_modules") || strings.Contains(path, "npm"):
		return "npm"
	case strings.Contains(path, ".git/") || strings.Contains(path, "gitconfig"):
		return "git"
	case strings.Contains(path, "cron") || strings.Contains(path, "periodic"):
		return "cron"
	case strings.Contains(path, "Chrome") || strings.Contains(path, "Safari") || strings.Contains(path, "Firefox"):
		return "browser"
	case strings.Contains(path, "claude") || strings.Contains(path, "cursor") ||
		strings.Contains(path, "clawdbot") || strings.Contains(path, "/clawd/"):
		return "ai_agents"
	case strings.Contains(path, "/Extensions/"):
		return "kernel"
	default:
		return "other"
	}
}

// HasCriticalChanges returns true if any changes are critical severity
func HasCriticalChanges(changes []Change) bool {
	for _, c := range changes {
		if c.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// FilterBySeverity returns changes at or above the given severity
func FilterBySeverity(changes []Change, minSeverity Severity) []Change {
	var filtered []Change
	for _, c := range changes {
		if c.Severity >= minSeverity {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

// LoadIgnoreList reads the ignore list from ~/.config/feelgoodbot/ignore.txt
func LoadIgnoreList() (map[string]bool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	ignorePath := filepath.Join(home, ".config", "feelgoodbot", "ignore.txt")
	ignored := make(map[string]bool)

	data, err := os.ReadFile(ignorePath)
	if os.IsNotExist(err) {
		return ignored, nil // No ignore file is fine
	}
	if err != nil {
		return nil, err
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			ignored[line] = true
		}
	}

	return ignored, nil
}

// FilterIgnored removes changes for paths in the ignore list
func FilterIgnored(changes []Change, ignored map[string]bool) []Change {
	if len(ignored) == 0 {
		return changes
	}

	var filtered []Change
	for _, c := range changes {
		if !ignored[c.Path] {
			filtered = append(filtered, c)
		}
	}
	return filtered
}
