// Package scanner provides file integrity scanning functionality
package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// FileInfo represents metadata and hash of a monitored file
type FileInfo struct {
	Path       string      `json:"path"`
	Hash       string      `json:"hash"`
	Size       int64       `json:"size"`
	Mode       os.FileMode `json:"mode"`
	ModTime    time.Time   `json:"mod_time"`
	Owner      int         `json:"owner"`
	Group      int         `json:"group"`
	Codesigned bool        `json:"codesigned,omitempty"`
	SignedBy   string      `json:"signed_by,omitempty"`
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

// Change represents a detected file change
type Change struct {
	Path     string   `json:"path"`
	Type     string   `json:"type"` // "added", "removed", "modified"
	Severity Severity `json:"severity"`
	Before   *FileInfo `json:"before,omitempty"`
	After    *FileInfo `json:"after,omitempty"`
	Details  string   `json:"details,omitempty"`
}

// Scanner scans files for changes
type Scanner struct {
	indicators []string
}

// New creates a new Scanner with default indicators
func New() *Scanner {
	return &Scanner{
		indicators: DefaultIndicators(),
	}
}

// DefaultIndicators returns the default macOS paths to monitor
func DefaultIndicators() []string {
	home, _ := os.UserHomeDir()
	
	return []string{
		// System binaries
		"/usr/bin",
		"/usr/sbin",
		"/bin",
		"/sbin",
		
		// Persistence mechanisms (CRITICAL)
		"/Library/LaunchDaemons",
		"/Library/LaunchAgents",
		filepath.Join(home, "Library/LaunchAgents"),
		
		// System configuration
		"/etc/pam.d",
		"/etc/sudoers",
		"/etc/sudoers.d",
		"/etc/ssh",
		"/etc/hosts",
		
		// SSH keys
		filepath.Join(home, ".ssh/authorized_keys"),
		filepath.Join(home, ".ssh/config"),
		
		// Browser extensions (common locations)
		filepath.Join(home, "Library/Application Support/Google/Chrome/Default/Extensions"),
		filepath.Join(home, "Library/Application Support/Firefox/Profiles"),
		filepath.Join(home, "Library/Safari/Extensions"),
		
		// Homebrew binaries
		"/opt/homebrew/bin",
		"/usr/local/bin",
	}
}

// HashFile computes SHA-256 hash of a file
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// ScanFile gathers info about a single file
func ScanFile(path string) (*FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	// Only hash regular files
	var hash string
	if info.Mode().IsRegular() {
		hash, err = HashFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to hash %s: %w", path, err)
		}
	}

	return &FileInfo{
		Path:    path,
		Hash:    hash,
		Size:    info.Size(),
		Mode:    info.Mode(),
		ModTime: info.ModTime(),
		// TODO: Get owner/group from syscall
	}, nil
}

// ScanDirectory recursively scans a directory
func (s *Scanner) ScanDirectory(root string) (map[string]*FileInfo, error) {
	files := make(map[string]*FileInfo)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Log but continue on permission errors
			if os.IsPermission(err) {
				return nil
			}
			return err
		}

		// Skip directories themselves, just scan files
		if info.IsDir() {
			return nil
		}

		fileInfo, err := ScanFile(path)
		if err != nil {
			// Log but continue
			return nil
		}

		files[path] = fileInfo
		return nil
	})

	return files, err
}

// Scan performs a full scan of all indicators
func (s *Scanner) Scan() (map[string]*FileInfo, error) {
	allFiles := make(map[string]*FileInfo)

	for _, indicator := range s.indicators {
		info, err := os.Stat(indicator)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			continue
		}

		if info.IsDir() {
			files, err := s.ScanDirectory(indicator)
			if err != nil {
				continue
			}
			for path, fileInfo := range files {
				allFiles[path] = fileInfo
			}
		} else {
			fileInfo, err := ScanFile(indicator)
			if err != nil {
				continue
			}
			allFiles[indicator] = fileInfo
		}
	}

	return allFiles, nil
}

// Compare compares current scan to baseline and returns changes
func Compare(baseline, current map[string]*FileInfo) []Change {
	var changes []Change

	// Check for removed and modified files
	for path, baseInfo := range baseline {
		curInfo, exists := current[path]
		if !exists {
			changes = append(changes, Change{
				Path:     path,
				Type:     "removed",
				Severity: classifySeverity(path, "removed"),
				Before:   baseInfo,
			})
			continue
		}

		// Check for modifications
		if baseInfo.Hash != curInfo.Hash {
			changes = append(changes, Change{
				Path:     path,
				Type:     "modified",
				Severity: classifySeverity(path, "modified"),
				Before:   baseInfo,
				After:    curInfo,
				Details:  "hash changed",
			})
		} else if baseInfo.Mode != curInfo.Mode {
			changes = append(changes, Change{
				Path:     path,
				Type:     "modified",
				Severity: SeverityWarning,
				Before:   baseInfo,
				After:    curInfo,
				Details:  "permissions changed",
			})
		}
	}

	// Check for new files
	for path, curInfo := range current {
		if _, exists := baseline[path]; !exists {
			changes = append(changes, Change{
				Path:     path,
				Type:     "added",
				Severity: classifySeverity(path, "added"),
				After:    curInfo,
			})
		}
	}

	return changes
}

// classifySeverity determines severity based on path and change type
func classifySeverity(path string, changeType string) Severity {
	// LaunchDaemons and LaunchAgents are critical
	if filepath.Dir(path) == "/Library/LaunchDaemons" ||
		filepath.Dir(path) == "/Library/LaunchAgents" ||
		filepath.Base(filepath.Dir(path)) == "LaunchAgents" {
		return SeverityCritical
	}

	// System binaries modifications are critical
	if filepath.HasPrefix(path, "/usr/bin") ||
		filepath.HasPrefix(path, "/usr/sbin") ||
		filepath.HasPrefix(path, "/bin") ||
		filepath.HasPrefix(path, "/sbin") {
		if changeType == "modified" {
			return SeverityCritical
		}
		return SeverityWarning
	}

	// sudoers and PAM are critical
	if filepath.HasPrefix(path, "/etc/sudoers") ||
		filepath.HasPrefix(path, "/etc/pam.d") {
		return SeverityCritical
	}

	// SSH authorized_keys changes are critical
	if filepath.Base(path) == "authorized_keys" {
		return SeverityCritical
	}

	// Browser extensions are warnings
	if filepath.Contains(path, "Extensions") ||
		filepath.Contains(path, "Profiles") {
		return SeverityWarning
	}

	return SeverityInfo
}
