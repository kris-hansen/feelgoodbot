package scanner

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSeverityString(t *testing.T) {
	tests := []struct {
		severity Severity
		want     string
	}{
		{SeverityInfo, "INFO"},
		{SeverityWarning, "WARNING"},
		{SeverityCritical, "CRITICAL"},
		{Severity(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		if got := tt.severity.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

func TestSeverityEmoji(t *testing.T) {
	tests := []struct {
		severity Severity
		want     string
	}{
		{SeverityInfo, "ℹ️"},
		{SeverityWarning, "⚠️"},
		{SeverityCritical, "🚨"},
		{Severity(99), "❓"},
	}

	for _, tt := range tests {
		if got := tt.severity.Emoji(); got != tt.want {
			t.Errorf("Severity(%d).Emoji() = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

func TestHashFile(t *testing.T) {
	// Create temp file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")

	if err := os.WriteFile(testFile, []byte("hello world"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	hash, err := HashFile(testFile)
	if err != nil {
		t.Fatalf("HashFile() error = %v", err)
	}

	// SHA-256 of "hello world"
	expected := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if hash != expected {
		t.Errorf("HashFile() = %q, want %q", hash, expected)
	}
}

func TestHashFileNotFound(t *testing.T) {
	_, err := HashFile("/nonexistent/file")
	if err == nil {
		t.Error("HashFile() should error for nonexistent file")
	}
}

func TestScanFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")

	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	fi, err := ScanFile(testFile, false)
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if fi.Path != testFile {
		t.Errorf("Path = %q, want %q", fi.Path, testFile)
	}
	if fi.Size != 12 {
		t.Errorf("Size = %d, want 12", fi.Size)
	}
	if fi.Hash == "" || fi.Hash == "UNREADABLE" {
		t.Error("Hash should be computed")
	}
	if fi.IsSymlink {
		t.Error("IsSymlink should be false for regular file")
	}
}

func TestScanFileSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	realFile := filepath.Join(tmpDir, "real.txt")
	symlink := filepath.Join(tmpDir, "link.txt")

	if err := os.WriteFile(realFile, []byte("content"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}
	if err := os.Symlink(realFile, symlink); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	fi, err := ScanFile(symlink, false)
	if err != nil {
		t.Fatalf("ScanFile() error = %v", err)
	}

	if !fi.IsSymlink {
		t.Error("IsSymlink should be true")
	}
	if fi.SymlinkDest != realFile {
		t.Errorf("SymlinkDest = %q, want %q", fi.SymlinkDest, realFile)
	}
}

func TestCompare(t *testing.T) {
	now := time.Now()

	baseline := map[string]*FileInfo{
		"/unchanged": {Path: "/unchanged", Hash: "abc123", Size: 100, ModTime: now},
		"/modified":  {Path: "/modified", Hash: "old", Size: 100, ModTime: now},
		"/removed":   {Path: "/removed", Hash: "xyz", Size: 50, ModTime: now},
		"/perms":     {Path: "/perms", Hash: "same", Size: 100, Mode: 0644, ModTime: now},
	}

	current := map[string]*FileInfo{
		"/unchanged": {Path: "/unchanged", Hash: "abc123", Size: 100, ModTime: now},
		"/modified":  {Path: "/modified", Hash: "new", Size: 100, ModTime: now},
		"/added":     {Path: "/added", Hash: "new123", Size: 200, ModTime: now},
		"/perms":     {Path: "/perms", Hash: "same", Size: 100, Mode: 0755, ModTime: now},
	}

	changes := Compare(baseline, current)

	// Should have 4 changes: modified, removed, added, perms changed
	if len(changes) != 4 {
		t.Errorf("Compare() returned %d changes, want 4", len(changes))
	}

	// Check each change type exists
	types := make(map[string]bool)
	for _, c := range changes {
		types[c.Path] = true
	}

	if !types["/modified"] {
		t.Error("missing modified change")
	}
	if !types["/removed"] {
		t.Error("missing removed change")
	}
	if !types["/added"] {
		t.Error("missing added change")
	}
	if !types["/perms"] {
		t.Error("missing permissions change")
	}
}

func TestClassifySeverity(t *testing.T) {
	tests := []struct {
		path       string
		changeType string
		want       Severity
	}{
		{"/Library/LaunchDaemons/evil.plist", "added", SeverityCritical},
		{"/Library/LaunchAgents/agent.plist", "added", SeverityCritical},
		{"/usr/bin/ssh", "modified", SeverityCritical},
		{"/usr/bin/newbinary", "added", SeverityWarning},
		{"~/.ssh/authorized_keys", "modified", SeverityCritical},
		{"/etc/sudoers", "modified", SeverityCritical},
		{"~/.bashrc", "modified", SeverityWarning},
		{"/random/file.txt", "modified", SeverityInfo},
	}

	for _, tt := range tests {
		got := classifySeverity(tt.path, tt.changeType)
		if got != tt.want {
			t.Errorf("classifySeverity(%q, %q) = %v, want %v", tt.path, tt.changeType, got, tt.want)
		}
	}
}

func TestClassifyCategory(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/usr/bin/ssh", "system_binaries"},
		{"/Library/LaunchDaemons/daemon.plist", "persistence"},
		{"/etc/sudoers", "privilege_escalation"},
		{"~/.ssh/config", "ssh"},
		{"~/.bashrc", "shell_config"},
		{"/opt/homebrew/bin/brew", "package_managers"},
		{"/random/file", "other"},
	}

	for _, tt := range tests {
		got := classifyCategory(tt.path)
		if got != tt.want {
			t.Errorf("classifyCategory(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestHasCriticalChanges(t *testing.T) {
	changesWithCritical := []Change{
		{Severity: SeverityInfo},
		{Severity: SeverityCritical},
	}

	changesWithoutCritical := []Change{
		{Severity: SeverityInfo},
		{Severity: SeverityWarning},
	}

	if !HasCriticalChanges(changesWithCritical) {
		t.Error("HasCriticalChanges() should return true")
	}

	if HasCriticalChanges(changesWithoutCritical) {
		t.Error("HasCriticalChanges() should return false")
	}
}

func TestFilterBySeverity(t *testing.T) {
	changes := []Change{
		{Path: "/info", Severity: SeverityInfo},
		{Path: "/warn", Severity: SeverityWarning},
		{Path: "/crit", Severity: SeverityCritical},
	}

	// Filter warnings and above
	filtered := FilterBySeverity(changes, SeverityWarning)
	if len(filtered) != 2 {
		t.Errorf("FilterBySeverity(Warning) returned %d, want 2", len(filtered))
	}

	// Filter critical only
	filtered = FilterBySeverity(changes, SeverityCritical)
	if len(filtered) != 1 {
		t.Errorf("FilterBySeverity(Critical) returned %d, want 1", len(filtered))
	}
}

func TestScannerNew(t *testing.T) {
	s := New()
	if s == nil {
		t.Fatal("New() returned nil")
	}
	if len(s.indicators) == 0 {
		t.Error("Scanner should have default indicators")
	}
}

func TestScannerWithVerbose(t *testing.T) {
	s := New(WithVerbose(true))
	if !s.verbose {
		t.Error("WithVerbose(true) should set verbose")
	}
}

func TestScanDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	// Create some files
	_ = os.WriteFile(filepath.Join(tmpDir, "file1.txt"), []byte("content1"), 0644)
	_ = os.WriteFile(filepath.Join(tmpDir, "file2.txt"), []byte("content2"), 0644)
	_ = os.MkdirAll(filepath.Join(tmpDir, "subdir"), 0755)
	_ = os.WriteFile(filepath.Join(tmpDir, "subdir", "file3.txt"), []byte("content3"), 0644)

	s := New()
	files, errors := s.ScanDirectory(tmpDir, false)

	if len(errors) != 0 {
		t.Errorf("unexpected errors: %v", errors)
	}

	if len(files) != 3 {
		t.Errorf("expected 3 files, got %d", len(files))
	}
}
