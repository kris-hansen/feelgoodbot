package snapshot

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kris-hansen/feelgoodbot/internal/scanner"
)

func TestNewStore(t *testing.T) {
	// NewStore uses user home dir by default, so we test it creates successfully
	store, err := NewStore()
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	if store == nil {
		t.Fatal("NewStore() returned nil")
	}
}

func TestStoreSaveAndLoadBaseline(t *testing.T) {
	// Create temp dir and override store's dir
	tmpDir := t.TempDir()
	store := &Store{dir: tmpDir}

	now := time.Now()
	files := map[string]*scanner.FileInfo{
		"/test/file1": {
			Path:    "/test/file1",
			Hash:    "abc123",
			Size:    100,
			ModTime: now,
		},
		"/test/file2": {
			Path:    "/test/file2",
			Hash:    "def456",
			Size:    200,
			ModTime: now,
		},
	}

	// Save baseline
	snap, err := store.SaveBaseline(files)
	if err != nil {
		t.Fatalf("SaveBaseline() error = %v", err)
	}

	if snap.ID == "" {
		t.Error("snapshot should have ID")
	}
	if snap.Checksum == "" {
		t.Error("snapshot should have checksum")
	}

	// Check file exists
	if !store.HasBaseline() {
		t.Error("HasBaseline() should return true after save")
	}

	// Load baseline
	loaded, err := store.LoadBaseline()
	if err != nil {
		t.Fatalf("LoadBaseline() error = %v", err)
	}

	if loaded.ID != snap.ID {
		t.Errorf("loaded ID = %q, want %q", loaded.ID, snap.ID)
	}
	if len(loaded.Files) != len(files) {
		t.Errorf("loaded Files count = %d, want %d", len(loaded.Files), len(files))
	}
}

func TestStoreHasBaselineEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	store := &Store{dir: tmpDir}

	if store.HasBaseline() {
		t.Error("HasBaseline() should return false when no baseline exists")
	}
}

func TestStoreLoadBaselineNonexistent(t *testing.T) {
	tmpDir := t.TempDir()
	store := &Store{dir: tmpDir}

	_, err := store.LoadBaseline()
	if err == nil {
		t.Error("LoadBaseline() should error when no baseline exists")
	}
}

func TestStoreIntegrityCheck(t *testing.T) {
	tmpDir := t.TempDir()
	store := &Store{dir: tmpDir}

	files := map[string]*scanner.FileInfo{
		"/test/file": {Path: "/test/file", Hash: "abc123"},
	}

	_, err := store.SaveBaseline(files)
	if err != nil {
		t.Fatalf("SaveBaseline() error = %v", err)
	}

	// Tamper with the file
	baselinePath := filepath.Join(tmpDir, "baseline.json")
	data, _ := os.ReadFile(baselinePath)
	tampered := make([]byte, len(data)-10)
	copy(tampered, data[:len(data)-10])
	tampered = append(tampered, []byte(`"tampered"}`)...)
	_ = os.WriteFile(baselinePath, tampered, 0600)

	// Load should fail integrity check
	_, err = store.LoadBaseline()
	if err == nil {
		t.Error("LoadBaseline() should error when integrity check fails")
	}
}

func TestStoreSaveDiff(t *testing.T) {
	tmpDir := t.TempDir()
	store := &Store{dir: tmpDir}

	changes := []scanner.Change{
		{
			Path:     "/test/modified",
			Type:     "modified",
			Severity: scanner.SeverityWarning,
		},
		{
			Path:     "/test/added",
			Type:     "added",
			Severity: scanner.SeverityInfo,
		},
	}

	err := store.SaveDiff(changes)
	if err != nil {
		t.Fatalf("SaveDiff() error = %v", err)
	}

	// Check a diff file was created
	entries, _ := os.ReadDir(tmpDir)
	found := false
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" && e.Name() != "baseline.json" {
			found = true
			break
		}
	}

	if !found {
		t.Error("SaveDiff() should create a diff file")
	}
}

func TestStoreSaveDiffEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	store := &Store{dir: tmpDir}

	// Empty changes should not create file
	err := store.SaveDiff([]scanner.Change{})
	if err != nil {
		t.Fatalf("SaveDiff() error = %v", err)
	}

	entries, _ := os.ReadDir(tmpDir)
	if len(entries) != 0 {
		t.Error("SaveDiff() with empty changes should not create file")
	}
}

// writeDiff creates a fake diff file with the given size and mod time
func writeDiff(t *testing.T, dir, name string, size int, modTime time.Time) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, make([]byte, size), 0600); err != nil {
		t.Fatalf("failed to write diff: %v", err)
	}
	if err := os.Chtimes(path, modTime, modTime); err != nil {
		t.Fatalf("failed to set mod time: %v", err)
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		input   string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"0", 0, false},
		{"1024", 1024, false},
		{"500KB", 500 * 1024, false},
		{"500MB", 500 * 1024 * 1024, false},
		{"1GB", 1 << 30, false},
		{"1.5GB", 3 << 29, false},
		{"2TB", 2 << 40, false},
		{"1gb", 1 << 30, false},
		{" 10 MB ", 10 << 20, false},
		{"abc", 0, true},
		{"-1GB", 0, true},
	}

	for _, tt := range tests {
		got, err := ParseSize(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseSize(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr && got != tt.want {
			t.Errorf("ParseSize(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestPruneByAge(t *testing.T) {
	tmpDir := t.TempDir()
	store := &Store{dir: tmpDir}

	now := time.Now()
	writeDiff(t, tmpDir, "diff_old.json", 100, now.Add(-48*time.Hour))
	writeDiff(t, tmpDir, "diff_new.json", 100, now.Add(-1*time.Hour))

	result, err := store.Prune(RetentionPolicy{MaxAge: 24 * time.Hour}, false)
	if err != nil {
		t.Fatalf("Prune() error = %v", err)
	}

	if result.RemovedFiles != 1 {
		t.Errorf("RemovedFiles = %d, want 1", result.RemovedFiles)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "diff_old.json")); !os.IsNotExist(err) {
		t.Error("old diff should have been removed")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "diff_new.json")); err != nil {
		t.Error("recent diff should have been kept")
	}
}

func TestPruneBySize(t *testing.T) {
	tmpDir := t.TempDir()
	store := &Store{dir: tmpDir}

	now := time.Now()
	writeDiff(t, tmpDir, "diff_a.json", 400, now.Add(-3*time.Hour))
	writeDiff(t, tmpDir, "diff_b.json", 400, now.Add(-2*time.Hour))
	writeDiff(t, tmpDir, "diff_c.json", 400, now.Add(-1*time.Hour))

	// Cap at 1000 bytes: oldest diff must go
	result, err := store.Prune(RetentionPolicy{MaxBytes: 1000}, false)
	if err != nil {
		t.Fatalf("Prune() error = %v", err)
	}

	if result.RemovedFiles != 1 {
		t.Errorf("RemovedFiles = %d, want 1", result.RemovedFiles)
	}
	if result.RemainingBytes > 1000 {
		t.Errorf("RemainingBytes = %d, want <= 1000", result.RemainingBytes)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "diff_a.json")); !os.IsNotExist(err) {
		t.Error("oldest diff should have been removed first")
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "diff_c.json")); err != nil {
		t.Error("newest diff should have been kept")
	}
}

func TestPruneNeverRemovesBaseline(t *testing.T) {
	tmpDir := t.TempDir()
	store := &Store{dir: tmpDir}

	files := map[string]*scanner.FileInfo{
		"/test/file": {Path: "/test/file", Hash: "abc123"},
	}
	if _, err := store.SaveBaseline(files); err != nil {
		t.Fatalf("SaveBaseline() error = %v", err)
	}
	writeDiff(t, tmpDir, "diff_x.json", 100, time.Now().Add(-time.Hour))

	// Impossible cap: even removing every diff can't satisfy it
	result, err := store.Prune(RetentionPolicy{MaxBytes: 1}, false)
	if err != nil {
		t.Fatalf("Prune() error = %v", err)
	}

	if !store.HasBaseline() {
		t.Fatal("baseline must never be pruned")
	}
	if result.RemovedFiles != 1 {
		t.Errorf("RemovedFiles = %d, want 1 (all diffs)", result.RemovedFiles)
	}
}

func TestPruneDryRun(t *testing.T) {
	tmpDir := t.TempDir()
	store := &Store{dir: tmpDir}

	writeDiff(t, tmpDir, "diff_old.json", 100, time.Now().Add(-48*time.Hour))

	result, err := store.Prune(RetentionPolicy{MaxAge: 24 * time.Hour}, true)
	if err != nil {
		t.Fatalf("Prune() error = %v", err)
	}

	if result.RemovedFiles != 1 {
		t.Errorf("dry run RemovedFiles = %d, want 1", result.RemovedFiles)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "diff_old.json")); err != nil {
		t.Error("dry run must not delete files")
	}
}

func TestPruneNoLimits(t *testing.T) {
	tmpDir := t.TempDir()
	store := &Store{dir: tmpDir}

	writeDiff(t, tmpDir, "diff_old.json", 100, time.Now().Add(-1000*time.Hour))

	result, err := store.Prune(RetentionPolicy{}, false)
	if err != nil {
		t.Fatalf("Prune() error = %v", err)
	}
	if result.RemovedFiles != 0 {
		t.Errorf("zero policy should remove nothing, removed %d", result.RemovedFiles)
	}
}

func TestDiskUsage(t *testing.T) {
	tmpDir := t.TempDir()
	store := &Store{dir: tmpDir}

	writeDiff(t, tmpDir, "diff_a.json", 100, time.Now())
	writeDiff(t, tmpDir, "diff_b.json", 200, time.Now())

	usage, count, err := store.DiskUsage()
	if err != nil {
		t.Fatalf("DiskUsage() error = %v", err)
	}
	if usage != 300 {
		t.Errorf("usage = %d, want 300", usage)
	}
	if count != 2 {
		t.Errorf("diff count = %d, want 2", count)
	}
}

func TestGenerateID(t *testing.T) {
	id1 := generateID()
	id2 := generateID()

	if id1 == "" {
		t.Error("generateID() returned empty string")
	}
	if len(id1) != 16 { // 8 bytes = 16 hex chars
		t.Errorf("generateID() returned wrong length: %d", len(id1))
	}

	// IDs should be unique (technically could fail but extremely unlikely)
	// Adding a small delay to ensure different nanosecond timestamps
	time.Sleep(time.Nanosecond)
	if id1 == id2 {
		t.Error("generateID() returned same ID twice")
	}
}

func TestCalculateChecksum(t *testing.T) {
	snap := &Snapshot{
		ID:        "test-id",
		CreatedAt: time.Now(),
		Files: map[string]*scanner.FileInfo{
			"/test": {Path: "/test", Hash: "abc"},
		},
	}

	checksum1 := calculateChecksum(snap)
	checksum2 := calculateChecksum(snap)

	if checksum1 == "" {
		t.Error("calculateChecksum() returned empty string")
	}
	if checksum1 != checksum2 {
		t.Error("calculateChecksum() should be deterministic")
	}

	// Modify snapshot and checksum should change
	snap.Files["/test2"] = &scanner.FileInfo{Path: "/test2", Hash: "def"}
	checksum3 := calculateChecksum(snap)

	if checksum1 == checksum3 {
		t.Error("calculateChecksum() should change when data changes")
	}
}
