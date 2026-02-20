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
