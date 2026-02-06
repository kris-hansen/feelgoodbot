// Package snapshot manages baseline snapshots for file integrity
package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kris-hansen/feelgoodbot/internal/scanner"
)

// Snapshot represents a point-in-time capture of file states
type Snapshot struct {
	ID        string                        `json:"id"`
	CreatedAt time.Time                     `json:"created_at"`
	Files     map[string]*scanner.FileInfo  `json:"files"`
	Checksum  string                        `json:"checksum"` // integrity check
}

// Store manages snapshot persistence
type Store struct {
	dir string
}

// NewStore creates a new snapshot store
func NewStore() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	dir := filepath.Join(home, ".config", "feelgoodbot", "snapshots")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create snapshot directory: %w", err)
	}

	return &Store{dir: dir}, nil
}

// baselinePath returns the path to the baseline snapshot
func (s *Store) baselinePath() string {
	return filepath.Join(s.dir, "baseline.json")
}

// HasBaseline returns true if a baseline snapshot exists
func (s *Store) HasBaseline() bool {
	_, err := os.Stat(s.baselinePath())
	return err == nil
}

// SaveBaseline saves a new baseline snapshot
func (s *Store) SaveBaseline(files map[string]*scanner.FileInfo) (*Snapshot, error) {
	snap := &Snapshot{
		ID:        generateID(),
		CreatedAt: time.Now(),
		Files:     files,
	}

	// Calculate checksum for integrity
	snap.Checksum = calculateChecksum(snap)

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal snapshot: %w", err)
	}

	// Write with restrictive permissions
	if err := os.WriteFile(s.baselinePath(), data, 0600); err != nil {
		return nil, fmt.Errorf("failed to write snapshot: %w", err)
	}

	return snap, nil
}

// LoadBaseline loads the current baseline snapshot
func (s *Store) LoadBaseline() (*Snapshot, error) {
	data, err := os.ReadFile(s.baselinePath())
	if err != nil {
		return nil, fmt.Errorf("failed to read baseline: %w", err)
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("failed to parse baseline: %w", err)
	}

	// Verify integrity
	expected := snap.Checksum
	snap.Checksum = ""
	actual := calculateChecksum(&snap)
	snap.Checksum = expected

	if expected != actual {
		return nil, fmt.Errorf("baseline integrity check failed - file may be tampered")
	}

	return &snap, nil
}

// SaveDiff saves a diff snapshot for historical tracking
func (s *Store) SaveDiff(changes []scanner.Change) error {
	if len(changes) == 0 {
		return nil
	}

	filename := fmt.Sprintf("diff_%s.json", time.Now().Format("2006-01-02_15-04-05"))
	path := filepath.Join(s.dir, filename)

	data, err := json.MarshalIndent(changes, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// generateID creates a unique snapshot ID
func generateID() string {
	now := time.Now().UnixNano()
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d", now)))
	return hex.EncodeToString(hash[:8])
}

// calculateChecksum computes integrity checksum
func calculateChecksum(snap *Snapshot) string {
	// Zero out checksum for calculation
	original := snap.Checksum
	snap.Checksum = ""
	defer func() { snap.Checksum = original }()

	data, _ := json.Marshal(snap)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
