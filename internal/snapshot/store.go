// Package snapshot manages baseline snapshots for file integrity
package snapshot

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kris-hansen/feelgoodbot/internal/scanner"
)

// Snapshot represents a point-in-time capture of file states
type Snapshot struct {
	ID        string                       `json:"id"`
	CreatedAt time.Time                    `json:"created_at"`
	Files     map[string]*scanner.FileInfo `json:"files"`
	Checksum  string                       `json:"checksum"` // integrity check
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

// lastScanPath stores the most recent observed state. It is deliberately
// separate from the baseline: a baseline is a trusted security anchor, while
// the last scan is only a checkpoint used to make the forensic journal small
// and useful.
func (s *Store) lastScanPath() string {
	return filepath.Join(s.dir, "last_scan.json")
}

// HasBaseline returns true if a baseline snapshot exists
func (s *Store) HasBaseline() bool {
	_, err := os.Stat(s.baselinePath())
	return err == nil
}

// SaveBaseline saves a new baseline snapshot
func (s *Store) SaveBaseline(files map[string]*scanner.FileInfo) (*Snapshot, error) {
	snap, err := s.saveSnapshot(s.baselinePath(), files)
	if err != nil {
		return nil, fmt.Errorf("failed to save baseline: %w", err)
	}

	// Accepting a new baseline explicitly accepts the current state as trusted,
	// so reset the incremental checkpoint at the same time.
	if _, err := s.SaveLastScan(files); err != nil {
		return nil, fmt.Errorf("failed to initialize last-scan checkpoint: %w", err)
	}

	return snap, nil
}

// SaveLastScan persists the current observed state for the next incremental
// comparison. It must never replace the trusted baseline.
func (s *Store) SaveLastScan(files map[string]*scanner.FileInfo) (*Snapshot, error) {
	snap, err := s.saveSnapshot(s.lastScanPath(), files)
	if err != nil {
		return nil, fmt.Errorf("failed to save last scan: %w", err)
	}
	return snap, nil
}

func (s *Store) saveSnapshot(path string, files map[string]*scanner.FileInfo) (*Snapshot, error) {
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

	if err := writePrivateFile(path, data); err != nil {
		return nil, err
	}

	return snap, nil
}

// LoadBaseline loads the current baseline snapshot
func (s *Store) LoadBaseline() (*Snapshot, error) {
	return s.loadSnapshot(s.baselinePath(), "baseline")
}

// LoadLastScan loads the untrusted incremental checkpoint. A missing
// checkpoint is expected when upgrading from versions before incremental
// journaling and is handled by the daemon without falling back to baseline.
func (s *Store) LoadLastScan() (*Snapshot, error) {
	return s.loadSnapshot(s.lastScanPath(), "last scan")
}

func (s *Store) loadSnapshot(path, label string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", label, err)
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", label, err)
	}

	// Verify integrity
	expected := snap.Checksum
	snap.Checksum = ""
	actual := calculateChecksum(&snap)
	snap.Checksum = expected

	if expected != actual {
		return nil, fmt.Errorf("%s integrity check failed - file may be tampered", label)
	}

	return &snap, nil
}

// SaveDiff saves an incremental diff snapshot for historical tracking. Callers
// should pass changes since the previous scan, not all changes since baseline.
func (s *Store) SaveDiff(changes []scanner.Change) error {
	if len(changes) == 0 {
		return nil
	}

	filename := fmt.Sprintf("diff_%s.json", time.Now().UTC().Format("20060102T150405.000000000Z"))
	path := filepath.Join(s.dir, filename)

	// scanner.Compare walks maps, so normalize the persisted ordering. That
	// makes a diff readable and stable rather than producing needless churn.
	persisted := append([]scanner.Change(nil), changes...)
	sort.SliceStable(persisted, func(i, j int) bool {
		if persisted[i].Path != persisted[j].Path {
			return persisted[i].Path < persisted[j].Path
		}
		if persisted[i].Type != persisted[j].Type {
			return persisted[i].Type < persisted[j].Type
		}
		return persisted[i].Details < persisted[j].Details
	})

	data, err := json.MarshalIndent(persisted, "", "  ")
	if err != nil {
		return err
	}

	return writePrivateFile(path, data)
}

// RetentionPolicy bounds how much disk space snapshot history may consume.
// A zero value for either field disables that limit.
type RetentionPolicy struct {
	MaxBytes int64         // total size cap for the snapshot directory
	MaxAge   time.Duration // diffs older than this are removed
}

// DefaultRetentionPolicy returns the default limits: 250 MB total, 30 days of
// incremental diffs. Baseline and last-scan checkpoint files are retained.
func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		MaxBytes: 250 << 20, // 250 MB
		MaxAge:   30 * 24 * time.Hour,
	}
}

// PruneResult reports what a prune pass did (or would do, in dry-run mode)
type PruneResult struct {
	RemovedFiles   int
	RemovedBytes   int64
	RemainingFiles int
	RemainingBytes int64
}

// diffFile pairs a diff's path with its metadata for pruning
type diffFile struct {
	path    string
	size    int64
	modTime time.Time
}

// listDiffs returns all diff files sorted oldest-first, plus the size of the
// protected baseline and last-scan checkpoint files.
func (s *Store) listDiffs() ([]diffFile, int64, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read snapshot directory: %w", err)
	}

	var diffs []diffFile
	var protectedSize int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if e.Name() == "baseline.json" || e.Name() == "last_scan.json" {
			protectedSize += info.Size()
			continue
		}
		if strings.HasPrefix(e.Name(), "diff_") && strings.HasSuffix(e.Name(), ".json") {
			diffs = append(diffs, diffFile{
				path:    filepath.Join(s.dir, e.Name()),
				size:    info.Size(),
				modTime: info.ModTime(),
			})
		}
	}

	sort.Slice(diffs, func(i, j int) bool {
		return diffs[i].modTime.Before(diffs[j].modTime)
	})

	return diffs, protectedSize, nil
}

// DiskUsage returns the total size of the snapshot directory and the number of diff files
func (s *Store) DiskUsage() (int64, int, error) {
	diffs, protectedSize, err := s.listDiffs()
	if err != nil {
		return 0, 0, err
	}
	total := protectedSize
	for _, d := range diffs {
		total += d.size
	}
	return total, len(diffs), nil
}

// Prune removes diff files that violate the retention policy: first any diff
// older than MaxAge, then the oldest remaining diffs until the directory
// (including the baseline and last-scan checkpoint) fits within MaxBytes. The
// baseline and checkpoint are never removed.
// With dryRun set, it reports what would be removed without deleting anything.
func (s *Store) Prune(policy RetentionPolicy, dryRun bool) (*PruneResult, error) {
	diffs, protectedSize, err := s.listDiffs()
	if err != nil {
		return nil, err
	}

	total := protectedSize
	for _, d := range diffs {
		total += d.size
	}

	result := &PruneResult{}
	remove := func(d diffFile) error {
		if !dryRun {
			if err := os.Remove(d.path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("failed to remove %s: %w", d.path, err)
			}
		}
		result.RemovedFiles++
		result.RemovedBytes += d.size
		total -= d.size
		return nil
	}

	var kept []diffFile
	if policy.MaxAge > 0 {
		cutoff := time.Now().Add(-policy.MaxAge)
		for _, d := range diffs {
			if d.modTime.Before(cutoff) {
				if err := remove(d); err != nil {
					return result, err
				}
			} else {
				kept = append(kept, d)
			}
		}
	} else {
		kept = diffs
	}

	if policy.MaxBytes > 0 {
		for len(kept) > 0 && total > policy.MaxBytes {
			if err := remove(kept[0]); err != nil {
				return result, err
			}
			kept = kept[1:]
		}
	}

	result.RemainingFiles = len(kept)
	result.RemainingBytes = total
	return result, nil
}

// ParseSize parses a human-readable size string like "500MB", "1GB", or a
// plain byte count. Supported units: B, KB, MB, GB, TB (powers of 1024).
// An empty string or "0" returns 0, meaning no limit.
func ParseSize(s string) (int64, error) {
	original := s
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, nil
	}

	multiplier := int64(1)
	switch {
	case strings.HasSuffix(s, "TB"):
		multiplier = 1 << 40
		s = s[:len(s)-2]
	case strings.HasSuffix(s, "GB"):
		multiplier = 1 << 30
		s = s[:len(s)-2]
	case strings.HasSuffix(s, "MB"):
		multiplier = 1 << 20
		s = s[:len(s)-2]
	case strings.HasSuffix(s, "KB"):
		multiplier = 1 << 10
		s = s[:len(s)-2]
	case strings.HasSuffix(s, "B"):
		s = s[:len(s)-1]
	}

	value, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", original, err)
	}
	if value < 0 {
		return 0, fmt.Errorf("size must not be negative")
	}

	return int64(value * float64(multiplier)), nil
}

// FormatSize renders a byte count as a human-readable string
func FormatSize(bytes int64) string {
	switch {
	case bytes >= 1<<40:
		return fmt.Sprintf("%.1f TB", float64(bytes)/float64(1<<40))
	case bytes >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(1<<30))
	case bytes >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

// generateID creates a unique snapshot ID
func generateID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		// Fall back to a timestamp hash if the system RNG is unavailable
		hash := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
		return hex.EncodeToString(hash[:8])
	}
	return hex.EncodeToString(buf)
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

// writePrivateFile atomically replaces a private snapshot file. A crash during
// a scan must not leave a partial baseline or checkpoint that disables future
// monitoring.
func writePrivateFile(path string, data []byte) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".snapshot-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary snapshot: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if err = tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to set snapshot permissions: %w", err)
	}
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to write snapshot: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("failed to sync snapshot: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("failed to close snapshot: %w", err)
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to replace snapshot: %w", err)
	}
	return nil
}
