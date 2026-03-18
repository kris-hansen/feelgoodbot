// Package scanner provides file integrity scanning functionality
package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// AlertedState tracks which changes have already been alerted on
type AlertedState struct {
	// Map of path -> hash of the change details (type + before/after hash)
	// This allows us to re-alert if the SAME file changes AGAIN to a different state
	AlertedChanges map[string]string `json:"alerted_changes"`
	LastUpdated    time.Time         `json:"last_updated"`
}

// alertedStatePath returns the path to the alerted state file
func alertedStatePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "feelgoodbot", "alerted_state.json"), nil
}

// LoadAlertedState loads the previously alerted state
func LoadAlertedState() (*AlertedState, error) {
	path, err := alertedStatePath()
	if err != nil {
		return nil, err
	}

	state := &AlertedState{
		AlertedChanges: make(map[string]string),
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return state, nil // New state is fine
	}
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, state); err != nil {
		// Corrupted file, start fresh
		return &AlertedState{AlertedChanges: make(map[string]string)}, nil
	}

	return state, nil
}

// Save persists the alerted state to disk
func (s *AlertedState) Save() error {
	path, err := alertedStatePath()
	if err != nil {
		return err
	}

	s.LastUpdated = time.Now()

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// hashChange creates a unique hash for a change to detect if it's the same change
func hashChange(c Change) string {
	// Include type, before hash, after hash to uniquely identify this specific change
	data := c.Type
	if c.Before != nil {
		data += "|before:" + c.Before.Hash
	}
	if c.After != nil {
		data += "|after:" + c.After.Hash
	}
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}

// MarkAlerted marks a set of changes as alerted
func (s *AlertedState) MarkAlerted(changes []Change) {
	for _, c := range changes {
		s.AlertedChanges[c.Path] = hashChange(c)
	}
}

// FilterNewChanges returns only changes that haven't been alerted on yet
// or have changed state since last alert (e.g., file modified again)
func (s *AlertedState) FilterNewChanges(changes []Change) []Change {
	var newChanges []Change

	for _, c := range changes {
		currentHash := hashChange(c)
		previousHash, wasAlerted := s.AlertedChanges[c.Path]

		if !wasAlerted || previousHash != currentHash {
			// Either never alerted, or the change is different now
			newChanges = append(newChanges, c)
		}
	}

	return newChanges
}

// AcknowledgeAll marks all current changes as acknowledged without permanent ignore
// This is like saying "I see these, don't alert me until something NEW happens"
func (s *AlertedState) AcknowledgeAll(changes []Change) {
	s.MarkAlerted(changes)
}

// ClearPath removes a path from alerted state (will re-alert on next scan if still changed)
func (s *AlertedState) ClearPath(path string) {
	delete(s.AlertedChanges, path)
}

// ClearAll resets all alerted state
func (s *AlertedState) ClearAll() {
	s.AlertedChanges = make(map[string]string)
}

// PruneStale removes entries for paths that are no longer in the change list
// Call this after filtering to clean up old entries
func (s *AlertedState) PruneStale(currentChanges []Change) {
	currentPaths := make(map[string]bool)
	for _, c := range currentChanges {
		currentPaths[c.Path] = true
	}

	for path := range s.AlertedChanges {
		if !currentPaths[path] {
			delete(s.AlertedChanges, path)
		}
	}
}

// String returns a summary of alerted state
func (s *AlertedState) String() string {
	return fmt.Sprintf("AlertedState: %d paths tracked, last updated %s",
		len(s.AlertedChanges), s.LastUpdated.Format(time.RFC3339))
}
