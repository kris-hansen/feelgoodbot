// Package logging provides secure, tamper-evident logging.
package logging

import (
	cryptoRand "crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// EventType categorizes log events.
type EventType string

const (
	EventAuth       EventType = "auth"        // Authentication events
	EventGate       EventType = "gate"        // Gate request/approve/deny
	EventAlert      EventType = "alert"       // Security alerts
	EventIntegrity  EventType = "integrity"   // File integrity events
	EventLockdown   EventType = "lockdown"    // Lockdown events
	EventSystem     EventType = "system"      // System events (startup, shutdown)
)

// Event represents a single log event.
type Event struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	Type      EventType         `json:"type"`
	Action    string            `json:"action"`
	Status    string            `json:"status"` // "success", "failure", "pending"
	Source    string            `json:"source"` // "cli", "telegram", "daemon"
	Details   map[string]string `json:"details,omitempty"`
	PrevHash  string            `json:"prev_hash"` // Hash of previous entry (chain)
	Hash      string            `json:"hash"`      // HMAC of this entry
}

// Summary provides aggregated log statistics.
type Summary struct {
	Period         string         `json:"period"`
	StartTime      time.Time      `json:"start_time"`
	EndTime        time.Time      `json:"end_time"`
	TotalEvents    int            `json:"total_events"`
	AuthAttempts   int            `json:"auth_attempts"`
	AuthFailures   int            `json:"auth_failures"`
	GateRequests   int            `json:"gate_requests"`
	GateApprovals  int            `json:"gate_approvals"`
	GateDenials    int            `json:"gate_denials"`
	BlockedActions int            `json:"blocked_actions"`
	IntegrityAlerts int           `json:"integrity_alerts"`
	RecentEvents   []*Event       `json:"recent_events,omitempty"`
	ByType         map[string]int `json:"by_type"`
}

// SecureLog provides tamper-evident logging.
type SecureLog struct {
	mu       sync.Mutex
	path     string
	secret   []byte // HMAC secret
	lastHash string
	file     *os.File
}

// NewSecureLog creates a new secure log.
func NewSecureLog(path string, secret []byte) (*SecureLog, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}

	log := &SecureLog{
		path:   path,
		secret: secret,
	}

	// Load last hash from existing log
	if err := log.loadLastHash(); err != nil {
		return nil, err
	}

	return log, nil
}

// Log writes a new event to the log.
func (l *SecureLog) Log(eventType EventType, action, status, source string, details map[string]string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	event := &Event{
		ID:        generateEventID(),
		Timestamp: time.Now(),
		Type:      eventType,
		Action:    action,
		Status:    status,
		Source:    source,
		Details:   details,
		PrevHash:  l.lastHash,
	}

	// Compute HMAC
	event.Hash = l.computeHash(event)
	l.lastHash = event.Hash

	// Append to file
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	defer f.Close()

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	if _, err := f.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write event: %w", err)
	}

	return nil
}

// LogAuth logs an authentication event.
func (l *SecureLog) LogAuth(action, status, source string, details map[string]string) error {
	return l.Log(EventAuth, action, status, source, details)
}

// LogGate logs a gate event.
func (l *SecureLog) LogGate(action, status, source string, details map[string]string) error {
	return l.Log(EventGate, action, status, source, details)
}

// LogAlert logs a security alert.
func (l *SecureLog) LogAlert(action, status, source string, details map[string]string) error {
	return l.Log(EventAlert, action, status, source, details)
}

// LogIntegrity logs a file integrity event.
func (l *SecureLog) LogIntegrity(action, status, source string, details map[string]string) error {
	return l.Log(EventIntegrity, action, status, source, details)
}

// LogLockdown logs a lockdown event.
func (l *SecureLog) LogLockdown(action, status, source string, details map[string]string) error {
	return l.Log(EventLockdown, action, status, source, details)
}

// GetSummary returns a summary of events within the given duration.
func (l *SecureLog) GetSummary(since time.Duration, includeRecent int) (*Summary, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	events, err := l.readEvents()
	if err != nil {
		return nil, err
	}

	cutoff := time.Now().Add(-since)
	summary := &Summary{
		Period:    since.String(),
		StartTime: cutoff,
		EndTime:   time.Now(),
		ByType:    make(map[string]int),
	}

	var recent []*Event

	for _, event := range events {
		if event.Timestamp.Before(cutoff) {
			continue
		}

		summary.TotalEvents++
		summary.ByType[string(event.Type)]++

		switch event.Type {
		case EventAuth:
			summary.AuthAttempts++
			if event.Status == "failure" {
				summary.AuthFailures++
			}
		case EventGate:
			switch event.Status {
			case "pending":
				summary.GateRequests++
			case "approved":
				summary.GateApprovals++
			case "denied":
				summary.GateDenials++
			case "blocked":
				summary.BlockedActions++
			}
		case EventIntegrity:
			if event.Status == "alert" {
				summary.IntegrityAlerts++
			}
		}

		if includeRecent > 0 {
			recent = append(recent, event)
		}
	}

	// Keep only the most recent N events
	if len(recent) > includeRecent {
		recent = recent[len(recent)-includeRecent:]
	}
	summary.RecentEvents = recent

	return summary, nil
}

// GetRecent returns the most recent N events.
func (l *SecureLog) GetRecent(n int, eventType EventType) ([]*Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	events, err := l.readEvents()
	if err != nil {
		return nil, err
	}

	var filtered []*Event
	for _, event := range events {
		if eventType == "" || event.Type == eventType {
			filtered = append(filtered, event)
		}
	}

	// Return last N
	if len(filtered) > n {
		filtered = filtered[len(filtered)-n:]
	}

	return filtered, nil
}

// Verify checks the integrity of the log chain.
func (l *SecureLog) Verify() (bool, []string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	events, err := l.readEvents()
	if err != nil {
		return false, nil, err
	}

	var errors []string
	prevHash := ""

	for i, event := range events {
		// Check prev_hash chain
		if event.PrevHash != prevHash {
			errors = append(errors, fmt.Sprintf("entry %d: chain broken (expected prev_hash %s, got %s)", i, prevHash, event.PrevHash))
		}

		// Verify HMAC
		expectedHash := l.computeHash(event)
		if event.Hash != expectedHash {
			errors = append(errors, fmt.Sprintf("entry %d: hash mismatch (tampering detected)", i))
		}

		prevHash = event.Hash
	}

	return len(errors) == 0, errors, nil
}

// readEvents reads all events from the log file.
func (l *SecureLog) readEvents() ([]*Event, error) {
	data, err := os.ReadFile(l.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read log file: %w", err)
	}

	var events []*Event
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var event Event
		if err := json.Unmarshal(line, &event); err != nil {
			continue // Skip malformed lines
		}
		events = append(events, &event)
	}

	return events, nil
}

// loadLastHash loads the hash of the last entry.
func (l *SecureLog) loadLastHash() error {
	events, err := l.readEvents()
	if err != nil {
		return err
	}
	if len(events) > 0 {
		l.lastHash = events[len(events)-1].Hash
	}
	return nil
}

// computeHash computes the HMAC for an event.
func (l *SecureLog) computeHash(event *Event) string {
	// Hash all fields except Hash itself
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s",
		event.ID,
		event.Timestamp.Format(time.RFC3339Nano),
		event.Type,
		event.Action,
		event.Status,
		event.Source,
		event.PrevHash,
	)

	h := hmac.New(sha256.New, l.secret)
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			lines = append(lines, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

func generateEventID() string {
	b := make([]byte, 8)
	cryptoRand.Read(b)
	return hex.EncodeToString(b)
}
