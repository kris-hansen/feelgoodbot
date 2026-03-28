// Package egress provides network egress monitoring for feelgoodbot.
// It profiles outbound connections using lsof and alerts on anomalies.
package egress

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Connection represents an established outbound network connection
type Connection struct {
	Process     string `json:"process"`
	PID         int    `json:"pid"`
	Destination string `json:"destination"` // host:port
}

// ProcessProfile tracks known destinations for a process
type ProcessProfile struct {
	Destinations map[string]bool `json:"destinations"` // host:port -> seen
	FirstSeen    time.Time       `json:"first_seen"`
	LastSeen     time.Time       `json:"last_seen"`
}

// Baseline stores the learned egress profile
type Baseline struct {
	Processes map[string]*ProcessProfile `json:"processes"`
	Ignored   []string                   `json:"ignored"`
	CreatedAt time.Time                  `json:"created_at"`
	UpdatedAt time.Time                  `json:"updated_at"`
}

// Anomaly represents a deviation from the baseline
type Anomaly struct {
	Type        string `json:"type"`        // "new_process" or "new_destination"
	Process     string `json:"process"`
	Destination string `json:"destination"`
	Timestamp   time.Time `json:"timestamp"`
}

// baselinePath returns the path to the egress baseline file
func baselinePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "feelgoodbot", "egress-baseline.json")
}

// statusPath returns the path to the egress status file
func statusPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "feelgoodbot", "egress-status.json")
}

// EgressStatus tracks the current state of egress monitoring
type EgressStatus struct {
	Learning      bool      `json:"learning"`
	Enabled       bool      `json:"enabled"`
	LearningStart time.Time `json:"learning_start,omitempty"`
	LastScan      time.Time `json:"last_scan,omitempty"`
	TotalScans    int       `json:"total_scans"`
}

// NewBaseline creates a new empty baseline
func NewBaseline() *Baseline {
	return &Baseline{
		Processes: make(map[string]*ProcessProfile),
		Ignored:   []string{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// SaveBaseline writes the baseline to disk
func SaveBaseline(b *Baseline) error {
	b.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	path := baselinePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

// LoadBaseline reads the baseline from disk
func LoadBaseline() (*Baseline, error) {
	data, err := os.ReadFile(baselinePath())
	if err != nil {
		return nil, fmt.Errorf("failed to read baseline: %w", err)
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("failed to parse baseline: %w", err)
	}

	return &b, nil
}

// HasBaseline checks if an egress baseline exists
func HasBaseline() bool {
	_, err := os.Stat(baselinePath())
	return err == nil
}

// SaveStatus writes the egress status to disk
func SaveStatus(s *EgressStatus) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	path := statusPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// LoadStatus reads the egress status from disk
func LoadStatus() (*EgressStatus, error) {
	data, err := os.ReadFile(statusPath())
	if err != nil {
		return nil, err
	}

	var s EgressStatus
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}

	return &s, nil
}

// CaptureConnections runs lsof and parses ESTABLISHED outbound connections
func CaptureConnections() ([]Connection, error) {
	cmd := exec.Command("lsof", "-i", "-n", "-P")
	out, err := cmd.Output()
	if err != nil {
		// lsof may return exit code 1 if some files can't be accessed
		if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
			// Still try to parse stdout
		} else if len(out) == 0 {
			return nil, fmt.Errorf("lsof failed: %w", err)
		}
	}

	return parseLsof(string(out)), nil
}

// parseLsof parses lsof -i -n -P output and returns ESTABLISHED connections
func parseLsof(output string) []Connection {
	var conns []Connection
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		// Skip header and non-ESTABLISHED lines
		if !strings.Contains(line, "ESTABLISHED") {
			continue
		}

		// Skip IPv6 localhost connections (typically internal)
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		processName := fields[0]
		pid := 0
		fmt.Sscanf(fields[1], "%d", &pid)

		// The name field contains something like "host:port->remote:port"
		nameField := fields[len(fields)-2] // Second to last field usually has the connection info
		if !strings.Contains(nameField, "->") {
			// Try the last field
			nameField = fields[len(fields)-1]
			if !strings.Contains(nameField, "->") {
				continue
			}
		}

		parts := strings.SplitN(nameField, "->", 2)
		if len(parts) != 2 {
			continue
		}

		remote := parts[1]

		conns = append(conns, Connection{
			Process:     processName,
			PID:         pid,
			Destination: remote,
		})
	}

	return conns
}

// MergeIntoBaseline adds captured connections to the baseline (learning mode)
func MergeIntoBaseline(b *Baseline, conns []Connection) {
	now := time.Now()

	for _, conn := range conns {
		// Skip ignored processes
		if isIgnored(b, conn.Process) {
			continue
		}

		profile, exists := b.Processes[conn.Process]
		if !exists {
			profile = &ProcessProfile{
				Destinations: make(map[string]bool),
				FirstSeen:    now,
			}
			b.Processes[conn.Process] = profile
		}

		profile.Destinations[conn.Destination] = true
		profile.LastSeen = now
	}

	b.UpdatedAt = now
}

// CompareToBaseline checks current connections against baseline and returns anomalies
func CompareToBaseline(b *Baseline, conns []Connection) []Anomaly {
	var anomalies []Anomaly
	now := time.Now()

	// Deduplicate: only report each process+destination combo once
	seen := make(map[string]bool)

	for _, conn := range conns {
		if isIgnored(b, conn.Process) {
			continue
		}

		key := conn.Process + "|" + conn.Destination
		if seen[key] {
			continue
		}
		seen[key] = true

		profile, exists := b.Processes[conn.Process]
		if !exists {
			anomalies = append(anomalies, Anomaly{
				Type:        "new_process",
				Process:     conn.Process,
				Destination: conn.Destination,
				Timestamp:   now,
			})
			continue
		}

		// Check if destination is known (exact match or wildcard)
		if !matchesDestination(profile, conn.Destination) {
			anomalies = append(anomalies, Anomaly{
				Type:        "new_destination",
				Process:     conn.Process,
				Destination: conn.Destination,
				Timestamp:   now,
			})
		}
	}

	return anomalies
}

// matchesDestination checks if a destination matches any known pattern for the process
func matchesDestination(profile *ProcessProfile, dest string) bool {
	// Check wildcard: if process has "*" it can talk anywhere
	if profile.Destinations["*"] {
		return true
	}

	// Exact match
	if profile.Destinations[dest] {
		return true
	}

	// Check port wildcards: "host:*" matches any port on that host
	destHost := dest
	if idx := strings.LastIndex(dest, ":"); idx != -1 {
		destHost = dest[:idx]
	}

	wildcardKey := destHost + ":*"
	if profile.Destinations[wildcardKey] {
		return true
	}

	// Check "localhost:*" style for 127.0.0.1
	if destHost == "127.0.0.1" && profile.Destinations["localhost:*"] {
		return true
	}

	return false
}

// isIgnored checks if a process is in the ignore list
func isIgnored(b *Baseline, process string) bool {
	for _, ignored := range b.Ignored {
		if strings.EqualFold(ignored, process) {
			return true
		}
	}
	return false
}

// AddIgnored adds a process to the ignore list
func AddIgnored(b *Baseline, process string) bool {
	// Check if already ignored
	for _, ignored := range b.Ignored {
		if strings.EqualFold(ignored, process) {
			return false
		}
	}
	b.Ignored = append(b.Ignored, process)
	return true
}

// FormatBaseline returns a human-readable representation of the baseline
func FormatBaseline(b *Baseline) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Egress Baseline (created %s, updated %s)\n",
		b.CreatedAt.Format("2006-01-02 15:04:05"),
		b.UpdatedAt.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Processes: %d, Ignored: %d\n\n", len(b.Processes), len(b.Ignored)))

	// Sort process names for consistent output
	names := make([]string, 0, len(b.Processes))
	for name := range b.Processes {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		profile := b.Processes[name]
		sb.WriteString(fmt.Sprintf("  %s (%d destinations)\n", name, len(profile.Destinations)))
		sb.WriteString(fmt.Sprintf("    first seen: %s\n", profile.FirstSeen.Format("2006-01-02 15:04:05")))
		sb.WriteString(fmt.Sprintf("    last seen:  %s\n", profile.LastSeen.Format("2006-01-02 15:04:05")))

		// Sort destinations
		dests := make([]string, 0, len(profile.Destinations))
		for d := range profile.Destinations {
			dests = append(dests, d)
		}
		sort.Strings(dests)

		for _, d := range dests {
			sb.WriteString(fmt.Sprintf("    → %s\n", d))
		}
		sb.WriteString("\n")
	}

	if len(b.Ignored) > 0 {
		sb.WriteString("Ignored processes:\n")
		for _, p := range b.Ignored {
			sb.WriteString(fmt.Sprintf("  • %s\n", p))
		}
	}

	return sb.String()
}

// FormatSnapshot returns a human-readable view of current connections
func FormatSnapshot(conns []Connection) string {
	var sb strings.Builder

	// Group by process
	byProcess := make(map[string][]string)
	for _, c := range conns {
		byProcess[c.Process] = append(byProcess[c.Process], c.Destination)
	}

	names := make([]string, 0, len(byProcess))
	for name := range byProcess {
		names = append(names, name)
	}
	sort.Strings(names)

	sb.WriteString(fmt.Sprintf("Current connections: %d across %d processes\n\n", len(conns), len(byProcess)))

	for _, name := range names {
		dests := byProcess[name]
		sort.Strings(dests)
		sb.WriteString(fmt.Sprintf("  %s (%d connections)\n", name, len(dests)))
		for _, d := range dests {
			sb.WriteString(fmt.Sprintf("    → %s\n", d))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// FormatAnomalies returns a human-readable view of detected anomalies
func FormatAnomalies(anomalies []Anomaly) string {
	if len(anomalies) == 0 {
		return "No anomalies detected."
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("⚠️  %d anomalies detected:\n\n", len(anomalies)))

	for _, a := range anomalies {
		switch a.Type {
		case "new_process":
			sb.WriteString(fmt.Sprintf("  🔴 NEW PROCESS: %s → %s\n", a.Process, a.Destination))
		case "new_destination":
			sb.WriteString(fmt.Sprintf("  🟡 NEW DESTINATION: %s → %s\n", a.Process, a.Destination))
		}
	}

	return sb.String()
}
