// Package daemon provides background monitoring functionality
package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kris-hansen/feelgoodbot/internal/alerts"
	"github.com/kris-hansen/feelgoodbot/internal/scanner"
	"github.com/kris-hansen/feelgoodbot/internal/snapshot"
)

// Config holds daemon configuration
type Config struct {
	ScanInterval time.Duration
	AlertConfig  alerts.Config
	LogFile      string
	PidFile      string
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	home, _ := os.UserHomeDir()
	return Config{
		ScanInterval: 5 * time.Minute,
		LogFile:      filepath.Join(home, ".config", "feelgoodbot", "daemon.log"),
		PidFile:      filepath.Join(home, ".config", "feelgoodbot", "daemon.pid"),
		AlertConfig: alerts.Config{
			LocalNotify: true,
		},
	}
}

// Daemon runs continuous file integrity monitoring
type Daemon struct {
	config   Config
	store    *snapshot.Store
	scanner  *scanner.Scanner
	alerter  *alerts.Alerter
	logger   *log.Logger
	stopChan chan struct{}
}

// New creates a new daemon instance
func New(cfg Config) (*Daemon, error) {
	store, err := snapshot.NewStore()
	if err != nil {
		return nil, fmt.Errorf("failed to create snapshot store: %w", err)
	}

	// Set up logging
	var logger *log.Logger
	if cfg.LogFile != "" {
		// Ensure log directory exists
		if err := os.MkdirAll(filepath.Dir(cfg.LogFile), 0700); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}

		logFile, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		logger = log.New(logFile, "[feelgoodbot] ", log.LstdFlags)
	} else {
		logger = log.New(os.Stdout, "[feelgoodbot] ", log.LstdFlags)
	}

	return &Daemon{
		config:   cfg,
		store:    store,
		scanner:  scanner.New(),
		alerter:  alerts.NewAlerter(cfg.AlertConfig),
		logger:   logger,
		stopChan: make(chan struct{}),
	}, nil
}

// Run starts the daemon and blocks until stopped
func (d *Daemon) Run(ctx context.Context) error {
	// Check baseline exists
	if !d.store.HasBaseline() {
		return fmt.Errorf("no baseline found - run 'feelgoodbot init' first")
	}

	// Write PID file
	if err := d.writePidFile(); err != nil {
		d.logger.Printf("Warning: failed to write PID file: %v", err)
	}
	defer d.removePidFile()

	d.logger.Printf("Daemon started (scan interval: %s)", d.config.ScanInterval)

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Initial scan
	d.runScan()

	// Main loop
	ticker := time.NewTicker(d.config.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			d.runScan()
		case <-sigChan:
			d.logger.Println("Received shutdown signal")
			return nil
		case <-ctx.Done():
			d.logger.Println("Context cancelled")
			return nil
		case <-d.stopChan:
			d.logger.Println("Stop requested")
			return nil
		}
	}
}

// Stop signals the daemon to stop
func (d *Daemon) Stop() {
	close(d.stopChan)
}

// runScan performs a single scan and handles results
func (d *Daemon) runScan() {
	d.logger.Println("Starting scan...")

	// Load baseline
	baseline, err := d.store.LoadBaseline()
	if err != nil {
		d.logger.Printf("Error loading baseline: %v", err)
		return
	}

	// Perform scan
	result := d.scanner.Scan()
	d.logger.Printf("Scanned %d files in %s", result.FilesScanned, result.EndTime.Sub(result.StartTime).Round(time.Millisecond))

	// Compare with baseline
	changes := scanner.Compare(baseline.Files, result.Files)

	if len(changes) == 0 {
		d.logger.Println("No changes detected")
		return
	}

	// Log and alert on changes
	critical := scanner.FilterBySeverity(changes, scanner.SeverityCritical)
	warnings := scanner.FilterBySeverity(changes, scanner.SeverityWarning)

	d.logger.Printf("Detected %d changes (%d critical, %d warnings)",
		len(changes), len(critical), len(warnings)-len(critical))

	// Save diff for forensics
	if err := d.store.SaveDiff(changes); err != nil {
		d.logger.Printf("Warning: failed to save diff: %v", err)
	}

	// Send alerts
	if len(critical) > 0 || len(warnings) > 0 {
		hostname := alerts.GetHostname()

		var message string
		if len(critical) > 0 {
			message = fmt.Sprintf("🚨 CRITICAL: %d file(s) tampered!", len(critical))
			for i, c := range critical {
				if i >= 5 {
					message += fmt.Sprintf("\n... and %d more", len(critical)-5)
					break
				}
				message += fmt.Sprintf("\n• %s: %s", c.Type, c.Path)
			}
		} else {
			message = fmt.Sprintf("⚠️ WARNING: %d suspicious change(s) detected", len(warnings))
		}

		alert := alerts.Alert{
			Timestamp: time.Now(),
			Severity:  scanner.SeverityCritical,
			Message:   message,
			Changes:   changes,
			Hostname:  hostname,
		}

		if len(critical) == 0 {
			alert.Severity = scanner.SeverityWarning
		}

		if err := d.alerter.Send(alert); err != nil {
			d.logger.Printf("Error sending alert: %v", err)
		} else {
			d.logger.Println("Alert sent successfully")
		}

		// Execute response actions for critical changes
		if len(critical) > 0 {
			d.logger.Println("CRITICAL changes detected - review immediately!")
			// Future: configurable response actions (disconnect network, shutdown)
		}
	}
}

// writePidFile writes the daemon PID to a file
func (d *Daemon) writePidFile() error {
	if d.config.PidFile == "" {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(d.config.PidFile), 0700); err != nil {
		return err
	}

	return os.WriteFile(d.config.PidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0600)
}

// removePidFile removes the PID file
func (d *Daemon) removePidFile() {
	if d.config.PidFile != "" {
		os.Remove(d.config.PidFile)
	}
}

// Status represents daemon status
type Status struct {
	Running   bool      `json:"running"`
	PID       int       `json:"pid,omitempty"`
	StartTime time.Time `json:"start_time,omitempty"`
}

// GetStatus checks if the daemon is running
func GetStatus(pidFile string) Status {
	if pidFile == "" {
		home, _ := os.UserHomeDir()
		pidFile = filepath.Join(home, ".config", "feelgoodbot", "daemon.pid")
	}

	data, err := os.ReadFile(pidFile)
	if err != nil {
		return Status{Running: false}
	}

	var pid int
	if _, err := fmt.Sscanf(string(data), "%d", &pid); err != nil {
		return Status{Running: false}
	}

	// Check if process is running
	process, err := os.FindProcess(pid)
	if err != nil {
		return Status{Running: false}
	}

	// On Unix, FindProcess always succeeds, so we need to send signal 0
	if err := process.Signal(syscall.Signal(0)); err != nil {
		return Status{Running: false}
	}

	return Status{
		Running: true,
		PID:     pid,
	}
}

// LaunchdPlist generates the launchd plist content
func LaunchdPlist(binaryPath string, scanInterval time.Duration) string {
	intervalSeconds := int(scanInterval.Seconds())
	if intervalSeconds < 60 {
		intervalSeconds = 60 // Minimum 1 minute
	}

	home, _ := os.UserHomeDir()
	logPath := filepath.Join(home, ".config", "feelgoodbot", "daemon.log")
	errPath := filepath.Join(home, ".config", "feelgoodbot", "daemon.err")

	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.feelgoodbot.daemon</string>
    
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>daemon</string>
        <string>run</string>
        <string>--interval</string>
        <string>%ds</string>
    </array>
    
    <key>RunAtLoad</key>
    <true/>
    
    <key>KeepAlive</key>
    <true/>
    
    <key>StandardOutPath</key>
    <string>%s</string>
    
    <key>StandardErrorPath</key>
    <string>%s</string>
    
    <key>ProcessType</key>
    <string>Background</string>
    
    <key>LowPriorityIO</key>
    <true/>
    
    <key>Nice</key>
    <integer>10</integer>
</dict>
</plist>
`, binaryPath, intervalSeconds, logPath, errPath)
}

// LaunchdPlistPath returns the path to the launchd plist
func LaunchdPlistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", "com.feelgoodbot.daemon.plist")
}

// Install installs the daemon as a launchd service
func Install(binaryPath string, scanInterval time.Duration) error {
	plistPath := LaunchdPlistPath()

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(plistPath), 0755); err != nil {
		return fmt.Errorf("failed to create LaunchAgents directory: %w", err)
	}

	// Write plist
	plist := LaunchdPlist(binaryPath, scanInterval)
	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return fmt.Errorf("failed to write plist: %w", err)
	}

	return nil
}

// Uninstall removes the launchd service
func Uninstall() error {
	plistPath := LaunchdPlistPath()

	if _, err := os.Stat(plistPath); os.IsNotExist(err) {
		return nil // Already uninstalled
	}

	return os.Remove(plistPath)
}

// WriteLastScan writes the last scan result to a status file
func WriteLastScan(result *scanner.ScanResult, changes []scanner.Change) error {
	home, _ := os.UserHomeDir()
	statusFile := filepath.Join(home, ".config", "feelgoodbot", "last_scan.json")

	status := map[string]interface{}{
		"timestamp":     result.EndTime,
		"files_scanned": result.FilesScanned,
		"duration_ms":   result.EndTime.Sub(result.StartTime).Milliseconds(),
		"changes":       len(changes),
		"critical":      len(scanner.FilterBySeverity(changes, scanner.SeverityCritical)),
	}

	data, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(statusFile, data, 0600)
}
