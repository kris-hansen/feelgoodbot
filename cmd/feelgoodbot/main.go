package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kris-hansen/feelgoodbot/internal/config"
	"github.com/kris-hansen/feelgoodbot/internal/daemon"
	"github.com/kris-hansen/feelgoodbot/internal/scanner"
	"github.com/kris-hansen/feelgoodbot/internal/snapshot"
	"github.com/kris-hansen/feelgoodbot/internal/totp"
	"github.com/kris-hansen/feelgoodbot/pkg/indicators"
)

var version = "0.1.0-dev"

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "feelgoodbot",
	Short: "Malware detection for macOS",
	Long: `feelgoodbot - Know when you've been compromised.

Monitors critical system files for unauthorized changes and alerts you 
immediately when tampering is detected.

Based on analysis of real-world attacks including:
  • GTG-1002 Claude Code espionage campaign
  • Shai-Hulud npm supply chain attack
  • Various coding agent compromises

Quick start:
  feelgoodbot init           # Create baseline snapshot
  feelgoodbot scan           # Check for changes
  feelgoodbot daemon install # Install as boot service
  feelgoodbot daemon start   # Start monitoring`,
	Version: version,
}

func init() {
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(snapshotCmd)
	rootCmd.AddCommand(diffCmd)
	rootCmd.AddCommand(daemonCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(indicatorsCmd)
	rootCmd.AddCommand(totpCmd)
}

// init command - create initial baseline
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize feelgoodbot and create baseline snapshot",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("🛡️  Initializing feelgoodbot...")
		fmt.Println()

		// Create snapshot store
		store, err := snapshot.NewStore()
		if err != nil {
			return fmt.Errorf("failed to create snapshot store: %w", err)
		}

		// Check if baseline already exists
		if store.HasBaseline() {
			fmt.Println("⚠️  Baseline already exists. Use 'feelgoodbot snapshot' to update it.")
			fmt.Println("   Or delete ~/.config/feelgoodbot/snapshots/baseline.json to reinitialize.")
			return nil
		}

		// Create scanner and perform initial scan
		fmt.Println("📸 Creating baseline snapshot of key file indicators...")
		fmt.Println()

		s := scanner.New()
		result := s.Scan()

		fmt.Printf("   Scanned %d files in %s\n", result.FilesScanned, result.EndTime.Sub(result.StartTime).Round(time.Millisecond))

		if len(result.Errors) > 0 {
			fmt.Printf("   ⚠️  %d files could not be scanned (permission denied)\n", len(result.Errors))
		}

		// Save baseline
		snap, err := store.SaveBaseline(result.Files)
		if err != nil {
			return fmt.Errorf("failed to save baseline: %w", err)
		}

		fmt.Println()
		fmt.Printf("✅ Baseline snapshot created (ID: %s)\n", snap.ID)
		fmt.Println()
		fmt.Println("Next steps:")
		fmt.Println("  feelgoodbot scan           - Run integrity check")
		fmt.Println("  feelgoodbot daemon install - Install as boot service")
		fmt.Println("  feelgoodbot daemon start   - Start monitoring")
		return nil
	},
}

// scan command - check for changes
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan system for unauthorized changes",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("🔍 Scanning system integrity...")
		fmt.Println()

		// Load baseline
		store, err := snapshot.NewStore()
		if err != nil {
			return fmt.Errorf("failed to access snapshot store: %w", err)
		}

		if !store.HasBaseline() {
			fmt.Println("❌ No baseline found. Run 'feelgoodbot init' first.")
			return nil
		}

		baseline, err := store.LoadBaseline()
		if err != nil {
			return fmt.Errorf("failed to load baseline: %w", err)
		}

		// Perform scan
		s := scanner.New()
		result := s.Scan()

		fmt.Printf("   Scanned %d files in %s\n", result.FilesScanned, result.EndTime.Sub(result.StartTime).Round(time.Millisecond))
		fmt.Println()

		// Compare with baseline
		changes := scanner.Compare(baseline.Files, result.Files)

		if len(changes) == 0 {
			fmt.Println("✅ No tampering detected. System integrity verified.")
			return nil
		}

		// Group by severity
		critical := scanner.FilterBySeverity(changes, scanner.SeverityCritical)
		warnings := scanner.FilterBySeverity(changes, scanner.SeverityWarning)
		warnings = filterOut(warnings, critical)
		info := scanner.FilterBySeverity(changes, scanner.SeverityInfo)
		info = filterOut(info, append(critical, warnings...))

		// Display results
		if len(critical) > 0 {
			fmt.Printf("🚨 CRITICAL: %d changes detected!\n", len(critical))
			for _, c := range critical {
				fmt.Printf("   %s %s: %s\n", c.Severity.Emoji(), c.Type, c.Path)
				if c.Details != "" {
					fmt.Printf("      └─ %s\n", c.Details)
				}
			}
			fmt.Println()
		}

		if len(warnings) > 0 {
			fmt.Printf("⚠️  WARNING: %d changes detected\n", len(warnings))
			for _, c := range warnings {
				fmt.Printf("   %s %s: %s\n", c.Severity.Emoji(), c.Type, c.Path)
			}
			fmt.Println()
		}

		if len(info) > 0 {
			fmt.Printf("ℹ️  INFO: %d changes detected\n", len(info))
		}

		// Summary
		fmt.Println()
		if scanner.HasCriticalChanges(changes) {
			fmt.Println("🔴 SYSTEM MAY BE COMPROMISED - Review critical changes immediately!")
		} else if len(warnings) > 0 {
			fmt.Println("🟡 Suspicious changes detected - Review recommended")
		}

		return nil
	},
}

// snapshot command - update baseline
var snapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Update baseline snapshot (accepts current state as trusted)",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("📸 Updating baseline snapshot...")
		fmt.Println()
		fmt.Println("⚠️  WARNING: This will accept the current system state as trusted.")
		fmt.Println("   Only do this after verifying no compromise has occurred.")
		fmt.Println()

		// Create scanner and perform scan
		s := scanner.New()
		result := s.Scan()

		fmt.Printf("   Scanned %d files in %s\n", result.FilesScanned, result.EndTime.Sub(result.StartTime).Round(time.Millisecond))

		// Save new baseline
		store, err := snapshot.NewStore()
		if err != nil {
			return fmt.Errorf("failed to access snapshot store: %w", err)
		}

		snap, err := store.SaveBaseline(result.Files)
		if err != nil {
			return fmt.Errorf("failed to save baseline: %w", err)
		}

		fmt.Println()
		fmt.Printf("✅ Baseline updated (ID: %s)\n", snap.ID)
		return nil
	},
}

// diff command - show changes
var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Show all changes since baseline",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Load baseline
		store, err := snapshot.NewStore()
		if err != nil {
			return fmt.Errorf("failed to access snapshot store: %w", err)
		}

		if !store.HasBaseline() {
			fmt.Println("❌ No baseline found. Run 'feelgoodbot init' first.")
			return nil
		}

		baseline, err := store.LoadBaseline()
		if err != nil {
			return fmt.Errorf("failed to load baseline: %w", err)
		}

		fmt.Printf("📊 Changes since baseline (created %s)\n", baseline.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Println()

		// Perform scan
		s := scanner.New()
		result := s.Scan()

		// Compare
		changes := scanner.Compare(baseline.Files, result.Files)

		if len(changes) == 0 {
			fmt.Println("  (no changes)")
			return nil
		}

		// Sort by severity (critical first)
		sort.Slice(changes, func(i, j int) bool {
			return changes[i].Severity > changes[j].Severity
		})

		// Display all changes with details
		for _, c := range changes {
			fmt.Printf("%s [%s] %s: %s\n", c.Severity.Emoji(), c.Category, c.Type, c.Path)
			if c.Details != "" {
				fmt.Printf("   └─ %s\n", c.Details)
			}
			if c.Before != nil && c.After != nil {
				if c.Before.Hash != c.After.Hash {
					fmt.Printf("   └─ hash: %s... → %s...\n",
						truncate(c.Before.Hash, 16), truncate(c.After.Hash, 16))
				}
			}
		}

		return nil
	},
}

// Daemon command flags
var (
	daemonInterval string
	daemonClawdbot string
)

// daemon command - background monitoring
var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Manage background monitoring daemon",
	Long: `Manage the feelgoodbot background monitoring daemon.

The daemon continuously monitors your system for file integrity changes
and can alert you via local notifications or Clawdbot webhooks.

Commands:
  install   Install as a launchd service (runs on boot)
  uninstall Remove the launchd service
  start     Start the daemon (via launchd or foreground)
  stop      Stop the running daemon
  run       Run daemon in foreground (used by launchd)
  status    Show daemon status`,
}

var daemonInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install as a launchd service (runs on boot)",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get binary path
		binaryPath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to get executable path: %w", err)
		}

		// Resolve symlinks
		binaryPath, err = filepath.EvalSymlinks(binaryPath)
		if err != nil {
			return fmt.Errorf("failed to resolve binary path: %w", err)
		}

		// Parse interval
		interval := 5 * time.Minute
		if daemonInterval != "" {
			parsed, err := time.ParseDuration(daemonInterval)
			if err != nil {
				return fmt.Errorf("invalid interval: %w", err)
			}
			interval = parsed
		}

		fmt.Println("📦 Installing feelgoodbot daemon...")
		fmt.Printf("   Binary: %s\n", binaryPath)
		fmt.Printf("   Interval: %s\n", interval)
		fmt.Println()

		if err := daemon.Install(binaryPath, interval); err != nil {
			return fmt.Errorf("failed to install: %w", err)
		}

		plistPath := daemon.LaunchdPlistPath()
		fmt.Printf("✅ Installed launchd service: %s\n", plistPath)
		fmt.Println()
		fmt.Println("To start the daemon:")
		fmt.Println("  feelgoodbot daemon start")
		fmt.Println()
		fmt.Println("The daemon will start automatically on boot.")
		return nil
	},
}

var daemonUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove the launchd service",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("🗑️  Uninstalling feelgoodbot daemon...")

		// Stop first if running
		status := daemon.GetStatus("")
		if status.Running {
			fmt.Println("   Stopping daemon...")
			_ = exec.Command("launchctl", "unload", daemon.LaunchdPlistPath()).Run()
		}

		if err := daemon.Uninstall(); err != nil {
			return fmt.Errorf("failed to uninstall: %w", err)
		}

		fmt.Println("✅ Daemon uninstalled")
		return nil
	},
}

var daemonStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the monitoring daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Check if plist exists
		plistPath := daemon.LaunchdPlistPath()
		if _, err := os.Stat(plistPath); os.IsNotExist(err) {
			fmt.Println("❌ Daemon not installed. Run 'feelgoodbot daemon install' first.")
			return nil
		}

		// Check if already running
		status := daemon.GetStatus("")
		if status.Running {
			fmt.Printf("ℹ️  Daemon already running (PID %d)\n", status.PID)
			return nil
		}

		fmt.Println("🚀 Starting feelgoodbot daemon...")

		// Load via launchctl
		output, err := exec.Command("launchctl", "load", plistPath).CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to start daemon: %w\n%s", err, output)
		}

		// Wait a moment and check status
		time.Sleep(500 * time.Millisecond)
		status = daemon.GetStatus("")
		if status.Running {
			fmt.Printf("✅ Daemon started (PID %d)\n", status.PID)
		} else {
			fmt.Println("⚠️  Daemon may have failed to start. Check logs:")
			fmt.Println("   ~/.config/feelgoodbot/daemon.log")
		}

		return nil
	},
}

var daemonStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the monitoring daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		status := daemon.GetStatus("")
		if !status.Running {
			fmt.Println("ℹ️  Daemon is not running")
			return nil
		}

		fmt.Println("🛑 Stopping feelgoodbot daemon...")

		plistPath := daemon.LaunchdPlistPath()
		if _, err := os.Stat(plistPath); err == nil {
			// Unload via launchctl
			_ = exec.Command("launchctl", "unload", plistPath).Run()
		} else {
			// Kill directly
			if p, err := os.FindProcess(status.PID); err == nil {
				_ = p.Signal(os.Interrupt)
			}
		}

		fmt.Println("✅ Daemon stopped")
		return nil
	},
}

var daemonRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run daemon in foreground (used by launchd)",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Load config file
		fileCfg, err := config.Load()
		if err != nil {
			// Non-fatal - use defaults
			fileCfg = config.DefaultConfig()
		}

		// Parse interval from CLI or config
		interval := fileCfg.ScanInterval
		if daemonInterval != "" {
			parsed, err := time.ParseDuration(daemonInterval)
			if err != nil {
				return fmt.Errorf("invalid interval: %w", err)
			}
			interval = parsed
		}

		// Build daemon config
		cfg := daemon.DefaultConfig()
		cfg.ScanInterval = interval

		// Map config file alerts to daemon alert config
		if fileCfg.Alerts.Clawdbot.Enabled {
			cfg.AlertConfig.ClawdbotURL = fileCfg.Alerts.Clawdbot.Webhook
			cfg.AlertConfig.ClawdbotSecret = fileCfg.Alerts.Clawdbot.Secret
			cfg.AlertConfig.ClawdbotTo = fileCfg.Alerts.Clawdbot.To
		}
		if fileCfg.Alerts.Slack.Enabled {
			cfg.AlertConfig.SlackURL = fileCfg.Alerts.Slack.WebhookURL
		}
		cfg.AlertConfig.LocalNotify = fileCfg.Alerts.LocalNotification

		// CLI flag overrides config file
		if daemonClawdbot != "" {
			cfg.AlertConfig.ClawdbotURL = daemonClawdbot
		}

		// Create and run daemon
		d, err := daemon.New(cfg)
		if err != nil {
			return fmt.Errorf("failed to create daemon: %w", err)
		}

		return d.Run(context.Background())
	},
}

var daemonStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show daemon status",
	RunE: func(cmd *cobra.Command, args []string) error {
		status := daemon.GetStatus("")

		fmt.Println("📊 Daemon Status")
		fmt.Println()

		if status.Running {
			fmt.Printf("   Status:  🟢 Running (PID %d)\n", status.PID)
		} else {
			fmt.Println("   Status:  🔴 Stopped")
		}

		// Check if installed
		plistPath := daemon.LaunchdPlistPath()
		if _, err := os.Stat(plistPath); err == nil {
			fmt.Println("   Service: ✓ Installed (runs on boot)")
		} else {
			fmt.Println("   Service: ✗ Not installed")
		}

		// Check logs
		home, _ := os.UserHomeDir()
		logPath := filepath.Join(home, ".config", "feelgoodbot", "daemon.log")
		if info, err := os.Stat(logPath); err == nil {
			fmt.Printf("   Log:     %s (%.1f KB)\n", logPath, float64(info.Size())/1024)
		}

		return nil
	},
}

func init() {
	// Add flags to daemon commands
	daemonInstallCmd.Flags().StringVar(&daemonInterval, "interval", "5m", "Scan interval (e.g., 5m, 1h)")
	daemonRunCmd.Flags().StringVar(&daemonInterval, "interval", "5m", "Scan interval (e.g., 5m, 1h)")
	daemonRunCmd.Flags().StringVar(&daemonClawdbot, "clawdbot", "", "Clawdbot webhook URL for alerts")

	daemonCmd.AddCommand(daemonInstallCmd)
	daemonCmd.AddCommand(daemonUninstallCmd)
	daemonCmd.AddCommand(daemonStartCmd)
	daemonCmd.AddCommand(daemonStopCmd)
	daemonCmd.AddCommand(daemonRunCmd)
	daemonCmd.AddCommand(daemonStatusCmd)
}

// status command - show status
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show feelgoodbot status",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("📊 feelgoodbot status")
		fmt.Println()

		// Baseline info
		store, err := snapshot.NewStore()
		if err != nil {
			fmt.Println("Baseline:    error accessing store")
		} else if store.HasBaseline() {
			baseline, err := store.LoadBaseline()
			if err != nil {
				fmt.Println("Baseline:    error loading")
			} else {
				fmt.Printf("Baseline:    %s (created %s)\n", baseline.ID, baseline.CreatedAt.Format("2006-01-02 15:04"))
				fmt.Printf("Files:       %d monitored\n", len(baseline.Files))
			}
		} else {
			fmt.Println("Baseline:    not initialized (run 'feelgoodbot init')")
		}

		// Daemon info
		status := daemon.GetStatus("")
		if status.Running {
			fmt.Printf("Daemon:      🟢 running (PID %d)\n", status.PID)
		} else {
			fmt.Println("Daemon:      🔴 stopped")
		}

		// Service info
		plistPath := daemon.LaunchdPlistPath()
		if _, err := os.Stat(plistPath); err == nil {
			fmt.Println("Service:     ✓ installed (runs on boot)")
		} else {
			fmt.Println("Service:     ✗ not installed")
		}

		fmt.Printf("Indicators:  %d paths configured\n", len(indicators.DefaultIndicators()))

		return nil
	},
}

// config command
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Show or edit configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("📝 Configuration")
		fmt.Println()
		fmt.Println("Config file: ~/.config/feelgoodbot/config.yaml")
		fmt.Println()
		fmt.Println("Default settings:")
		fmt.Println("  scan_interval: 5m")
		fmt.Println("  alerts.local_notification: true")
		fmt.Println("  response.on_critical: [alert]")
		return nil
	},
}

// indicators command
var indicatorsCmd = &cobra.Command{
	Use:   "indicators",
	Short: "Manage monitored file indicators",
}

var indicatorsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all monitored paths",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("📁 Monitored Key File Indicators")
		fmt.Println()

		inds := indicators.DefaultIndicators()

		// Group by category
		byCategory := make(map[string][]indicators.Indicator)
		for _, ind := range inds {
			byCategory[ind.Category] = append(byCategory[ind.Category], ind)
		}

		// Print in order
		categoryOrder := []string{
			"system_binaries",
			"persistence",
			"privilege_escalation",
			"ssh",
			"shell_config",
			"kernel",
			"package_managers",
			"npm",
			"git",
			"cron",
			"browser",
			"ai_agents",
			"network",
			"system_config",
			"apps",
		}

		for _, cat := range categoryOrder {
			if inds, ok := byCategory[cat]; ok {
				fmt.Printf("%s:\n", formatCategory(cat))
				for _, ind := range inds {
					sev := "●"
					switch ind.Severity {
					case indicators.Critical:
						sev = "🔴"
					case indicators.Warning:
						sev = "🟡"
					case indicators.Info:
						sev = "🔵"
					}
					fmt.Printf("  %s %s\n", sev, ind.Path)
				}
				fmt.Println()
			}
		}

		fmt.Println("Legend: 🔴 Critical  🟡 Warning  🔵 Info")
		return nil
	},
}

var indicatorsAddCmd = &cobra.Command{
	Use:   "add <path>",
	Short: "Add a custom path to monitor",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("✓ Added indicator: %s\n", args[0])
		fmt.Println("   (Note: Custom indicators not yet persisted)")
		return nil
	},
}

func init() {
	indicatorsCmd.AddCommand(indicatorsListCmd)
	indicatorsCmd.AddCommand(indicatorsAddCmd)
}

// Helper functions

func filterOut(changes []scanner.Change, exclude []scanner.Change) []scanner.Change {
	excludeMap := make(map[string]bool)
	for _, c := range exclude {
		excludeMap[c.Path] = true
	}
	var result []scanner.Change
	for _, c := range changes {
		if !excludeMap[c.Path] {
			result = append(result, c)
		}
	}
	return result
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func formatCategory(cat string) string {
	switch cat {
	case "system_binaries":
		return "System Binaries"
	case "persistence":
		return "Persistence Mechanisms"
	case "privilege_escalation":
		return "Privilege Escalation"
	case "ssh":
		return "SSH Access"
	case "shell_config":
		return "Shell Configuration"
	case "kernel":
		return "Kernel Extensions"
	case "package_managers":
		return "Package Managers"
	case "npm":
		return "npm Packages"
	case "git":
		return "Git Configuration"
	case "cron":
		return "Scheduled Tasks"
	case "browser":
		return "Browser Extensions"
	case "ai_agents":
		return "AI Agent Configuration"
	case "network":
		return "Network Configuration"
	case "system_config":
		return "System Configuration"
	case "apps":
		return "Application Binaries"
	default:
		return cat
	}
}

// =============================================================================
// TOTP Step-Up Authentication Commands
// =============================================================================

// totp command - manage TOTP step-up authentication
var totpCmd = &cobra.Command{
	Use:   "totp",
	Short: "Manage TOTP step-up authentication",
	Long: `Manage TOTP-based step-up authentication for sensitive actions.

TOTP (Time-based One-Time Password) provides an additional security layer
for sensitive operations. When enabled, certain actions will require you
to enter a code from your authenticator app (e.g., Google Authenticator).

Commands:
  init      Set up TOTP with QR code for authenticator app
  verify    Test a TOTP code
  reset     Remove TOTP configuration (requires current code)
  backup    Show or regenerate backup codes
  status    Show TOTP configuration status
  actions   Manage which actions require step-up`,
}

var totpAccountName string

var totpInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize TOTP authentication",
	Long: `Set up TOTP authentication by generating a secret and displaying
a QR code that can be scanned with Google Authenticator or similar apps.

This command must be run from the CLI (not remotely) for security.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := totp.NewStore()
		if err != nil {
			return fmt.Errorf("failed to create TOTP store: %w", err)
		}

		if store.IsInitialized() {
			fmt.Println("⚠️  TOTP is already initialized.")
			fmt.Println("   Use 'feelgoodbot totp reset' to reinitialize.")
			return nil
		}

		// Get account name
		accountName := totpAccountName
		if accountName == "" {
			hostname, _ := os.Hostname()
			accountName = fmt.Sprintf("feelgoodbot@%s", hostname)
		}

		fmt.Println("🔐 Initializing TOTP step-up authentication...")
		fmt.Println()

		// Initialize TOTP
		data, uri, err := store.Initialize(accountName)
		if err != nil {
			return fmt.Errorf("failed to initialize TOTP: %w", err)
		}

		// Generate and display QR code
		qrCode, err := totp.GenerateQRCode(uri)
		if err != nil {
			return fmt.Errorf("failed to generate QR code: %w", err)
		}

		fmt.Println("📱 Scan this QR code with Google Authenticator:")
		fmt.Println()
		fmt.Println(qrCode)
		fmt.Println()
		fmt.Printf("   Account: %s\n", accountName)
		fmt.Printf("   Issuer:  %s\n", totp.Issuer)
		fmt.Println()

		// Show backup codes
		fmt.Println("🔑 Backup codes (save these somewhere safe!):")
		fmt.Println()
		for _, code := range data.BackupCodes {
			fmt.Printf("   %s\n", code)
		}
		fmt.Println()

		// Verify setup
		fmt.Println("Please verify setup by entering the current code from your authenticator:")
		fmt.Print("   Code: ")

		reader := bufio.NewReader(os.Stdin)
		code, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		code = strings.TrimSpace(code)
		valid, err := store.Validate(code)
		if err != nil {
			return fmt.Errorf("validation error: %w", err)
		}

		if !valid {
			// Remove the setup since verification failed
			_ = store.Reset()
			fmt.Println()
			fmt.Println("❌ Invalid code. TOTP setup canceled.")
			fmt.Println("   Please run 'feelgoodbot totp init' again.")
			return nil
		}

		fmt.Println()
		fmt.Println("✅ TOTP initialized successfully!")
		fmt.Println()
		fmt.Println("Next steps:")
		fmt.Println("  feelgoodbot totp actions add <action>  - Add actions requiring step-up")
		fmt.Println("  feelgoodbot totp status                - View current configuration")

		return nil
	},
}

var totpVerifyCmd = &cobra.Command{
	Use:   "verify [code]",
	Short: "Verify a TOTP code",
	Long:  `Test that a TOTP code is valid. Useful for debugging.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := totp.NewStore()
		if err != nil {
			return fmt.Errorf("failed to access TOTP store: %w", err)
		}

		if !store.IsInitialized() {
			fmt.Println("❌ TOTP not initialized. Run 'feelgoodbot totp init' first.")
			return nil
		}

		var code string
		if len(args) > 0 {
			code = args[0]
		} else {
			fmt.Print("Enter code: ")
			reader := bufio.NewReader(os.Stdin)
			input, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read input: %w", err)
			}
			code = strings.TrimSpace(input)
		}

		valid, err := store.Validate(code)
		if err != nil {
			return fmt.Errorf("validation error: %w", err)
		}

		if valid {
			fmt.Println("✅ Code is valid")
		} else {
			fmt.Println("❌ Code is invalid")
		}

		return nil
	},
}

var totpResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset TOTP configuration",
	Long: `Remove the current TOTP configuration. This requires entering a valid
code to confirm you have access to the authenticator.

After reset, you can run 'feelgoodbot totp init' to set up a new secret.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := totp.NewStore()
		if err != nil {
			return fmt.Errorf("failed to access TOTP store: %w", err)
		}

		if !store.IsInitialized() {
			fmt.Println("ℹ️  TOTP is not initialized. Nothing to reset.")
			return nil
		}

		fmt.Println("⚠️  This will remove your TOTP configuration.")
		fmt.Println("   You will need to set up a new authenticator entry.")
		fmt.Println()
		fmt.Print("Enter current code to confirm: ")

		reader := bufio.NewReader(os.Stdin)
		code, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		code = strings.TrimSpace(code)
		valid, err := store.Validate(code)
		if err != nil {
			return fmt.Errorf("validation error: %w", err)
		}

		if !valid {
			fmt.Println("❌ Invalid code. Reset canceled.")
			return nil
		}

		if err := store.Reset(); err != nil {
			return fmt.Errorf("failed to reset TOTP: %w", err)
		}

		fmt.Println("✅ TOTP configuration removed.")
		fmt.Println("   Run 'feelgoodbot totp init' to set up again.")

		return nil
	},
}

var totpBackupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Show or regenerate backup codes",
}

var totpBackupShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show remaining backup codes",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := totp.NewStore()
		if err != nil {
			return fmt.Errorf("failed to access TOTP store: %w", err)
		}

		if !store.IsInitialized() {
			fmt.Println("❌ TOTP not initialized. Run 'feelgoodbot totp init' first.")
			return nil
		}

		// Require authentication to view backup codes
		fmt.Print("Enter code to view backup codes: ")
		reader := bufio.NewReader(os.Stdin)
		code, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		valid, err := store.Validate(strings.TrimSpace(code))
		if err != nil {
			return fmt.Errorf("validation error: %w", err)
		}

		if !valid {
			fmt.Println("❌ Invalid code.")
			return nil
		}

		codes, err := store.GetBackupCodes()
		if err != nil {
			return fmt.Errorf("failed to get backup codes: %w", err)
		}

		fmt.Println()
		fmt.Println("🔑 Remaining backup codes:")
		fmt.Println()
		if len(codes) == 0 {
			fmt.Println("   (no backup codes remaining)")
		} else {
			for _, c := range codes {
				fmt.Printf("   %s\n", c)
			}
		}
		fmt.Printf("\n   %d of %d codes remaining\n", len(codes), totp.BackupCodeCount)

		return nil
	},
}

var totpBackupRegenCmd = &cobra.Command{
	Use:   "regenerate",
	Short: "Generate new backup codes (invalidates old ones)",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := totp.NewStore()
		if err != nil {
			return fmt.Errorf("failed to access TOTP store: %w", err)
		}

		if !store.IsInitialized() {
			fmt.Println("❌ TOTP not initialized. Run 'feelgoodbot totp init' first.")
			return nil
		}

		fmt.Println("⚠️  This will invalidate all existing backup codes.")
		fmt.Print("Enter code to confirm: ")

		reader := bufio.NewReader(os.Stdin)
		code, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		valid, err := store.Validate(strings.TrimSpace(code))
		if err != nil {
			return fmt.Errorf("validation error: %w", err)
		}

		if !valid {
			fmt.Println("❌ Invalid code.")
			return nil
		}

		codes, err := store.RegenerateBackupCodes()
		if err != nil {
			return fmt.Errorf("failed to regenerate backup codes: %w", err)
		}

		fmt.Println()
		fmt.Println("🔑 New backup codes (save these somewhere safe!):")
		fmt.Println()
		for _, c := range codes {
			fmt.Printf("   %s\n", c)
		}
		fmt.Println()
		fmt.Println("✅ Backup codes regenerated. Old codes are now invalid.")

		return nil
	},
}

var totpStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show TOTP configuration status",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("🔐 TOTP Status")
		fmt.Println()

		store, err := totp.NewStore()
		if err != nil {
			fmt.Printf("   Status: ❌ Error accessing store: %v\n", err)
			return nil
		}

		if !store.IsInitialized() {
			fmt.Println("   Status:  🔴 Not initialized")
			fmt.Println()
			fmt.Println("   Run 'feelgoodbot totp init' to set up step-up authentication.")
			return nil
		}

		fmt.Println("   Status:  🟢 Initialized")

		// Load data for details
		data, err := store.Load()
		if err == nil {
			fmt.Printf("   Account: %s\n", data.AccountName)
			fmt.Printf("   Created: %s\n", data.CreatedAt.Format("2006-01-02 15:04"))
			fmt.Printf("   Backup codes remaining: %d/%d\n", len(data.BackupCodes), totp.BackupCodeCount)
		}

		// Check session
		sm, err := totp.NewSessionManager(0)
		if err == nil && sm.IsValid() {
			remaining := sm.TimeRemaining()
			fmt.Printf("   Session: 🟢 Active (%.0f min remaining)\n", remaining.Minutes())
		} else {
			fmt.Println("   Session: ⚪ No active session")
		}

		// Show step-up config
		mgr, err := totp.NewStepUpManager()
		if err == nil {
			cfg := mgr.GetConfig()
			fmt.Println()
			fmt.Println("   Step-up actions:")
			if len(cfg.RequireStepUp) == 0 {
				fmt.Println("     (none configured)")
			} else {
				for _, action := range cfg.RequireStepUp {
					fmt.Printf("     • %s\n", action)
				}
			}
			fmt.Printf("   Session TTL: %d minutes\n", cfg.SessionTTLMinutes)
		}

		return nil
	},
}

var totpActionsCmd = &cobra.Command{
	Use:   "actions",
	Short: "Manage actions that require step-up authentication",
}

var totpActionsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List actions requiring step-up",
	RunE: func(cmd *cobra.Command, args []string) error {
		mgr, err := totp.NewStepUpManager()
		if err != nil {
			return fmt.Errorf("failed to load step-up config: %w", err)
		}

		cfg := mgr.GetConfig()

		fmt.Println("🔐 Actions requiring step-up authentication:")
		fmt.Println()

		if len(cfg.RequireStepUp) == 0 {
			fmt.Println("   (none configured)")
		} else {
			for _, action := range cfg.RequireStepUp {
				fmt.Printf("   • %s\n", action)
			}
		}

		fmt.Println()
		fmt.Printf("Session TTL: %d minutes\n", cfg.SessionTTLMinutes)
		fmt.Printf("Enabled: %v\n", cfg.Enabled)

		return nil
	},
}

var totpActionsAddCmd = &cobra.Command{
	Use:   "add <action>",
	Short: "Add an action that requires step-up",
	Long: `Add an action pattern that requires step-up authentication.

Patterns support wildcards:
  send_email       - Exact match
  payment:*        - Matches any action starting with "payment:"
  *                - Matches all actions

Examples:
  feelgoodbot totp actions add send_email
  feelgoodbot totp actions add "delete:*"
  feelgoodbot totp actions add config:update`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		action := args[0]

		mgr, err := totp.NewStepUpManager()
		if err != nil {
			return fmt.Errorf("failed to load step-up config: %w", err)
		}

		// Require step-up to modify step-up config
		if mgr.IsInitialized() {
			ok, err := mgr.CheckOrPrompt("config:update")
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}
		}

		if err := mgr.AddAction(action); err != nil {
			return err
		}

		fmt.Printf("✅ Added '%s' to step-up requirements\n", action)
		return nil
	},
}

var totpActionsRemoveCmd = &cobra.Command{
	Use:   "remove <action>",
	Short: "Remove an action from step-up requirements",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		action := args[0]

		mgr, err := totp.NewStepUpManager()
		if err != nil {
			return fmt.Errorf("failed to load step-up config: %w", err)
		}

		// Require step-up to modify step-up config
		if mgr.IsInitialized() {
			ok, err := mgr.CheckOrPrompt("config:update")
			if err != nil {
				return err
			}
			if !ok {
				return nil
			}
		}

		if err := mgr.RemoveAction(action); err != nil {
			return err
		}

		fmt.Printf("✅ Removed '%s' from step-up requirements\n", action)
		return nil
	},
}

var totpRespondCmd = &cobra.Command{
	Use:    "respond <code>",
	Short:  "Submit an OTP response to a pending prompt",
	Long:   `Used by Clawdbot to submit an OTP code received via Telegram to a pending step-up prompt.`,
	Args:   cobra.ExactArgs(1),
	Hidden: true, // Internal command for Clawdbot integration
	RunE: func(cmd *cobra.Command, args []string) error {
		code := strings.TrimSpace(args[0])
		if code == "" {
			return fmt.Errorf("code cannot be empty")
		}

		if err := totp.SubmitResponse(code); err != nil {
			return err
		}

		fmt.Println("✅ OTP response submitted")
		return nil
	},
}

var totpCheckCmd = &cobra.Command{
	Use:   "check <action>",
	Short: "Check if an action requires step-up and prompt if needed",
	Long: `Check if an action requires step-up authentication. If it does and 
there's no valid session, prompts for an OTP code.

Exit codes:
  0 - Authenticated (or action doesn't require step-up)
  1 - Authentication failed or denied

Examples:
  feelgoodbot totp check send_email
  feelgoodbot totp check "delete:important_file"`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		action := args[0]

		mgr, err := totp.NewStepUpManager()
		if err != nil {
			return fmt.Errorf("failed to create step-up manager: %w", err)
		}

		if !mgr.IsInitialized() {
			// TOTP not set up, allow action
			fmt.Println("ℹ️  TOTP not initialized, action allowed")
			return nil
		}

		ok, err := mgr.CheckOrPrompt(action)
		if err != nil {
			return err
		}

		if !ok {
			os.Exit(1)
		}

		return nil
	},
}

func init() {
	// TOTP init flags
	totpInitCmd.Flags().StringVar(&totpAccountName, "account", "", "Account name for authenticator (default: feelgoodbot@hostname)")

	// Add TOTP subcommands
	totpCmd.AddCommand(totpInitCmd)
	totpCmd.AddCommand(totpVerifyCmd)
	totpCmd.AddCommand(totpResetCmd)
	totpCmd.AddCommand(totpBackupCmd)
	totpCmd.AddCommand(totpStatusCmd)
	totpCmd.AddCommand(totpActionsCmd)
	totpCmd.AddCommand(totpRespondCmd)
	totpCmd.AddCommand(totpCheckCmd)

	// Backup subcommands
	totpBackupCmd.AddCommand(totpBackupShowCmd)
	totpBackupCmd.AddCommand(totpBackupRegenCmd)

	// Actions subcommands
	totpActionsCmd.AddCommand(totpActionsListCmd)
	totpActionsCmd.AddCommand(totpActionsAddCmd)
	totpActionsCmd.AddCommand(totpActionsRemoveCmd)
}
