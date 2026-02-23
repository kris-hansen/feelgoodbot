// Package alerts provides Clawdbot webhook integration for feelgoodbot
package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kris-hansen/feelgoodbot/internal/scanner"
)

// ClawdbotWakePayload is the webhook payload for Clawdbot's /hooks/wake endpoint
type ClawdbotWakePayload struct {
	Text string `json:"text"` // The alert text
	Mode string `json:"mode"` // "now" or "next-heartbeat"
}

// Alert represents a security alert
type Alert struct {
	Timestamp time.Time        `json:"timestamp"`
	Severity  scanner.Severity `json:"severity"`
	Message   string           `json:"message"`
	Changes   []scanner.Change `json:"changes"`
	Hostname  string           `json:"hostname"`
}

// Config holds alerter configuration
type Config struct {
	ClawdbotURL    string `yaml:"clawdbot_url"`
	ClawdbotSecret string `yaml:"clawdbot_secret"`
	ClawdbotTo     string `yaml:"clawdbot_to"`
	SlackURL       string `yaml:"slack_url"`
	LocalNotify    bool   `yaml:"local_notify"`
}

// Alerter sends alerts through various channels
type Alerter struct {
	clawdbotURL    string
	clawdbotSecret string
	clawdbotTo     string
	slackURL       string
	localNotify    bool
}

// NewAlerter creates a new alerter with the given config
func NewAlerter(cfg Config) *Alerter {
	return &Alerter{
		clawdbotURL:    cfg.ClawdbotURL,
		clawdbotSecret: cfg.ClawdbotSecret,
		clawdbotTo:     cfg.ClawdbotTo,
		slackURL:       cfg.SlackURL,
		localNotify:    cfg.LocalNotify,
	}
}

// Send sends an alert through all configured channels
func (a *Alerter) Send(alert Alert) error {
	var errs []error

	if a.clawdbotURL != "" {
		if err := a.sendClawdbot(alert); err != nil {
			errs = append(errs, fmt.Errorf("clawdbot: %w", err))
		}
	}

	if a.slackURL != "" {
		if err := a.sendSlack(alert); err != nil {
			errs = append(errs, fmt.Errorf("slack: %w", err))
		}
	}

	if a.localNotify {
		if err := a.sendLocalNotification(alert); err != nil {
			errs = append(errs, fmt.Errorf("local: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("some alerts failed: %v", errs)
	}
	return nil
}

// sendClawdbot sends alert to Clawdbot's /hooks/agent endpoint
func (a *Alerter) sendClawdbot(alert Alert) error {
	// Build the alert message
	message := formatAlertMessage(alert)

	payload := ClawdbotWakePayload{
		Text: message,
		Mode: "now", // Trigger immediate heartbeat
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", a.clawdbotURL, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "feelgoodbot/0.1")

	// Auth via x-clawdbot-token header
	if a.clawdbotSecret != "" {
		req.Header.Set("x-clawdbot-token", a.clawdbotSecret)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// deduplicateChanges removes duplicate entries for the same path, keeping the highest severity
func deduplicateChanges(changes []scanner.Change) []scanner.Change {
	seen := make(map[string]int) // path -> index in result
	result := make([]scanner.Change, 0, len(changes))

	for _, c := range changes {
		if idx, exists := seen[c.Path]; exists {
			// Keep the higher severity one
			if c.Severity > result[idx].Severity {
				result[idx] = c
			}
		} else {
			seen[c.Path] = len(result)
			result = append(result, c)
		}
	}
	return result
}

// formatAlertMessage builds a human-readable alert message
func formatAlertMessage(alert Alert) string {
	var sb strings.Builder

	// Deduplicate changes
	changes := deduplicateChanges(alert.Changes)

	// Count by severity
	critical := 0
	warning := 0
	for _, c := range changes {
		switch c.Severity {
		case scanner.SeverityCritical:
			critical++
		case scanner.SeverityWarning:
			warning++
		}
	}

	// Header
	switch {
	case critical > 0:
		sb.WriteString(fmt.Sprintf("🚨 **CRITICAL: %d file(s) tampered on %s!**\n\n", critical, alert.Hostname))
	case warning > 0:
		sb.WriteString(fmt.Sprintf("⚠️ **WARNING: %d suspicious change(s) on %s**\n\n", warning, alert.Hostname))
	default:
		sb.WriteString(fmt.Sprintf("ℹ️ **%d change(s) detected on %s**\n\n", len(changes), alert.Hostname))
	}

	// Group changes by severity for cleaner presentation
	var criticalChanges, warningChanges, otherChanges []scanner.Change
	for _, c := range changes {
		switch c.Severity {
		case scanner.SeverityCritical:
			criticalChanges = append(criticalChanges, c)
		case scanner.SeverityWarning:
			warningChanges = append(warningChanges, c)
		default:
			otherChanges = append(otherChanges, c)
		}
	}

	// Show critical first, then warnings, then others
	maxShow := 10
	shown := 0

	for _, c := range criticalChanges {
		if shown >= maxShow {
			break
		}
		sb.WriteString(fmt.Sprintf("🔴 `%s` (%s", c.Path, c.Type))
		if c.Category != "" {
			sb.WriteString(fmt.Sprintf(", %s", c.Category))
		}
		sb.WriteString(")\n")
		shown++
	}

	for _, c := range warningChanges {
		if shown >= maxShow {
			break
		}
		sb.WriteString(fmt.Sprintf("🟡 `%s` (%s", c.Path, c.Type))
		if c.Category != "" {
			sb.WriteString(fmt.Sprintf(", %s", c.Category))
		}
		sb.WriteString(")\n")
		shown++
	}

	for _, c := range otherChanges {
		if shown >= maxShow {
			break
		}
		sb.WriteString(fmt.Sprintf("📄 `%s` (%s", c.Path, c.Type))
		if c.Category != "" {
			sb.WriteString(fmt.Sprintf(", %s", c.Category))
		}
		sb.WriteString(")\n")
		shown++
	}

	remaining := len(changes) - shown
	if remaining > 0 {
		sb.WriteString(fmt.Sprintf("\n... and %d more files", remaining))
	}

	// Timestamp
	sb.WriteString(fmt.Sprintf("\n🕐 Detected at %s", alert.Timestamp.Format("2006-01-02 15:04:05 MST")))

	return sb.String()
}

// sendSlack sends alert to Slack webhook
func (a *Alerter) sendSlack(alert Alert) error {
	// Deduplicate changes
	changes := deduplicateChanges(alert.Changes)

	emoji := "ℹ️"
	color := "#36a64f"

	switch alert.Severity {
	case scanner.SeverityWarning:
		emoji = "⚠️"
		color = "#ffcc00"
	case scanner.SeverityCritical:
		emoji = "🚨"
		color = "#ff0000"
	}

	// Build file list
	var fileList strings.Builder
	for i, c := range changes {
		if i >= 10 {
			fileList.WriteString(fmt.Sprintf("\n... and %d more", len(changes)-10))
			break
		}
		fileList.WriteString(fmt.Sprintf("• `%s` (%s)\n", c.Path, c.Type))
	}

	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"title": fmt.Sprintf("%s feelgoodbot Alert - %s", emoji, alert.Hostname),
				"text":  alert.Message,
				"fields": []map[string]interface{}{
					{
						"title": "Severity",
						"value": alert.Severity.String(),
						"short": true,
					},
					{
						"title": "Changes",
						"value": fmt.Sprintf("%d files", len(changes)),
						"short": true,
					},
					{
						"title": "Affected Files",
						"value": fileList.String(),
						"short": false,
					},
				},
				"ts": alert.Timestamp.Unix(),
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := http.Post(a.slackURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	return nil
}

// sendLocalNotification uses macOS notification center
func (a *Alerter) sendLocalNotification(alert Alert) error {
	// Deduplicate changes
	changes := deduplicateChanges(alert.Changes)

	// Count by severity
	critical := 0
	warning := 0
	for _, c := range changes {
		switch c.Severity {
		case scanner.SeverityCritical:
			critical++
		case scanner.SeverityWarning:
			warning++
		}
	}

	// Build title
	title := "feelgoodbot"
	subtitle := ""
	switch {
	case critical > 0:
		subtitle = fmt.Sprintf("🚨 %d critical file(s) tampered!", critical)
	case warning > 0:
		subtitle = fmt.Sprintf("⚠️ %d suspicious change(s)", warning)
	default:
		subtitle = fmt.Sprintf("ℹ️ %d file(s) changed", len(changes))
	}

	// Build concise message showing just filenames (not full paths)
	var msgParts []string
	maxFiles := 5
	for i, c := range changes {
		if i >= maxFiles {
			msgParts = append(msgParts, fmt.Sprintf("+%d more", len(changes)-maxFiles))
			break
		}
		// Show just the filename for brevity
		filename := filepath.Base(c.Path)
		msgParts = append(msgParts, filename)
	}
	message := strings.Join(msgParts, ", ")

	// Write detailed alert file for "Show" button
	detailsPath := writeAlertDetails(alert, changes)

	// Try terminal-notifier first (supports click actions)
	if tnPath, err := exec.LookPath("terminal-notifier"); err == nil {
		args := []string{
			"-title", title,
			"-subtitle", subtitle,
			"-message", message,
			"-sound", "Basso",
			"-group", "feelgoodbot",
		}
		if detailsPath != "" {
			args = append(args, "-open", "file://"+detailsPath)
		}
		cmd := exec.Command(tnPath, args...)
		return cmd.Run()
	}

	// Fall back to osascript (basic notification)
	fullMessage := subtitle + "\n" + message
	script := fmt.Sprintf(`display notification %q with title %q sound name "Basso"`,
		fullMessage, title)

	cmd := exec.Command("osascript", "-e", script)
	return cmd.Run()
}

// writeAlertDetails writes full alert details to a file and returns the path
func writeAlertDetails(alert Alert, changes []scanner.Change) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	alertsDir := filepath.Join(home, ".config", "feelgoodbot", "alerts")
	if err := os.MkdirAll(alertsDir, 0700); err != nil {
		return ""
	}

	filename := fmt.Sprintf("alert_%s.txt", alert.Timestamp.Format("2006-01-02_15-04-05"))
	filePath := filepath.Join(alertsDir, filename)

	var sb strings.Builder
	sb.WriteString("═══════════════════════════════════════════════════════════════\n")
	sb.WriteString("                    FEELGOODBOT ALERT DETAILS\n")
	sb.WriteString("═══════════════════════════════════════════════════════════════\n\n")

	sb.WriteString(fmt.Sprintf("Time:     %s\n", alert.Timestamp.Format("2006-01-02 15:04:05 MST")))
	sb.WriteString(fmt.Sprintf("Host:     %s\n", alert.Hostname))
	sb.WriteString(fmt.Sprintf("Severity: %s\n", alert.Severity.String()))
	sb.WriteString(fmt.Sprintf("Files:    %d changed\n", len(changes)))

	// Count by severity
	critical := 0
	warning := 0
	for _, c := range changes {
		switch c.Severity {
		case scanner.SeverityCritical:
			critical++
		case scanner.SeverityWarning:
			warning++
		}
	}
	if critical > 0 {
		sb.WriteString(fmt.Sprintf("          └─ %d CRITICAL\n", critical))
	}
	if warning > 0 {
		sb.WriteString(fmt.Sprintf("          └─ %d warning\n", warning))
	}

	sb.WriteString("\n───────────────────────────────────────────────────────────────\n")
	sb.WriteString("                         CHANGED FILES\n")
	sb.WriteString("───────────────────────────────────────────────────────────────\n\n")

	// Group by severity
	var criticalChanges, warningChanges, otherChanges []scanner.Change
	for _, c := range changes {
		switch c.Severity {
		case scanner.SeverityCritical:
			criticalChanges = append(criticalChanges, c)
		case scanner.SeverityWarning:
			warningChanges = append(warningChanges, c)
		default:
			otherChanges = append(otherChanges, c)
		}
	}

	if len(criticalChanges) > 0 {
		sb.WriteString("🔴 CRITICAL:\n")
		for _, c := range criticalChanges {
			writeChangeDetail(&sb, c)
		}
		sb.WriteString("\n")
	}

	if len(warningChanges) > 0 {
		sb.WriteString("🟡 WARNING:\n")
		for _, c := range warningChanges {
			writeChangeDetail(&sb, c)
		}
		sb.WriteString("\n")
	}

	if len(otherChanges) > 0 {
		sb.WriteString("📄 OTHER:\n")
		for _, c := range otherChanges {
			writeChangeDetail(&sb, c)
		}
		sb.WriteString("\n")
	}

	sb.WriteString("───────────────────────────────────────────────────────────────\n")
	sb.WriteString("To investigate:\n")
	sb.WriteString("  • Run: feelgoodbot scan --verbose\n")
	sb.WriteString("  • Check: ~/.config/feelgoodbot/diffs/\n")
	sb.WriteString("───────────────────────────────────────────────────────────────\n")

	if err := os.WriteFile(filePath, []byte(sb.String()), 0600); err != nil {
		return ""
	}

	return filePath
}

// writeChangeDetail writes details for a single change
func writeChangeDetail(sb *strings.Builder, c scanner.Change) {
	sb.WriteString(fmt.Sprintf("   %s\n", c.Path))
	sb.WriteString(fmt.Sprintf("      Type:     %s\n", c.Type))
	if c.Category != "" {
		sb.WriteString(fmt.Sprintf("      Category: %s\n", c.Category))
	}
	if c.Before != nil && c.After != nil {
		if c.Before.Hash != c.After.Hash {
			sb.WriteString(fmt.Sprintf("      Hash:     %s... → %s...\n", truncHash(c.Before.Hash), truncHash(c.After.Hash)))
		}
		if c.Before.Size != c.After.Size {
			sb.WriteString(fmt.Sprintf("      Size:     %d → %d bytes\n", c.Before.Size, c.After.Size))
		}
		if c.Before.Mode != c.After.Mode {
			sb.WriteString(fmt.Sprintf("      Mode:     %s → %s\n", c.Before.Mode, c.After.Mode))
		}
	} else if c.Before != nil {
		sb.WriteString(fmt.Sprintf("      Was:      %d bytes, %s\n", c.Before.Size, truncHash(c.Before.Hash)))
	} else if c.After != nil {
		sb.WriteString(fmt.Sprintf("      Now:      %d bytes, %s\n", c.After.Size, truncHash(c.After.Hash)))
	}
}

// truncHash truncates a hash for display
func truncHash(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}

// Response actions

// DisconnectNetwork disables network interfaces
func DisconnectNetwork() error {
	// Disable Wi-Fi
	if err := exec.Command("networksetup", "-setairportpower", "en0", "off").Run(); err != nil {
		// Try alternate interface
		_ = exec.Command("networksetup", "-setairportpower", "en1", "off").Run()
	}
	return nil
}

// Shutdown powers off the system
func Shutdown() error {
	return exec.Command("osascript", "-e",
		`tell app "System Events" to shut down`).Run()
}

// ExecuteResponse runs configured response actions
func ExecuteResponse(severity scanner.Severity, actions []string) error {
	for _, action := range actions {
		switch action {
		case "disconnect_network":
			if err := DisconnectNetwork(); err != nil {
				return fmt.Errorf("failed to disconnect network: %w", err)
			}
		case "shutdown":
			if err := Shutdown(); err != nil {
				return fmt.Errorf("failed to shutdown: %w", err)
			}
		case "alert":
			// Already handled by Send()
		case "log":
			// Already handled by logging
		}
	}
	return nil
}

// GetHostname returns the current hostname
func GetHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}
