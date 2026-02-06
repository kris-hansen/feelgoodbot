// Package alerts provides Clawdbot webhook integration for feelgoodbot
package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/kris-hansen/feelgoodbot/internal/scanner"
)

// ClawdbotAgentPayload is the webhook payload for Clawdbot's /hooks/agent endpoint
type ClawdbotAgentPayload struct {
	Message string `json:"message"`           // The alert message
	Name    string `json:"name"`              // Hook name (e.g., "feelgoodbot")
	Deliver bool   `json:"deliver"`           // Whether to deliver to chat
	Channel string `json:"channel,omitempty"` // Target channel (telegram, last, etc.)
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
	SlackURL       string `yaml:"slack_url"`
	LocalNotify    bool   `yaml:"local_notify"`
}

// Alerter sends alerts through various channels
type Alerter struct {
	clawdbotURL    string
	clawdbotSecret string
	slackURL       string
	localNotify    bool
}

// NewAlerter creates a new alerter with the given config
func NewAlerter(cfg Config) *Alerter {
	return &Alerter{
		clawdbotURL:    cfg.ClawdbotURL,
		clawdbotSecret: cfg.ClawdbotSecret,
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

	payload := ClawdbotAgentPayload{
		Message: message,
		Name:    "feelgoodbot",
		Deliver: true,
		Channel: "last", // Use last active channel
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
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// formatAlertMessage builds a human-readable alert message
func formatAlertMessage(alert Alert) string {
	var sb strings.Builder

	// Count by severity
	critical := 0
	warning := 0
	for _, c := range alert.Changes {
		switch c.Severity {
		case scanner.SeverityCritical:
			critical++
		case scanner.SeverityWarning:
			warning++
		}
	}

	// Header
	if critical > 0 {
		sb.WriteString(fmt.Sprintf("🚨 **CRITICAL: %d file(s) tampered on %s!**\n\n", critical, alert.Hostname))
	} else if warning > 0 {
		sb.WriteString(fmt.Sprintf("⚠️ **WARNING: %d suspicious change(s) on %s**\n\n", warning, alert.Hostname))
	} else {
		sb.WriteString(fmt.Sprintf("ℹ️ **%d change(s) detected on %s**\n\n", len(alert.Changes), alert.Hostname))
	}

	// List changes (limit to 10 for readability)
	maxShow := 10
	for i, c := range alert.Changes {
		if i >= maxShow {
			sb.WriteString(fmt.Sprintf("\n... and %d more files", len(alert.Changes)-maxShow))
			break
		}

		emoji := "📄"
		switch c.Severity {
		case scanner.SeverityCritical:
			emoji = "🔴"
		case scanner.SeverityWarning:
			emoji = "🟡"
		}

		sb.WriteString(fmt.Sprintf("%s `%s` (%s", emoji, c.Path, c.Type))
		if c.Category != "" {
			sb.WriteString(fmt.Sprintf(", %s", c.Category))
		}
		sb.WriteString(")\n")
	}

	// Timestamp
	sb.WriteString(fmt.Sprintf("\n🕐 Detected at %s", alert.Timestamp.Format("2006-01-02 15:04:05 MST")))

	return sb.String()
}

// sendSlack sends alert to Slack webhook
func (a *Alerter) sendSlack(alert Alert) error {
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
	for i, c := range alert.Changes {
		if i >= 10 {
			fileList.WriteString(fmt.Sprintf("\n... and %d more", len(alert.Changes)-10))
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
						"value": fmt.Sprintf("%d files", len(alert.Changes)),
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
	defer resp.Body.Close()

	return nil
}

// sendLocalNotification uses macOS notification center
func (a *Alerter) sendLocalNotification(alert Alert) error {
	title := "feelgoodbot Alert"

	switch alert.Severity {
	case scanner.SeverityCritical:
		title = "🚨 CRITICAL: System Tampering Detected"
	case scanner.SeverityWarning:
		title = "⚠️ Suspicious Changes Detected"
	}

	// Build message with top files
	message := alert.Message
	if len(alert.Changes) > 0 && len(message) < 200 {
		message += "\n\nTop changes:"
		for i, c := range alert.Changes {
			if i >= 3 {
				break
			}
			message += fmt.Sprintf("\n• %s", c.Path)
		}
	}

	script := fmt.Sprintf(`display notification %q with title %q sound name "Basso"`,
		message, title)

	cmd := exec.Command("osascript", "-e", script)
	return cmd.Run()
}

// Response actions

// DisconnectNetwork disables network interfaces
func DisconnectNetwork() error {
	// Disable Wi-Fi
	if err := exec.Command("networksetup", "-setairportpower", "en0", "off").Run(); err != nil {
		// Try alternate interface
		exec.Command("networksetup", "-setairportpower", "en1", "off").Run()
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
