// Package alerts provides Clawdbot webhook integration for feelgoodbot
package alerts

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/kris-hansen/feelgoodbot/internal/scanner"
)

// ClawdbotPayload is the webhook payload sent to Clawdbot
type ClawdbotPayload struct {
	Event     string    `json:"event"`
	Timestamp time.Time `json:"timestamp"`
	Hostname  string    `json:"hostname"`
	Severity  string    `json:"severity"`
	Summary   string    `json:"summary"`
	Details   Details   `json:"details"`
}

// Details contains the detailed change information
type Details struct {
	FilesScanned   int             `json:"files_scanned"`
	TotalChanges   int             `json:"total_changes"`
	CriticalCount  int             `json:"critical_count"`
	WarningCount   int             `json:"warning_count"`
	Changes        []ChangeDetail  `json:"changes"`
}

// ChangeDetail is a simplified change for the webhook
type ChangeDetail struct {
	Path     string `json:"path"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Details  string `json:"details,omitempty"`
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

// sendClawdbot sends alert to Clawdbot webhook
func (a *Alerter) sendClawdbot(alert Alert) error {
	// Build change details
	changes := make([]ChangeDetail, 0, len(alert.Changes))
	for _, c := range alert.Changes {
		changes = append(changes, ChangeDetail{
			Path:     c.Path,
			Type:     c.Type,
			Severity: c.Severity.String(),
			Category: c.Category,
			Details:  c.Details,
		})
	}

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

	// Build summary message
	var summary string
	if critical > 0 {
		summary = fmt.Sprintf("🚨 CRITICAL: %d file(s) tampered on %s!", critical, alert.Hostname)
	} else if warning > 0 {
		summary = fmt.Sprintf("⚠️ WARNING: %d suspicious change(s) on %s", warning, alert.Hostname)
	} else {
		summary = fmt.Sprintf("ℹ️ %d change(s) detected on %s", len(alert.Changes), alert.Hostname)
	}

	payload := ClawdbotPayload{
		Event:     "feelgoodbot.alert",
		Timestamp: alert.Timestamp,
		Hostname:  alert.Hostname,
		Severity:  alert.Severity.String(),
		Summary:   summary,
		Details: Details{
			TotalChanges:  len(alert.Changes),
			CriticalCount: critical,
			WarningCount:  warning,
			Changes:       changes,
		},
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
	req.Header.Set("X-Feelgoodbot-Event", "security_alert")
	
	// Add HMAC signature if secret is configured
	if a.clawdbotSecret != "" {
		sig := computeHMAC(data, a.clawdbotSecret)
		req.Header.Set("X-Feelgoodbot-Signature", sig)
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

// computeHMAC computes HMAC-SHA256 signature
func computeHMAC(message []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(message)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
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
