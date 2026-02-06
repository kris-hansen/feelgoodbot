// Package alerts handles notifications when tampering is detected
package alerts

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"time"

	"github.com/kris-hansen/feelgoodbot/internal/scanner"
)

// Alert represents a security alert
type Alert struct {
	Timestamp time.Time         `json:"timestamp"`
	Severity  scanner.Severity  `json:"severity"`
	Message   string            `json:"message"`
	Changes   []scanner.Change  `json:"changes"`
	Hostname  string            `json:"hostname"`
}

// Alerter sends alerts through various channels
type Alerter struct {
	clawdbotURL    string
	clawdbotSecret string
	slackURL       string
	localNotify    bool
}

// Config for alerter
type Config struct {
	ClawdbotURL    string `yaml:"clawdbot_url"`
	ClawdbotSecret string `yaml:"clawdbot_secret"`
	SlackURL       string `yaml:"slack_url"`
	LocalNotify    bool   `yaml:"local_notify"`
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
	payload, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", a.clawdbotURL, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Feelgoodbot-Event", "security_alert")
	
	// Add HMAC signature if secret is configured
	if a.clawdbotSecret != "" {
		sig := computeHMAC(payload, a.clawdbotSecret)
		req.Header.Set("X-Feelgoodbot-Signature", sig)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
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

	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"title": fmt.Sprintf("%s feelgoodbot Security Alert", emoji),
				"text":  alert.Message,
				"fields": []map[string]interface{}{
					{
						"title": "Severity",
						"value": alert.Severity.String(),
						"short": true,
					},
					{
						"title": "Changes",
						"value": fmt.Sprintf("%d files affected", len(alert.Changes)),
						"short": true,
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
	message := alert.Message
	
	if alert.Severity == scanner.SeverityCritical {
		title = "🚨 CRITICAL: System Tampering Detected"
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
	
	// Could also disable Ethernet if needed
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
