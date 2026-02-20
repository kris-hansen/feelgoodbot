// Package clawdbot provides integration with Clawdbot for notifications and gating.
package clawdbot

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Notifier sends alerts to Clawdbot
type Notifier struct {
	webhookURL string
	apiToken   string
	httpClient *http.Client
}

// NotifierConfig configures the Clawdbot notifier
type NotifierConfig struct {
	// WebhookURL is the Clawdbot webhook endpoint
	// Defaults to CLAWDBOT_WEBHOOK_URL env var
	WebhookURL string

	// APIToken for authentication
	// Defaults to CLAWDBOT_API_TOKEN env var
	APIToken string

	// Timeout for HTTP requests
	Timeout time.Duration
}

// Alert represents a security alert to send to Clawdbot
type Alert struct {
	Type     string                 `json:"type"`     // "skill_scan", "threat_detected", "gate_request"
	Severity string                 `json:"severity"` // "critical", "high", "medium", "low", "info"
	Title    string                 `json:"title"`
	Message  string                 `json:"message"`
	Details  map[string]interface{} `json:"details,omitempty"`
	Actions  []AlertAction          `json:"actions,omitempty"`
}

// AlertAction represents an action button in the alert
type AlertAction struct {
	Label    string `json:"label"`
	Callback string `json:"callback"` // Callback data for inline buttons
}

// GateRequest represents a request for user approval
type GateRequest struct {
	Action       string                 `json:"action"` // e.g., "install_skill"
	SkillName    string                 `json:"skill_name"`
	SkillPath    string                 `json:"skill_path"`
	RiskLevel    string                 `json:"risk_level"`
	Findings     int                    `json:"findings"`
	Summary      string                 `json:"summary"`
	RequiresTOTP bool                   `json:"requires_totp"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// GateResponse is the response from a gate request
type GateResponse struct {
	Approved   bool   `json:"approved"`
	ApprovedBy string `json:"approved_by,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Token      string `json:"token,omitempty"` // For subsequent gated actions
}

// NewNotifier creates a new Clawdbot notifier
func NewNotifier(cfg *NotifierConfig) (*Notifier, error) {
	if cfg == nil {
		cfg = &NotifierConfig{}
	}

	webhookURL := cfg.WebhookURL
	if webhookURL == "" {
		webhookURL = os.Getenv("CLAWDBOT_WEBHOOK_URL")
	}
	if webhookURL == "" {
		// Try default local socket path
		webhookURL = "http://localhost:3456/webhook/feelgoodbot"
	}

	apiToken := cfg.APIToken
	if apiToken == "" {
		apiToken = os.Getenv("CLAWDBOT_API_TOKEN")
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &Notifier{
		webhookURL: webhookURL,
		apiToken:   apiToken,
		httpClient: &http.Client{Timeout: timeout},
	}, nil
}

// SendAlert sends a security alert to Clawdbot
func (n *Notifier) SendAlert(alert *Alert) error {
	payload, err := json.Marshal(map[string]interface{}{
		"event": "feelgoodbot_alert",
		"data":  alert,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %w", err)
	}

	return n.post(payload)
}

// SendScanResult sends a skill scan result to Clawdbot
func (n *Notifier) SendScanResult(skillPath string, clean bool, findings int, critical int, high int, summary string) error {
	severity := "info"
	if critical > 0 {
		severity = "critical"
	} else if high > 0 {
		severity = "high"
	} else if findings > 0 {
		severity = "medium"
	}

	emoji := "✅"
	title := "Skill Scan Clean"
	if !clean {
		if severity == "critical" {
			emoji = "🚨"
			title = "CRITICAL: Malicious Skill Detected"
		} else if severity == "high" {
			emoji = "🔴"
			title = "HIGH RISK: Suspicious Skill Detected"
		} else {
			emoji = "⚠️"
			title = "Skill Scan Found Issues"
		}
	}

	alert := &Alert{
		Type:     "skill_scan",
		Severity: severity,
		Title:    fmt.Sprintf("%s %s", emoji, title),
		Message:  summary,
		Details: map[string]interface{}{
			"skill_path": skillPath,
			"findings":   findings,
			"critical":   critical,
			"high":       high,
			"clean":      clean,
		},
	}

	if !clean && (critical > 0 || high > 0) {
		alert.Actions = []AlertAction{
			{Label: "🚫 Block Skill", Callback: fmt.Sprintf("fgb:block:%s", skillPath)},
			{Label: "📋 View Details", Callback: fmt.Sprintf("fgb:details:%s", skillPath)},
		}
	}

	return n.SendAlert(alert)
}

// RequestGate sends a gate request to Clawdbot and waits for approval
// This is used for interactive approval workflows
func (n *Notifier) RequestGate(req *GateRequest) (*GateResponse, error) {
	payload, err := json.Marshal(map[string]interface{}{
		"event": "feelgoodbot_gate_request",
		"data":  req,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal gate request: %w", err)
	}

	respBody, err := n.postWithResponse(payload)
	if err != nil {
		return nil, err
	}

	var resp GateResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse gate response: %w", err)
	}

	return &resp, nil
}

func (n *Notifier) post(payload []byte) error {
	_, err := n.postWithResponse(payload)
	return err
}

func (n *Notifier) postWithResponse(payload []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", n.webhookURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if n.apiToken != "" {
		req.Header.Set("Authorization", "Bearer "+n.apiToken)
	}
	req.Header.Set("User-Agent", "feelgoodbot/1.0")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("webhook error (status %d): %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// FormatAlertMessage formats an alert for Telegram/messaging
func FormatAlertMessage(skillPath string, findings int, critical int, high int, medium int, aiSummary string) string {
	var sb strings.Builder

	if critical > 0 {
		sb.WriteString("🚨 **CRITICAL THREAT DETECTED**\n\n")
	} else if high > 0 {
		sb.WriteString("🔴 **High Risk Skill Detected**\n\n")
	} else if findings > 0 {
		sb.WriteString("⚠️ **Skill Scan Found Issues**\n\n")
	} else {
		sb.WriteString("✅ **Skill Scan Clean**\n\n")
	}

	sb.WriteString(fmt.Sprintf("📁 `%s`\n\n", skillPath))

	if findings > 0 {
		sb.WriteString("**Findings:**\n")
		if critical > 0 {
			sb.WriteString(fmt.Sprintf("  🚨 Critical: %d\n", critical))
		}
		if high > 0 {
			sb.WriteString(fmt.Sprintf("  🔴 High: %d\n", high))
		}
		if medium > 0 {
			sb.WriteString(fmt.Sprintf("  🟡 Medium: %d\n", medium))
		}
		sb.WriteString("\n")
	}

	if aiSummary != "" {
		sb.WriteString("**AI Analysis:**\n")
		sb.WriteString(aiSummary)
		sb.WriteString("\n")
	}

	return sb.String()
}
