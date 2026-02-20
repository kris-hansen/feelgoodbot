package clawdbot

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewNotifier(t *testing.T) {
	// Test with explicit config
	cfg := &NotifierConfig{
		WebhookURL: "http://test.local/webhook",
		APIToken:   "test-token",
	}

	notifier, err := NewNotifier(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if notifier.webhookURL != cfg.WebhookURL {
		t.Errorf("got webhookURL=%s, want %s", notifier.webhookURL, cfg.WebhookURL)
	}
	if notifier.apiToken != cfg.APIToken {
		t.Errorf("got apiToken=%s, want %s", notifier.apiToken, cfg.APIToken)
	}
}

func TestSendAlert(t *testing.T) {
	// Create test server
	var receivedPayload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json")
		}

		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Errorf("failed to decode payload: %v", err)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer server.Close()

	// Create notifier pointing to test server
	notifier, err := NewNotifier(&NotifierConfig{
		WebhookURL: server.URL,
	})
	if err != nil {
		t.Fatalf("failed to create notifier: %v", err)
	}

	// Send alert
	alert := &Alert{
		Type:     "test_alert",
		Severity: "high",
		Title:    "Test Alert",
		Message:  "This is a test",
	}

	err = notifier.SendAlert(alert)
	if err != nil {
		t.Fatalf("SendAlert failed: %v", err)
	}

	// Verify payload
	if receivedPayload["event"] != "feelgoodbot_alert" {
		t.Errorf("expected event feelgoodbot_alert, got %v", receivedPayload["event"])
	}

	data, ok := receivedPayload["data"].(map[string]interface{})
	if !ok {
		t.Fatal("expected data object in payload")
	}
	if data["type"] != "test_alert" {
		t.Errorf("expected type test_alert, got %v", data["type"])
	}
}

func TestSendScanResult(t *testing.T) {
	var receivedPayload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedPayload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier, _ := NewNotifier(&NotifierConfig{WebhookURL: server.URL})

	// Test critical findings
	err := notifier.SendScanResult("/path/to/skill", false, 5, 2, 3, "Malware detected")
	if err != nil {
		t.Fatalf("SendScanResult failed: %v", err)
	}

	data := receivedPayload["data"].(map[string]interface{})
	if data["severity"] != "critical" {
		t.Errorf("expected severity critical, got %v", data["severity"])
	}

	// Test clean scan
	err = notifier.SendScanResult("/path/to/safe-skill", true, 0, 0, 0, "")
	if err != nil {
		t.Fatalf("SendScanResult failed: %v", err)
	}

	data = receivedPayload["data"].(map[string]interface{})
	if data["severity"] != "info" {
		t.Errorf("expected severity info for clean scan, got %v", data["severity"])
	}
}

func TestFormatAlertMessage(t *testing.T) {
	tests := []struct {
		name      string
		critical  int
		high      int
		medium    int
		wantEmoji string
	}{
		{
			name:      "critical",
			critical:  1,
			wantEmoji: "🚨",
		},
		{
			name:      "high",
			high:      2,
			wantEmoji: "🔴",
		},
		{
			name:      "medium only",
			medium:    3,
			wantEmoji: "⚠️",
		},
		{
			name:      "clean",
			wantEmoji: "✅",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := tt.critical + tt.high + tt.medium
			msg := FormatAlertMessage("/test/skill", findings, tt.critical, tt.high, tt.medium, "Test summary")
			if !contains(msg, tt.wantEmoji) {
				t.Errorf("expected %s in message, got: %s", tt.wantEmoji, msg)
			}
		})
	}
}

func TestRequestGate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return approval response
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"approved": true, "approved_by": "kris", "token": "abc123"}`))
	}))
	defer server.Close()

	notifier, _ := NewNotifier(&NotifierConfig{WebhookURL: server.URL})

	req := &GateRequest{
		Action:    "install_skill",
		SkillName: "test-skill",
		RiskLevel: "high",
	}

	resp, err := notifier.RequestGate(req)
	if err != nil {
		t.Fatalf("RequestGate failed: %v", err)
	}

	if !resp.Approved {
		t.Error("expected approved=true")
	}
	if resp.ApprovedBy != "kris" {
		t.Errorf("expected approved_by=kris, got %s", resp.ApprovedBy)
	}
}

func TestWebhookError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error": "server error"}`))
	}))
	defer server.Close()

	notifier, _ := NewNotifier(&NotifierConfig{WebhookURL: server.URL})

	err := notifier.SendAlert(&Alert{Type: "test"})
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
