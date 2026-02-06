package alerts

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kris-hansen/feelgoodbot/internal/scanner"
)

func TestFormatAlertMessage(t *testing.T) {
	tests := []struct {
		name    string
		alert   Alert
		wantSub []string // Substrings that should appear
		wantNot []string // Substrings that should NOT appear
	}{
		{
			name: "critical alert",
			alert: Alert{
				Timestamp: time.Date(2026, 2, 6, 16, 0, 0, 0, time.UTC),
				Severity:  scanner.SeverityCritical,
				Hostname:  "macbook.local",
				Changes: []scanner.Change{
					{Path: "/usr/bin/ssh", Type: "modified", Severity: scanner.SeverityCritical, Category: "system_binary"},
				},
			},
			wantSub: []string{"🚨", "CRITICAL", "1 file(s) tampered", "macbook.local", "/usr/bin/ssh", "🔴"},
		},
		{
			name: "warning alert",
			alert: Alert{
				Timestamp: time.Date(2026, 2, 6, 16, 0, 0, 0, time.UTC),
				Severity:  scanner.SeverityWarning,
				Hostname:  "server.local",
				Changes: []scanner.Change{
					{Path: "~/.ssh/authorized_keys", Type: "added", Severity: scanner.SeverityWarning, Category: "ssh"},
				},
			},
			wantSub: []string{"⚠️", "WARNING", "1 suspicious change", "🟡"},
		},
		{
			name: "info alert",
			alert: Alert{
				Timestamp: time.Date(2026, 2, 6, 16, 0, 0, 0, time.UTC),
				Severity:  scanner.SeverityInfo,
				Hostname:  "dev.local",
				Changes: []scanner.Change{
					{Path: "/etc/hosts", Type: "modified", Severity: scanner.SeverityInfo},
				},
			},
			wantSub: []string{"ℹ️", "1 change(s) detected"},
		},
		{
			name: "truncated list",
			alert: Alert{
				Timestamp: time.Date(2026, 2, 6, 16, 0, 0, 0, time.UTC),
				Severity:  scanner.SeverityWarning,
				Hostname:  "test.local",
				Changes: func() []scanner.Change {
					changes := make([]scanner.Change, 15)
					for i := range changes {
						changes[i] = scanner.Change{Path: "/path/" + string(rune('a'+i)), Type: "modified", Severity: scanner.SeverityWarning}
					}
					return changes
				}(),
			},
			wantSub: []string{"... and 5 more files"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatAlertMessage(tt.alert)

			for _, sub := range tt.wantSub {
				if !strings.Contains(got, sub) {
					t.Errorf("formatAlertMessage() missing %q in:\n%s", sub, got)
				}
			}

			for _, sub := range tt.wantNot {
				if strings.Contains(got, sub) {
					t.Errorf("formatAlertMessage() should not contain %q in:\n%s", sub, got)
				}
			}
		})
	}
}

func TestSendClawdbot(t *testing.T) {
	var receivedPayload ClawdbotAgentPayload
	var receivedToken string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedToken = r.Header.Get("x-clawdbot-token")

		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &receivedPayload)

		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	alerter := NewAlerter(Config{
		ClawdbotURL:    server.URL,
		ClawdbotSecret: "test-secret",
	})

	alert := Alert{
		Timestamp: time.Now(),
		Severity:  scanner.SeverityCritical,
		Hostname:  "test.local",
		Changes: []scanner.Change{
			{Path: "/usr/bin/ssh", Type: "modified", Severity: scanner.SeverityCritical},
		},
	}

	err := alerter.sendClawdbot(alert)
	if err != nil {
		t.Fatalf("sendClawdbot() error = %v", err)
	}

	// Check auth header
	if receivedToken != "test-secret" {
		t.Errorf("expected token 'test-secret', got %q", receivedToken)
	}

	// Check payload structure
	if receivedPayload.Name != "feelgoodbot" {
		t.Errorf("expected name 'feelgoodbot', got %q", receivedPayload.Name)
	}
	if !receivedPayload.Deliver {
		t.Error("expected deliver=true")
	}
	if receivedPayload.Channel != "last" {
		t.Errorf("expected channel 'last', got %q", receivedPayload.Channel)
	}
	if !strings.Contains(receivedPayload.Message, "CRITICAL") {
		t.Error("message should contain CRITICAL")
	}
}

func TestSendClawdbotError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	alerter := NewAlerter(Config{
		ClawdbotURL: server.URL,
	})

	alert := Alert{
		Timestamp: time.Now(),
		Severity:  scanner.SeverityInfo,
		Hostname:  "test.local",
	}

	err := alerter.sendClawdbot(alert)
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should mention status code: %v", err)
	}
}

func TestAlerterSend(t *testing.T) {
	clawdbotCalled := false
	slackCalled := false

	clawdbotServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clawdbotCalled = true
		w.WriteHeader(http.StatusAccepted)
	}))
	defer clawdbotServer.Close()

	slackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slackCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer slackServer.Close()

	alerter := NewAlerter(Config{
		ClawdbotURL: clawdbotServer.URL,
		SlackURL:    slackServer.URL,
	})

	alert := Alert{
		Timestamp: time.Now(),
		Severity:  scanner.SeverityWarning,
		Message:   "Test alert",
		Hostname:  "test.local",
		Changes: []scanner.Change{
			{Path: "/test", Type: "modified", Severity: scanner.SeverityWarning},
		},
	}

	err := alerter.Send(alert)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	if !clawdbotCalled {
		t.Error("Clawdbot webhook not called")
	}
	if !slackCalled {
		t.Error("Slack webhook not called")
	}
}

func TestGetHostname(t *testing.T) {
	hostname := GetHostname()
	if hostname == "" || hostname == "unknown" {
		t.Skip("Could not determine hostname")
	}
	// Just verify it returns something
	if len(hostname) == 0 {
		t.Error("GetHostname() returned empty string")
	}
}
