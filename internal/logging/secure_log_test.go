package logging

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewSecureLog(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")
	secret := []byte("test-secret-key")

	log, err := NewSecureLog(logPath, secret)
	if err != nil {
		t.Fatalf("NewSecureLog failed: %v", err)
	}
	if log == nil {
		t.Fatal("expected non-nil log")
	}
}

func TestLogAndRead(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")
	secret := []byte("test-secret-key")

	log, _ := NewSecureLog(logPath, secret)

	// Log some events
	err := log.Log(EventAuth, "login", "success", "cli", map[string]string{"user": "test"})
	if err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	err = log.Log(EventGate, "send_email", "pending", "cli", nil)
	if err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	// Read events back
	events, err := log.GetRecent(10, "")
	if err != nil {
		t.Fatalf("GetRecent failed: %v", err)
	}

	if len(events) != 2 {
		t.Errorf("expected 2 events, got %d", len(events))
	}
}

func TestLogHelpers(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")
	secret := []byte("test-secret-key")

	log, _ := NewSecureLog(logPath, secret)

	// Test helper methods
	if err := log.LogAuth("login", "success", "cli", nil); err != nil {
		t.Errorf("LogAuth failed: %v", err)
	}
	if err := log.LogGate("send_email", "approved", "cli", nil); err != nil {
		t.Errorf("LogGate failed: %v", err)
	}
	if err := log.LogAlert("suspicious_activity", "detected", "daemon", nil); err != nil {
		t.Errorf("LogAlert failed: %v", err)
	}
	if err := log.LogIntegrity("file_changed", "alert", "daemon", nil); err != nil {
		t.Errorf("LogIntegrity failed: %v", err)
	}
	if err := log.LogLockdown("activate", "success", "cli", nil); err != nil {
		t.Errorf("LogLockdown failed: %v", err)
	}

	events, _ := log.GetRecent(10, "")
	if len(events) != 5 {
		t.Errorf("expected 5 events, got %d", len(events))
	}
}

func TestVerifyIntegrity(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")
	secret := []byte("test-secret-key")

	log, _ := NewSecureLog(logPath, secret)

	// Log some events
	log.Log(EventAuth, "login", "success", "cli", nil)
	log.Log(EventGate, "send_email", "approved", "cli", nil)
	log.Log(EventAlert, "warning", "detected", "daemon", nil)

	// Verify integrity
	valid, errors, err := log.Verify()
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !valid {
		t.Errorf("expected valid log, got errors: %v", errors)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")
	secret := []byte("test-secret-key")

	log, _ := NewSecureLog(logPath, secret)

	// Log some events
	log.Log(EventAuth, "login", "success", "cli", nil)
	log.Log(EventGate, "send_email", "approved", "cli", nil)

	// Tamper with the file
	data, _ := os.ReadFile(logPath)
	tampered := append(data, []byte(`{"id":"fake","timestamp":"2024-01-01T00:00:00Z","type":"auth","action":"hack","status":"success","source":"evil","prev_hash":"wrong","hash":"fake"}`)...)
	tampered = append(tampered, '\n')
	os.WriteFile(logPath, tampered, 0600)

	// Reload and verify
	log2, _ := NewSecureLog(logPath, secret)
	valid, errors, err := log2.Verify()
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if valid {
		t.Error("expected invalid log after tampering")
	}
	if len(errors) == 0 {
		t.Error("expected errors after tampering")
	}
}

func TestGetSummary(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")
	secret := []byte("test-secret-key")

	log, _ := NewSecureLog(logPath, secret)

	// Log various events
	log.LogAuth("login", "success", "cli", nil)
	log.LogAuth("login", "failure", "cli", nil)
	log.LogAuth("login", "failure", "cli", nil)
	log.LogGate("send_email", "pending", "cli", nil)
	log.LogGate("send_email", "approved", "cli", nil)
	log.LogGate("payment", "denied", "cli", nil)
	log.LogIntegrity("file_changed", "alert", "daemon", nil)

	summary, err := log.GetSummary(time.Hour, 5)
	if err != nil {
		t.Fatalf("GetSummary failed: %v", err)
	}

	if summary.TotalEvents != 7 {
		t.Errorf("TotalEvents = %d, want 7", summary.TotalEvents)
	}
	if summary.AuthAttempts != 3 {
		t.Errorf("AuthAttempts = %d, want 3", summary.AuthAttempts)
	}
	if summary.AuthFailures != 2 {
		t.Errorf("AuthFailures = %d, want 2", summary.AuthFailures)
	}
	if summary.GateRequests != 1 {
		t.Errorf("GateRequests = %d, want 1", summary.GateRequests)
	}
	if summary.GateApprovals != 1 {
		t.Errorf("GateApprovals = %d, want 1", summary.GateApprovals)
	}
	if summary.GateDenials != 1 {
		t.Errorf("GateDenials = %d, want 1", summary.GateDenials)
	}
	if summary.IntegrityAlerts != 1 {
		t.Errorf("IntegrityAlerts = %d, want 1", summary.IntegrityAlerts)
	}
	if len(summary.RecentEvents) != 5 {
		t.Errorf("RecentEvents count = %d, want 5", len(summary.RecentEvents))
	}
}

func TestGetRecentByType(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")
	secret := []byte("test-secret-key")

	log, _ := NewSecureLog(logPath, secret)

	// Log various events
	log.LogAuth("login", "success", "cli", nil)
	log.LogGate("send_email", "approved", "cli", nil)
	log.LogAuth("logout", "success", "cli", nil)
	log.LogAlert("warning", "detected", "daemon", nil)

	// Get only auth events
	authEvents, err := log.GetRecent(10, EventAuth)
	if err != nil {
		t.Fatalf("GetRecent failed: %v", err)
	}
	if len(authEvents) != 2 {
		t.Errorf("expected 2 auth events, got %d", len(authEvents))
	}

	// Get only gate events
	gateEvents, err := log.GetRecent(10, EventGate)
	if err != nil {
		t.Fatalf("GetRecent failed: %v", err)
	}
	if len(gateEvents) != 1 {
		t.Errorf("expected 1 gate event, got %d", len(gateEvents))
	}
}

func TestHashChain(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")
	secret := []byte("test-secret-key")

	log, _ := NewSecureLog(logPath, secret)

	// Log events
	log.Log(EventAuth, "action1", "success", "cli", nil)
	log.Log(EventAuth, "action2", "success", "cli", nil)
	log.Log(EventAuth, "action3", "success", "cli", nil)

	events, _ := log.GetRecent(10, "")

	// Verify hash chain
	for i := 1; i < len(events); i++ {
		if events[i].PrevHash != events[i-1].Hash {
			t.Errorf("hash chain broken at index %d", i)
		}
	}

	// First event should have empty prev_hash
	if events[0].PrevHash != "" {
		t.Error("first event should have empty prev_hash")
	}
}

func TestPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")
	secret := []byte("test-secret-key")

	// Create log and write events
	log1, _ := NewSecureLog(logPath, secret)
	log1.Log(EventAuth, "login", "success", "cli", nil)
	log1.Log(EventGate, "send_email", "approved", "cli", nil)

	// Create new log instance (simulates restart)
	log2, _ := NewSecureLog(logPath, secret)

	// Should be able to continue the chain
	log2.Log(EventAuth, "logout", "success", "cli", nil)

	// Verify all events
	events, _ := log2.GetRecent(10, "")
	if len(events) != 3 {
		t.Errorf("expected 3 events after reload, got %d", len(events))
	}

	// Verify chain integrity
	valid, _, _ := log2.Verify()
	if !valid {
		t.Error("expected valid chain after reload and append")
	}
}
