package gate

import (
	"testing"
	"time"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine(nil)
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
	if e.config == nil {
		t.Fatal("expected default config")
	}
}

func TestRequiresGate(t *testing.T) {
	cfg := &Config{
		BlockedActions: []ActionRule{
			{Pattern: "send_email", Mode: "strict"},
			{Pattern: "payment:*", Mode: "strict"},
			{Pattern: "delete:*", Mode: "session"},
		},
	}
	e := NewEngine(cfg)

	tests := []struct {
		action   string
		expected bool
	}{
		{"send_email", true},
		{"send_sms", false},
		{"payment:transfer", true},
		{"payment:refund", true},
		{"delete:file", true},
		{"delete:backup", true},
		{"read:file", false},
	}

	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			requires, _ := e.RequiresGate(tt.action)
			if requires != tt.expected {
				t.Errorf("RequiresGate(%q) = %v, want %v", tt.action, requires, tt.expected)
			}
		})
	}
}

func TestCreateRequest(t *testing.T) {
	cfg := &Config{
		RequestTTL: 5 * time.Minute,
		TokenTTL:   15 * time.Minute,
		BlockedActions: []ActionRule{
			{Pattern: "send_email", Mode: "strict"},
		},
	}
	e := NewEngine(cfg)

	req, err := e.CreateRequest("send_email", "cli", nil)
	if err != nil {
		t.Fatalf("CreateRequest failed: %v", err)
	}

	if req.ID == "" {
		t.Error("expected non-empty ID")
	}
	if req.Action != "send_email" {
		t.Errorf("Action = %q, want %q", req.Action, "send_email")
	}
	if req.Status != StatusPending {
		t.Errorf("Status = %q, want %q", req.Status, StatusPending)
	}
	if req.Source != "cli" {
		t.Errorf("Source = %q, want %q", req.Source, "cli")
	}
}

func TestApproveRequest(t *testing.T) {
	cfg := &Config{
		RequestTTL: 5 * time.Minute,
		TokenTTL:   15 * time.Minute,
		BlockedActions: []ActionRule{
			{Pattern: "send_email", Mode: "strict"},
		},
	}
	e := NewEngine(cfg)

	// Set up TOTP verifier that always succeeds
	e.SetTOTPVerifier(func(code string) bool {
		return code == "123456"
	})

	req, _ := e.CreateRequest("send_email", "cli", nil)

	// Try with wrong code
	_, err := e.Approve(req.ID, "000000")
	if err == nil {
		t.Error("expected error for invalid code")
	}

	// Try with correct code
	approved, err := e.Approve(req.ID, "123456")
	if err != nil {
		t.Fatalf("Approve failed: %v", err)
	}

	if approved.Status != StatusApproved {
		t.Errorf("Status = %q, want %q", approved.Status, StatusApproved)
	}
	if approved.Token == "" {
		t.Error("expected non-empty token")
	}
}

func TestDenyRequest(t *testing.T) {
	e := NewEngine(nil)

	req, _ := e.CreateRequest("send_email", "cli", nil)

	denied, err := e.Deny(req.ID, "not authorized")
	if err != nil {
		t.Fatalf("Deny failed: %v", err)
	}

	if denied.Status != StatusDenied {
		t.Errorf("Status = %q, want %q", denied.Status, StatusDenied)
	}
	if denied.Reason != "not authorized" {
		t.Errorf("Reason = %q, want %q", denied.Reason, "not authorized")
	}
}

func TestGetPending(t *testing.T) {
	e := NewEngine(nil)

	// Create a few requests
	e.CreateRequest("action1", "cli", nil)
	e.CreateRequest("action2", "cli", nil)
	req3, _ := e.CreateRequest("action3", "cli", nil)

	// Deny one
	e.Deny(req3.ID, "denied")

	pending := e.GetPending()
	if len(pending) != 2 {
		t.Errorf("GetPending() returned %d, want 2", len(pending))
	}
}

func TestValidateToken(t *testing.T) {
	cfg := &Config{
		RequestTTL: 5 * time.Minute,
		TokenTTL:   15 * time.Minute,
	}
	e := NewEngine(cfg)
	e.SetTOTPVerifier(func(code string) bool { return true })

	req, _ := e.CreateRequest("send_email", "cli", nil)
	approved, _ := e.Approve(req.ID, "123456")

	// Valid token for same action
	if !e.ValidateToken(approved.Token, "send_email") {
		t.Error("expected token to be valid for same action")
	}

	// Invalid token
	if e.ValidateToken("invalid_token", "send_email") {
		t.Error("expected invalid token to fail")
	}
}

func TestRevokeToken(t *testing.T) {
	cfg := &Config{
		RequestTTL: 5 * time.Minute,
		TokenTTL:   15 * time.Minute,
	}
	e := NewEngine(cfg)
	e.SetTOTPVerifier(func(code string) bool { return true })

	req, _ := e.CreateRequest("send_email", "cli", nil)
	approved, _ := e.Approve(req.ID, "123456")

	// Token should be valid
	if !e.ValidateToken(approved.Token, "send_email") {
		t.Error("expected token to be valid before revoke")
	}

	// Revoke it
	if err := e.RevokeToken(approved.Token); err != nil {
		t.Fatalf("RevokeToken failed: %v", err)
	}

	// Token should now be invalid
	if e.ValidateToken(approved.Token, "send_email") {
		t.Error("expected token to be invalid after revoke")
	}
}

func TestRevokeAll(t *testing.T) {
	cfg := &Config{
		RequestTTL: 5 * time.Minute,
		TokenTTL:   15 * time.Minute,
	}
	e := NewEngine(cfg)
	e.SetTOTPVerifier(func(code string) bool { return true })

	// Create and approve multiple requests
	req1, _ := e.CreateRequest("action1", "cli", nil)
	req2, _ := e.CreateRequest("action2", "cli", nil)
	approved1, _ := e.Approve(req1.ID, "123456")
	approved2, _ := e.Approve(req2.ID, "123456")

	// Both tokens should be valid
	if !e.ValidateToken(approved1.Token, "action1") || !e.ValidateToken(approved2.Token, "action2") {
		t.Error("expected both tokens to be valid before revoke")
	}

	// Revoke all
	count := e.RevokeAll()
	if count != 2 {
		t.Errorf("RevokeAll() = %d, want 2", count)
	}

	// Both tokens should be invalid
	if e.ValidateToken(approved1.Token, "action1") || e.ValidateToken(approved2.Token, "action2") {
		t.Error("expected both tokens to be invalid after revoke all")
	}
}

func TestSessionModeAutoApproval(t *testing.T) {
	cfg := &Config{
		RequestTTL: 5 * time.Minute,
		TokenTTL:   15 * time.Minute,
		BlockedActions: []ActionRule{
			{Pattern: "delete:*", Mode: "session"},
		},
	}
	e := NewEngine(cfg)

	// Set session as valid
	e.SetSessionChecker(func() bool { return true })

	// Request should auto-approve
	req, err := e.CreateRequest("delete:file", "cli", nil)
	if err != nil {
		t.Fatalf("CreateRequest failed: %v", err)
	}

	if req.Status != StatusApproved {
		t.Errorf("Status = %q, want %q (session mode auto-approval)", req.Status, StatusApproved)
	}
	if req.Token == "" {
		t.Error("expected token for auto-approved request")
	}
}

func TestStats(t *testing.T) {
	cfg := &Config{
		RequestTTL: 5 * time.Minute,
		TokenTTL:   15 * time.Minute,
	}
	e := NewEngine(cfg)
	e.SetTOTPVerifier(func(code string) bool { return true })

	// Create some requests
	req1, _ := e.CreateRequest("action1", "cli", nil)
	req2, _ := e.CreateRequest("action2", "cli", nil)
	req3, _ := e.CreateRequest("action3", "cli", nil)

	// Approve one, deny one, leave one pending
	e.Approve(req1.ID, "123456")
	e.Deny(req2.ID, "denied")

	stats := e.Stats()

	if stats["pending_requests"].(int) != 1 {
		t.Errorf("pending_requests = %v, want 1", stats["pending_requests"])
	}
	if stats["approved_total"].(int) != 1 {
		t.Errorf("approved_total = %v, want 1", stats["approved_total"])
	}
	if stats["denied_total"].(int) != 1 {
		t.Errorf("denied_total = %v, want 1", stats["denied_total"])
	}
	if stats["active_tokens"].(int) != 1 {
		t.Errorf("active_tokens = %v, want 1", stats["active_tokens"])
	}

	_ = req3 // unused but created
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		action  string
		want    bool
	}{
		{"send_email", "send_email", true},
		{"send_email", "send_sms", false},
		{"payment:*", "payment:transfer", true},
		{"payment:*", "payment:refund", true},
		{"payment:*", "delete:file", false},
		{"*", "anything", true},
		{"delete:*", "delete:file", true},
		{"delete:*", "delete:", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.action, func(t *testing.T) {
			got := matchPattern(tt.pattern, tt.action)
			if got != tt.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.pattern, tt.action, got, tt.want)
			}
		})
	}
}
