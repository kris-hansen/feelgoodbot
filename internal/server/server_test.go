package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kris-hansen/feelgoodbot/internal/gate"
	"github.com/kris-hansen/feelgoodbot/internal/logging"
)

func setupTestServer(t *testing.T) *Server {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")
	socketPath := filepath.Join(tmpDir, "test.sock")

	log, err := logging.NewSecureLog(logPath, []byte("test-secret"))
	if err != nil {
		t.Fatalf("failed to create log: %v", err)
	}

	gateEngine := gate.NewEngine(&gate.Config{
		RequestTTL: 5 * time.Minute,
		TokenTTL:   15 * time.Minute,
		BlockedActions: []gate.ActionRule{
			{Pattern: "send_email", Mode: "strict"},
			{Pattern: "payment:*", Mode: "strict"},
		},
	})
	gateEngine.SetTOTPVerifier(func(code string) bool {
		return code == "123456"
	})

	return New(&Config{
		SocketPath: socketPath,
		Gate:       gateEngine,
		Log:        log,
	})
}

func TestGateRequestEndpoint(t *testing.T) {
	srv := setupTestServer(t)

	body := bytes.NewBufferString(`{"action":"send_email","source":"test"}`)
	req := httptest.NewRequest("POST", "/gate/request", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp apiResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if !resp.Success {
		t.Errorf("expected success, got error: %s", resp.Error)
	}
}

func TestGateApproveEndpoint(t *testing.T) {
	srv := setupTestServer(t)

	// First create a request
	body := bytes.NewBufferString(`{"action":"send_email","source":"test"}`)
	req := httptest.NewRequest("POST", "/gate/request", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	var createResp struct {
		Success bool `json:"success"`
		Data    struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &createResp)

	// Now approve it
	approveBody := bytes.NewBufferString(`{"request_id":"` + createResp.Data.ID + `","code":"123456"}`)
	approveReq := httptest.NewRequest("POST", "/gate/approve", approveBody)
	approveReq.Header.Set("Content-Type", "application/json")

	w2 := httptest.NewRecorder()
	srv.mux.ServeHTTP(w2, approveReq)

	if w2.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var approveResp struct {
		Success bool `json:"success"`
		Data    struct {
			Status string `json:"status"`
			Token  string `json:"token"`
		} `json:"data"`
	}
	json.Unmarshal(w2.Body.Bytes(), &approveResp)

	if !approveResp.Success {
		t.Error("expected approval success")
	}
	if approveResp.Data.Status != "approved" {
		t.Errorf("expected status 'approved', got '%s'", approveResp.Data.Status)
	}
	if approveResp.Data.Token == "" {
		t.Error("expected non-empty token")
	}
}

func TestGateDenyEndpoint(t *testing.T) {
	srv := setupTestServer(t)

	// Create a request
	body := bytes.NewBufferString(`{"action":"send_email","source":"test"}`)
	req := httptest.NewRequest("POST", "/gate/request", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	var createResp struct {
		Success bool `json:"success"`
		Data    struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &createResp)

	// Deny it
	denyBody := bytes.NewBufferString(`{"request_id":"` + createResp.Data.ID + `","reason":"not authorized"}`)
	denyReq := httptest.NewRequest("POST", "/gate/deny", denyBody)
	denyReq.Header.Set("Content-Type", "application/json")

	w2 := httptest.NewRecorder()
	srv.mux.ServeHTTP(w2, denyReq)

	if w2.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w2.Code)
	}
}

func TestGatePendingEndpoint(t *testing.T) {
	srv := setupTestServer(t)

	// Create a couple requests
	for i := 0; i < 3; i++ {
		body := bytes.NewBufferString(`{"action":"send_email","source":"test"}`)
		req := httptest.NewRequest("POST", "/gate/request", body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.mux.ServeHTTP(w, req)
	}

	// Get pending
	req := httptest.NewRequest("GET", "/gate/pending", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Count int `json:"count"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Data.Count != 3 {
		t.Errorf("expected 3 pending, got %d", resp.Data.Count)
	}
}

func TestLogsSummaryEndpoint(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest("GET", "/logs/summary?since=1h", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestStatusEndpoint(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest("GET", "/status", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Lockdown bool `json:"lockdown"`
		} `json:"data"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Data.Lockdown {
		t.Error("expected lockdown to be false initially")
	}
}

func TestLockdownEndpoint(t *testing.T) {
	srv := setupTestServer(t)

	// Activate lockdown
	req := httptest.NewRequest("POST", "/lockdown", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// Check lockdown status
	statusReq := httptest.NewRequest("GET", "/lockdown/status", nil)
	w2 := httptest.NewRecorder()
	srv.mux.ServeHTTP(w2, statusReq)

	var resp struct {
		Success bool `json:"success"`
		Data    struct {
			Lockdown bool `json:"lockdown"`
		} `json:"data"`
	}
	json.Unmarshal(w2.Body.Bytes(), &resp)

	if !resp.Data.Lockdown {
		t.Error("expected lockdown to be true after activation")
	}

	// Try to create a gate request - should fail
	body := bytes.NewBufferString(`{"action":"send_email","source":"test"}`)
	gateReq := httptest.NewRequest("POST", "/gate/request", body)
	gateReq.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	srv.mux.ServeHTTP(w3, gateReq)

	if w3.Code != http.StatusForbidden {
		t.Errorf("expected status 403 during lockdown, got %d", w3.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	srv := setupTestServer(t)

	// POST to a GET endpoint
	req := httptest.NewRequest("POST", "/status", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}

	// GET to a POST endpoint
	req2 := httptest.NewRequest("GET", "/gate/request", nil)
	w2 := httptest.NewRecorder()
	srv.mux.ServeHTTP(w2, req2)

	if w2.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w2.Code)
	}
}

func TestInvalidJSON(t *testing.T) {
	srv := setupTestServer(t)

	body := bytes.NewBufferString(`{invalid json}`)
	req := httptest.NewRequest("POST", "/gate/request", body)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

// Cleanup any test files
func TestMain(m *testing.M) {
	code := m.Run()
	os.Exit(code)
}
