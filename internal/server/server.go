// Package server provides the Unix socket API server.
package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kris-hansen/feelgoodbot/internal/gate"
	"github.com/kris-hansen/feelgoodbot/internal/logging"
)

// Server is the Unix socket API server.
type Server struct {
	socketPath string
	listener   net.Listener
	gate       *gate.Engine
	log        *logging.SecureLog
	lockdown   bool
	lockdownMu sync.RWMutex
	mux        *http.ServeMux
}

// Config holds server configuration.
type Config struct {
	SocketPath string
	Gate       *gate.Engine
	Log        *logging.SecureLog
}

// New creates a new server.
func New(cfg *Config) *Server {
	s := &Server{
		socketPath: cfg.SocketPath,
		gate:       cfg.Gate,
		log:        cfg.Log,
		mux:        http.NewServeMux(),
	}
	s.setupRoutes()
	return s
}

// Start starts the server.
func (s *Server) Start() error {
	// Remove existing socket
	_ = os.Remove(s.socketPath)

	// Create socket directory
	dir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}

	// Listen on Unix socket
	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen on socket: %w", err)
	}
	s.listener = listener

	// Set socket permissions (owner only)
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}

	// Log startup
	if s.log != nil {
		_ = s.log.Log(logging.EventSystem, "server_start", "success", "daemon", nil)
	}

	// Serve
	server := &http.Server{Handler: s.mux}
	return server.Serve(listener)
}

// Stop stops the server.
func (s *Server) Stop() error {
	if s.log != nil {
		_ = s.log.Log(logging.EventSystem, "server_stop", "success", "daemon", nil)
	}
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// setupRoutes configures HTTP routes.
func (s *Server) setupRoutes() {
	// Gate endpoints
	s.mux.HandleFunc("/gate/request", s.handleGateRequest)
	s.mux.HandleFunc("/gate/approve", s.handleGateApprove)
	s.mux.HandleFunc("/gate/deny", s.handleGateDeny)
	s.mux.HandleFunc("/gate/status/", s.handleGateStatus)
	s.mux.HandleFunc("/gate/pending", s.handleGatePending)
	s.mux.HandleFunc("/gate/revoke", s.handleGateRevoke)
	s.mux.HandleFunc("/gate/validate", s.handleGateValidate)

	// Logging endpoints
	s.mux.HandleFunc("/logs/summary", s.handleLogsSummary)
	s.mux.HandleFunc("/logs/recent", s.handleLogsRecent)
	s.mux.HandleFunc("/logs/verify", s.handleLogsVerify)
	s.mux.HandleFunc("/logs/scan", s.handleLogScan)

	// Security endpoints
	s.mux.HandleFunc("/lockdown", s.handleLockdown)
	s.mux.HandleFunc("/lockdown/lift", s.handleLockdownLift)
	s.mux.HandleFunc("/lockdown/status", s.handleLockdownStatus)

	// Status endpoint
	s.mux.HandleFunc("/status", s.handleStatus)
}

// Response helpers
type apiResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(apiResponse{Success: true, Data: data})
}

func jsonError(w http.ResponseWriter, status int, err string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiResponse{Success: false, Error: err})
}

func readJSON(r *http.Request, v interface{}) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

// Gate handlers

func (s *Server) handleGateRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Check lockdown
	s.lockdownMu.RLock()
	if s.lockdown {
		s.lockdownMu.RUnlock()
		jsonError(w, http.StatusForbidden, "system is in lockdown")
		return
	}
	s.lockdownMu.RUnlock()

	var req struct {
		Action   string            `json:"action"`
		Source   string            `json:"source"`
		Metadata map[string]string `json:"metadata"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Action == "" {
		jsonError(w, http.StatusBadRequest, "action is required")
		return
	}

	gateReq, err := s.gate.CreateRequest(req.Action, req.Source, req.Metadata)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Log the request
	if s.log != nil {
		_ = s.log.LogGate(req.Action, string(gateReq.Status), req.Source, map[string]string{
			"request_id": gateReq.ID,
		})
	}

	jsonResponse(w, gateReq)
}

func (s *Server) handleGateApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		RequestID string `json:"request_id"`
		Code      string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	gateReq, err := s.gate.Approve(req.RequestID, req.Code)
	if err != nil {
		// Log failure
		if s.log != nil {
			_ = s.log.LogAuth("gate_approve", "failure", "api", map[string]string{
				"request_id": req.RequestID,
				"error":      err.Error(),
			})
		}
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Log success
	if s.log != nil {
		_ = s.log.LogGate(gateReq.Action, "approved", "api", map[string]string{
			"request_id": gateReq.ID,
			"token":      gateReq.Token[:8] + "...", // Truncate for log
		})
	}

	jsonResponse(w, gateReq)
}

func (s *Server) handleGateDeny(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		RequestID string `json:"request_id"`
		Reason    string `json:"reason"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	gateReq, err := s.gate.Deny(req.RequestID, req.Reason)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Log denial
	if s.log != nil {
		_ = s.log.LogGate(gateReq.Action, "denied", "api", map[string]string{
			"request_id": gateReq.ID,
			"reason":     req.Reason,
		})
	}

	jsonResponse(w, gateReq)
}

func (s *Server) handleGateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Extract ID from path: /gate/status/{id}
	id := strings.TrimPrefix(r.URL.Path, "/gate/status/")
	if id == "" {
		jsonError(w, http.StatusBadRequest, "request ID required")
		return
	}

	req, ok := s.gate.GetRequest(id)
	if !ok {
		jsonError(w, http.StatusNotFound, "request not found")
		return
	}

	jsonResponse(w, req)
}

func (s *Server) handleGatePending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	pending := s.gate.GetPending()
	jsonResponse(w, map[string]interface{}{
		"pending": pending,
		"count":   len(pending),
	})
}

func (s *Server) handleGateRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		Token string `json:"token"`
		All   bool   `json:"all"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.All {
		count := s.gate.RevokeAll()
		if s.log != nil {
			_ = s.log.LogGate("revoke_all", "success", "api", map[string]string{
				"count": fmt.Sprintf("%d", count),
			})
		}
		jsonResponse(w, map[string]int{"revoked": count})
		return
	}

	if req.Token == "" {
		jsonError(w, http.StatusBadRequest, "token or all=true required")
		return
	}

	if err := s.gate.RevokeToken(req.Token); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	if s.log != nil {
		_ = s.log.LogGate("revoke_token", "success", "api", map[string]string{
			"token": req.Token[:8] + "...",
		})
	}

	jsonResponse(w, map[string]bool{"revoked": true})
}

func (s *Server) handleGateValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		Token  string `json:"token"`
		Action string `json:"action"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	valid := s.gate.ValidateToken(req.Token, req.Action)
	jsonResponse(w, map[string]bool{"valid": valid})
}

// Logging handlers

func (s *Server) handleLogsSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	sinceStr := r.URL.Query().Get("since")
	since := time.Hour // default
	if sinceStr != "" {
		if d, err := time.ParseDuration(sinceStr); err == nil {
			since = d
		}
	}

	recentCount := 10
	if rc := r.URL.Query().Get("recent"); rc != "" {
		_, _ = fmt.Sscanf(rc, "%d", &recentCount)
	}

	summary, err := s.log.GetSummary(since, recentCount)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonResponse(w, summary)
}

func (s *Server) handleLogsRecent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	count := 20
	if c := r.URL.Query().Get("count"); c != "" {
		_, _ = fmt.Sscanf(c, "%d", &count)
	}

	eventType := logging.EventType(r.URL.Query().Get("type"))

	events, err := s.log.GetRecent(count, eventType)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonResponse(w, events)
}

func (s *Server) handleLogsVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	valid, errors, err := s.log.Verify()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonResponse(w, map[string]interface{}{
		"valid":  valid,
		"errors": errors,
	})
}

func (s *Server) handleLogScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		File     string `json:"file"`
		Findings int    `json:"findings"`
		Status   string `json:"status"` // "clean" or "findings"
		Details  string `json:"details,omitempty"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	if s.log != nil {
		details := map[string]string{
			"file":     req.File,
			"findings": fmt.Sprintf("%d", req.Findings),
		}
		if req.Details != "" {
			details["details"] = req.Details
		}
		_ = s.log.LogScan("markdown_scan", req.Status, "cli", details)
	}

	jsonResponse(w, map[string]bool{"logged": true})
}

// Security handlers

func (s *Server) handleLockdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	s.lockdownMu.Lock()
	s.lockdown = true
	s.lockdownMu.Unlock()

	// Revoke all tokens
	tokensRevoked := s.gate.RevokeAll()

	// Deny all pending requests
	requestsDenied := 0
	for _, req := range s.gate.GetPending() {
		if _, err := s.gate.Deny(req.ID, "lockdown activated"); err == nil {
			requestsDenied++
		}
	}

	if s.log != nil {
		_ = s.log.LogLockdown("activate", "success", "api", map[string]string{
			"tokens_revoked":  fmt.Sprintf("%d", tokensRevoked),
			"requests_denied": fmt.Sprintf("%d", requestsDenied),
		})
	}

	jsonResponse(w, map[string]interface{}{
		"lockdown":        true,
		"tokens_revoked":  tokensRevoked,
		"requests_denied": requestsDenied,
	})
}

func (s *Server) handleLockdownLift(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// This will need TOTP verification - for now just a placeholder
	// The actual implementation will verify against the TOTP secret
	if req.Code == "" {
		jsonError(w, http.StatusBadRequest, "TOTP code required")
		return
	}

	s.lockdownMu.Lock()
	s.lockdown = false
	s.lockdownMu.Unlock()

	if s.log != nil {
		_ = s.log.LogLockdown("lift", "success", "api", nil)
	}

	jsonResponse(w, map[string]bool{"lockdown": false})
}

func (s *Server) handleLockdownStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	s.lockdownMu.RLock()
	lockdown := s.lockdown
	s.lockdownMu.RUnlock()

	jsonResponse(w, map[string]bool{"lockdown": lockdown})
}

// Status handler

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	s.lockdownMu.RLock()
	lockdown := s.lockdown
	s.lockdownMu.RUnlock()

	stats := s.gate.Stats()
	stats["lockdown"] = lockdown
	stats["socket"] = s.socketPath

	jsonResponse(w, stats)
}

// SetTOTPVerifier sets the TOTP verification function for lockdown lift.
func (s *Server) SetTOTPVerifier(fn func(code string) bool) {
	// This will be wired up to the actual TOTP verification
}
