package gate

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// DefaultConfig returns sensible defaults for gate configuration.
func DefaultConfig() *Config {
	return &Config{
		RequestTTL: 5 * time.Minute,
		TokenTTL:   15 * time.Minute,
		SessionTTL: 15 * time.Minute,
		RateLimit: RateLimitConfig{
			MaxAttempts:     5,
			Window:          time.Minute,
			LockoutAfter:    10,
			LockoutDuration: 15 * time.Minute,
		},
	}
}

// NewEngine creates a new gate engine.
func NewEngine(cfg *Config) *Engine {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Engine{
		requests: make(map[string]*Request),
		tokens:   make(map[string]*Token),
		config:   cfg,
	}
}

// SetRequestCallback sets the callback for new requests (e.g., to notify via Telegram).
func (e *Engine) SetRequestCallback(fn func(*Request)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onRequest = fn
}

// SetTOTPVerifier sets the function to verify TOTP codes.
func (e *Engine) SetTOTPVerifier(fn func(code string) bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.totpVerify = fn
}

// SetSessionChecker sets the function to check if session is valid.
func (e *Engine) SetSessionChecker(fn func() bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sessionValid = fn
}

// RequiresGate checks if an action requires gate approval.
func (e *Engine) RequiresGate(action string) (bool, *ActionRule) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.config.BlockedActions {
		if matchPattern(rule.Pattern, action) {
			return true, &rule
		}
	}
	return false, nil
}

// CreateRequest creates a new gate request for an action.
func (e *Engine) CreateRequest(action, source string, metadata map[string]string) (*Request, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Check if action requires gate
	var rule *ActionRule
	for _, r := range e.config.BlockedActions {
		if matchPattern(r.Pattern, action) {
			rule = &r
			break
		}
	}

	// If session mode and session valid, auto-approve
	if rule != nil && rule.Mode == "session" && e.sessionValid != nil && e.sessionValid() {
		req := &Request{
			ID:        generateID(),
			Action:    action,
			Status:    StatusApproved,
			Token:     generateToken(),
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(e.config.TokenTTL),
			UpdatedAt: time.Now(),
			Source:    source,
			Metadata:  metadata,
		}
		e.requests[req.ID] = req

		// Create token
		token := &Token{
			ID:        req.Token,
			Action:    action,
			RequestID: req.ID,
			IssuedAt:  time.Now(),
			ExpiresAt: req.ExpiresAt,
		}
		e.tokens[token.ID] = token

		return req, nil
	}

	// Create pending request
	req := &Request{
		ID:        generateID(),
		Action:    action,
		Status:    StatusPending,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(e.config.RequestTTL),
		UpdatedAt: time.Now(),
		Source:    source,
		Metadata:  metadata,
	}
	e.requests[req.ID] = req

	// Notify callback (e.g., send Telegram message)
	if e.onRequest != nil {
		go e.onRequest(req)
	}

	return req, nil
}

// Approve approves a pending request with TOTP code.
func (e *Engine) Approve(requestID, code string) (*Request, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	req, ok := e.requests[requestID]
	if !ok {
		return nil, fmt.Errorf("request not found: %s", requestID)
	}

	if req.Status != StatusPending {
		return nil, fmt.Errorf("request already %s", req.Status)
	}

	if time.Now().After(req.ExpiresAt) {
		req.Status = StatusExpired
		req.UpdatedAt = time.Now()
		return nil, fmt.Errorf("request expired")
	}

	// Verify TOTP
	if e.totpVerify == nil {
		return nil, fmt.Errorf("TOTP verifier not configured")
	}
	if !e.totpVerify(code) {
		return nil, fmt.Errorf("invalid TOTP code")
	}

	// Approve and issue token
	req.Status = StatusApproved
	req.Token = generateToken()
	req.UpdatedAt = time.Now()
	req.ExpiresAt = time.Now().Add(e.config.TokenTTL)

	// Create token
	token := &Token{
		ID:        req.Token,
		Action:    req.Action,
		RequestID: req.ID,
		IssuedAt:  time.Now(),
		ExpiresAt: req.ExpiresAt,
	}
	e.tokens[token.ID] = token

	return req, nil
}

// Deny denies a pending request.
func (e *Engine) Deny(requestID, reason string) (*Request, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	req, ok := e.requests[requestID]
	if !ok {
		return nil, fmt.Errorf("request not found: %s", requestID)
	}

	if req.Status != StatusPending {
		return nil, fmt.Errorf("request already %s", req.Status)
	}

	req.Status = StatusDenied
	req.Reason = reason
	req.UpdatedAt = time.Now()

	return req, nil
}

// GetRequest retrieves a request by ID.
func (e *Engine) GetRequest(id string) (*Request, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	req, ok := e.requests[id]
	return req, ok
}

// GetPending returns all pending requests.
func (e *Engine) GetPending() []*Request {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var pending []*Request
	now := time.Now()
	for _, req := range e.requests {
		if req.Status == StatusPending && now.Before(req.ExpiresAt) {
			pending = append(pending, req)
		}
	}
	return pending
}

// ValidateToken checks if a token is valid for an action.
func (e *Engine) ValidateToken(tokenID, action string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	token, ok := e.tokens[tokenID]
	if !ok {
		return false
	}

	if token.Revoked {
		return false
	}

	if time.Now().After(token.ExpiresAt) {
		return false
	}

	// Check action matches (or token action is wildcard)
	if !matchPattern(token.Action, action) {
		return false
	}

	return true
}

// RevokeToken revokes a specific token.
func (e *Engine) RevokeToken(tokenID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	token, ok := e.tokens[tokenID]
	if !ok {
		return fmt.Errorf("token not found: %s", tokenID)
	}

	token.Revoked = true
	return nil
}

// RevokeAll revokes all active tokens.
func (e *Engine) RevokeAll() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	count := 0
	for _, token := range e.tokens {
		if !token.Revoked && time.Now().Before(token.ExpiresAt) {
			token.Revoked = true
			count++
		}
	}
	return count
}

// Cleanup removes expired requests and tokens.
func (e *Engine) Cleanup() {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-24 * time.Hour) // Keep for 24h for audit

	for id, req := range e.requests {
		if req.UpdatedAt.Before(cutoff) {
			delete(e.requests, id)
		} else if req.Status == StatusPending && now.After(req.ExpiresAt) {
			req.Status = StatusExpired
			req.UpdatedAt = now
		}
	}

	for id, token := range e.tokens {
		if token.ExpiresAt.Before(cutoff) {
			delete(e.tokens, id)
		}
	}
}

// Stats returns engine statistics.
func (e *Engine) Stats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	pending := 0
	approved := 0
	denied := 0
	activeTokens := 0
	now := time.Now()

	for _, req := range e.requests {
		switch req.Status {
		case StatusPending:
			if now.Before(req.ExpiresAt) {
				pending++
			}
		case StatusApproved:
			approved++
		case StatusDenied:
			denied++
		}
	}

	for _, token := range e.tokens {
		if !token.Revoked && now.Before(token.ExpiresAt) {
			activeTokens++
		}
	}

	return map[string]interface{}{
		"pending_requests": pending,
		"approved_total":   approved,
		"denied_total":     denied,
		"active_tokens":    activeTokens,
	}
}

// matchPattern matches an action against a glob pattern.
func matchPattern(pattern, action string) bool {
	// Simple glob: * matches any suffix
	if strings.HasSuffix(pattern, ":*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(action, prefix)
	}
	if pattern == "*" {
		return true
	}
	// Try filepath.Match for more complex patterns
	matched, _ := filepath.Match(pattern, action)
	return matched || pattern == action
}

func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate random ID: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func generateToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate random token: " + err.Error())
	}
	return hex.EncodeToString(b)
}
