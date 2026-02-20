// Package gate provides the gating engine for action approval.
package gate

import (
	"sync"
	"time"
)

// RequestStatus represents the state of a gate request.
type RequestStatus string

const (
	StatusPending  RequestStatus = "pending"
	StatusApproved RequestStatus = "approved"
	StatusDenied   RequestStatus = "denied"
	StatusExpired  RequestStatus = "expired"
)

// Request represents a gate approval request.
type Request struct {
	ID        string            `json:"id"`
	Action    string            `json:"action"`
	Status    RequestStatus     `json:"status"`
	Token     string            `json:"token,omitempty"`  // Set when approved
	Reason    string            `json:"reason,omitempty"` // Set when denied
	CreatedAt time.Time         `json:"created_at"`
	ExpiresAt time.Time         `json:"expires_at"`
	UpdatedAt time.Time         `json:"updated_at"`
	Source    string            `json:"source,omitempty"` // "cli", "telegram", etc.
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// Token represents an issued gate token.
type Token struct {
	ID        string    `json:"id"`
	Action    string    `json:"action"`
	RequestID string    `json:"request_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

// Engine manages gate requests and tokens.
type Engine struct {
	mu           sync.RWMutex
	requests     map[string]*Request
	tokens       map[string]*Token
	config       *Config
	onRequest    func(*Request) // Callback when new request created
	totpVerify   func(code string) bool
	sessionValid func() bool
}

// Config holds gate engine configuration.
type Config struct {
	RequestTTL     time.Duration   `yaml:"request_ttl"`     // How long requests stay pending
	TokenTTL       time.Duration   `yaml:"token_ttl"`       // How long tokens are valid
	SessionTTL     time.Duration   `yaml:"session_ttl"`     // How long sessions last after TOTP
	BlockedActions []ActionRule    `yaml:"blocked_actions"` // Actions requiring gate
	RateLimit      RateLimitConfig `yaml:"rate_limit"`
}

// ActionRule defines a gated action pattern.
type ActionRule struct {
	Pattern string `yaml:"pattern"` // Glob pattern like "send_email" or "payment:*"
	Mode    string `yaml:"mode"`    // "strict" (always TOTP) or "session" (use session)
}

// RateLimitConfig controls rate limiting for TOTP attempts.
type RateLimitConfig struct {
	MaxAttempts     int           `yaml:"max_attempts"`  // Max attempts per window
	Window          time.Duration `yaml:"window"`        // Time window
	LockoutAfter    int           `yaml:"lockout_after"` // Lockout after N total failures
	LockoutDuration time.Duration `yaml:"lockout_duration"`
}
