package totp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// DefaultSessionTTL is the default session validity period
	DefaultSessionTTL = 15 * time.Minute
)

// Session represents an authenticated session
type Session struct {
	ValidUntil time.Time `json:"valid_until"`
	CreatedAt  time.Time `json:"created_at"`
}

// SessionManager handles session caching for step-up auth
type SessionManager struct {
	configDir  string
	sessionTTL time.Duration
}

// NewSessionManager creates a new session manager
func NewSessionManager(ttl time.Duration) (*SessionManager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	configDir := filepath.Join(home, ".config", "feelgoodbot")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	if ttl == 0 {
		ttl = DefaultSessionTTL
	}

	return &SessionManager{
		configDir:  configDir,
		sessionTTL: ttl,
	}, nil
}

// sessionPath returns the path to the session file
func (sm *SessionManager) sessionPath() string {
	return filepath.Join(sm.configDir, "totp-session")
}

// IsValid checks if there's a valid (non-expired) session
func (sm *SessionManager) IsValid() bool {
	session, err := sm.load()
	if err != nil {
		return false
	}
	return time.Now().Before(session.ValidUntil)
}

// Create creates a new authenticated session
func (sm *SessionManager) Create() error {
	session := &Session{
		CreatedAt:  time.Now(),
		ValidUntil: time.Now().Add(sm.sessionTTL),
	}

	return sm.save(session)
}

// Clear removes the current session
func (sm *SessionManager) Clear() error {
	path := sm.sessionPath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to clear session: %w", err)
	}
	return nil
}

// TimeRemaining returns how much time is left in the current session
func (sm *SessionManager) TimeRemaining() time.Duration {
	session, err := sm.load()
	if err != nil {
		return 0
	}
	remaining := time.Until(session.ValidUntil)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// load reads the session from disk
func (sm *SessionManager) load() (*Session, error) {
	path := sm.sessionPath()
	
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

// save writes the session to disk
func (sm *SessionManager) save(session *Session) error {
	path := sm.sessionPath()
	
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to serialize session: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write session: %w", err)
	}

	return nil
}

// Extend extends the current session by the TTL
func (sm *SessionManager) Extend() error {
	session, err := sm.load()
	if err != nil {
		// No existing session, create new one
		return sm.Create()
	}

	session.ValidUntil = time.Now().Add(sm.sessionTTL)
	return sm.save(session)
}
