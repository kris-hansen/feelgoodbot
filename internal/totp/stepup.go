package totp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// StepUpConfig defines which actions require step-up authentication
type StepUpConfig struct {
	RequireStepUp     []string      `json:"requireStepUp"`
	SessionTTLMinutes int           `json:"sessionTTLMinutes"`
	Enabled           bool          `json:"enabled"`
}

// DefaultStepUpConfig returns the default step-up configuration
func DefaultStepUpConfig() *StepUpConfig {
	return &StepUpConfig{
		RequireStepUp: []string{
			"config:update",
		},
		SessionTTLMinutes: 15,
		Enabled:           true,
	}
}

// StepUpManager handles step-up authentication requirements
type StepUpManager struct {
	config    *StepUpConfig
	store     *Store
	session   *SessionManager
	configDir string
	prompter  Prompter
}

// StepUpOption is a functional option for configuring StepUpManager
type StepUpOption func(*StepUpManager)

// WithPrompter sets a custom prompter for the StepUpManager
func WithPrompter(p Prompter) StepUpOption {
	return func(sm *StepUpManager) {
		sm.prompter = p
	}
}

// WithTelegramPrompter configures Telegram-based prompting
func WithTelegramPrompter(cfg TelegramConfig) StepUpOption {
	return func(sm *StepUpManager) {
		sm.prompter = NewTelegramPrompter(cfg)
	}
}

// NewStepUpManager creates a new step-up manager
func NewStepUpManager(opts ...StepUpOption) (*StepUpManager, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	configDir := filepath.Join(home, ".config", "feelgoodbot")

	store, err := NewStore()
	if err != nil {
		return nil, err
	}

	// Load config
	config, err := loadStepUpConfig(configDir)
	if err != nil {
		config = DefaultStepUpConfig()
	}

	session, err := NewSessionManager(time.Duration(config.SessionTTLMinutes) * time.Minute)
	if err != nil {
		return nil, err
	}

	sm := &StepUpManager{
		config:    config,
		store:     store,
		session:   session,
		configDir: configDir,
		prompter:  NewCLIPrompter(), // Default to CLI
	}

	// Apply options
	for _, opt := range opts {
		opt(sm)
	}

	return sm, nil
}

// loadStepUpConfig loads the step-up config from disk
func loadStepUpConfig(configDir string) (*StepUpConfig, error) {
	path := filepath.Join(configDir, "stepup-config.json")
	
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config StepUpConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// SaveStepUpConfig saves the step-up config to disk
func (sm *StepUpManager) SaveStepUpConfig(config *StepUpConfig) error {
	path := filepath.Join(sm.configDir, "stepup-config.json")
	
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	sm.config = config
	return nil
}

// RequiresStepUp checks if an action requires step-up authentication
func (sm *StepUpManager) RequiresStepUp(action string) bool {
	if !sm.config.Enabled {
		return false
	}

	if !sm.store.IsInitialized() {
		return false
	}

	for _, pattern := range sm.config.RequireStepUp {
		if matchPattern(pattern, action) {
			return true
		}
	}

	return false
}

// matchPattern checks if an action matches a pattern (supports * wildcard)
func matchPattern(pattern, action string) bool {
	// Exact match
	if pattern == action {
		return true
	}

	// Wildcard suffix (e.g., "delete:*" matches "delete:file")
	if strings.HasSuffix(pattern, ":*") {
		prefix := strings.TrimSuffix(pattern, "*")
		if strings.HasPrefix(action, prefix) {
			return true
		}
	}

	// Wildcard match all
	if pattern == "*" {
		return true
	}

	return false
}

// CheckOrPrompt checks for a valid session, or prompts for OTP if needed
// Returns true if authenticated, false otherwise
func (sm *StepUpManager) CheckOrPrompt(action string) (bool, error) {
	return sm.CheckOrPromptWithContext(context.Background(), action)
}

// CheckOrPromptWithContext checks for a valid session, or prompts for OTP if needed
// Returns true if authenticated, false otherwise
func (sm *StepUpManager) CheckOrPromptWithContext(ctx context.Context, action string) (bool, error) {
	if !sm.RequiresStepUp(action) {
		return true, nil
	}

	// Check for valid session
	if sm.session.IsValid() {
		remaining := sm.session.TimeRemaining()
		_ = sm.prompter.Notify(ctx, fmt.Sprintf("🔐 Step-up session valid (%.0f minutes remaining)", remaining.Minutes()))
		return true, nil
	}

	// Prompt for OTP using the configured prompter
	code, err := sm.prompter.Prompt(ctx, action)
	if err != nil {
		return false, fmt.Errorf("failed to get OTP: %w", err)
	}

	code = strings.TrimSpace(code)
	if code == "" {
		return false, nil
	}

	// Validate the code
	valid, err := sm.store.Validate(code)
	if err != nil {
		return false, fmt.Errorf("validation error: %w", err)
	}

	if !valid {
		_ = sm.prompter.Notify(ctx, "❌ Invalid code")
		return false, nil
	}

	// Create session
	if err := sm.session.Create(); err != nil {
		return false, fmt.Errorf("failed to create session: %w", err)
	}

	_ = sm.prompter.Notify(ctx, fmt.Sprintf("✅ Authenticated (session valid for %d minutes)", sm.config.SessionTTLMinutes))
	return true, nil
}

// ValidateCode validates a code without creating a session
func (sm *StepUpManager) ValidateCode(code string) (bool, error) {
	return sm.store.Validate(code)
}

// IsInitialized returns true if TOTP is set up
func (sm *StepUpManager) IsInitialized() bool {
	return sm.store.IsInitialized()
}

// ClearSession clears the current session
func (sm *StepUpManager) ClearSession() error {
	return sm.session.Clear()
}

// GetConfig returns the current step-up config
func (sm *StepUpManager) GetConfig() *StepUpConfig {
	return sm.config
}

// AddAction adds an action to the step-up requirements
func (sm *StepUpManager) AddAction(action string) error {
	// Check if already exists
	for _, existing := range sm.config.RequireStepUp {
		if existing == action {
			return fmt.Errorf("action '%s' already requires step-up", action)
		}
	}

	sm.config.RequireStepUp = append(sm.config.RequireStepUp, action)
	return sm.SaveStepUpConfig(sm.config)
}

// RemoveAction removes an action from the step-up requirements
func (sm *StepUpManager) RemoveAction(action string) error {
	found := false
	newActions := make([]string, 0, len(sm.config.RequireStepUp))
	
	for _, existing := range sm.config.RequireStepUp {
		if existing == action {
			found = true
			continue
		}
		newActions = append(newActions, existing)
	}

	if !found {
		return fmt.Errorf("action '%s' not found in step-up requirements", action)
	}

	sm.config.RequireStepUp = newActions
	return sm.SaveStepUpConfig(sm.config)
}
