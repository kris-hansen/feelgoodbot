package totp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Prompter defines the interface for prompting users for OTP codes
type Prompter interface {
	// Prompt asks the user for an OTP code and returns their response
	Prompt(ctx context.Context, action string) (string, error)
	// Notify sends a message to the user without expecting a response
	Notify(ctx context.Context, message string) error
}

// CLIPrompter prompts via stdin (for direct CLI use)
type CLIPrompter struct{}

// NewCLIPrompter creates a CLI-based prompter
func NewCLIPrompter() *CLIPrompter {
	return &CLIPrompter{}
}

// Prompt asks for input via stdin
func (p *CLIPrompter) Prompt(ctx context.Context, action string) (string, error) {
	fmt.Printf("🔐 Action '%s' requires step-up authentication\n", action)
	fmt.Print("   Enter OTP code: ")

	reader := bufio.NewReader(os.Stdin)
	code, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read input: %w", err)
	}

	return strings.TrimSpace(code), nil
}

// Notify prints a message to stdout
func (p *CLIPrompter) Notify(ctx context.Context, message string) error {
	fmt.Println(message)
	return nil
}

// TelegramPrompter prompts via Telegram using Clawdbot webhooks
type TelegramPrompter struct {
	webhookURL string
	secret     string
	chatID     string
	timeout    time.Duration
	// responseCallback is set when waiting for a response
	responseCallback chan string
}

// TelegramConfig holds configuration for Telegram prompting
type TelegramConfig struct {
	WebhookURL string        // Clawdbot webhook URL (e.g., http://127.0.0.1:18789/hooks/wake)
	Secret     string        // Clawdbot webhook secret
	ChatID     string        // Telegram chat ID to send to
	Timeout    time.Duration // How long to wait for response
}

// NewTelegramPrompter creates a Telegram-based prompter
func NewTelegramPrompter(cfg TelegramConfig) *TelegramPrompter {
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Minute
	}
	return &TelegramPrompter{
		webhookURL: cfg.WebhookURL,
		secret:     cfg.Secret,
		chatID:     cfg.ChatID,
		timeout:    cfg.Timeout,
	}
}

// webhookPayload represents the payload sent to Clawdbot
type webhookPayload struct {
	Text string `json:"text"`
	Mode string `json:"mode"`
	To   string `json:"to,omitempty"`
}

// Prompt sends a message to Telegram and waits for a response
// Note: For full async flow, this would need a callback mechanism
// For now, we'll use a simplified approach with a response file
func (p *TelegramPrompter) Prompt(ctx context.Context, action string) (string, error) {
	message := fmt.Sprintf("🔐 **Step-up authentication required**\n\nAction: `%s`\n\nPlease reply with your OTP code from Google Authenticator.", action)
	
	if err := p.sendMessage(message); err != nil {
		return "", fmt.Errorf("failed to send prompt: %w", err)
	}

	// Wait for response via response file mechanism
	return p.waitForResponse(ctx)
}

// Notify sends a message without expecting a response
func (p *TelegramPrompter) Notify(ctx context.Context, message string) error {
	return p.sendMessage(message)
}

// sendMessage sends a message via Clawdbot webhook
func (p *TelegramPrompter) sendMessage(message string) error {
	payload := webhookPayload{
		Text: message,
		Mode: "now",
		To:   p.chatID,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", p.webhookURL, strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if p.secret != "" {
		req.Header.Set("x-clawdbot-token", p.secret)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// waitForResponse waits for the user to respond with an OTP code
// This uses a file-based mechanism for the response
func (p *TelegramPrompter) waitForResponse(ctx context.Context) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	// Create a unique response file
	responseFile := fmt.Sprintf("%s/.config/feelgoodbot/totp-response-%d", home, time.Now().UnixNano())
	
	// Clean up any existing response file
	_ = os.Remove(responseFile)

	// Poll for response file
	deadline := time.Now().Add(p.timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return "", fmt.Errorf("timeout waiting for OTP response")
			}

			data, err := os.ReadFile(responseFile)
			if err == nil {
				// Got response, clean up and return
				_ = os.Remove(responseFile)
				return strings.TrimSpace(string(data)), nil
			}
		}
	}
}

// SubmitResponse writes a response to the pending response file
// This is called by Clawdbot when it receives the user's OTP
func SubmitResponse(code string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configDir := fmt.Sprintf("%s/.config/feelgoodbot", home)
	
	// Find the pending response file
	entries, err := os.ReadDir(configDir)
	if err != nil {
		return fmt.Errorf("failed to read config dir: %w", err)
	}

	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "totp-response-") {
			responsePath := fmt.Sprintf("%s/%s", configDir, entry.Name())
			return os.WriteFile(responsePath, []byte(code), 0600)
		}
	}

	return fmt.Errorf("no pending OTP prompt found")
}

// InteractivePrompter combines Telegram notification with CLI input
// Useful when the agent can notify via Telegram but needs CLI for response
type InteractivePrompter struct {
	telegram *TelegramPrompter
	cli      *CLIPrompter
}

// NewInteractivePrompter creates a prompter that notifies via Telegram but reads from CLI
func NewInteractivePrompter(cfg TelegramConfig) *InteractivePrompter {
	return &InteractivePrompter{
		telegram: NewTelegramPrompter(cfg),
		cli:      NewCLIPrompter(),
	}
}

// Prompt notifies via Telegram and then waits for CLI input
func (p *InteractivePrompter) Prompt(ctx context.Context, action string) (string, error) {
	// Send Telegram notification
	message := fmt.Sprintf("🔐 Step-up authentication required for action: %s", action)
	_ = p.telegram.Notify(ctx, message)

	// Read from CLI
	return p.cli.Prompt(ctx, action)
}

// Notify sends via Telegram
func (p *InteractivePrompter) Notify(ctx context.Context, message string) error {
	return p.telegram.Notify(ctx, message)
}
