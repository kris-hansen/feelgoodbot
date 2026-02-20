package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var socketPath string

func init() {
	home, _ := os.UserHomeDir()
	socketPath = filepath.Join(home, ".config", "feelgoodbot", "daemon.sock")
}

// gateCmd is the parent command for gate operations
var gateCmd = &cobra.Command{
	Use:   "gate",
	Short: "Manage gate requests and tokens",
	Long: `Manage gate requests for sensitive actions.

Gate mode requires TOTP authentication before certain actions can proceed.
This provides an additional security layer beyond the standard session.

Commands:
  request   Request approval for an action
  approve   Approve a pending request with TOTP code
  deny      Deny a pending request
  status    Check status of a request
  pending   List all pending requests
  revoke    Revoke tokens`,
}

var gateWait bool
var gateTimeout string
var gateAsync bool

var gateRequestCmd = &cobra.Command{
	Use:   "request <action>",
	Short: "Request approval for an action",
	Long: `Request approval for a gated action. If --wait is specified,
blocks until the request is approved, denied, or times out.

Examples:
  feelgoodbot gate request send_email
  feelgoodbot gate request --wait --timeout 2m payment:transfer
  feelgoodbot gate request --async delete:backup`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		action := args[0]

		// Make request to socket
		resp, err := socketPost("/gate/request", map[string]interface{}{
			"action": action,
			"source": "cli",
		})
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		var result struct {
			Success bool `json:"success"`
			Data    struct {
				ID        string `json:"id"`
				Action    string `json:"action"`
				Status    string `json:"status"`
				Token     string `json:"token,omitempty"`
				ExpiresAt string `json:"expires_at"`
			} `json:"data"`
			Error string `json:"error"`
		}

		if err := json.Unmarshal(resp, &result); err != nil {
			return fmt.Errorf("invalid response: %w", err)
		}

		if !result.Success {
			return errors.New(result.Error)
		}

		// If already approved (session was valid), return token
		if result.Data.Status == "approved" {
			fmt.Printf("✅ Approved (session valid)\n")
			fmt.Printf("Token: %s\n", result.Data.Token)
			return nil
		}

		// Request is pending
		fmt.Printf("🔐 Request created: %s\n", result.Data.ID)
		fmt.Printf("   Action: %s\n", result.Data.Action)
		fmt.Printf("   Status: pending\n")

		if gateAsync {
			fmt.Println()
			fmt.Println("Use 'feelgoodbot gate approve <id> <code>' to approve")
			return nil
		}

		if gateWait {
			return waitForApproval(result.Data.ID, gateTimeout)
		}

		// Interactive mode - prompt for code
		fmt.Println()
		fmt.Print("Enter TOTP code: ")
		var code string
		if _, err := fmt.Scanln(&code); err != nil {
			return fmt.Errorf("failed to read code: %w", err)
		}

		return approveRequest(result.Data.ID, strings.TrimSpace(code))
	},
}

var gateApproveCmd = &cobra.Command{
	Use:   "approve <request-id> [code]",
	Short: "Approve a pending request",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		requestID := args[0]
		var code string
		if len(args) > 1 {
			code = args[1]
		} else {
			fmt.Print("Enter TOTP code: ")
			if _, err := fmt.Scanln(&code); err != nil {
				return fmt.Errorf("failed to read code: %w", err)
			}
		}
		return approveRequest(requestID, strings.TrimSpace(code))
	},
}

var gateDenyCmd = &cobra.Command{
	Use:   "deny <request-id> [reason]",
	Short: "Deny a pending request",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		requestID := args[0]
		reason := "denied by user"
		if len(args) > 1 {
			reason = args[1]
		}

		resp, err := socketPost("/gate/deny", map[string]interface{}{
			"request_id": requestID,
			"reason":     reason,
		})
		if err != nil {
			return err
		}

		var result struct {
			Success bool   `json:"success"`
			Error   string `json:"error"`
		}
		_ = json.Unmarshal(resp, &result)

		if !result.Success {
			return errors.New(result.Error)
		}

		fmt.Println("❌ Request denied")
		return nil
	},
}

var gateStatusCmd = &cobra.Command{
	Use:   "status <request-id>",
	Short: "Check status of a request",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		requestID := args[0]

		resp, err := socketGet("/gate/status/" + requestID)
		if err != nil {
			return err
		}

		var result struct {
			Success bool `json:"success"`
			Data    struct {
				ID        string `json:"id"`
				Action    string `json:"action"`
				Status    string `json:"status"`
				Token     string `json:"token,omitempty"`
				CreatedAt string `json:"created_at"`
				ExpiresAt string `json:"expires_at"`
			} `json:"data"`
			Error string `json:"error"`
		}
		_ = json.Unmarshal(resp, &result)

		if !result.Success {
			return errors.New(result.Error)
		}

		fmt.Printf("Request: %s\n", result.Data.ID)
		fmt.Printf("Action:  %s\n", result.Data.Action)
		fmt.Printf("Status:  %s\n", result.Data.Status)
		if result.Data.Token != "" {
			fmt.Printf("Token:   %s\n", result.Data.Token)
		}
		fmt.Printf("Expires: %s\n", result.Data.ExpiresAt)

		return nil
	},
}

var gatePendingCmd = &cobra.Command{
	Use:   "pending",
	Short: "List pending requests",
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := socketGet("/gate/pending")
		if err != nil {
			return err
		}

		var result struct {
			Success bool `json:"success"`
			Data    struct {
				Pending []struct {
					ID        string `json:"id"`
					Action    string `json:"action"`
					CreatedAt string `json:"created_at"`
					ExpiresAt string `json:"expires_at"`
				} `json:"pending"`
				Count int `json:"count"`
			} `json:"data"`
		}
		_ = json.Unmarshal(resp, &result)

		if result.Data.Count == 0 {
			fmt.Println("No pending requests")
			return nil
		}

		fmt.Printf("🔐 Pending requests (%d):\n\n", result.Data.Count)
		for _, req := range result.Data.Pending {
			fmt.Printf("  ID:     %s\n", req.ID)
			fmt.Printf("  Action: %s\n", req.Action)
			fmt.Printf("  Expires: %s\n", req.ExpiresAt)
			fmt.Println()
		}

		return nil
	},
}

var gateRevokeAll bool

var gateRevokeCmd = &cobra.Command{
	Use:   "revoke [token]",
	Short: "Revoke tokens",
	Long: `Revoke a specific token or all active tokens.

Examples:
  feelgoodbot gate revoke abc123...  # Revoke specific token
  feelgoodbot gate revoke --all      # Revoke all tokens`,
	RunE: func(cmd *cobra.Command, args []string) error {
		payload := map[string]interface{}{}
		if gateRevokeAll {
			payload["all"] = true
		} else if len(args) > 0 {
			payload["token"] = args[0]
		} else {
			return fmt.Errorf("specify token or use --all")
		}

		resp, err := socketPost("/gate/revoke", payload)
		if err != nil {
			return err
		}

		var result struct {
			Success bool `json:"success"`
			Data    struct {
				Revoked int `json:"revoked"`
			} `json:"data"`
			Error string `json:"error"`
		}
		_ = json.Unmarshal(resp, &result)

		if !result.Success {
			return errors.New(result.Error)
		}

		if gateRevokeAll {
			fmt.Printf("✅ Revoked %d tokens\n", result.Data.Revoked)
		} else {
			fmt.Println("✅ Token revoked")
		}
		return nil
	},
}

// lockdownCmd is the command for emergency lockdown
var lockdownCmd = &cobra.Command{
	Use:   "lockdown",
	Short: "Emergency lockdown mode",
	Long: `Activate emergency lockdown to immediately revoke all sessions and block all gated actions.

Usage:
  feelgoodbot lockdown        # Activate lockdown (no TOTP needed - emergency!)
  feelgoodbot lockdown lift   # Lift lockdown (requires TOTP)
  feelgoodbot lockdown status # Check lockdown status

In lockdown mode:
  - All active tokens are revoked
  - All pending gate requests are denied
  - New gate requests will be blocked
  - Requires TOTP to lift`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Activate lockdown
		resp, err := socketPost("/lockdown", nil)
		if err != nil {
			return fmt.Errorf("failed to activate lockdown: %w", err)
		}

		var result struct {
			Success bool `json:"success"`
			Data    struct {
				Lockdown       bool `json:"lockdown"`
				TokensRevoked  int  `json:"tokens_revoked"`
				RequestsDenied int  `json:"requests_denied"`
			} `json:"data"`
			Error string `json:"error"`
		}
		_ = json.Unmarshal(resp, &result)

		if !result.Success {
			return errors.New(result.Error)
		}

		fmt.Println("🚨 LOCKDOWN ACTIVATED")
		fmt.Printf("   Tokens revoked: %d\n", result.Data.TokensRevoked)
		fmt.Printf("   Requests denied: %d\n", result.Data.RequestsDenied)
		fmt.Println()
		fmt.Println("All gated actions are now blocked.")
		fmt.Println("Use 'feelgoodbot lockdown lift' with TOTP to restore access.")
		return nil
	},
}

var lockdownLiftCmd = &cobra.Command{
	Use:   "lift [code]",
	Short: "Lift lockdown (requires TOTP)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		var code string
		if len(args) > 0 {
			code = args[0]
		} else {
			fmt.Print("Enter TOTP code: ")
			if _, err := fmt.Scanln(&code); err != nil {
				return fmt.Errorf("failed to read code: %w", err)
			}
		}

		resp, err := socketPost("/lockdown/lift", map[string]interface{}{
			"code": strings.TrimSpace(code),
		})
		if err != nil {
			return fmt.Errorf("failed to lift lockdown: %w", err)
		}

		var result struct {
			Success bool `json:"success"`
			Data    struct {
				Lockdown bool `json:"lockdown"`
			} `json:"data"`
			Error string `json:"error"`
		}
		_ = json.Unmarshal(resp, &result)

		if !result.Success {
			return errors.New(result.Error)
		}

		fmt.Println("✅ Lockdown lifted")
		fmt.Println("Gated actions are now permitted again.")
		return nil
	},
}

var lockdownStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check lockdown status",
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := socketGet("/lockdown/status")
		if err != nil {
			return fmt.Errorf("failed to check status: %w", err)
		}

		var result struct {
			Success bool `json:"success"`
			Data    struct {
				Lockdown bool `json:"lockdown"`
			} `json:"data"`
			Error string `json:"error"`
		}
		_ = json.Unmarshal(resp, &result)

		if !result.Success {
			return errors.New(result.Error)
		}

		if result.Data.Lockdown {
			fmt.Println("🚨 LOCKDOWN ACTIVE")
			fmt.Println("All gated actions are blocked.")
			fmt.Println("Use 'feelgoodbot lockdown lift' to restore access.")
		} else {
			fmt.Println("✅ System operating normally")
		}
		return nil
	},
}

func init() {
	gateRequestCmd.Flags().BoolVar(&gateWait, "wait", false, "Wait for approval")
	gateRequestCmd.Flags().StringVar(&gateTimeout, "timeout", "5m", "Timeout when waiting")
	gateRequestCmd.Flags().BoolVar(&gateAsync, "async", false, "Return immediately with request ID")

	gateRevokeCmd.Flags().BoolVar(&gateRevokeAll, "all", false, "Revoke all tokens")

	gateCmd.AddCommand(gateRequestCmd)
	gateCmd.AddCommand(gateApproveCmd)
	gateCmd.AddCommand(gateDenyCmd)
	gateCmd.AddCommand(gateStatusCmd)
	gateCmd.AddCommand(gatePendingCmd)
	gateCmd.AddCommand(gateRevokeCmd)

	lockdownCmd.AddCommand(lockdownLiftCmd)
	lockdownCmd.AddCommand(lockdownStatusCmd)

	rootCmd.AddCommand(gateCmd)
	rootCmd.AddCommand(lockdownCmd)
}

// Helper functions

func socketGet(path string) ([]byte, error) {
	return socketRequest("GET", path, nil)
}

func socketPost(path string, data map[string]interface{}) ([]byte, error) {
	return socketRequest("POST", path, data)
}

func socketRequest(method, path string, data map[string]interface{}) ([]byte, error) {
	// Create HTTP client with Unix socket transport
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: 30 * time.Second,
	}

	var body io.Reader
	if data != nil {
		jsonData, _ := json.Marshal(data)
		body = strings.NewReader(string(jsonData))
	}

	req, err := http.NewRequest(method, "http://localhost"+path, body)
	if err != nil {
		return nil, err
	}

	if data != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("daemon not running? %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	return io.ReadAll(resp.Body)
}

func approveRequest(requestID, code string) error {
	resp, err := socketPost("/gate/approve", map[string]interface{}{
		"request_id": requestID,
		"code":       code,
	})
	if err != nil {
		return err
	}

	var result struct {
		Success bool `json:"success"`
		Data    struct {
			Token string `json:"token"`
		} `json:"data"`
		Error string `json:"error"`
	}
	_ = json.Unmarshal(resp, &result)

	if !result.Success {
		return errors.New(result.Error)
	}

	fmt.Println("✅ Approved")
	fmt.Printf("Token: %s\n", result.Data.Token)
	return nil
}

func waitForApproval(requestID, timeoutStr string) error {
	timeout, _ := time.ParseDuration(timeoutStr)
	if timeout == 0 {
		timeout = 5 * time.Minute
	}

	deadline := time.Now().Add(timeout)
	fmt.Println("Waiting for approval...")

	for time.Now().Before(deadline) {
		resp, err := socketGet("/gate/status/" + requestID)
		if err != nil {
			time.Sleep(time.Second)
			continue
		}

		var result struct {
			Success bool `json:"success"`
			Data    struct {
				Status string `json:"status"`
				Token  string `json:"token"`
			} `json:"data"`
		}
		_ = json.Unmarshal(resp, &result)

		switch result.Data.Status {
		case "approved":
			fmt.Println("✅ Approved")
			fmt.Printf("Token: %s\n", result.Data.Token)
			return nil
		case "denied":
			return fmt.Errorf("request denied")
		case "expired":
			return fmt.Errorf("request expired")
		}

		time.Sleep(time.Second)
	}

	return fmt.Errorf("timeout waiting for approval")
}
