package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var auditSince string
var auditType string
var auditJSON bool
var auditLimit int

// auditCmd is the parent command for audit operations
var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "View security audit trail",
	Long: `View the security audit trail showing all security-relevant events.

Events include:
  auth      - Authentication events (TOTP attempts)
  gate      - Gate requests, approvals, denials
  alert     - Security alerts
  integrity - File integrity changes
  lockdown  - Lockdown activations and lifts
  system    - Daemon start/stop

Examples:
  feelgoodbot audit                    # Recent events
  feelgoodbot audit --since 24h        # Last 24 hours
  feelgoodbot audit --type auth,gate   # Filter by type
  feelgoodbot audit --json             # JSON output
  feelgoodbot audit summary            # Aggregated stats
  feelgoodbot audit verify             # Verify log integrity`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAuditRecent()
	},
}

var auditSummaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Show audit summary statistics",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAuditSummary()
	},
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify audit log integrity",
	Long:  `Verify the cryptographic integrity of the audit log chain.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAuditVerify()
	},
}

func runAuditRecent() error {
	// Build query params
	params := fmt.Sprintf("?count=%d", auditLimit)
	if auditType != "" {
		params += "&type=" + auditType
	}

	resp, err := socketGet("/logs/recent" + params)
	if err != nil {
		return fmt.Errorf("failed to get audit logs: %w", err)
	}

	var result struct {
		Success bool `json:"success"`
		Data    []struct {
			ID        string            `json:"id"`
			Timestamp time.Time         `json:"timestamp"`
			Type      string            `json:"type"`
			Action    string            `json:"action"`
			Status    string            `json:"status"`
			Source    string            `json:"source"`
			Details   map[string]string `json:"details,omitempty"`
		} `json:"data"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("invalid response: %w", err)
	}

	if !result.Success {
		return errors.New(result.Error)
	}

	// Filter by time if --since specified
	var events = result.Data
	if auditSince != "" {
		duration, err := time.ParseDuration(auditSince)
		if err != nil {
			return fmt.Errorf("invalid --since duration: %w", err)
		}
		cutoff := time.Now().Add(-duration)
		var filtered []struct {
			ID        string            `json:"id"`
			Timestamp time.Time         `json:"timestamp"`
			Type      string            `json:"type"`
			Action    string            `json:"action"`
			Status    string            `json:"status"`
			Source    string            `json:"source"`
			Details   map[string]string `json:"details,omitempty"`
		}
		for _, e := range events {
			if e.Timestamp.After(cutoff) {
				filtered = append(filtered, e)
			}
		}
		events = filtered
	}

	if auditJSON {
		out, _ := json.MarshalIndent(events, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	// Human-readable output
	if len(events) == 0 {
		fmt.Println("No audit events found.")
		return nil
	}

	fmt.Printf("Audit Trail (%d events)\n", len(events))
	fmt.Println(strings.Repeat("─", 60))

	for _, e := range events {
		icon := getEventIcon(e.Type, e.Status)
		ts := e.Timestamp.Local().Format("2006-01-02 15:04:05")
		fmt.Printf("%s  %s  [%s] %s: %s\n", icon, ts, e.Type, e.Action, e.Status)
		if len(e.Details) > 0 {
			for k, v := range e.Details {
				fmt.Printf("      %s: %s\n", k, v)
			}
		}
	}

	return nil
}

func runAuditSummary() error {
	// Parse since duration for summary
	since := "24h"
	if auditSince != "" {
		since = auditSince
	}
	duration, err := time.ParseDuration(since)
	if err != nil {
		return fmt.Errorf("invalid --since duration: %w", err)
	}

	params := fmt.Sprintf("?since=%d&recent=5", int(duration.Seconds()))
	resp, err := socketGet("/logs/summary" + params)
	if err != nil {
		return fmt.Errorf("failed to get summary: %w", err)
	}

	var result struct {
		Success bool `json:"success"`
		Data    struct {
			Period          string         `json:"period"`
			TotalEvents     int            `json:"total_events"`
			AuthAttempts    int            `json:"auth_attempts"`
			AuthFailures    int            `json:"auth_failures"`
			GateRequests    int            `json:"gate_requests"`
			GateApprovals   int            `json:"gate_approvals"`
			GateDenials     int            `json:"gate_denials"`
			IntegrityAlerts int            `json:"integrity_alerts"`
			ByType          map[string]int `json:"by_type"`
		} `json:"data"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("invalid response: %w", err)
	}

	if !result.Success {
		return errors.New(result.Error)
	}

	if auditJSON {
		out, _ := json.MarshalIndent(result.Data, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	// Human-readable summary
	s := result.Data
	fmt.Printf("Audit Summary (last %s)\n", since)
	fmt.Println(strings.Repeat("─", 40))
	fmt.Printf("Total Events:      %d\n", s.TotalEvents)
	fmt.Println()
	fmt.Println("Authentication:")
	fmt.Printf("  Attempts:        %d\n", s.AuthAttempts)
	fmt.Printf("  Failures:        %d\n", s.AuthFailures)
	if s.AuthAttempts > 0 {
		rate := float64(s.AuthFailures) / float64(s.AuthAttempts) * 100
		fmt.Printf("  Failure Rate:    %.1f%%\n", rate)
	}
	fmt.Println()
	fmt.Println("Gate Requests:")
	fmt.Printf("  Total:           %d\n", s.GateRequests)
	fmt.Printf("  Approved:        %d\n", s.GateApprovals)
	fmt.Printf("  Denied:          %d\n", s.GateDenials)
	fmt.Println()
	if s.IntegrityAlerts > 0 {
		fmt.Printf("⚠️  Integrity Alerts: %d\n", s.IntegrityAlerts)
	}

	if len(s.ByType) > 0 {
		fmt.Println()
		fmt.Println("Events by Type:")
		for t, count := range s.ByType {
			fmt.Printf("  %-12s %d\n", t, count)
		}
	}

	return nil
}

func runAuditVerify() error {
	resp, err := socketGet("/logs/verify")
	if err != nil {
		return fmt.Errorf("failed to verify logs: %w", err)
	}

	var result struct {
		Success bool `json:"success"`
		Data    struct {
			Valid  bool     `json:"valid"`
			Errors []string `json:"errors,omitempty"`
		} `json:"data"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(resp, &result); err != nil {
		return fmt.Errorf("invalid response: %w", err)
	}

	if !result.Success {
		return errors.New(result.Error)
	}

	if auditJSON {
		out, _ := json.MarshalIndent(result.Data, "", "  ")
		fmt.Println(string(out))
		return nil
	}

	if result.Data.Valid {
		fmt.Println("✅ Audit log integrity verified")
		fmt.Println("   No tampering detected. Hash chain is intact.")
	} else {
		fmt.Println("🚨 AUDIT LOG INTEGRITY CHECK FAILED")
		fmt.Println()
		fmt.Println("Errors detected:")
		for _, e := range result.Data.Errors {
			fmt.Printf("  • %s\n", e)
		}
		fmt.Println()
		fmt.Println("The audit log may have been tampered with!")
	}

	return nil
}

func getEventIcon(eventType, status string) string {
	switch eventType {
	case "auth":
		if status == "success" {
			return "🔓"
		}
		return "🔒"
	case "gate":
		switch status {
		case "approved":
			return "✅"
		case "denied":
			return "❌"
		case "pending":
			return "⏳"
		default:
			return "🚪"
		}
	case "alert":
		return "⚠️"
	case "integrity":
		return "📁"
	case "lockdown":
		if status == "success" && strings.Contains(status, "lift") {
			return "🔓"
		}
		return "🚨"
	case "system":
		return "⚙️"
	default:
		return "📋"
	}
}

func init() {
	auditCmd.Flags().StringVar(&auditSince, "since", "", "Show events since duration (e.g., 24h, 7d)")
	auditCmd.Flags().StringVar(&auditType, "type", "", "Filter by event type (comma-separated: auth,gate,alert)")
	auditCmd.Flags().BoolVar(&auditJSON, "json", false, "Output as JSON")
	auditCmd.Flags().IntVar(&auditLimit, "limit", 50, "Maximum events to show")

	auditSummaryCmd.Flags().StringVar(&auditSince, "since", "24h", "Summary period")
	auditSummaryCmd.Flags().BoolVar(&auditJSON, "json", false, "Output as JSON")

	auditVerifyCmd.Flags().BoolVar(&auditJSON, "json", false, "Output as JSON")

	auditCmd.AddCommand(auditSummaryCmd)
	auditCmd.AddCommand(auditVerifyCmd)

	rootCmd.AddCommand(auditCmd)
}
