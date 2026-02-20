package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/kris-hansen/feelgoodbot/internal/clawdbot"
	"github.com/kris-hansen/feelgoodbot/internal/gate"
	"github.com/kris-hansen/feelgoodbot/internal/mdscanner"
)

var gateSkillAIReview bool
var gateSkillAutoApprove bool
var gateSkillTimeout int

// gateSkillCmd scans a skill and requires approval if risky
var gateSkillCmd = &cobra.Command{
	Use:   "gate-skill <directory>",
	Short: "Scan skill and require approval before installation if risky",
	Long: `Scan an agent skill for security threats and require user approval
before allowing installation if risks are detected.

This command integrates with:
  • Clawdbot for Telegram-based approval prompts
  • TOTP for local approval when Clawdbot unavailable
  • feelgoodbot's gate system for approval tracking

Workflow:
  1. Scans the skill directory for threats
  2. If clean (no high/critical findings): exits 0 immediately
  3. If risky: sends approval request to Clawdbot/user
  4. Waits for approval (with timeout)
  5. Exits 0 if approved, 1 if denied/timeout

Examples:
  # Gate a skill installation
  feelgoodbot gate-skill ./untrusted-skill && clawdhub install ./untrusted-skill

  # With AI review for better risk assessment
  feelgoodbot gate-skill ./skill --ai-review

  # Auto-approve low/medium risks (only gate critical/high)
  feelgoodbot gate-skill ./skill --auto-approve-low

Exit codes:
  0 - Clean or approved
  1 - Denied, timeout, or error
  2 - Error during scan`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		skillPath := args[0]

		// Resolve to absolute path
		absPath, err := filepath.Abs(skillPath)
		if err != nil {
			return fmt.Errorf("cannot resolve path: %w", err)
		}

		// Verify path exists
		info, err := os.Stat(absPath)
		if err != nil {
			return fmt.Errorf("cannot access skill path: %w", err)
		}
		if !info.IsDir() {
			return fmt.Errorf("skill path must be a directory: %s", absPath)
		}

		skillName := filepath.Base(absPath)

		fmt.Printf("🔍 Scanning skill: %s\n", skillName)

		// Create scanner
		scanner := mdscanner.New(&mdscanner.Config{
			MaxLineLength:      10000,
			CheckBase64:        true,
			CheckShellCommands: true,
			CheckCredentials:   true,
			CheckURLs:          true,
		})

		// Scan the skill
		result, err := scanner.ScanSkillDirectory(absPath)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		// Perform AI review if requested
		var aiResult *mdscanner.AIAnalysisResult
		var aiSummary string
		if gateSkillAIReview {
			aiResult, err = performAIReview(absPath, result)
			if err != nil {
				fmt.Fprintf(os.Stderr, "⚠️  AI review failed: %v\n", err)
			} else {
				aiSummary = aiResult.Summary
			}
		}

		// Determine if gating is needed
		needsGate := false
		riskLevel := "safe"

		if result.Critical > 0 || (aiResult != nil && aiResult.RiskLevel == "critical") {
			needsGate = true
			riskLevel = "critical"
		} else if result.High > 0 || (aiResult != nil && aiResult.RiskLevel == "high") {
			needsGate = true
			riskLevel = "high"
		} else if !gateSkillAutoApprove && (result.Medium > 0 || (aiResult != nil && aiResult.RiskLevel == "medium")) {
			needsGate = true
			riskLevel = "medium"
		}

		// If clean or auto-approved, exit immediately
		if !needsGate {
			fmt.Printf("✅ Skill approved: %s (risk: %s)\n", skillName, riskLevel)
			return nil
		}

		// Print findings summary
		fmt.Println()
		fmt.Print(mdscanner.FormatSkillResult(result))
		if aiResult != nil {
			fmt.Print(mdscanner.FormatAIResult(aiResult))
		}

		// Request approval
		fmt.Println()
		fmt.Printf("⚠️  Skill requires approval (risk level: %s)\n", riskLevel)

		approved, err := requestSkillApproval(skillName, absPath, riskLevel, result.TotalIssues, aiSummary)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Approval request failed: %v\n", err)
			os.Exit(1)
		}

		if approved {
			fmt.Printf("✅ Skill approved by user: %s\n", skillName)
			return nil
		}

		fmt.Printf("❌ Skill denied: %s\n", skillName)
		os.Exit(1)
		return nil
	},
}

func requestSkillApproval(skillName, skillPath, riskLevel string, findings int, summary string) (bool, error) {
	// Try Clawdbot first
	notifier, err := clawdbot.NewNotifier(nil)
	if err == nil {
		req := &clawdbot.GateRequest{
			Action:       "install_skill",
			SkillName:    skillName,
			SkillPath:    skillPath,
			RiskLevel:    riskLevel,
			Findings:     findings,
			Summary:      summary,
			RequiresTOTP: riskLevel == "critical",
		}

		fmt.Println("📱 Requesting approval via Clawdbot...")

		resp, err := notifier.RequestGate(req)
		if err == nil {
			return resp.Approved, nil
		}
		fmt.Fprintf(os.Stderr, "⚠️  Clawdbot unavailable: %v\n", err)
	}

	// Fall back to local gate system
	fmt.Println("🔐 Falling back to local TOTP approval...")

	return requestLocalApproval(skillName, riskLevel, findings)
}

func requestLocalApproval(skillName, riskLevel string, findings int) (bool, error) {
	// Create gate request
	engine := gate.NewEngine(nil)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(gateSkillTimeout)*time.Second)
	defer cancel()

	action := fmt.Sprintf("skill:install:%s", skillName)
	metadata := map[string]string{
		"skill_name": skillName,
		"risk_level": riskLevel,
		"findings":   fmt.Sprintf("%d", findings),
	}

	req, err := engine.CreateRequest(action, "gate-skill", metadata)
	if err != nil {
		return false, err
	}

	fmt.Printf("\n🔑 Enter TOTP code to approve (request ID: %s):\n", req.ID[:8])
	fmt.Printf("   Or run: feelgoodbot gate approve %s <totp-code>\n\n", req.ID[:8])

	// Wait for approval
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return false, fmt.Errorf("approval timeout")
		case <-ticker.C:
			status, ok := engine.GetRequest(req.ID)
			if !ok || status == nil {
				continue
			}
			if status.Status == gate.StatusApproved {
				return true, nil
			}
			if status.Status == gate.StatusDenied || status.Status == gate.StatusExpired {
				return false, nil
			}
		}
	}
}

func init() {
	gateSkillCmd.Flags().BoolVar(&gateSkillAIReview, "ai-review", false, "Use AI for risk assessment")
	gateSkillCmd.Flags().BoolVar(&gateSkillAutoApprove, "auto-approve-low", false, "Auto-approve low/medium risks")
	gateSkillCmd.Flags().IntVar(&gateSkillTimeout, "timeout", 300, "Approval timeout in seconds")

	rootCmd.AddCommand(gateSkillCmd)
}
