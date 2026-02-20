package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/kris-hansen/feelgoodbot/internal/mdscanner"
)

var scanSkillJSON bool
var scanSkillQuiet bool
var scanSkillStrict bool
var scanSkillAIReview bool

// scanSkillCmd scans an entire skill directory for threats
var scanSkillCmd = &cobra.Command{
	Use:   "scan-skill <directory>",
	Short: "Scan an agent skill directory for security threats",
	Long: `Scan an entire agent skill directory for security threats.

This command scans all relevant files in a skill directory including:
  • SKILL.md and other markdown files
  • Shell scripts (.sh, .bash, .zsh)
  • Python scripts (.py)
  • JavaScript/TypeScript (.js, .ts)
  • Other executable scripts

Threat categories detected:
  • Prompt injection (hidden instructions, jailbreak attempts)
  • Shell injection (curl|sh, reverse shells, rm -rf)
  • Credential theft (SSH keys, API tokens, .env access)
  • Security bypass (quarantine removal, firewall disable)
  • Data exfiltration (webhooks, curl POST, discord/telegram)
  • Staged delivery (social engineering install patterns)
  • Suspicious URLs (raw IPs, shady TLDs, shorteners)
  • Kill chains (download → chmod → execute)

Examples:
  feelgoodbot scan-skill ./my-skill/
  feelgoodbot scan-skill ~/skills/twitter-bot --json
  feelgoodbot scan-skill /path/to/skill --strict
  feelgoodbot scan-skill ./suspicious-skill --ai-review

Exit codes:
  0 - Clean (no findings)
  1 - Findings detected (or critical/high in strict mode)
  2 - Error

Flags:
  --json       Output detailed JSON results
  --quiet      Only output if issues found
  --strict     Exit 1 on any high/critical findings (CI mode)
  --ai-review  Use AI (Claude) for deep analysis of suspicious patterns`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		skillPath := args[0]

		// Verify path exists
		info, err := os.Stat(skillPath)
		if err != nil {
			return fmt.Errorf("cannot access skill path: %w", err)
		}
		if !info.IsDir() {
			return fmt.Errorf("skill path must be a directory: %s", skillPath)
		}

		// Create scanner with all checks enabled
		scanner := mdscanner.New(&mdscanner.Config{
			MaxLineLength:      10000,
			CheckBase64:        true,
			CheckShellCommands: true,
			CheckCredentials:   true,
			CheckURLs:          true,
		})

		// Scan the skill directory
		result, err := scanner.ScanSkillDirectory(skillPath)
		if err != nil {
			return fmt.Errorf("scan failed: %w", err)
		}

		// Log to audit trail (best effort)
		logSkillScanResult(skillPath, result)

		// Perform AI review if requested
		var aiResult *mdscanner.AIAnalysisResult
		if scanSkillAIReview {
			aiResult, err = performAIReview(skillPath, result)
			if err != nil {
				fmt.Fprintf(os.Stderr, "⚠️  AI review failed: %v\n\n", err)
				// Continue with static results
			}
		}

		// JSON output
		if scanSkillJSON {
			output := struct {
				StaticAnalysis *mdscanner.SkillScanResult  `json:"static_analysis"`
				AIAnalysis     *mdscanner.AIAnalysisResult `json:"ai_analysis,omitempty"`
			}{
				StaticAnalysis: result,
				AIAnalysis:     aiResult,
			}
			out, _ := json.MarshalIndent(output, "", "  ")
			fmt.Println(string(out))
			if !result.Clean || (aiResult != nil && isHighRisk(aiResult.RiskLevel)) {
				os.Exit(1)
			}
			return nil
		}

		// Human-readable output
		if result.Clean && aiResult == nil {
			if !scanSkillQuiet {
				fmt.Printf("✅ Skill scan clean: %s\n", skillPath)
				fmt.Printf("   Scanned %d files, no issues found.\n", result.TotalFiles)
			}
			return nil
		}

		// Print static analysis results
		if !result.Clean {
			fmt.Print(mdscanner.FormatSkillResult(result))
		} else if !scanSkillQuiet {
			fmt.Printf("✅ Static scan clean: %s (%d files)\n\n", skillPath, result.TotalFiles)
		}

		// Print AI analysis if available
		if aiResult != nil {
			fmt.Println("─────────────────────────────────────────────────────────")
			fmt.Println("🤖 AI-Powered Deep Analysis")
			fmt.Println("─────────────────────────────────────────────────────────")
			fmt.Print(mdscanner.FormatAIResult(aiResult))
		}

		// Determine exit code
		exitCode := 0
		if !result.Clean {
			exitCode = 1
		}
		if aiResult != nil && isHighRisk(aiResult.RiskLevel) {
			exitCode = 1
		}

		if scanSkillStrict && (result.Critical > 0 || result.High > 0) {
			fmt.Println("❌ Strict mode: failing due to critical/high severity findings")
			exitCode = 1
		}
		if scanSkillStrict && aiResult != nil && isHighRisk(aiResult.RiskLevel) {
			fmt.Println("❌ Strict mode: failing due to AI risk assessment")
			exitCode = 1
		}

		if exitCode != 0 {
			os.Exit(exitCode)
		}
		return nil
	},
}

func isHighRisk(level string) bool {
	return level == "critical" || level == "high"
}

func performAIReview(skillPath string, staticResult *mdscanner.SkillScanResult) (*mdscanner.AIAnalysisResult, error) {
	fmt.Println("🤖 Running AI-powered deep analysis...")

	// Create AI analyzer
	analyzer, err := mdscanner.NewAIAnalyzer(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AI analyzer: %w", err)
	}

	// Read skill files
	files, err := mdscanner.ReadSkillFiles(skillPath, 500*1024) // 500KB max total
	if err != nil {
		return nil, fmt.Errorf("failed to read skill files: %w", err)
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no analyzable files found in skill directory")
	}

	// Perform analysis
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	result, err := analyzer.AnalyzeSkill(ctx, files, staticResult)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// logSkillScanResult logs the skill scan result to audit trail
func logSkillScanResult(path string, result *mdscanner.SkillScanResult) {
	status := "clean"
	if !result.Clean {
		status = "findings"
	}

	// Best effort - ignore errors if daemon not running
	_, _ = socketPost("/logs/skill-scan", map[string]interface{}{
		"path":     path,
		"files":    result.TotalFiles,
		"findings": result.TotalIssues,
		"critical": result.Critical,
		"high":     result.High,
		"medium":   result.Medium,
		"low":      result.Low,
		"status":   status,
	})
}

func init() {
	scanSkillCmd.Flags().BoolVar(&scanSkillJSON, "json", false, "Output detailed JSON results")
	scanSkillCmd.Flags().BoolVar(&scanSkillQuiet, "quiet", false, "Only output if issues found")
	scanSkillCmd.Flags().BoolVar(&scanSkillStrict, "strict", false, "Exit 1 on critical/high findings (CI mode)")
	scanSkillCmd.Flags().BoolVar(&scanSkillAIReview, "ai-review", false, "Use AI (Claude) for deep analysis")

	rootCmd.AddCommand(scanSkillCmd)
}
