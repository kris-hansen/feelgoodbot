package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kris-hansen/feelgoodbot/internal/mdscanner"
)

var scanSkillJSON bool
var scanSkillQuiet bool
var scanSkillStrict bool

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

Exit codes:
  0 - Clean (no findings)
  1 - Findings detected (or critical/high in strict mode)
  2 - Error

Flags:
  --json     Output detailed JSON results
  --quiet    Only output if issues found
  --strict   Exit 1 on any high/critical findings (CI mode)`,
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

		// JSON output
		if scanSkillJSON {
			out, _ := json.MarshalIndent(result, "", "  ")
			fmt.Println(string(out))
			if !result.Clean {
				if scanSkillStrict && (result.Critical > 0 || result.High > 0) {
					os.Exit(1)
				}
				if !result.Clean {
					os.Exit(1)
				}
			}
			return nil
		}

		// Human-readable output
		if result.Clean {
			if !scanSkillQuiet {
				fmt.Printf("✅ Skill scan clean: %s\n", skillPath)
				fmt.Printf("   Scanned %d files, no issues found.\n", result.TotalFiles)
			}
			return nil
		}

		// Print formatted results
		fmt.Print(mdscanner.FormatSkillResult(result))

		// Determine exit code
		if scanSkillStrict && (result.Critical > 0 || result.High > 0) {
			fmt.Println("❌ Strict mode: failing due to critical/high severity findings")
			os.Exit(1)
		}

		os.Exit(1)
		return nil
	},
}

// logSkillScanResult logs the skill scan result to audit trail
func logSkillScanResult(path string, result *mdscanner.SkillScanResult) {
	status := "clean"
	if !result.Clean {
		status = "findings"
	}

	// Best effort - ignore errors if daemon not running
	_, _ = socketPost("/logs/skill-scan", map[string]interface{}{
		"path":      path,
		"files":     result.TotalFiles,
		"findings":  result.TotalIssues,
		"critical":  result.Critical,
		"high":      result.High,
		"medium":    result.Medium,
		"low":       result.Low,
		"status":    status,
	})
}

func init() {
	scanSkillCmd.Flags().BoolVar(&scanSkillJSON, "json", false, "Output detailed JSON results")
	scanSkillCmd.Flags().BoolVar(&scanSkillQuiet, "quiet", false, "Only output if issues found")
	scanSkillCmd.Flags().BoolVar(&scanSkillStrict, "strict", false, "Exit 1 on critical/high findings (CI mode)")

	rootCmd.AddCommand(scanSkillCmd)
}
