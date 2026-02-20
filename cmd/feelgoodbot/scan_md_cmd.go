package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kris-hansen/feelgoodbot/internal/mdscanner"
)

var scanMdJSON bool
var scanMdQuiet bool

// scanMdCmd scans markdown files for prompt injection
var scanMdCmd = &cobra.Command{
	Use:   "scan-md [file...]",
	Short: "Scan markdown for prompt injection attempts",
	Long: `Scan markdown files for potential prompt injection attacks.

Detects:
  • Hidden instructions in HTML comments
  • Unicode tricks (RTL override, zero-width chars, homoglyphs)
  • Hidden text (CSS display:none, visibility:hidden, etc.)
  • Instruction-like patterns ("ignore previous", "you are now", etc.)
  • Suspicious link mismatches (text vs URL)
  • Base64-encoded payloads with suspicious content

Examples:
  feelgoodbot scan-md README.md
  feelgoodbot scan-md *.md
  cat file.md | feelgoodbot scan-md --stdin
  feelgoodbot scan-md --json doc.md | jq '.findings'

Exit codes:
  0 - Clean (no findings)
  1 - Findings detected
  2 - Error`,
	RunE: func(cmd *cobra.Command, args []string) error {
		stdin, _ := cmd.Flags().GetBool("stdin")

		if stdin {
			return scanMarkdownReader(os.Stdin, "<stdin>")
		}

		if len(args) == 0 {
			return fmt.Errorf("no files specified; use --stdin or provide file paths")
		}

		hasFindings := false
		hasErrors := false

		for _, path := range args {
			f, err := os.Open(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error opening %s: %v\n", path, err)
				hasErrors = true
				continue
			}

			if err := scanMarkdownReader(f, path); err != nil {
				if err == errFindingsDetected {
					hasFindings = true
				} else {
					fmt.Fprintf(os.Stderr, "Error scanning %s: %v\n", path, err)
					hasErrors = true
				}
			}
			f.Close()
		}

		if hasErrors {
			os.Exit(2)
		}
		if hasFindings {
			os.Exit(1)
		}
		return nil
	},
}

var errFindingsDetected = fmt.Errorf("findings detected")

func scanMarkdownReader(r io.Reader, name string) error {
	scanner := mdscanner.New(nil)
	result, err := scanner.ScanReader(r)
	if err != nil {
		return err
	}

	// Log to audit trail (best effort - don't fail if daemon not running)
	logScanResult(name, result)

	if scanMdJSON {
		out, _ := json.MarshalIndent(struct {
			File   string                `json:"file"`
			Result *mdscanner.ScanResult `json:"result"`
		}{
			File:   name,
			Result: result,
		}, "", "  ")
		fmt.Println(string(out))
		if !result.Clean {
			return errFindingsDetected
		}
		return nil
	}

	if result.Clean {
		if !scanMdQuiet {
			fmt.Printf("✅ %s: Clean (%d lines scanned)\n", name, result.LinesTotal)
		}
		return nil
	}

	// Output findings
	fmt.Printf("⚠️  %s: %d potential issue(s) found\n", name, len(result.Findings))
	fmt.Println(strings.Repeat("─", 60))

	for _, f := range result.Findings {
		icon := getSeverityIcon(f.Severity)
		fmt.Printf("%s Line %d: %s\n", icon, f.Line, f.Message)
		if f.Content != "" {
			fmt.Printf("   └─ %s\n", f.Content)
		}
	}
	fmt.Println()

	return errFindingsDetected
}

func getSeverityIcon(sev mdscanner.Severity) string {
	switch sev {
	case mdscanner.SeverityHigh:
		return "🔴"
	case mdscanner.SeverityMedium:
		return "🟡"
	case mdscanner.SeverityLow:
		return "🟢"
	default:
		return "⚪"
	}
}

// logScanResult logs the scan result to the audit trail (if daemon running)
func logScanResult(file string, result *mdscanner.ScanResult) {
	status := "clean"
	details := ""

	if !result.Clean {
		status = "findings"
		// Summarize findings
		var types []string
		typeCount := make(map[string]int)
		for _, f := range result.Findings {
			typeCount[string(f.Type)]++
		}
		for t, c := range typeCount {
			types = append(types, fmt.Sprintf("%s:%d", t, c))
		}
		details = strings.Join(types, ",")
	}

	// Best effort - ignore errors if daemon not running
	_, _ = socketPost("/logs/scan", map[string]interface{}{
		"file":     file,
		"findings": len(result.Findings),
		"status":   status,
		"details":  details,
	})
}

func init() {
	scanMdCmd.Flags().Bool("stdin", false, "Read from stdin")
	scanMdCmd.Flags().BoolVar(&scanMdJSON, "json", false, "Output as JSON")
	scanMdCmd.Flags().BoolVar(&scanMdQuiet, "quiet", false, "Suppress output for clean files")

	rootCmd.AddCommand(scanMdCmd)
}
