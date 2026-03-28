package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kris-hansen/feelgoodbot/internal/egress"
)

var egressCmd = &cobra.Command{
	Use:   "egress",
	Short: "Network egress monitoring",
	Long: `Monitor outbound network connections and alert on anomalies.

Commands:
  init      Start learning mode, baseline current egress patterns
  stop      Stop learning mode, save baseline
  status    Show egress monitoring status and baseline stats
  snapshot  One-shot capture of current connections
  diff      Compare current connections vs baseline
  baseline  Show current baseline contents
  ignore    Add process to ignore list`,
}

var egressInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Start learning mode and baseline egress patterns",
	Long: `Start egress learning mode. The daemon will capture outbound connections
at each interval and build up a baseline of normal network behavior.

Run 'feelgoodbot egress stop' when you're satisfied with the baseline.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Check if already learning
		status, _ := egress.LoadStatus()
		if status != nil && status.Learning {
			fmt.Println("⚠️  Already in learning mode (started", status.LearningStart.Format("2006-01-02 15:04:05"), ")")
			fmt.Println("   Run 'feelgoodbot egress stop' to finish learning.")
			return nil
		}

		// Create or load baseline
		var baseline *egress.Baseline
		if egress.HasBaseline() {
			var err error
			baseline, err = egress.LoadBaseline()
			if err != nil {
				return fmt.Errorf("failed to load existing baseline: %w", err)
			}
			fmt.Println("📡 Resuming egress learning with existing baseline...")
		} else {
			baseline = egress.NewBaseline()
			fmt.Println("📡 Starting egress learning mode...")
		}

		// Do an initial capture
		fmt.Println("   Capturing current connections...")
		conns, err := egress.CaptureConnections()
		if err != nil {
			return fmt.Errorf("failed to capture connections: %w", err)
		}

		egress.MergeIntoBaseline(baseline, conns)
		if err := egress.SaveBaseline(baseline); err != nil {
			return fmt.Errorf("failed to save baseline: %w", err)
		}

		// Save learning status
		s := &egress.EgressStatus{
			Learning:      true,
			Enabled:       false,
			LearningStart: time.Now(),
			LastScan:      time.Now(),
			TotalScans:    1,
		}
		if err := egress.SaveStatus(s); err != nil {
			return fmt.Errorf("failed to save status: %w", err)
		}

		fmt.Printf("\n✅ Initial capture: %d connections from %d processes\n", len(conns), len(baseline.Processes))
		fmt.Println()
		fmt.Println("Learning mode is active. The daemon will continue building the baseline.")
		fmt.Println("Run 'feelgoodbot egress stop' when ready to switch to monitoring mode.")
		return nil
	},
}

var egressStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop learning mode and switch to monitoring",
	RunE: func(cmd *cobra.Command, args []string) error {
		status, err := egress.LoadStatus()
		if err != nil || !status.Learning {
			fmt.Println("ℹ️  Not currently in learning mode.")
			return nil
		}

		baseline, err := egress.LoadBaseline()
		if err != nil {
			return fmt.Errorf("failed to load baseline: %w", err)
		}

		// Do one final capture
		conns, err := egress.CaptureConnections()
		if err != nil {
			fmt.Printf("⚠️  Final capture failed: %v (saving baseline anyway)\n", err)
		} else {
			egress.MergeIntoBaseline(baseline, conns)
			if err := egress.SaveBaseline(baseline); err != nil {
				return fmt.Errorf("failed to save baseline: %w", err)
			}
		}

		// Update status
		status.Learning = false
		status.Enabled = true
		status.LastScan = time.Now()
		if err := egress.SaveStatus(status); err != nil {
			return fmt.Errorf("failed to save status: %w", err)
		}

		duration := time.Since(status.LearningStart).Round(time.Second)
		fmt.Printf("✅ Learning complete (%s, %d scans)\n", duration, status.TotalScans)
		fmt.Printf("   Baseline: %d processes profiled\n", len(baseline.Processes))

		totalDests := 0
		for _, p := range baseline.Processes {
			totalDests += len(p.Destinations)
		}
		fmt.Printf("   Destinations: %d unique endpoints\n", totalDests)
		fmt.Println()
		fmt.Println("Egress monitoring is now active. The daemon will alert on anomalies.")
		return nil
	},
}

var egressStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show egress monitoring status",
	RunE: func(cmd *cobra.Command, args []string) error {
		status, err := egress.LoadStatus()
		if err != nil {
			fmt.Println("📡 Egress monitoring: not initialized")
			fmt.Println("   Run 'feelgoodbot egress init' to start learning.")
			return nil
		}

		fmt.Println("📡 Egress Monitoring Status")
		fmt.Println()

		if status.Learning {
			fmt.Println("   Mode:     LEARNING")
			fmt.Printf("   Started:  %s\n", status.LearningStart.Format("2006-01-02 15:04:05"))
			fmt.Printf("   Duration: %s\n", time.Since(status.LearningStart).Round(time.Second))
		} else if status.Enabled {
			fmt.Println("   Mode:     MONITORING")
		} else {
			fmt.Println("   Mode:     DISABLED")
		}

		fmt.Printf("   Scans:    %d\n", status.TotalScans)
		if !status.LastScan.IsZero() {
			fmt.Printf("   Last:     %s\n", status.LastScan.Format("2006-01-02 15:04:05"))
		}

		if egress.HasBaseline() {
			baseline, err := egress.LoadBaseline()
			if err == nil {
				totalDests := 0
				for _, p := range baseline.Processes {
					totalDests += len(p.Destinations)
				}
				fmt.Println()
				fmt.Printf("   Processes:    %d\n", len(baseline.Processes))
				fmt.Printf("   Destinations: %d\n", totalDests)
				fmt.Printf("   Ignored:      %d\n", len(baseline.Ignored))
			}
		}

		return nil
	},
}

var egressSnapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "One-shot capture of current connections",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("📡 Capturing current connections...")
		fmt.Println()

		conns, err := egress.CaptureConnections()
		if err != nil {
			return fmt.Errorf("failed to capture connections: %w", err)
		}

		if len(conns) == 0 {
			fmt.Println("No ESTABLISHED connections found.")
			return nil
		}

		fmt.Print(egress.FormatSnapshot(conns))
		return nil
	},
}

var egressDiffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Compare current connections vs baseline",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !egress.HasBaseline() {
			fmt.Println("❌ No egress baseline found. Run 'feelgoodbot egress init' first.")
			return nil
		}

		baseline, err := egress.LoadBaseline()
		if err != nil {
			return fmt.Errorf("failed to load baseline: %w", err)
		}

		fmt.Println("📡 Comparing current connections to baseline...")
		fmt.Println()

		conns, err := egress.CaptureConnections()
		if err != nil {
			return fmt.Errorf("failed to capture connections: %w", err)
		}

		anomalies := egress.CompareToBaseline(baseline, conns)
		if len(anomalies) == 0 {
			fmt.Println("✅ All connections match baseline. No anomalies.")
			return nil
		}

		fmt.Print(egress.FormatAnomalies(anomalies))
		return nil
	},
}

var egressBaselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Show current baseline contents",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !egress.HasBaseline() {
			fmt.Println("❌ No egress baseline found. Run 'feelgoodbot egress init' first.")
			return nil
		}

		baseline, err := egress.LoadBaseline()
		if err != nil {
			return fmt.Errorf("failed to load baseline: %w", err)
		}

		fmt.Print(egress.FormatBaseline(baseline))
		return nil
	},
}

var egressIgnoreCmd = &cobra.Command{
	Use:   "ignore <process>",
	Short: "Add process to ignore list",
	Long: `Add a process name to the egress ignore list. Ignored processes
will not be tracked or generate alerts.

Common candidates: curl, wget, dig, nslookup`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		process := strings.TrimSpace(args[0])
		if process == "" {
			return fmt.Errorf("process name cannot be empty")
		}

		if !egress.HasBaseline() {
			// Create baseline just to store the ignore list
			baseline := egress.NewBaseline()
			egress.AddIgnored(baseline, process)
			if err := egress.SaveBaseline(baseline); err != nil {
				return fmt.Errorf("failed to save baseline: %w", err)
			}
			fmt.Printf("✅ Added '%s' to egress ignore list.\n", process)
			return nil
		}

		baseline, err := egress.LoadBaseline()
		if err != nil {
			return fmt.Errorf("failed to load baseline: %w", err)
		}

		if !egress.AddIgnored(baseline, process) {
			fmt.Printf("ℹ️  '%s' is already ignored.\n", process)
			return nil
		}

		if err := egress.SaveBaseline(baseline); err != nil {
			return fmt.Errorf("failed to save baseline: %w", err)
		}

		fmt.Printf("✅ Added '%s' to egress ignore list.\n", process)
		return nil
	},
}

func init() {
	egressCmd.AddCommand(egressInitCmd)
	egressCmd.AddCommand(egressStopCmd)
	egressCmd.AddCommand(egressStatusCmd)
	egressCmd.AddCommand(egressSnapshotCmd)
	egressCmd.AddCommand(egressDiffCmd)
	egressCmd.AddCommand(egressBaselineCmd)
	egressCmd.AddCommand(egressIgnoreCmd)
}
