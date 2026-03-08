package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/kris-hansen/feelgoodbot/internal/console"
)

var consoleCmd = &cobra.Command{
	Use:   "console",
	Short: "Live monitoring console for security alerts",
	Long: `The feelgoodbot console provides a live view of security alerts.

Keep this open in a terminal window to monitor file integrity changes
in real-time. You can ignore, accept, or investigate alerts as they appear.

Example:
  feelgoodbot console`,
	RunE: runConsole,
}

func init() {
	rootCmd.AddCommand(consoleCmd)
}

func runConsole(cmd *cobra.Command, args []string) error {
	fmt.Println()
	fmt.Println("\033[1m\033[36m╔══════════════════════════════════════════════════╗\033[0m")
	fmt.Println("\033[1m\033[36m║  🛡️  FEELGOODBOT CONSOLE                         ║\033[0m")
	fmt.Println("\033[1m\033[36m╚══════════════════════════════════════════════════╝\033[0m")
	fmt.Println()

	// Start the console listener
	c := console.New()
	if err := c.Start(); err != nil {
		return fmt.Errorf("failed to start console: %w", err)
	}
	defer c.Stop()

	fmt.Printf("\033[90mListening for alerts... (Ctrl+C to exit)\033[0m\n")
	fmt.Printf("\033[90mLast check: %s\033[0m\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println()

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\n\033[90mShutting down console...\033[0m")
	return nil
}
