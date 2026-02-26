//go:build darwin

package console

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const socketName = "feelgoodbot.sock"

type Alert struct {
	Timestamp string   `json:"timestamp"`
	Severity  string   `json:"severity"`
	Changes   []Change `json:"changes"`
}

type Change struct {
	Path     string `json:"path"`
	Type     string `json:"type"`
	Category string `json:"category"`
	Severity string `json:"severity"`
}

type Console struct {
	mu           sync.Mutex
	alertCount   int
	running      bool
	stopCh       chan struct{}
	listener     net.Listener
	socketPath   string
	currentAlert *Alert
	alertCh      chan Alert
	inputReader  *bufio.Reader
}

func New() *Console {
	home, _ := os.UserHomeDir()
	return &Console{
		stopCh:      make(chan struct{}),
		socketPath:  filepath.Join(home, ".config", "feelgoodbot", socketName),
		alertCh:     make(chan Alert, 10),
		inputReader: bufio.NewReader(os.Stdin),
	}
}

func (c *Console) Start() error {
	c.mu.Lock()
	c.running = true
	c.mu.Unlock()

	// Remove existing socket
	os.Remove(c.socketPath)

	// Ensure directory exists
	_ = os.MkdirAll(filepath.Dir(c.socketPath), 0700)

	// Create Unix socket listener
	listener, err := net.Listen("unix", c.socketPath)
	if err != nil {
		return fmt.Errorf("failed to create socket: %w", err)
	}
	c.listener = listener

	go c.acceptConnections()
	go c.processAlerts()

	return nil
}

func (c *Console) Stop() {
	c.mu.Lock()
	c.running = false
	c.mu.Unlock()

	if c.listener != nil {
		c.listener.Close()
	}
	os.Remove(c.socketPath)
	close(c.stopCh)
}

func (c *Console) acceptConnections() {
	for {
		conn, err := c.listener.Accept()
		if err != nil {
			select {
			case <-c.stopCh:
				return
			default:
				continue
			}
		}
		go c.handleConnection(conn)
	}
}

func (c *Console) handleConnection(conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		var alert Alert
		if err := json.Unmarshal(scanner.Bytes(), &alert); err != nil {
			continue
		}
		c.alertCh <- alert
	}
}

func (c *Console) processAlerts() {
	for {
		select {
		case <-c.stopCh:
			return
		case alert := <-c.alertCh:
			c.mu.Lock()
			c.alertCount++
			c.currentAlert = &alert
			c.mu.Unlock()
			c.displayAlert(alert)
			c.handleInput(alert)
		}
	}
}

func (c *Console) displayAlert(alert Alert) {
	reset := "\033[0m"
	bold := "\033[1m"
	red := "\033[31m"
	yellow := "\033[33m"
	gray := "\033[90m"

	severityIcon := "🔵"
	severityColor := gray
	switch alert.Severity {
	case "critical":
		severityIcon = "🔴"
		severityColor = red
	case "warning":
		severityIcon = "🟡"
		severityColor = yellow
	}

	timestamp := formatTimestamp(alert.Timestamp)

	fmt.Printf("%s───────────────────────────────────────────────────────────────%s\n", gray, reset)
	fmt.Printf("%s%s %s — %d change(s) detected%s\n", severityColor, severityIcon, timestamp, len(alert.Changes), reset)
	fmt.Println()

	for i, change := range alert.Changes {
		icon := "🟡"
		if change.Severity == "critical" {
			icon = "🔴"
		}
		filename := filepath.Base(change.Path)
		fmt.Printf("   %2d. %s %s%s%s %s(%s)%s %s\n", i+1, icon, bold, filename, reset, gray, change.Category, reset, change.Type)
	}

	fmt.Println()
	fmt.Printf("   %si <n>  ignore    d <n>  details    I/D  all    h  help    q  dismiss%s\n", gray, reset)
	fmt.Println()
}

func (c *Console) handleInput(alert Alert) {
	reset := "\033[0m"
	bold := "\033[1m"
	gray := "\033[90m"
	green := "\033[32m"
	cyan := "\033[36m"
	red := "\033[31m"

	for {
		fmt.Printf("%s> %s", gray, reset)
		input, err := c.inputReader.ReadString('\n')
		if err != nil {
			return
		}
		input = strings.TrimSpace(input)

		// Parse command and arguments
		parts := strings.Fields(input)
		if len(parts) == 0 {
			continue
		}

		cmd := parts[0]

		switch cmd {
		case "i":
			if len(parts) > 1 {
				// Parse item numbers (supports: "i 3" or "i 3,5,7" or "i 3-7" or "i 3, 5, 7")
				// Join all args to handle spaces after commas
				args := strings.Join(parts[1:], "")
				items := parseItemList(args, len(alert.Changes))
				if len(items) == 0 {
					fmt.Printf("   %s⚠️  Invalid item number(s) (1-%d)%s\n", red, len(alert.Changes), reset)
					continue
				}

				// Show what will be ignored
				var names []string
				for _, idx := range items {
					names = append(names, filepath.Base(alert.Changes[idx-1].Path))
				}
				if len(items) == 1 {
					fmt.Printf("\n%sIgnore '%s' permanently? [y/n]:%s ", cyan, names[0], reset)
				} else {
					fmt.Printf("\n%sIgnore %d items permanently? [y/n]:%s ", cyan, len(items), reset)
				}

				answer, _ := c.inputReader.ReadString('\n')
				answer = strings.TrimSpace(strings.ToLower(answer))
				if answer == "y" || answer == "yes" {
					for _, idx := range items {
						change := alert.Changes[idx-1]
						if err := addToIgnoreList(change.Path); err != nil {
							fmt.Printf("   %s⚠️  Failed to add %s: %v%s\n", red, filepath.Base(change.Path), err, reset)
						}
					}
					fmt.Printf("   %s✓ Added %d path(s) to permanent ignore list%s\n", green, len(items), reset)
				} else {
					fmt.Printf("   %s✓ Ignored this time only%s\n", green, reset)
				}
				fmt.Println()
			} else {
				fmt.Printf("   %sUsage: i <n> or i <n,n,n> (e.g., i 3 or i 3,5,7)%s\n", gray, reset)
			}

		case "I", "ignore", "ia":
			// Ignore ALL
			fmt.Printf("\n%sIgnore ALL %d items permanently? [y/n]:%s ", cyan, len(alert.Changes), reset)
			answer, _ := c.inputReader.ReadString('\n')
			answer = strings.TrimSpace(strings.ToLower(answer))
			if answer == "y" || answer == "yes" {
				for _, change := range alert.Changes {
					if err := addToIgnoreList(change.Path); err != nil {
						fmt.Printf("   %s⚠️  Failed to add %s: %v%s\n", red, filepath.Base(change.Path), err, reset)
					}
				}
				fmt.Printf("   %s✓ Added %d path(s) to permanent ignore list%s\n", green, len(alert.Changes), reset)
			} else {
				fmt.Printf("   %s✓ Ignored this time only%s\n", green, reset)
			}
			fmt.Println()
			return

		case "d":
			if len(parts) > 1 {
				// Parse item numbers (supports: "d 3" or "d 3,5,7" or "d 3, 5, 7")
				// Join all args to handle spaces after commas
				args := strings.Join(parts[1:], "")
				items := parseItemList(args, len(alert.Changes))
				if len(items) == 0 {
					fmt.Printf("   %s⚠️  Invalid item number(s) (1-%d)%s\n", red, len(alert.Changes), reset)
					continue
				}
				fmt.Println()
				for _, idx := range items {
					change := alert.Changes[idx-1]
					icon := "🟡"
					if change.Severity == "critical" {
						icon = "🔴"
					}
					fmt.Printf("   %2d. %s %s%s%s\n", idx, icon, bold, change.Path, reset)
					fmt.Printf("       %sType: %s | Category: %s%s\n", gray, change.Type, change.Category, reset)
					showFilePreview(change.Path, gray, reset)
					fmt.Println()
				}
			} else {
				fmt.Printf("   %sUsage: d <n> or d <n,n,n> (e.g., d 3 or d 3,5,7)%s\n", gray, reset)
			}

		case "D", "details":
			// Details for ALL
			fmt.Println()
			fmt.Printf("   %s%sFull details:%s\n", bold, cyan, reset)
			for i, change := range alert.Changes {
				icon := "🟡"
				if change.Severity == "critical" {
					icon = "🔴"
				}
				fmt.Printf("\n   %2d. %s %s%s%s\n", i+1, icon, bold, change.Path, reset)
				fmt.Printf("       %sType: %s | Category: %s%s\n", gray, change.Type, change.Category, reset)
				showFilePreview(change.Path, gray, reset)
			}
			fmt.Println()

		case "h", "help", "?":
			fmt.Println()
			fmt.Printf("   %s%sCommands:%s\n", bold, cyan, reset)
			fmt.Printf("   %si <n>%s     Ignore item n (e.g., i 3)\n", bold, reset)
			fmt.Printf("   %sd <n>%s     Details for item n (e.g., d 5)\n", bold, reset)
			fmt.Printf("   %sI%s         Ignore ALL items\n", bold, reset)
			fmt.Printf("   %sD%s         Details for ALL items\n", bold, reset)
			fmt.Printf("   %sq%s         Dismiss this alert\n", bold, reset)
			fmt.Printf("   %sh%s         Show this help\n", bold, reset)
			fmt.Println()

		case "q", "quit", "exit":
			return

		case "":
			continue

		default:
			fmt.Printf("   %sUnknown command. Type 'h' for help.%s\n", gray, reset)
		}
	}
}

func addToIgnoreList(path string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	ignorePath := filepath.Join(home, ".config", "feelgoodbot", "ignore.txt")

	// Read existing entries
	existing := make(map[string]bool)
	if data, err := os.ReadFile(ignorePath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				existing[line] = true
			}
		}
	}

	// Already ignored?
	if existing[path] {
		return nil
	}

	// Append to file
	f, err := os.OpenFile(ignorePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(path + "\n")
	return err
}

func showFilePreview(path, gray, reset string) {
	info, err := os.Stat(path)
	if err != nil {
		fmt.Printf("      %s(file not accessible: %v)%s\n", gray, err, reset)
		return
	}

	// Show metadata
	fmt.Printf("      %sSize: %d bytes | Modified: %s | Mode: %s%s\n",
		gray, info.Size(), info.ModTime().Format("2006-01-02 15:04:05"), info.Mode(), reset)

	// Skip if too large or binary
	if info.Size() > 100*1024 { // 100KB limit
		fmt.Printf("      %s(file too large to preview)%s\n", gray, reset)
		return
	}

	if info.IsDir() {
		return
	}

	// Try to read and show preview
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}

	// Check if binary
	if isBinary(content) {
		fmt.Printf("      %s(binary file)%s\n", gray, reset)
		return
	}

	// Show first 10 lines
	lines := strings.Split(string(content), "\n")
	maxLines := 10
	if len(lines) > maxLines {
		fmt.Printf("      %s─── Preview (first %d of %d lines) ───%s\n", gray, maxLines, len(lines), reset)
	} else {
		fmt.Printf("      %s─── Content ───%s\n", gray, reset)
	}

	for i, line := range lines {
		if i >= maxLines {
			fmt.Printf("      %s...%s\n", gray, reset)
			break
		}
		// Truncate long lines
		if len(line) > 80 {
			line = line[:77] + "..."
		}
		fmt.Printf("      %s%s%s\n", gray, line, reset)
	}
}

func isBinary(content []byte) bool {
	// Check first 512 bytes for null bytes or high concentration of non-printable chars
	checkLen := 512
	if len(content) < checkLen {
		checkLen = len(content)
	}

	nonPrintable := 0
	for i := 0; i < checkLen; i++ {
		if content[i] == 0 {
			return true
		}
		if content[i] < 32 && content[i] != '\n' && content[i] != '\r' && content[i] != '\t' {
			nonPrintable++
		}
	}

	return nonPrintable > checkLen/10 // More than 10% non-printable
}

func formatTimestamp(iso string) string {
	t, err := time.Parse("2006-01-02T15:04:05-07:00", iso)
	if err != nil {
		return iso
	}
	return t.Format("15:04:05")
}

// parseItemList parses "3", "3,5,7", or "3-7" into a list of valid item numbers
func parseItemList(input string, max int) []int {
	var result []int
	seen := make(map[int]bool)

	// Split by comma
	parts := strings.Split(input, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Check for range (e.g., "3-7")
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				var start, end int
				if _, err := fmt.Sscanf(rangeParts[0], "%d", &start); err != nil {
					continue
				}
				if _, err := fmt.Sscanf(rangeParts[1], "%d", &end); err != nil {
					continue
				}
				if start > end {
					start, end = end, start
				}
				for i := start; i <= end; i++ {
					if i >= 1 && i <= max && !seen[i] {
						result = append(result, i)
						seen[i] = true
					}
				}
			}
		} else {
			// Single number
			var num int
			if _, err := fmt.Sscanf(part, "%d", &num); err != nil {
				continue
			}
			if num >= 1 && num <= max && !seen[num] {
				result = append(result, num)
				seen[num] = true
			}
		}
	}

	return result
}
