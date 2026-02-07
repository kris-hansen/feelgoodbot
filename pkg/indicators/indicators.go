// Package indicators defines the key file indicators for macOS malware detection
package indicators

import (
	"os"
	"path/filepath"
	"strings"
)

// Severity of a monitored path
type Severity int

const (
	Info Severity = iota
	Warning
	Critical
)

// String returns the string representation of severity
func (s Severity) String() string {
	switch s {
	case Info:
		return "info"
	case Warning:
		return "warning"
	case Critical:
		return "critical"
	default:
		return "unknown"
	}
}

// ParseSeverity converts a string to Severity
func ParseSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "critical":
		return Critical
	case "warning":
		return Warning
	default:
		return Info
	}
}

// Indicator represents a path to monitor
type Indicator struct {
	Path        string   `json:"path" yaml:"path"`
	Description string   `json:"description" yaml:"description"`
	Severity    Severity `json:"severity" yaml:"severity"`
	Recursive   bool     `json:"recursive" yaml:"recursive"`
	Category    string   `json:"category" yaml:"category"`
}

// CustomIndicator represents a user-defined indicator from config
// Uses string severity for YAML compatibility
type CustomIndicator struct {
	Path        string `yaml:"path"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"` // "info", "warning", "critical"
	Recursive   bool   `yaml:"recursive"`
	Category    string `yaml:"category"`
}

// ToIndicator converts a CustomIndicator to an Indicator
func (c CustomIndicator) ToIndicator() Indicator {
	// Expand ~ to home directory
	path := c.Path
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, path[2:])
	}

	return Indicator{
		Path:        path,
		Description: c.Description,
		Severity:    ParseSeverity(c.Severity),
		Recursive:   c.Recursive,
		Category:    c.Category,
	}
}

// DefaultIndicators returns the comprehensive set of macOS paths to monitor
// Based on analysis of real-world attacks including:
// - GTG-1002 (Claude Code espionage campaign)
// - Shai-Hulud npm supply chain attack
// - Various coding agent compromises
func DefaultIndicators() []Indicator {
	home, _ := os.UserHomeDir()

	return []Indicator{
		// ============================================================
		// CRITICAL: System Binaries
		// These are the primary targets - modification = likely compromise
		// ============================================================
		{
			Path:        "/usr/bin",
			Description: "System binaries - core Unix utilities",
			Severity:    Critical,
			Recursive:   true,
			Category:    "system_binaries",
		},
		{
			Path:        "/usr/sbin",
			Description: "System admin binaries",
			Severity:    Critical,
			Recursive:   true,
			Category:    "system_binaries",
		},
		{
			Path:        "/bin",
			Description: "Essential command binaries",
			Severity:    Critical,
			Recursive:   true,
			Category:    "system_binaries",
		},
		{
			Path:        "/sbin",
			Description: "Essential system binaries",
			Severity:    Critical,
			Recursive:   true,
			Category:    "system_binaries",
		},

		// ============================================================
		// CRITICAL: Persistence Mechanisms
		// How malware survives reboots - LaunchAgents/Daemons
		// ============================================================
		{
			Path:        "/Library/LaunchDaemons",
			Description: "System-wide launch daemons (root)",
			Severity:    Critical,
			Recursive:   true,
			Category:    "persistence",
		},
		{
			Path:        "/Library/LaunchAgents",
			Description: "System-wide launch agents",
			Severity:    Critical,
			Recursive:   true,
			Category:    "persistence",
		},
		{
			Path:        filepath.Join(home, "Library/LaunchAgents"),
			Description: "User launch agents",
			Severity:    Critical,
			Recursive:   true,
			Category:    "persistence",
		},
		{
			Path:        "/System/Library/LaunchDaemons",
			Description: "Apple system launch daemons",
			Severity:    Critical,
			Recursive:   true,
			Category:    "persistence",
		},

		// ============================================================
		// CRITICAL: Privilege Escalation
		// Sudoers, PAM - used to gain root access
		// ============================================================
		{
			Path:        "/etc/sudoers",
			Description: "Sudo configuration",
			Severity:    Critical,
			Recursive:   false,
			Category:    "privilege_escalation",
		},
		{
			Path:        "/etc/sudoers.d",
			Description: "Additional sudo rules",
			Severity:    Critical,
			Recursive:   true,
			Category:    "privilege_escalation",
		},
		{
			Path:        "/etc/pam.d",
			Description: "PAM authentication modules",
			Severity:    Critical,
			Recursive:   true,
			Category:    "privilege_escalation",
		},

		// ============================================================
		// CRITICAL: SSH Access
		// Remote access - favorite target for persistence
		// ============================================================
		{
			Path:        filepath.Join(home, ".ssh/authorized_keys"),
			Description: "SSH authorized keys",
			Severity:    Critical,
			Recursive:   false,
			Category:    "ssh",
		},
		{
			Path:        filepath.Join(home, ".ssh/config"),
			Description: "SSH client configuration",
			Severity:    Warning,
			Recursive:   false,
			Category:    "ssh",
		},
		{
			Path:        "/etc/ssh/sshd_config",
			Description: "SSH daemon configuration",
			Severity:    Critical,
			Recursive:   false,
			Category:    "ssh",
		},

		// ============================================================
		// WARNING: Shell Configuration
		// Shai-Hulud and similar attacks inject into shell configs
		// ============================================================
		{
			Path:        filepath.Join(home, ".zshrc"),
			Description: "Zsh configuration",
			Severity:    Warning,
			Recursive:   false,
			Category:    "shell_config",
		},
		{
			Path:        filepath.Join(home, ".bashrc"),
			Description: "Bash configuration",
			Severity:    Warning,
			Recursive:   false,
			Category:    "shell_config",
		},
		{
			Path:        filepath.Join(home, ".bash_profile"),
			Description: "Bash profile",
			Severity:    Warning,
			Recursive:   false,
			Category:    "shell_config",
		},
		{
			Path:        filepath.Join(home, ".zprofile"),
			Description: "Zsh profile",
			Severity:    Warning,
			Recursive:   false,
			Category:    "shell_config",
		},
		{
			Path:        filepath.Join(home, ".profile"),
			Description: "Shell profile",
			Severity:    Warning,
			Recursive:   false,
			Category:    "shell_config",
		},
		{
			Path:        "/etc/zshrc",
			Description: "System zsh configuration",
			Severity:    Warning,
			Recursive:   false,
			Category:    "shell_config",
		},
		{
			Path:        "/etc/bashrc",
			Description: "System bash configuration",
			Severity:    Warning,
			Recursive:   false,
			Category:    "shell_config",
		},

		// ============================================================
		// WARNING: Homebrew Binaries
		// Attackers target package manager binaries
		// ============================================================
		{
			Path:        "/opt/homebrew/bin",
			Description: "Homebrew binaries (Apple Silicon)",
			Severity:    Warning,
			Recursive:   true,
			Category:    "package_managers",
		},
		{
			Path:        "/usr/local/bin",
			Description: "Local binaries / Homebrew (Intel)",
			Severity:    Warning,
			Recursive:   true,
			Category:    "package_managers",
		},
		{
			Path:        "/opt/homebrew/sbin",
			Description: "Homebrew system binaries",
			Severity:    Warning,
			Recursive:   true,
			Category:    "package_managers",
		},

		// ============================================================
		// WARNING: npm Global Packages
		// Shai-Hulud specifically targets npm
		// ============================================================
		{
			Path:        "/opt/homebrew/lib/node_modules",
			Description: "npm global packages (Homebrew)",
			Severity:    Warning,
			Recursive:   false, // Just top level, not recursive (too noisy)
			Category:    "npm",
		},
		{
			Path:        filepath.Join(home, ".npm/_cacache"),
			Description: "npm cache (potential malware staging)",
			Severity:    Info,
			Recursive:   false,
			Category:    "npm",
		},

		// ============================================================
		// WARNING: Git Hooks
		// Malware can execute code on git operations
		// ============================================================
		{
			Path:        filepath.Join(home, ".config/git/hooks"),
			Description: "Global git hooks",
			Severity:    Warning,
			Recursive:   true,
			Category:    "git",
		},
		{
			Path:        "/etc/gitconfig",
			Description: "System git configuration",
			Severity:    Warning,
			Recursive:   false,
			Category:    "git",
		},

		// ============================================================
		// WARNING: Cron Jobs
		// Scheduled task persistence
		// ============================================================
		{
			Path:        "/etc/crontab",
			Description: "System crontab",
			Severity:    Warning,
			Recursive:   false,
			Category:    "cron",
		},
		{
			Path:        "/var/at/tabs",
			Description: "User crontabs",
			Severity:    Warning,
			Recursive:   true,
			Category:    "cron",
		},
		{
			Path:        "/etc/periodic",
			Description: "Periodic scripts",
			Severity:    Warning,
			Recursive:   true,
			Category:    "cron",
		},

		// ============================================================
		// WARNING: Browser Extensions
		// Used for credential theft
		// ============================================================
		{
			Path:        filepath.Join(home, "Library/Application Support/Google/Chrome/Default/Extensions"),
			Description: "Chrome extensions",
			Severity:    Warning,
			Recursive:   false,
			Category:    "browser",
		},
		{
			Path:        filepath.Join(home, "Library/Safari/Extensions"),
			Description: "Safari extensions",
			Severity:    Warning,
			Recursive:   false,
			Category:    "browser",
		},

		// ============================================================
		// WARNING: AI Agent Configurations
		// AI agent tool access - GTG-1002 attack vector
		// ============================================================
		{
			Path:        filepath.Join(home, ".config/claude"),
			Description: "Claude configuration (MCP servers)",
			Severity:    Warning,
			Recursive:   true,
			Category:    "ai_agents",
		},
		{
			Path:        filepath.Join(home, "Library/Application Support/Claude"),
			Description: "Claude app data",
			Severity:    Warning,
			Recursive:   false,
			Category:    "ai_agents",
		},
		{
			Path:        filepath.Join(home, ".cursor"),
			Description: "Cursor AI configuration",
			Severity:    Warning,
			Recursive:   true,
			Category:    "ai_agents",
		},

		// ============================================================
		// CRITICAL: Clawdbot/OpenClaw Agent Files
		// Agent personality, memory, and configuration
		// Compromise = agent exfiltrates data or behaves maliciously
		// ============================================================
		{
			Path:        filepath.Join(home, "clawd/SOUL.md"),
			Description: "Clawdbot agent personality - hijack = malicious behavior",
			Severity:    Critical,
			Recursive:   false,
			Category:    "ai_agents",
		},
		{
			Path:        filepath.Join(home, "clawd/AGENTS.md"),
			Description: "Clawdbot workspace rules - injection = behavior change",
			Severity:    Critical,
			Recursive:   false,
			Category:    "ai_agents",
		},
		{
			Path:        filepath.Join(home, ".config/clawdbot/config.yaml"),
			Description: "Clawdbot config (API keys, secrets)",
			Severity:    Critical,
			Recursive:   false,
			Category:    "ai_agents",
		},
		{
			Path:        filepath.Join(home, "clawd/skills"),
			Description: "Clawdbot custom skills - malicious skill injection",
			Severity:    Critical,
			Recursive:   false, // Top-level to detect new skills
			Category:    "ai_agents",
		},
		{
			Path:        filepath.Join(home, "clawd/HEARTBEAT.md"),
			Description: "Clawdbot heartbeat instructions",
			Severity:    Warning,
			Recursive:   false,
			Category:    "ai_agents",
		},
		{
			Path:        filepath.Join(home, "clawd/MEMORY.md"),
			Description: "Clawdbot long-term memory",
			Severity:    Warning,
			Recursive:   false,
			Category:    "ai_agents",
		},
		{
			Path:        filepath.Join(home, "clawd/USER.md"),
			Description: "Clawdbot user profile (PII)",
			Severity:    Warning,
			Recursive:   false,
			Category:    "ai_agents",
		},
		{
			Path:        filepath.Join(home, "clawd/IDENTITY.md"),
			Description: "Clawdbot agent identity",
			Severity:    Warning,
			Recursive:   false,
			Category:    "ai_agents",
		},
		{
			Path:        "/opt/homebrew/lib/node_modules/clawdbot",
			Description: "Clawdbot core installation",
			Severity:    Warning,
			Recursive:   false, // Top-level to detect tampering
			Category:    "ai_agents",
		},

		// ============================================================
		// INFO: System Configuration
		// General system config changes
		// ============================================================
		{
			Path:        "/etc/hosts",
			Description: "DNS hosts file",
			Severity:    Warning,
			Recursive:   false,
			Category:    "network",
		},
		{
			Path:        "/etc/resolv.conf",
			Description: "DNS resolver configuration",
			Severity:    Warning,
			Recursive:   false,
			Category:    "network",
		},
		{
			Path:        "/Library/Preferences",
			Description: "System preferences",
			Severity:    Info,
			Recursive:   false,
			Category:    "system_config",
		},

		// ============================================================
		// CRITICAL: Kernel Extensions
		// Rootkit territory
		// ============================================================
		{
			Path:        "/Library/Extensions",
			Description: "Third-party kernel extensions",
			Severity:    Critical,
			Recursive:   true,
			Category:    "kernel",
		},
		{
			Path:        "/System/Library/Extensions",
			Description: "System kernel extensions",
			Severity:    Critical,
			Recursive:   true,
			Category:    "kernel",
		},

		// ============================================================
		// CRITICAL: Application Bundles (selected)
		// ============================================================
		{
			Path:        "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
			Description: "Terminal.app binary",
			Severity:    Critical,
			Recursive:   false,
			Category:    "apps",
		},
	}
}

// GetIndicatorsByCategory returns indicators filtered by category
func GetIndicatorsByCategory(category string) []Indicator {
	var result []Indicator
	for _, ind := range DefaultIndicators() {
		if ind.Category == category {
			result = append(result, ind)
		}
	}
	return result
}

// GetCriticalIndicators returns only critical severity indicators
func GetCriticalIndicators() []Indicator {
	var result []Indicator
	for _, ind := range DefaultIndicators() {
		if ind.Severity == Critical {
			result = append(result, ind)
		}
	}
	return result
}

// MergeIndicators combines default indicators with custom ones
// Custom indicators override defaults if paths match
func MergeIndicators(defaults []Indicator, custom []CustomIndicator) []Indicator {
	result := make([]Indicator, len(defaults))
	copy(result, defaults)

	// Convert and append custom indicators
	for _, c := range custom {
		ind := c.ToIndicator()
		if ind.Path != "" {
			result = append(result, ind)
		}
	}

	return result
}

// Categories returns all unique categories
func Categories() []string {
	return []string{
		"system_binaries",
		"persistence",
		"privilege_escalation",
		"ssh",
		"shell_config",
		"package_managers",
		"npm",
		"git",
		"cron",
		"browser",
		"ai_agents",
		"network",
		"system_config",
		"kernel",
		"apps",
		"custom",
	}
}
