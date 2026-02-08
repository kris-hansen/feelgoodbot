# FeelGoodBot 🛡️
## Pronounced "Feel good, bot"

**Malware Detection + TOTP Step-Up Auth for macOS** — Know when you've been compromised, and control what your AI can do.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Philosophy

Traditional antivirus tries to *prevent* malware. **feelgoodbot** focuses on *detection* — continuously monitoring your system for signs of compromise and alerting you immediately when something changes.

The reality: determined attackers might get in. The question is how fast you detect it, and what will you do about it.

## Features

1. **File Integrity Monitoring** — Detect tampering of critical system files
2. **TOTP Step-Up Authentication** — Require OTP codes for sensitive AI agent actions

## How It Works

1. **Snapshot** — Capture cryptographic signatures of critical system files
2. **Monitor** — Continuously watch for unauthorized changes  
3. **Detect** — Identify tampering using signature comparison
4. **Alert** — Notify via Clawdbot, webhook, or local notification
5. **Respond** — Configurable actions (alert only, disconnect network, shutdown)

## Key File Indicators (KFIs)

feelgoodbot monitors critical macOS locations:

- `/System/Library/` — System frameworks and binaries
- `/usr/bin/`, `/usr/sbin/` — Core utilities
- `/Library/LaunchDaemons/`, `/Library/LaunchAgents/` — Persistence mechanisms
- `~/Library/LaunchAgents/` — User-level persistence
- `/etc/` — System configuration
- Browser extensions and plugins
- SSH authorized_keys
- Sudoers and PAM modules

### AI Agent Protection 🤖

feelgoodbot protects AI agents from compromise:

| Path | Threat | Severity |
|------|--------|----------|
| `~/clawd/SOUL.md` | Agent personality hijack | **CRITICAL** |
| `~/clawd/AGENTS.md` | Instruction injection | **CRITICAL** |
| `~/.config/clawdbot/config.yaml` | API key theft | **CRITICAL** |
| `~/clawd/skills/` | Malicious skill injection | **CRITICAL** |
| `~/clawd/MEMORY.md` | Memory poisoning | WARNING |
| `~/.config/claude/` | MCP server tampering | WARNING |
| `~/.cursor/` | Cursor AI config | WARNING |

**Why this matters:** A compromised AI agent could exfiltrate sensitive data, execute malicious commands, or manipulate its own behavior to serve an attacker.

## Installation

```bash
# Install via Homebrew (coming soon)
brew install kris-hansen/tap/feelgoodbot

# Or build from source
go install github.com/kris-hansen/feelgoodbot/cmd/feelgoodbot@latest
```

## Quick Start

```bash
# Initialize — creates baseline snapshot
feelgoodbot init

# Run a scan
feelgoodbot scan

# Start the daemon
feelgoodbot daemon start

# Check status
feelgoodbot status
```

## Configuration

```yaml
# ~/.config/feelgoodbot/config.yaml

# What to monitor
indicators:
  system_binaries: true
  launch_agents: true
  launch_daemons: true
  browser_extensions: true
  ssh_keys: true
  etc_files: true
  custom_paths:
    - /opt/homebrew/bin
  
  # Custom indicators with full options
  custom:
    - path: ~/my-project/config.yaml
      description: My project config
      severity: critical
      recursive: false
      category: custom
    
    - path: ~/my-agent/workspace
      description: Agent workspace files
      severity: warning
      recursive: true
      category: ai_agents

# Scan frequency (daemon mode)
scan_interval: 5m

# Alert configuration  
alerts:
  clawdbot:
    enabled: true
    webhook: "http://127.0.0.1:18789/hooks/wake"
    secret: "your-clawdbot-hooks-token"
  
  slack:
    enabled: false
    webhook_url: ""
  
  local_notification: true

# Response actions
response:
  # What to do when tampering is detected
  on_critical:
    - alert
    - disconnect_network  # Disable Wi-Fi and Ethernet
    - shutdown            # Power off immediately
  
  on_warning:
    - alert
  
  on_info:
    - log
```

## Custom Indicators

Define custom paths to monitor with full control over severity and behavior:

```yaml
# ~/.config/feelgoodbot/config.yaml
indicators:
  custom:
    # Monitor a specific file
    - path: ~/my-secrets/vault.db
      description: Secret vault database
      severity: critical    # critical, warning, or info
      recursive: false
      category: custom
    
    # Monitor a directory (top-level only)
    - path: ~/my-agent/plugins
      description: Agent plugins directory
      severity: critical
      recursive: false      # Only alert on new top-level files
      category: ai_agents
    
    # Monitor a directory recursively
    - path: ~/sensitive-data
      description: Sensitive data folder
      severity: warning
      recursive: true       # Scan all subdirectories
      category: custom
```

### Custom Indicator Options

| Option | Type | Description |
|--------|------|-------------|
| `path` | string | Path to monitor. Supports `~` for home directory. |
| `description` | string | Human-readable description for alerts. |
| `severity` | string | `critical`, `warning`, or `info` |
| `recursive` | bool | If true, scan subdirectories. If false, only top-level. |
| `category` | string | Category for grouping (e.g., `ai_agents`, `custom`) |

## TOTP Step-Up Authentication 🔐

Require OTP verification before your AI agent can perform sensitive actions like sending emails, making payments, or deleting files.

### Setup

```bash
# Initialize TOTP (displays QR code for Google Authenticator)
feelgoodbot totp init --account "you@feelgoodbot"

# Verify it works
feelgoodbot totp verify

# Check status
feelgoodbot totp status
```

### Configure Protected Actions

```bash
# Add actions that require step-up
feelgoodbot totp actions add "send_email"
feelgoodbot totp actions add "payment:*"      # Wildcard: any payment action
feelgoodbot totp actions add "delete:*"
feelgoodbot totp actions add "ssh:*"
feelgoodbot totp actions add "gateway:*"      # Clawdbot config changes
feelgoodbot totp actions add "voice_call:*"
feelgoodbot totp actions add "publish:*"

# List protected actions
feelgoodbot totp actions list
```

### How It Works

1. AI agent attempts a sensitive action (e.g., `send_email`)
2. Agent calls `feelgoodbot totp check send_email`
3. If no valid session, user is prompted for OTP via Telegram/CLI
4. User enters 6-digit code from Google Authenticator
5. Session created (15 min cache) and action proceeds

### TOTP Commands

| Command | Description |
|---------|-------------|
| `feelgoodbot totp init` | Set up TOTP with QR code |
| `feelgoodbot totp verify [code]` | Test a code |
| `feelgoodbot totp status` | Show TOTP status and session |
| `feelgoodbot totp check <action>` | Check if action needs step-up |
| `feelgoodbot totp reset` | Remove TOTP config |
| `feelgoodbot totp backup show` | Show remaining backup codes |
| `feelgoodbot totp backup regenerate` | Generate new backup codes |
| `feelgoodbot totp actions list` | List protected actions |
| `feelgoodbot totp actions add <action>` | Add protected action |
| `feelgoodbot totp actions remove <action>` | Remove protected action |

### Security Model

- **CLI-only setup/reset** — Requires physical/SSH access
- **Telegram prompts** — Convenient for daily use
- **15-minute sessions** — Balance security and usability
- **Backup codes** — Recovery if phone is lost
- **Self-protecting config** — Modifying step-up config requires step-up

## Commands

| Command | Description |
|---------|-------------|
| `feelgoodbot init` | Create initial baseline snapshot |
| `feelgoodbot scan` | Run one-time integrity scan |
| `feelgoodbot snapshot` | Update baseline snapshot |
| `feelgoodbot diff` | Show changes since last snapshot |
| `feelgoodbot daemon start` | Start background monitoring |
| `feelgoodbot daemon stop` | Stop daemon |
| `feelgoodbot status` | Show daemon status and last scan |
| `feelgoodbot config` | Show/edit configuration |
| `feelgoodbot indicators list` | List monitored paths |
| `feelgoodbot indicators add <path>` | Add custom path |
| `feelgoodbot totp *` | TOTP step-up auth (see above) |

## Clawdbot Integration

feelgoodbot can alert Clawdbot when tampering is detected. Works locally or remotely.

### Clawdbot Setup

Enable webhook ingress in your Clawdbot config (`~/.clawdbot/clawdbot.json`):

```json
{
  "hooks": {
    "enabled": true,
    "token": "your-shared-secret",
    "path": "/hooks"
  }
}
```

### feelgoodbot Configuration

```yaml
# ~/.config/feelgoodbot/config.yaml
alerts:
  clawdbot:
    enabled: true
    webhook: "http://127.0.0.1:18789/hooks/wake"  # Local Clawdbot
    secret: "your-shared-secret"                   # Matches hooks.token
```

For remote Clawdbot, change the webhook URL to your server's address.

### Webhook Payload

feelgoodbot uses Clawdbot's `/hooks/wake` endpoint:

```json
{
  "text": "🚨 **CRITICAL: 3 file(s) tampered on macbook.local!**\n\n🔴 `/Library/LaunchDaemons/malware.plist` (added, persistence)\n...",
  "mode": "now"
}
```

### Headers

- `Content-Type: application/json`
- `x-clawdbot-token: <secret>` (auth token)

### What Happens

When an alert fires, Clawdbot:
1. Receives the webhook and triggers an immediate heartbeat
2. The agent sees the alert and notifies you on your active channel
3. Can investigate and take follow-up actions

## Severity Levels

| Level | Description | Examples |
|-------|-------------|----------|
| **CRITICAL** | Active compromise likely | System binary modified, new launch daemon |
| **WARNING** | Suspicious change | New browser extension, SSH key added |
| **INFO** | Notable but expected | Config file updated, new app installed |

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     feelgoodbot                         │
├─────────────────────────────────────────────────────────┤
│  CLI (cobra)                                            │
│    ├── init, scan, snapshot, diff                       │
│    ├── daemon start/stop/status                         │
│    └── config, indicators                               │
├─────────────────────────────────────────────────────────┤
│  Scanner                                                │
│    ├── File hasher (SHA-256)                           │
│    ├── Permission checker                               │
│    ├── Signature validator (codesign)                   │
│    └── Diff engine                                      │
├─────────────────────────────────────────────────────────┤
│  Snapshot Store                                         │
│    ├── Baseline snapshots (SQLite)                      │
│    ├── Historical diffs                                 │
│    └── Tamper-resistant storage                         │
├─────────────────────────────────────────────────────────┤
│  Daemon                                                 │
│    ├── launchd integration                              │
│    ├── Scheduled scans                                  │
│    └── fsnotify real-time watching                      │
├─────────────────────────────────────────────────────────┤
│  Alerts                                                 │
│    ├── Clawdbot webhook                                 │
│    ├── macOS notifications                              │
│    ├── Slack/Discord webhooks                           │
│    └── Response actions (disconnect, shutdown)          │
└─────────────────────────────────────────────────────────┘
```

## Security Considerations

- Snapshot database is integrity-protected
- Daemon runs with minimal privileges (escalates only when needed)
- Alert webhooks use HMAC signing
- Config file permissions enforced (0600)

## License

MIT — Use it, fork it, improve it.

---

**feelgoodbot.com** — Sleep better knowing you'll know.
