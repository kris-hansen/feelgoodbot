# feelgoodbot 🛡️

**Malware Detection for macOS** — Know when you've been compromised.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Philosophy

Traditional antivirus tries to *prevent* malware. **feelgoodbot** focuses on *detection* — continuously monitoring your system for signs of compromise and alerting you immediately when something changes.

The reality: determined attackers might get in. The question is how fast you detect it, and what will you do about it.

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

# Scan frequency (daemon mode)
scan_interval: 5m

# Alert configuration  
alerts:
  clawdbot:
    enabled: true
    webhook: "http://127.0.0.1:18789/hooks/agent"
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
    webhook: "http://127.0.0.1:18789/hooks/agent"  # Local Clawdbot
    secret: "your-shared-secret"                    # Matches hooks.token
```

For remote Clawdbot, change the webhook URL to your server's address.

### Webhook Payload

feelgoodbot uses Clawdbot's `/hooks/agent` endpoint:

```json
{
  "message": "🚨 **CRITICAL: 3 file(s) tampered on macbook.local!**\n\n🔴 `/Library/LaunchDaemons/malware.plist` (added, persistence)\n...",
  "name": "feelgoodbot",
  "deliver": true,
  "channel": "last"
}
```

### Headers

- `Content-Type: application/json`
- `x-clawdbot-token: <secret>` (auth token)

### What Happens

When an alert fires, Clawdbot/Openclaw:
1. Receives the webhook and runs an isolated agent session
2. Sends you a message on your last active channel (Telegram, Signal, etc.)
3. Can execute follow-up actions based on the alert

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

## Roadmap

- [ ] v0.1 — Core CLI, snapshot, scan, diff
- [ ] v0.2 — Daemon mode with launchd
- [ ] v0.3 — Clawdbot integration
- [ ] v0.4 — Response actions (network disconnect, shutdown)
- [ ] v0.5 — Real-time fsnotify monitoring
- [ ] v1.0 — Production ready, Homebrew tap

## License

MIT — Use it, fork it, improve it.

---

**feelgoodbot.com** — Sleep better knowing you'll know.
