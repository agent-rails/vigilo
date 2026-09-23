# Vigilo

> *Latin: "I watch. I am vigilant."*

OS-level observation and alerting for crypto infrastructure. Vigilo collects filesystem create/write events, polls process and network activity, and can scan npm and Terraform configuration for suspicious changes. Rule-based alerts run in the daemon; an optional LLM analyst queries its event history through MCP.

Vigilo does not block attacks or guarantee detection. The default file watcher does **not** detect file reads or identify the process responsible for a change. Linux audit-log ingestion is a separate, opt-in collector that requires configured audit rules and permission to read the log. See [SECURITY.md](SECURITY.md) for coverage limits.

```
┌──────────────────────────────────────────────────────────────┐
│  Monitored server (validator / signer / bridge node)         │
│                                                              │
│  File watcher ─┐                                             │
│  Proc poller  ─┼─► Event bus ─► SQLite buffer               │
│  Net poller   ─┘       │              │                      │
│                        │              └─► MCP server (:7070) │
│                        ▼                       ▲             │
│              Immediate alerter           LLM analyst agent   │
│         (Slack · Telegram · Email)       (Claude, every 5m)  │
└──────────────────────────────────────────────────────────────┘
```

## Two-tier alerting

| Tier | Timing | Mechanism | Triggers on |
|---|---|---|---|
| **Immediate** | On a collected event; delivery depends on the channel | Daemon pushes directly | Events meeting the configured severity threshold and cooldown |
| **LLM analysis** | Every 5 minutes by default | Claude queries and analyses event sequences | Candidate patterns across the configured hosts |

Collection and immediate alerting continue if the MCP transport closes. `/healthz` reports `mcp_transport_up` separately from daemon health. Process and network collectors sample state, so activity shorter than the polling interval can be missed. LLM conclusions require investigation; they are not proof of compromise.

---

## What it detects

| Signal | Tier | Severity |
|---|---|---|
| Private key / keystore file created or written | Immediate + LLM | Critical |
| `.env` or secret file written | Immediate + LLM | High |
| Shell spawned from node/python (RCE) | LLM | High |
| Outbound connection to suspicious port | Immediate + LLM | High |
| Env dump → outbound connection (exfiltration chain) | LLM | Critical |
| Package install from app process (supply chain) | LLM | High |
| Privilege escalation (sudo from app process) | LLM | High |
| Same attack pattern across multiple servers | LLM | Critical |

---

## Architecture

```
vigilo (Go daemon)              vigilo-agent (TypeScript)
├── collector/                  ├── collectors/mcp.ts
│   ├── file.go  (fsnotify)     │    multi-daemon aggregation
│   ├── process.go (/proc)      ├── agents/analyst.ts
│   ├── network.go (/proc/net)  │    ├── context compaction
│   └── suppress.go             │    ├── MOIM preamble
├── buffer/sqlite.go            │    └── inspector + retry
│   └── signal_dedup table      └── slack/alerter.ts
├── alerter/
│   ├── slack.go   (webhook)
│   ├── telegram.go (Bot API)
│   ├── email.go   (SMTP)
│   └── webhook.go (generic)
└── mcp/server.go   (6 tools)
```

---

## Quick start

### 1. Install the daemon

Download the archive for your OS and CPU from [Releases](https://github.com/agent-rails/vigilo/releases). On Linux with systemd, for example:

```bash
tar xzf vigilo_0.2.0_linux_amd64.tar.gz
sudo bash deploy/install.sh
```

The archive contains the compiled daemon; Go is not required. The installer preserves existing configuration and enables the service without starting or restarting it. Verify the archive against the release's `checksums.txt` before installation. For ARM64 use the `linux_arm64` archive.

For a source install, Go 1.25+ is required:

```bash
git clone https://github.com/agent-rails/vigilo && cd vigilo
sudo bash deploy/install.sh
```

### 2. Configure

```bash
sudoedit /etc/vigilo/config.yaml
```

Minimum config — edit `/etc/vigilo/config.yaml`:

```yaml
watch_paths:
  - /app/keystore
  - /app/.env
  - /run/secrets

mcp_transport: http
mcp_addr: "127.0.0.1:7070"

alerter:
  min_severity: high
  telegram:
    bot_token: "YOUR_BOT_TOKEN"
    chat_id: "-100YOUR_CHAT_ID"
  slack:
    webhook_url: https://hooks.slack.com/services/...
```

Use real absolute paths readable by the `vigilo` service user. Prefer watching a parent directory when applications replace files atomically. Put `VIGILO_MCP_TOKEN=<a generated token>` in `/etc/vigilo/env` (mode 0600); the MCP client must use the same token. Generate one with `openssl rand -hex 32`. Put alert credentials there too, using the variables listed below.

For collection without an MCP client, `mcp_transport: stdio` remains usable under systemd: stdin EOF is logged as transport unavailable and collection continues.

### 3. Run as a systemd service

The installer places the hardened unit at `/etc/systemd/system/vigilo.service`. After configuring paths and alerts:

```bash
sudo systemctl restart vigilo
sudo journalctl -u vigilo -f
```

On macOS, extract the matching Darwin archive, edit a local copy of `config.example.yaml`, and run `./vigilo -config ./config.yaml -db ./events.db`. The systemd installer is Linux-only.

### 4. Run the LLM analyst agent (optional but recommended)

The agent connects to the daemon via MCP and runs Claude to detect multi-step attack patterns.

```bash
cd agent
cp .env.example .env
# Fill in: ANTHROPIC_API_KEY, SLACK_BOT_TOKEN, VIGILO_ALERT_CHANNEL
npm ci && npm run dev
```

The release archives contain the daemon only. Get `agent/` from a source checkout. For a separately running service set `VIGILO_MCP_URL=http://127.0.0.1:7070` and the matching `VIGILO_MCP_TOKEN` in `agent/.env`.

### 5. Multi-server setup (Tailscale)

```bash
# On each monitored server, in config.yaml:
#   mcp_transport: http
#   mcp_addr: "100.64.0.1:7070"   # the address the agent dials, not 127.0.0.1
#   mcp_token: ...                # or export VIGILO_MCP_TOKEN for the daemon
#
# mcp_addr must be the interface the agent reaches. The default is loopback, so
# leaving it unset makes this topology unreachable.
# In agent/.env on your central host:
VIGILO_DAEMON_URLS=validator-1=http://100.64.0.1:7070,signer=http://100.64.0.2:7070
VIGILO_MCP_TOKEN=<the same token the daemons were given>
```

Every daemon behind `VIGILO_DAEMON_URLS` must accept the same token; the agent
sends one `Authorization: Bearer` header to all of them.

---

## MCP tools

The daemon exposes six tools to any MCP-compatible client:

| Tool | Description |
|---|---|
| `get_all_events` | All events in a time window |
| `get_file_access_events` | File watcher events only |
| `get_process_events` | Process spawn events only |
| `get_network_events` | Outbound connection events only |
| `get_critical_events` | High + critical severity — rapid triage |
| `get_events_ecs` | Events in Elastic Common Schema format |

---

## Alert channels

Configured under `alerter:` in `config.yaml`:

| Channel | Notes |
|---|---|
| **Slack** | Incoming webhook URL — no bot token needed |
| **Telegram** | Bot token (BotFather) + group/chat ID — best for mobile push |
| **Email** | SMTP — Gmail, SendGrid, AWS SES, Mailgun |
| **Webhook** | Generic JSON POST — PagerDuty, OpsGenie, custom SIEM |

---

## Suppression rules

Drop known-safe events before they reach the buffer:

```yaml
suppress_rules:
  - match: /var/backups/
    source: file_access
    reason: "known backup output writes"
  - match: datadog-agent
    source: process
    reason: "observability agent — known safe"
```

---

## Agent environment variables

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | required | Claude API key |
| `SLACK_BOT_TOKEN` | required | Slack bot token |
| `VIGILO_ALERT_CHANNEL` | required | Slack channel ID |
| `VIGILO_DAEMON_URLS` | — | Multi-server: `label=url,label=url,...` |
| `VIGILO_MCP_URL` | — | Single remote daemon URL |
| `VIGILO_MCP_TOKEN` | — | Bearer token for the daemon's MCP HTTP transport |
| `VIGILO_DAEMON_BIN` | `vigilo` | Binary path (stdio mode) |
| `SCAN_CRON` | `*/5 * * * *` | LLM scan schedule |
| `LOOKBACK_MINUTES` | `6` | Event window per scan |
| `SIGNAL_COOLDOWN_MS` | `3600000` | Agent-side dedup window (1 hour) |

---

## Security

### Web dashboard authentication

Set `VIGILO_WEB_TOKEN` (env var) or `web_token` in `config.yaml`. When set, every request to the dashboard requires `Authorization: Bearer <token>` or `?token=<token>`. Without a token configured there is no auth — do not expose the port publicly.

### MCP HTTP authentication

Set `VIGILO_MCP_TOKEN` (env var) or `mcp_token` in `config.yaml`. With `mcp_transport: http` the daemon refuses to start unless one is set, or `mcp_allow_unauthenticated: true` states the risk explicitly. Every request then requires `Authorization: Bearer <token>`, with the scheme matched case-insensitively per RFC 7235. There is deliberately no `?token=` form here, because a token in a URL reaches browser history, proxy logs and `Referer` headers; every MCP client can send a header.

Requests carrying an `Origin` header are rejected with 403 regardless of the token. MCP clients are not browsers, and the SSE library sets `Access-Control-Allow-Origin: *`, so without this a web page you visit could read the event stream. This is not by itself DNS-rebinding protection — a rebound request is same-origin and sends no `Origin` — which is why the token matters even on loopback.

Under `mcp_allow_unauthenticated: true` there is no auth and the daemon logs a warning at startup. The MCP tools return watched file paths, process lineage and command lines, so an unauthenticated listener answers "where are the secrets on this host".

### Network binding — never expose ports publicly

Always bind to `127.0.0.1`, never `0.0.0.0`:

```yaml
web_addr: "127.0.0.1:7080"
mcp_addr: "127.0.0.1:7070"
```

Use Tailscale or WireGuard for remote access. Opening vigilo ports to the public internet is unsupported and unsafe.

### Secrets via environment variables — not config.yaml

Set alert credentials via env vars so they never appear in config files or container images:

```bash
export VIGILO_TELEGRAM_BOT_TOKEN=...
export VIGILO_SLACK_WEBHOOK_URL=https://hooks.slack.com/...
export VIGILO_SMTP_PASSWORD=...
export VIGILO_WEB_TOKEN=$(openssl rand -hex 32)
```

### systemd hardening — dedicated vigilo user

The included `deploy/vigilo.service` runs vigilo as a dedicated system user with `ProtectSystem=strict`, `NoNewPrivileges=true`, and no capabilities. See [SECURITY.md](SECURITY.md) for the full threat model and deployment guide.

---

## What's done

- [x] File watcher (fsnotify, macOS + Linux)
- [x] Process watcher (Linux `/proc` polling)
- [x] Network watcher (Linux `/proc/net/tcp`)
- [x] `auditd` collector — tails audit log, kernel-level syscall events (opt-in)
- [x] SQLite event buffer with hourly auto-prune
- [x] Signal dedup — daemon-side (alerter cooldown) + agent-side (in-process cache)
- [x] Suppression rules — all three collectors (file, process, network)
- [x] MCP server — stdio and SSE/HTTP transports
- [x] MCP tool `get_events_ecs` — Elastic Common Schema output for SIEM pipelines
- [x] Web dashboard — event timeline, severity stats, live polling (`web_addr` config)
- [x] Immediate alerter — Slack webhook, Telegram Bot, SMTP email, generic webhook
- [x] LLM analyst agent (Claude Opus) — multi-step pattern detection
- [x] Multi-daemon aggregation (N servers → one Claude call)
- [x] Goose patterns: context compaction, MOIM preamble, inspector + retry
- [x] CI (GitHub Actions — Go build/test + TypeScript typecheck)
- [x] Dockerfile — daemon (alpine) + agent (node:22-alpine)
- [x] Docker Compose — daemon + agent, single `docker compose up`
- [x] systemd unit (`deploy/vigilo.service`) + `deploy/install.sh`
- [x] macOS watchers — process via `ps`, network via `netstat` (build-tagged)
