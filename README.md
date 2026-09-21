# Vigilo

> *Latin: "I watch. I am vigilant."*

OS-level security daemon for crypto infrastructure. Monitors file access, process spawns, and network connections in real time — alerts your team **before an attacker reaches the chain**.

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

| Tier | Latency | Mechanism | Triggers on |
|---|---|---|---|
| **Immediate** | ~1 second | Daemon pushes directly | Any `high` / `critical` event |
| **LLM analysis** | ~5 minutes | Claude correlates event sequences | Attack patterns, cross-server campaigns |

This means a private key access fires a Telegram push **within seconds**, while Claude still analyses the full pattern window to catch multi-step attacks.

---

## What it detects

| Signal | Tier | Severity |
|---|---|---|
| Private key / keystore file read | Immediate + LLM | Critical |
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

### 1. Build the daemon

```bash
git clone https://github.com/voltagebots/vigilo && cd vigilo
go build -o /usr/local/bin/vigilo ./cmd/vigilo/
```

### 2. Configure

```bash
cp config.example.yaml /etc/vigilo/config.yaml
mkdir -p /var/lib/vigilo
```

Minimum config — edit `/etc/vigilo/config.yaml`:

```yaml
watch_paths:
  - /app/keystore
  - /app/.env
  - /run/secrets

alerter:
  min_severity: high
  telegram:
    bot_token: "YOUR_BOT_TOKEN"
    chat_id: "-100YOUR_CHAT_ID"
  slack:
    webhook_url: https://hooks.slack.com/services/...
```

### 3. Run as a systemd service

```ini
# /etc/systemd/system/vigilo.service
[Unit]
Description=Vigilo Security Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/vigilo -config /etc/vigilo/config.yaml -db /var/lib/vigilo/events.db
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now vigilo
journalctl -u vigilo -f
```

### 4. Run the LLM analyst agent (optional but recommended)

The agent connects to the daemon via MCP and runs Claude to detect multi-step attack patterns.

```bash
cd agent
cp .env.example .env
# Fill in: ANTHROPIC_API_KEY, SLACK_BOT_TOKEN, VIGILO_ALERT_CHANNEL
npm install && npm run dev
```

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
    reason: "nightly backup reads credential dirs"
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
