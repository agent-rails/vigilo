# Security Policy

## Security Model

### What Vigilo protects against

Vigilo is an **observation and alerting** daemon. It watches OS-level signals and alerts on suspicious activity:

- Unauthorized reads of private keys, keystores, and secret files
- Shells spawned from application processes (RCE indicator)
- Outbound connections to unexpected destinations (exfiltration indicator)
- Supply-chain attacks via package install from running processes
- Privilege escalation (sudo from application processes)
- Multi-step attack chains across time (via LLM correlation)

### What Vigilo cannot protect against

Vigilo is not a prevention system. It does **not**:

- Block filesystem access or network connections
- Prevent privilege escalation
- Stop an attack in progress
- Protect against a compromised kernel (rootkit)
- Guarantee detection if an attacker kills the vigilo process before alerting

Vigilo raises the cost of attacks and shortens your detection window. It is one layer in a defence-in-depth strategy, not a complete solution.

---

## Recommended Deployment

### Network binding

**Never expose vigilo ports on the public internet.**

- MCP server (`127.0.0.1:7070`): always bind to loopback or a Tailscale/WireGuard interface, and set `mcp_token`.
- Web dashboard (e.g. `:7080`): always bind to `127.0.0.1`. Enable `VIGILO_WEB_TOKEN` auth.
- Use Tailscale for remote access instead of opening firewall ports.

Recommended config:

```yaml
web_addr: "127.0.0.1:7080"
mcp_transport: http
mcp_addr: "127.0.0.1:7070"
```

### systemd hardening

Run vigilo as a dedicated low-privilege user. The included `deploy/vigilo.service` sets:

```ini
[Service]
User=vigilo
Group=vigilo
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
NoNewPrivileges=true
CapabilityBoundingSet=
RestrictSUIDSGID=true
```

Create the user before installing:

```bash
useradd --system --no-create-home --shell /sbin/nologin vigilo
chown vigilo:vigilo /var/lib/vigilo
```

---

## Secret Management

### Rules

1. **Never commit `config.yaml` with real tokens or passwords.** The file often ends up in version control or container images.
2. **Never hardcode secrets in `docker-compose.yml` environment blocks.** Use `env_file` pointing to a file excluded by `.gitignore`.
3. **Always use environment variables** for secrets — they are overridden from the environment at startup.

### Supported environment variables

| Variable | Overrides |
|---|---|
| `VIGILO_TELEGRAM_BOT_TOKEN` | `alerter.telegram.bot_token` |
| `VIGILO_TELEGRAM_CHAT_ID` | `alerter.telegram.chat_id` |
| `VIGILO_SLACK_WEBHOOK_URL` | `alerter.slack.webhook_url` |
| `VIGILO_SMTP_PASSWORD` | `alerter.email.password` |
| `VIGILO_WEB_TOKEN` | `web_token` (web dashboard auth) |
| `VIGILO_MCP_TOKEN` | `mcp_token` (MCP HTTP transport auth) |

Set these in `/etc/vigilo/env` (mode 0600, owned by `vigilo`) and reference in the service unit:

```ini
EnvironmentFile=/etc/vigilo/env
```

---

## Threat Model

### Trust boundaries

```
[ OS kernel / collector ] --> [ event bus (chan) ] --> [ SQLite (local file) ]
                                                              |
                              [ MCP server ] <---------------+
                                    |
                              [ Agent / Claude ] (remote or local)
```

- **SQLite file**: local only, mode 0600. Vigilo user reads/writes. No network exposure.
- **MCP server**: stdio (no network) or HTTP. Over HTTP, a Bearer token is required (`VIGILO_MCP_TOKEN` / `mcp_token`), compared in constant time and accepted only in the `Authorization` header, never a query parameter. Requests carrying an `Origin` header are refused outright, because the SSE library sets `Access-Control-Allow-Origin: *` and browsers are never legitimate MCP clients. The daemon refuses to start on `mcp_transport: http` without a token unless `mcp_allow_unauthenticated: true` is set, which logs a warning at startup. Bind to loopback.
- **Web dashboard**: token auth via `VIGILO_WEB_TOKEN`. Rate-limited (60 req/min/IP). Bind to loopback only.
- **Alert channels**: outbound only (Slack webhook, Telegram API, SMTP). Credentials stored in env vars.

### STRIDE summary

| Threat | Mitigation |
|---|---|
| Spoofing web dashboard | Bearer token auth (`VIGILO_WEB_TOKEN`), bind to loopback |
| Spoofing MCP HTTP client | Bearer token auth (`VIGILO_MCP_TOKEN`), `Origin` rejection, bind to loopback |
| Tampering with event store | SQLite WAL mode, file permissions (0600), ProtectSystem=strict |
| Repudiation | Structured JSON logs via slog; all web requests access-logged |
| Information disclosure | MCP stdio relies on process isolation; MCP HTTP and the web dashboard both require a Bearer token |
| Denial of service (web) | Rate limiting 60 req/min/IP; graceful shutdown on SIGTERM |
| Elevation of privilege | `NoNewPrivileges=true`, dedicated vigilo user, no capabilities |

---

## Reporting Vulnerabilities

Please report security issues privately. Do **not** open a public GitHub issue.

Email: security@voltagebots.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations

We aim to respond within 48 hours and to release a fix within 14 days of confirmation.
