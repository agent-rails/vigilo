# Vigilo

Vigilo is an open-source host-monitoring tool, built with crypto infrastructure in mind. It watches paths you choose for file creates, writes, removes, and renames, samples process and network activity, and sends alerts when configured rules match. You can use it on other Linux and macOS hosts too.

Vigilo helps you investigate activity; it does not block attacks or guarantee detection. The default file watcher does not detect reads or identify which process changed a file. Process and network polling can miss brief activity. See [SECURITY.md](SECURITY.md) for coverage and deployment limits.

## Quick start (Linux with systemd)

### 1. Install

Download the archive for your Linux CPU from [Releases](https://github.com/agent-rails/vigilo/releases). For a typical 64-bit Intel/AMD host, extract and install it like this:

```bash
mkdir vigilo-v0.2.1
tar xzf vigilo_0.2.1_linux_amd64.tar.gz -C vigilo-v0.2.1
cd vigilo-v0.2.1
sudo bash deploy/install.sh
```

Use the `linux_arm64` archive for ARM64. The release archive includes the compiled daemon, so Go is not needed. The installer creates the service and example config but does not start Vigilo. Check the release's `checksums.txt` before installing.

### 2. Choose paths and configure an alert

Edit `/etc/vigilo/config.yaml`. Replace these example paths with absolute paths on your host that the `vigilo` service user can read:

```yaml
watch_paths:
  - /app/keystore
  - /app/.env
  - /run/secrets

alerter:
  min_severity: high
```

To receive Slack alerts, create an incoming webhook in Slack. Create or edit `/etc/vigilo/env` with `sudoedit` and add its URL:

```ini
VIGILO_SLACK_WEBHOOK_URL=<your Slack incoming webhook URL>
```

Then set the file's owner and permissions so only the service can read it:

```bash
sudo chown vigilo:vigilo /etc/vigilo/env
sudo chmod 600 /etc/vigilo/env
```

Telegram, email, and generic webhook alerts are also supported; their settings are in [`config.example.yaml`](config.example.yaml) and [SECURITY.md](SECURITY.md). Keep credentials in environment variables rather than committing them in config files.

### 3. Start and check Vigilo

```bash
sudo systemctl start vigilo
sudo systemctl status vigilo --no-pager
sudo journalctl -u vigilo -f
```

Vigilo starts monitoring when the service runs. Use the journal output to check startup and alert delivery. After changing configuration, apply it with `sudo systemctl restart vigilo`.

## What Vigilo watches

- **Files:** creates, writes, removes, and renames under configured paths. Newly created nested directories are watched too. Atomic file saves may generate a rename alert even when the file remains in the watched tree; see [issue #30](https://github.com/agent-rails/vigilo/issues/30).
- **Processes and network:** sampled host activity; very short-lived activity can be missed.
- **Project supply chain (optional):** scans configured npm and Terraform project roots for suspicious changes.
- **Multi-event patterns (optional):** an AI analyst can review event history through MCP. It requires separate API and client setup; the release archive contains the daemon only.

The default file watcher does not see file reads or identify the process responsible for a change. Linux audit-log collection is available separately and requires audit rules and permissions. See [SECURITY.md](SECURITY.md) for details.

## Other platforms and advanced setup

On macOS, download and extract the matching Darwin archive, then run `./vigilo -config ./config.yaml -db ./events.db` with a local copy of [`config.example.yaml`](config.example.yaml). The systemd installer is Linux-only.

For MCP clients, the web dashboard, multi-host monitoring, suppression rules, or source builds, see [`config.example.yaml`](config.example.yaml), [SECURITY.md](SECURITY.md), and [DESIGN.md](docs/DESIGN.md). Never expose Vigilo's MCP or dashboard ports directly to the public internet.
