# Vigilo

Vigilo is an open-source monitor for unexpected activity on Linux and macOS systems. It watches locations you choose for files being created, changed, removed, or renamed, and observes processes for suspicious activity. On Linux, optional audit rules can add short-lived execution events and identify which process accessed a watched file. Vigilo reports evidence to help you investigate; it does not block attacks or promise to catch every malicious action.

The default file watcher does not detect reads or identify which process changed a file. Process and network polling can miss brief activity. See [SECURITY.md](SECURITY.md) for coverage and deployment limits.

## Personal machine quick start (Linux and macOS)

For a personal machine, run Vigilo as the account whose files you want to monitor. The system-wide Linux service runs as the separate `vigilo` user and usually cannot read a private home directory. Granting it access is a deliberate permissions change; running as your login user avoids that extra access rule.

Download and extract the archive for your OS and CPU from [Releases](https://github.com/agent-rails/vigilo/releases). Run the personal installer as your login user (without `sudo`):

```bash
bash deploy/user/install.sh
```

The installer copies the binary, a personal config template, and a per-user startup service. Edit `~/.config/vigilo/config.yaml` before starting: remove any path that does not exist and add your source checkout (for example `~/src/job-assessment`) before running untrusted code there. Vigilo watches only configured paths; the file watcher reports changes but does not identify the writer. The template enables alerts for every observed file change and every process first seen by polling, so notifications can be frequent. Polling can miss short-lived processes.

To configure Slack notifications, add this line to `~/.config/vigilo/env` and replace the example URL:

```sh
VIGILO_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

The environment file is created with owner-only permissions. Other alert channels and settings are in [`config.example.yaml`](config.example.yaml). Start Vigilo in your user session:

```bash
# Linux with systemd --user
systemctl --user enable --now vigilo.service
journalctl --user -u vigilo -f

# macOS with launchd (run these instead of the Linux commands)
python3 deploy/macos/install-launch-agent.py --start
tail -f "$HOME/Library/Logs/Vigilo/stderr.log"
```

On Linux, `sudo loginctl enable-linger "$USER"` keeps the user service running after logout. The macOS installer keeps the LaunchAgent disabled until you run `--start`, then it starts now and at login. Stop it with `systemctl --user disable --now vigilo.service` on Linux or run the LaunchAgent installer with `--uninstall` on macOS. Linux auditd can add event-driven process and file attribution when matching host rules are installed; macOS currently uses polling for processes. See [personal monitoring coverage](docs/PERSONAL_MONITORING.md).

## System-wide Linux service

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

Edit `/etc/vigilo/config.yaml`. Replace these example paths with absolute paths on your host that the `vigilo` service user can read. This service account has no home directory and cannot automatically read files in a personal account's private home:

```yaml
watch_paths:
  - /app/keystore
  - /app/.env
  - /run/secrets

alerter:
  min_severity: high
  # Optional: alert on all creates/writes/removes/renames in watched paths.
  # This can be noisy for active project or cache directories.
  min_severity_by_source:
    file_access: info
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

Process collection is controlled by `process_monitor.enabled` and `process_monitor.report_new_processes`; alert thresholds under `alerter.min_severity_by_source` only control which collected events are delivered. Reporting every first-seen process is noisy, and polling can miss programs that start and exit between scans. A short list of OS-like names running outside standard system directories gets a high-severity triage alert; that path heuristic is not proof of malware. The default file watcher does not see file reads or identify the process responsible for a change. On Linux, optional audit rules can report matching executions, including short-lived processes, and attribute watched-file activity; rules must be configured for the paths and event types you want. See [personal monitoring coverage](docs/PERSONAL_MONITORING.md) for tested scope and platform limits, and [SECURITY.md](SECURITY.md) for deployment details.

## Other platforms and advanced setup

On macOS, download and extract the matching Darwin archive, then run Vigilo as your login user with the personal configuration above. The systemd installer is Linux-only.

For MCP clients, the web dashboard, multi-host monitoring, suppression rules, or source builds, see [`config.example.yaml`](config.example.yaml), [SECURITY.md](SECURITY.md), and [DESIGN.md](docs/DESIGN.md). Never expose Vigilo's MCP or dashboard ports directly to the public internet.
