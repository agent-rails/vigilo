# Vigilo

Vigilo is an open-source monitor for unexpected activity on personal Linux and macOS systems. It reports file changes under paths you choose and observes process activity to help you investigate things that happen while running unfamiliar software. Optional Linux audit rules can add short-lived execution events and identify which process accessed a watched file.

Vigilo reports evidence; it does not block activity or determine that something is malicious. The default file watcher does not see reads or identify which process changed a file. Process polling can miss brief activity. See [monitoring coverage](docs/PERSONAL_MONITORING.md) and [security limits](SECURITY.md).

## Quick start for a personal machine

Download and extract the archive for your operating system and CPU from [Releases](https://github.com/agent-rails/vigilo/releases). The archive includes the Vigilo binary, so you do not need Go. From the extracted directory, run the installer as your login user (no `sudo`):

```bash
bash deploy/user/install.sh
```

Before running unfamiliar code, edit `~/.config/vigilo/config.yaml`: remove example paths that do not exist and add the project or other locations you want Vigilo to watch. Vigilo only monitors configured paths. The template reports each observed file change and each process first seen by polling, so alerts may be frequent.

To receive Slack alerts, put your webhook URL in `~/.config/vigilo/env`:

```sh
VIGILO_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

Start Vigilo in your user session:

```bash
# Linux with systemd --user
systemctl --user enable --now vigilo.service

# macOS with launchd (use instead of the Linux command)
python3 deploy/macos/install-launch-agent.py --start
```

On Linux, use `journalctl --user -u vigilo -f` to view logs. To keep the user service running after logout, enable lingering with `sudo loginctl enable-linger "$USER"`. On macOS, use `tail -f "$HOME/Library/Logs/Vigilo/stderr.log"` to view logs. To stop, run `systemctl --user disable --now vigilo.service` on Linux or `python3 deploy/macos/install-launch-agent.py --uninstall` on macOS. See [`config.example.yaml`](config.example.yaml) for other alert channels and settings.

## What it monitors

- **Files:** creates, writes, removes, and renames under configured paths. File events do not identify the writer.
- **Processes and network:** sampled activity. Polling may miss processes that start and exit between scans.
- **Linux auditd (optional):** with matching host rules and readable audit logs, can report short-lived executions and attribute selected file activity. Vigilo does not install the rules automatically.
- **Project checks (optional):** scans configured npm and Terraform project roots for suspicious changes. These checks are indicators for review, not proof of compromise.

On macOS, process monitoring remains polling-based and can miss short-lived activity. On Linux, auditd coverage depends on your host rules, log access, and event volume. A file or process name alone does not establish intent. See [coverage and tested limits](docs/PERSONAL_MONITORING.md).

## System-wide Linux service

For a system-wide install, download and extract the `linux_amd64` or `linux_arm64` release archive. From the extracted directory, run `sudo bash deploy/install.sh`. The service runs as a separate `vigilo` account; configure paths it can read in `/etc/vigilo/config.yaml`. Review the permissions and alert setup in [SECURITY.md](SECURITY.md) before enabling it.

For MCP, the web dashboard, multi-host monitoring, suppression rules, or source builds, see [`config.example.yaml`](config.example.yaml), [DESIGN.md](docs/DESIGN.md), and [SECURITY.md](SECURITY.md). Do not expose Vigilo's MCP or dashboard ports directly to the public internet.
