# Vigilo

Vigilo watches selected paths and reports file changes and process activity on personal Linux and macOS systems. It can help you investigate what changed while running unfamiliar software.

Vigilo reports observations; it does not decide whether activity is malicious or block it. Coverage depends on the paths and providers you configure. The default file watcher does not identify which process changed a file, and process polling can miss short-lived processes. See [coverage and limitations](docs/PERSONAL_MONITORING.md).

## Install

Download and extract the archive for your operating system and CPU from [Releases](https://github.com/agent-rails/vigilo/releases). No Go installation is needed. Run the user-level installer from the extracted directory:

```sh
bash deploy/user/install.sh
```

## Configure

Edit `~/.config/vigilo/config.yaml` and add the project or system paths you want Vigilo to watch. Remove example paths you do not use. Vigilo only watches configured paths.

To receive Slack alerts, add your webhook to `~/.config/vigilo/env`:

```sh
VIGILO_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

## Start

```sh
# Linux
systemctl --user enable --now vigilo.service

# macOS
python3 deploy/macos/install-launch-agent.py --start
```

To stop Vigilo, use `systemctl --user disable --now vigilo.service` on Linux or `python3 deploy/macos/install-launch-agent.py --uninstall` on macOS.

## What to expect

- File changes are reported for watched paths. Rename events include an explicit note when the operating system does not reveal the destination. A same-directory rename followed by a file create is labeled as a possible atomic save or in-directory move; Vigilo cannot prove the two events are related.
- Process and network observations use polling and may miss brief activity.
- Optional Linux `auditd` rules can add short-lived execution events and identify processes that access selected files. Vigilo does not install these rules for you.
- Optional npm and Terraform checks report suspicious project changes for investigation; they do not prove compromise.

For Linux logs, run `journalctl --user -u vigilo -f`. For macOS logs, run `tail -f "$HOME/Library/Logs/Vigilo/stderr.log"`.

See [`config.example.yaml`](config.example.yaml) for settings, [security limits](SECURITY.md), and [monitoring coverage](docs/PERSONAL_MONITORING.md). For a [system-wide Linux install](deploy/install.sh), MCP, or the dashboard, see the [design guide](docs/DESIGN.md). Do not expose MCP or dashboard ports directly to the public internet.
