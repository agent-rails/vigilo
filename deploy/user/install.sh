#!/bin/sh
set -eu

if [ "$(id -u)" -eq 0 ]; then
	echo "Run this installer as your login user, not with sudo." >&2
	exit 1
fi

SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
RELEASE_DIR=$(CDPATH= cd "$SCRIPT_DIR/../.." && pwd)
HOME_DIR=${VIGILO_INSTALL_HOME:-${HOME:?HOME must be set}}
BIN_DIR="$HOME_DIR/.local/bin"
LIBEXEC_DIR="$HOME_DIR/.local/libexec"
CONFIG_DIR="$HOME_DIR/.config/vigilo"

mkdir -p "$BIN_DIR" "$LIBEXEC_DIR" "$CONFIG_DIR" "$HOME_DIR/.local/share/vigilo"
chmod 0700 "$LIBEXEC_DIR" "$CONFIG_DIR" "$HOME_DIR/.local/share/vigilo"

if [ -f "$RELEASE_DIR/vigilo" ]; then
	install -m 0755 "$RELEASE_DIR/vigilo" "$BIN_DIR/vigilo"
elif [ -f "$RELEASE_DIR/go.mod" ]; then
	command -v go >/dev/null 2>&1 || { echo "Source install requires Go." >&2; exit 1; }
	(cd "$RELEASE_DIR" && go build -o "$BIN_DIR/vigilo" ./cmd/vigilo)
else
	echo "No vigilo binary or source checkout found in $RELEASE_DIR." >&2
	exit 1
fi

install -m 0755 "$SCRIPT_DIR/run-vigilo.sh" "$LIBEXEC_DIR/vigilo-run"
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
	install -m 0600 "$RELEASE_DIR/config.personal.example.yaml" "$CONFIG_DIR/config.yaml"
fi
if [ ! -f "$CONFIG_DIR/env" ]; then
	cat >"$CONFIG_DIR/env" <<'EOF'
# Optional notification secrets. Use one KEY=VALUE line per credential.
# VIGILO_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
EOF
	chmod 0600 "$CONFIG_DIR/env"
fi
chmod 0600 "$CONFIG_DIR/config.yaml" "$CONFIG_DIR/env"

case "$(uname -s)" in
Linux)
	command -v systemctl >/dev/null 2>&1 || { echo "systemctl is required for the Linux user service." >&2; exit 1; }
	UNIT_DIR="$HOME_DIR/.config/systemd/user"
	mkdir -p "$UNIT_DIR"
	install -m 0644 "$SCRIPT_DIR/vigilo.service" "$UNIT_DIR/vigilo.service"
	systemctl --user daemon-reload
	cat <<EOF
Installed Vigilo for $HOME_DIR.
Edit $CONFIG_DIR/config.yaml and $CONFIG_DIR/env, then start it with:
  systemctl --user enable --now vigilo.service
Logs: journalctl --user -u vigilo -f
EOF
	;;
Darwin)
	python3 "$RELEASE_DIR/deploy/macos/install-launch-agent.py" \
		--home "$HOME_DIR" --label "${VIGILO_LAUNCHD_LABEL:-com.agentrails.vigilo}"
	cat <<EOF
Installed Vigilo for $HOME_DIR.
Edit $CONFIG_DIR/config.yaml and $CONFIG_DIR/env, then start it with:
  python3 "$RELEASE_DIR/deploy/macos/install-launch-agent.py" --start
Logs: $HOME_DIR/Library/Logs/Vigilo/stderr.log
EOF
	;;
*)
	echo "Personal service installation supports Linux and macOS." >&2
	exit 1
	;;
esac
