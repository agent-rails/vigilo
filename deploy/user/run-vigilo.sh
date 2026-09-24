#!/bin/sh
set -eu

: "${HOME:?HOME must be set for the personal Vigilo service}"
VIGILO_HOME=${VIGILO_HOME:-$HOME}
CONFIG_DIR="$VIGILO_HOME/.config/vigilo"
DATA_DIR="$VIGILO_HOME/.local/share/vigilo"
umask 077
mkdir -p "$DATA_DIR"

# Read a restricted KEY=VALUE format without evaluating shell code. The installer
# creates this credential file with mode 0600; only variables Vigilo consumes are
# accepted so a typo cannot silently become executable startup logic.
if [ -f "$CONFIG_DIR/env" ]; then
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in ''|\#*) continue ;; *=*) ;; *)
			echo "Invalid line in $CONFIG_DIR/env; expected KEY=VALUE." >&2
			exit 1
			;;
		esac
		name=${line%%=*}
		value=${line#*=}
		case "$name" in
			VIGILO_TELEGRAM_BOT_TOKEN|VIGILO_TELEGRAM_CHAT_ID|VIGILO_SLACK_WEBHOOK_URL|VIGILO_SMTP_PASSWORD|VIGILO_WEB_TOKEN|VIGILO_MCP_TOKEN)
				export "$name=$value"
				;;
			*)
				echo "Unsupported environment variable in $CONFIG_DIR/env: $name" >&2
				exit 1
				;;
		esac
	done < "$CONFIG_DIR/env"
fi

exec "$VIGILO_HOME/.local/bin/vigilo" \
	-config "$CONFIG_DIR/config.yaml" \
	-db "$DATA_DIR/events.db"
