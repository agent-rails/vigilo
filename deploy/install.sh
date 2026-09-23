#!/usr/bin/env bash
# Install from an extracted release or a source checkout on a Linux systemd host.
# Run: sudo bash deploy/install.sh
set -euo pipefail

if [ "$(uname -s)" != Linux ] || [ "$(id -u)" -ne 0 ]; then
  echo "Run this installer as root on a Linux systemd host." >&2
  exit 1
fi
command -v systemctl >/dev/null || { echo "systemctl is required." >&2; exit 1; }
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
RELEASE_DIR=$(cd -- "$SCRIPT_DIR/.." && pwd)
INSTALL_BIN=/usr/local/bin/vigilo
CONFIG_DIR=/etc/vigilo
DATA_DIR=/var/lib/vigilo
SERVICE_FILE=/etc/systemd/system/vigilo.service

# Prefer the packaged binary; a release archive needs no Go toolchain.
if [ -f "$RELEASE_DIR/vigilo" ]; then
  echo "==> Installing packaged vigilo..."
  "$RELEASE_DIR/vigilo" -version
  install -m 0755 "$RELEASE_DIR/vigilo" "$INSTALL_BIN"
elif [ -f "$RELEASE_DIR/go.mod" ]; then
  command -v go >/dev/null || { echo "Source installs require Go 1.25+." >&2; exit 1; }
  echo "==> Building vigilo from source..."
  BUILD_DIR=$(mktemp -d)
  trap 'rm -rf "$BUILD_DIR"' EXIT
  (cd "$RELEASE_DIR" && go build -o "$BUILD_DIR/vigilo" ./cmd/vigilo/)
  install -m 0755 "$BUILD_DIR/vigilo" "$INSTALL_BIN"
else
  echo "No packaged binary or source tree found next to deploy/. Extract the full release archive." >&2
  exit 1
fi

echo "==> Creating user and directories..."
id -u vigilo &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin vigilo
mkdir -p "$CONFIG_DIR" "$DATA_DIR"
chown vigilo:vigilo "$DATA_DIR"

echo "==> Installing config (skip if exists)..."
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
  install -m 0640 -o root -g vigilo "$RELEASE_DIR/config.example.yaml" "$CONFIG_DIR/config.yaml"
  echo "    Edit $CONFIG_DIR/config.yaml before starting the service."
fi

echo "==> Installing systemd service..."
install -m 0644 "$RELEASE_DIR/deploy/vigilo.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable vigilo

echo ""
echo "Done. Edit $CONFIG_DIR/config.yaml then run:"
echo "  Set absolute watch_paths readable by the vigilo user and configure an alert channel."
echo "  For an MCP client, set mcp_transport: http and VIGILO_MCP_TOKEN in /etc/vigilo/env."
echo "  Existing configuration and environment files are preserved; the service is not started or restarted."
echo "  systemctl start vigilo"
echo "  journalctl -u vigilo -f"
