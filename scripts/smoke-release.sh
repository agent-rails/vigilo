#!/usr/bin/env bash
# Destructive to the disposable runner's Vigilo install. Run only on fresh CI.
# Exercises the extracted archive installer and real systemd unit, without Go.
set -euo pipefail
if [ "${CI:-}" != true ] || [ "$(id -u)" -ne 0 ] || [ -e /etc/vigilo ] || [ -e /usr/local/bin/vigilo ]; then
  echo "This smoke test requires a fresh disposable CI runner as root." >&2
  exit 1
fi
ARCHIVE=$(realpath "$1")
SMOKE_DIR=$(mktemp -d)
cleanup() {
  systemctl stop vigilo 2>/dev/null || true
  systemctl disable vigilo 2>/dev/null || true
  rm -rf "$SMOKE_DIR"
}
trap cleanup EXIT
tar xzf "$ARCHIVE" -C "$SMOKE_DIR"
test -x "$SMOKE_DIR/vigilo"
test -f "$SMOKE_DIR/CHANGELOG.md"
test -f "$SMOKE_DIR/config.personal.example.yaml"
test -f "$SMOKE_DIR/deploy/user/install.sh"
test -f "$SMOKE_DIR/deploy/user/vigilo.service"
test -f "$SMOKE_DIR/deploy/user/run-vigilo.sh"
test -f "$SMOKE_DIR/deploy/macos/install-launch-agent.py"
sh -n "$SMOKE_DIR/deploy/user/install.sh"
sh -n "$SMOKE_DIR/deploy/user/run-vigilo.sh"
python3 "$SMOKE_DIR/deploy/macos/install-launch-agent.py" --help >/dev/null

# Go must never be used by the binary installer, even if present on the runner.
mkdir "$SMOKE_DIR/no-go"
printf '#!/bin/sh\necho "unexpected Go invocation" >&2\nexit 99\n' > "$SMOKE_DIR/no-go/go"
chmod +x "$SMOKE_DIR/no-go/go"
cd /tmp
PATH="$SMOKE_DIR/no-go:$PATH" bash "$SMOKE_DIR/deploy/install.sh"
cmp "$SMOKE_DIR/vigilo" /usr/local/bin/vigilo
vigilo -version
systemd-analyze verify /etc/systemd/system/vigilo.service

cat > /etc/vigilo/config.yaml <<'YAML'
watch_paths:
  - /var/lib/vigilo/release-smoke
exclude_paths: []
poll_interval: 1s
buffer_retention_hours: 1
mcp_transport: stdio
web_addr: "127.0.0.1:17080"
signal_cooldown: 0s
alerter:
  min_severity: high
  webhooks:
    - name: smoke
      url: http://127.0.0.1:17081/
YAML
printf '# existing environment must survive reinstall\n' > /etc/vigilo/env
chmod 0600 /etc/vigilo/env
cp /etc/vigilo/config.yaml "$SMOKE_DIR/config.before"
cp /etc/vigilo/env "$SMOKE_DIR/env.before"
PATH="$SMOKE_DIR/no-go:$PATH" bash "$SMOKE_DIR/deploy/install.sh"
cmp "$SMOKE_DIR/config.before" /etc/vigilo/config.yaml
cmp "$SMOKE_DIR/env.before" /etc/vigilo/env
install -d -m 0750 -o vigilo -g vigilo /var/lib/vigilo/release-smoke

python3 - <<'PY'
import http.server
import json
import pathlib
import queue
import subprocess
import threading
import time
import urllib.error
import urllib.request

received = queue.Queue()

class Receiver(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        received.put(json.loads(self.rfile.read(int(self.headers['Content-Length']))))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass

server = http.server.ThreadingHTTPServer(('127.0.0.1', 17081), Receiver)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    subprocess.run(['systemctl', 'start', 'vigilo'], check=True)
    deadline = time.monotonic() + 15
    while True:
        try:
            with urllib.request.urlopen('http://127.0.0.1:17080/healthz', timeout=1) as response:
                health = json.load(response)
            if health.get('mcp_transport_up') is False:
                break
        except (OSError, urllib.error.URLError):
            pass
        if time.monotonic() >= deadline:
            raise AssertionError('packaged service not healthy after stdin EOF')
        time.sleep(0.1)
    marker = pathlib.Path('/var/lib/vigilo/release-smoke/wallet.json')
    marker.write_text('{"release_smoke":true}\n')
    payload = received.get(timeout=10)
    assert payload['source'] == 'file_access', payload
    assert payload['resource'] == str(marker), payload
    assert payload['severity'] == 'critical', payload
    subprocess.run(['systemctl', 'stop', 'vigilo'], check=True, timeout=20)
    status = subprocess.check_output(
        ['systemctl', 'show', 'vigilo', '--property=ExecMainStatus', '--value'], text=True).strip()
    assert status == '0', status
    print('PASS: archive install without Go, preserved config, systemd startup, alert after EOF, clean stop')
finally:
    server.shutdown()
    server.server_close()
PY
