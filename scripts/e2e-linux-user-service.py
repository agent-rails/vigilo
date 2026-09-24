#!/usr/bin/env python3
"""End-to-end test of Vigilo's systemd --user service and webhook alerts."""

from __future__ import annotations

import http.server
import json
import os
import pathlib
import queue
import shutil
import subprocess
import tempfile
import threading
import time


ROOT = pathlib.Path(__file__).resolve().parents[1]


class Sink(http.server.BaseHTTPRequestHandler):
	received: queue.Queue[dict] = queue.Queue()

	def do_POST(self):  # noqa: N802 - stdlib handler API
		payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
		self.received.put(payload)
		self.send_response(200)
		self.end_headers()

	def log_message(self, *_args):
		pass


def systemctl(*args: str, check: bool = True) -> subprocess.CompletedProcess:
	return subprocess.run(["systemctl", "--user", *args], check=check, text=True, capture_output=True)


def main() -> int:
	if os.uname().sysname != "Linux" or os.geteuid() == 0:
		raise SystemExit("Run this test as an unprivileged Linux user with a systemd --user manager.")

	home = pathlib.Path.home()
	# Do not enable, stop, or disable a service supplied by the host or another
	# installation. The fresh CI user should have no unit with this name loaded.
	try:
		systemctl("cat", "vigilo.service")
	except subprocess.CalledProcessError:
		pass
	else:
		raise SystemExit("Refusing to interfere with an existing vigilo.service user unit.")
	owned = [home / ".local/bin/vigilo", home / ".local/libexec/vigilo-run", home / ".config/vigilo", home / ".config/systemd/user/vigilo.service", home / ".local/share/vigilo"]
	if any(path.exists() for path in owned):
		raise SystemExit("Refusing to overwrite an existing personal Vigilo installation in the disposable test home.")

	server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Sink)
	thread = threading.Thread(target=server.serve_forever, daemon=True)
	thread.start()
	child = None
	installed = False
	tmp = pathlib.Path(tempfile.mkdtemp(prefix="vigilo-systemd-user-e2e-"))
	try:
		watch_dir = tmp / "watched"
		watch_dir.mkdir()
		install_env = os.environ.copy()
		install_env["VIGILO_INSTALL_HOME"] = str(home)
		installed = True
		subprocess.run(["bash", str(ROOT / "deploy/user/install.sh")], cwd=ROOT, env=install_env, check=True)
		config_dir = home / ".config/vigilo"
		(config_dir / "env").write_text(f"VIGILO_SLACK_WEBHOOK_URL=http://127.0.0.1:{server.server_port}/slack\n")
		(config_dir / "env").chmod(0o600)
		config = f'''watch_paths:
  - {watch_dir}
exclude_paths: []
poll_interval: 200ms
process_monitor:
  enabled: true
  report_new_processes: true
alerter:
  min_severity: high
  min_severity_by_source:
    file_access: info
    process: info
  webhooks:
    - name: local-e2e
      url: http://127.0.0.1:{server.server_port}/
'''
		(config_dir / "config.yaml").write_text(config)
		(config_dir / "config.yaml").chmod(0o600)
		systemctl("enable", "--now", "vigilo.service")

		ready_deadline = time.monotonic() + 15
		while time.monotonic() < ready_deadline:
			result = systemctl("is-active", "vigilo.service", check=False)
			journal = subprocess.run(["journalctl", "--user", "-u", "vigilo.service", "-n", "100", "--no-pager"], text=True, capture_output=True)
			if result.returncode == 0 and "vigilo daemon ready" in journal.stdout:
				break
			time.sleep(0.1)
		else:
			raise AssertionError(f"systemd user service failed to become ready:\n{journal.stdout}\n{journal.stderr}")
		time.sleep(0.5)

		file_path = watch_dir / "arbitrary-assessment-payload.bin"
		file_path.write_bytes(b"created by systemd user service E2E\n")
		child = subprocess.Popen(["/bin/sleep", "12"])
		got_file = got_process = False
		slack_alerts = 0
		deadline = time.monotonic() + 10
		while time.monotonic() < deadline and not (got_file and got_process and slack_alerts >= 2):
			try:
				payload = Sink.received.get(timeout=0.25)
			except queue.Empty:
				continue
			if payload.get("source") == "file_access" and payload.get("resource") == str(file_path):
				got_file = True
			if payload.get("source") == "process" and payload.get("pid") == child.pid:
				if not payload.get("executable") or not payload.get("user_id"):
					raise AssertionError(f"process alert omitted identity context: {payload}")
				got_process = True
			if isinstance(payload.get("blocks"), list):
				slack_alerts += 1
		if not got_file or not got_process or slack_alerts < 2:
			journal = subprocess.run(["journalctl", "--user", "-u", "vigilo.service", "-n", "100", "--no-pager"], text=True, capture_output=True)
			raise AssertionError(f"missing alerts: file={got_file}, process={got_process}, slack={slack_alerts}\n{journal.stdout}")
		print("PASS: systemd --user startup, file/process webhooks, and environment-backed Slack delivery")
		return 0
	finally:
		if child is not None and child.poll() is None:
			child.terminate()
			child.wait(timeout=5)
		if installed:
			# Stop the loaded unit even if it is currently failing/restarting;
			# checking only `is-active` can leave a Restart=on-failure loop alive.
			systemctl("stop", "vigilo.service")
			if systemctl("is-enabled", "vigilo.service", check=False).returncode == 0:
				systemctl("disable", "vigilo.service")
			systemctl("daemon-reload")
			for path in owned:
				if path.is_dir():
					shutil.rmtree(path)
				else:
					path.unlink(missing_ok=True)
		server.shutdown()
		server.server_close()
		thread.join(timeout=3)
		shutil.rmtree(tmp)


if __name__ == "__main__":
	raise SystemExit(main())
