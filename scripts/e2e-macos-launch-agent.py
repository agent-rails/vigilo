#!/usr/bin/env python3
"""End-to-end test of Vigilo's macOS LaunchAgent, file alerts, and process alerts."""

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
INSTALLER = ROOT / "deploy/macos/install-launch-agent.py"
LABEL = f"com.agentrails.vigilo.e2e.{os.getpid()}"


class Sink(http.server.BaseHTTPRequestHandler):
	received: queue.Queue[dict] = queue.Queue()

	def do_POST(self):  # noqa: N802 - stdlib handler API
		try:
			payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
			self.received.put(payload)
			self.send_response(200)
			self.end_headers()
		except Exception as error:  # surface listener errors in the test thread
			self.send_error(500, str(error))

	def log_message(self, *_args):
		pass


def main() -> int:
	if os.uname().sysname != "Darwin":
		raise SystemExit("This E2E test must run on macOS.")

	server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Sink)
	thread = threading.Thread(target=server.serve_forever, daemon=True)
	thread.start()
	uid = os.getuid()
	domain = f"gui/{uid}"
	service = f"{domain}/{LABEL}"
	loaded = False
	child = None
	tmp = pathlib.Path(tempfile.mkdtemp(prefix="vigilo-launchd-e2e-"))
	try:
		home = tmp / "fixture-home"
		watch_dir = home / "watched"
		for directory in (home, watch_dir):
			directory.mkdir(parents=True, exist_ok=True)
		install_env = os.environ.copy()
		install_env["VIGILO_INSTALL_HOME"] = str(home)
		install_env["VIGILO_LAUNCHD_LABEL"] = LABEL
		subprocess.run(["bash", str(ROOT / "deploy/user/install.sh")], cwd=ROOT, env=install_env, check=True)
		config_dir = home / ".config/vigilo"
		(config_dir / "env").write_text(f"VIGILO_SLACK_WEBHOOK_URL=http://127.0.0.1:{server.server_port}/slack\n")
		(config_dir / "env").chmod(0o600)
		log_file = home / "Library/Logs/Vigilo/stderr.log"
		config = f'''watch_paths:
  - {watch_dir}
exclude_paths: []
poll_interval: 200ms
process_monitor:
  enabled: true
  report_new_processes: true
signal_cooldown: 0s
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

		loaded = True
		subprocess.run(["python3", str(INSTALLER), "--home", str(home), "--label", LABEL, "--start"], check=True)

		ready_deadline = time.monotonic() + 15
		while time.monotonic() < ready_deadline:
			if log_file.exists() and "vigilo daemon ready" in log_file.read_text(errors="replace"):
				break
			time.sleep(0.1)
		else:
			raise AssertionError(f"LaunchAgent did not become ready; log: {log_file.read_text(errors='replace') if log_file.exists() else '(no log)'}")
		# Let the process collector finish its initial baseline before starting the test child.
		time.sleep(0.5)

		file_path = watch_dir / "arbitrary-assessment-payload.bin"
		renamed_path = watch_dir / "renamed-assessment-payload.bin"
		nested_file = watch_dir / "created-after-start" / "deep" / "nested-payload.bin"
		seen_file_events = set()
		slack_alerts = [0]
		deadline = time.monotonic() + 20

		def next_payload() -> dict:
			while time.monotonic() < deadline:
				try:
					payload = Sink.received.get(timeout=min(0.25, max(0.01, deadline - time.monotonic())))
				except queue.Empty:
					continue
				if isinstance(payload.get("blocks"), list):
					slack_alerts[0] += 1
					continue
				return payload
			raise AssertionError(f"timed out waiting for E2E webhook; file events seen={sorted(seen_file_events)}")

		def wait_for_file_event(actions: set[str], path: pathlib.Path) -> str:
			while True:
				payload = next_payload()
				if payload.get("source") != "file_access":
					continue
				observed = (payload.get("action"), payload.get("resource"))
				seen_file_events.add(observed)
				if observed[0] in actions and observed[1] == str(path):
					return observed[0]

		file_path.write_bytes(b"created by LaunchAgent E2E\n")
		wait_for_file_event({"create"}, file_path)
		file_path.write_bytes(b"overwritten by LaunchAgent E2E, second write\n")
		wait_for_file_event({"write"}, file_path)
		file_path.rename(renamed_path)
		wait_for_file_event({"rename", "remove"}, file_path)
		renamed_path.unlink()
		wait_for_file_event({"remove"}, renamed_path)
		nested_file.parent.mkdir(parents=True)
		# Give the recursive watcher time to register the new tree. A file written
		# before registration finishes can be missed (documented coverage limit).
		time.sleep(0.3)
		nested_file.write_bytes(b"created in a nested directory after startup\n")
		wait_for_file_event({"create"}, nested_file)
		child = subprocess.Popen(["/bin/sleep", "12"])
		while True:
			payload = next_payload()
			if payload.get("source") == "process" and payload.get("pid") == child.pid:
				if not payload.get("executable") or not payload.get("user_id"):
					raise AssertionError(f"process alert omitted identity context: {payload}")
				break
		if slack_alerts[0] < 2:
			raise AssertionError(f"missing environment-backed Slack alerts: {slack_alerts[0]}; log={log_file.read_text(errors='replace')}")
		print("PASS: LaunchAgent startup, file create/write/rename/delete, nested-tree coverage, process webhook, and Slack delivery")
		child.terminate()
		child.wait(timeout=5)
		return 0
	finally:
		if child is not None and child.poll() is None:
			child.terminate()
			child.wait(timeout=5)
		if loaded:
			status = subprocess.run(["launchctl", "print", service], capture_output=True)
			if status.returncode == 0:
				subprocess.run(["launchctl", "bootout", service], check=True, capture_output=True)
		server.shutdown()
		server.server_close()
		thread.join(timeout=3)
		shutil.rmtree(tmp)


if __name__ == "__main__":
	raise SystemExit(main())
