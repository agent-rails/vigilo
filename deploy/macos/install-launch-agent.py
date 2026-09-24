#!/usr/bin/env python3
"""Install or remove Vigilo's per-user macOS LaunchAgent."""

from __future__ import annotations

import argparse
import os
import plistlib
import subprocess
import sys
from pathlib import Path


LABEL = "com.agentrails.vigilo"


def agent_paths(home: Path, label: str = LABEL) -> tuple[Path, Path, Path]:
	launch_agents = home / "Library" / "LaunchAgents"
	logs = home / "Library" / "Logs" / "Vigilo"
	return (
		launch_agents / f"{label}.plist",
		logs / "stdout.log",
		logs / "stderr.log",
	)


def main() -> int:
	parser = argparse.ArgumentParser(description=__doc__)
	group = parser.add_mutually_exclusive_group()
	group.add_argument("--start", action="store_true", help="load the agent now and start monitoring")
	group.add_argument("--uninstall", action="store_true", help="stop and remove the agent")
	default_home = Path(os.environ.get("VIGILO_INSTALL_HOME", str(Path.home())))
	parser.add_argument("--home", type=Path, default=default_home, help=argparse.SUPPRESS)
	parser.add_argument("--label", default=LABEL, help=argparse.SUPPRESS)
	args = parser.parse_args()

	if sys.platform != "darwin":
		parser.error("this installer only runs on macOS")

	home = args.home.expanduser().resolve()
	label = args.label
	plist_path, stdout_path, stderr_path = agent_paths(home, label)
	domain = f"gui/{os.getuid()}"
	service = f"{domain}/{label}"

	if args.uninstall:
		status = subprocess.run(["launchctl", "print", service], capture_output=True, text=True)
		if status.returncode == 0:
			subprocess.run(["launchctl", "bootout", service], check=True, capture_output=True, text=True)
		plist_path.unlink(missing_ok=True)
		print(f"Removed {plist_path}; Vigilo will not start at login.")
		return 0

	binary = home / ".local" / "bin" / "vigilo"
	runner = home / ".local" / "libexec" / "vigilo-run"
	config = home / ".config" / "vigilo" / "config.yaml"
	for path in (binary, runner, config):
		if not path.is_file():
			parser.error(f"required file is missing: {path}")

	for directory in (plist_path.parent, stdout_path.parent):
		directory.mkdir(parents=True, exist_ok=True)
		os.chmod(directory, 0o700)

	data = {
		"Label": label,
		"ProgramArguments": [str(runner)],
		"WorkingDirectory": str(home),
		"EnvironmentVariables": {"VIGILO_HOME": str(home)},
		"RunAtLoad": True,
		"KeepAlive": True,
		"ThrottleInterval": 5,
		"Umask": 0o077,
		"StandardOutPath": str(stdout_path),
		"StandardErrorPath": str(stderr_path),
	}
	with plist_path.open("wb") as output:
		plistlib.dump(data, output, fmt=plistlib.FMT_XML, sort_keys=True)
	os.chmod(plist_path, 0o600)

	if args.start:
		subprocess.run(["launchctl", "bootout", service], check=False, capture_output=True, text=True)
		subprocess.run(["launchctl", "enable", service], check=True)
		subprocess.run(["launchctl", "bootstrap", domain, str(plist_path)], check=True)
		print("Vigilo started. Logs: " + str(stderr_path))
	else:
		# A plist in LaunchAgents is loaded automatically at the next login. Keep
		# the job explicitly disabled until the user has reviewed the config.
		subprocess.run(["launchctl", "disable", service], check=True)
		print(f"Installed {plist_path}. Review config and env, then run this script with --start.")
	return 0


if __name__ == "__main__":
	try:
		raise SystemExit(main())
	except subprocess.CalledProcessError as error:
		print(f"launchctl failed ({error.returncode}): {error.cmd}", file=sys.stderr)
		raise SystemExit(error.returncode)
