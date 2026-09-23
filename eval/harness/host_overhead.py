"""V4 -- host overhead. Real docker stats sampling (idle vs under real
trigger load), plus SQLite write amplification (events.db byte growth per
real event). Event throughput ceiling (stress to the buffer's breaking
point) is NOT covered this pass -- disclosed as a gap, not silently
omitted, same as V1/V3's own disclosed scope limits."""

from __future__ import annotations

import re
import sqlite3
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

DAEMON_CONTAINER = "docker-daemon-1"


@dataclass(frozen=True)
class ResourceSample:
    cpu_pct: float
    mem_mib: float


@dataclass(frozen=True)
class OverheadReport:
    idle_cpu_pct_median: float
    idle_mem_mib_median: float
    load_cpu_pct_median: float
    load_mem_mib_median: float
    bytes_per_event: float | None  # None if db size didn't grow measurably


def _parse_mem_to_mib(mem_str: str) -> float:
    """docker stats reports like '15.19MiB' or '1.2GiB' -- normalize to MiB."""
    match = re.match(r"([\d.]+)(MiB|GiB|KiB)", mem_str)
    if not match:
        return 0.0
    value, unit = float(match.group(1)), match.group(2)
    return {"KiB": value / 1024, "MiB": value, "GiB": value * 1024}[unit]


def sample_resources(container: str) -> ResourceSample:
    out = subprocess.run(
        ["docker", "stats", container, "--no-stream", "--format", "{{.CPUPerc}} {{.MemUsage}}"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    cpu_str, mem_str = out.stdout.strip().split(" ", 1)
    mem_str = mem_str.split(" / ")[0]  # "15.19MiB / 15.66GiB" -> usage only
    return ResourceSample(cpu_pct=float(cpu_str.rstrip("%")), mem_mib=_parse_mem_to_mib(mem_str))


def sample_over_window(container: str, duration_s: float, interval_s: float = 1.0) -> list[ResourceSample]:
    samples = []
    start = time.time()
    while time.time() - start < duration_s:
        samples.append(sample_resources(container))
        time.sleep(interval_s)
    return samples


def _median(values: list[float]) -> float:
    s = sorted(values)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def get_db_size_bytes(container: str, db_path: str = "/var/lib/vigilo/events.db") -> int:
    """Steady-state on-disk bytes for the event store, measured after a WAL
    checkpoint.

    Two earlier approaches were both wrong, in opposite directions. Measuring
    only the main `.db` file reported zero growth across 15 real events,
    because SQLite in WAL mode holds the main file near-fixed and writes into
    the WAL until a checkpoint. Summing `.db` + `.db-wal` + `.db-shm` then
    overcorrected: the WAL is write-ahead churn whose size tracks write
    traffic and checkpoint timing, not retained data. Measured live at 40
    events, the sum reported 22,758 B/event while the checkpointed store held
    819 B/event -- a 28x overstatement.

    The daemon image ships no `sqlite3` binary, so the three files are copied
    out and checkpointed with `PRAGMA wal_checkpoint(TRUNCATE)` against the
    copy. The live daemon is never written to and never paused. Copying a
    database that is being written concurrently can capture a torn WAL tail;
    the checkpoint then recovers the last consistent commit, so the result can
    undercount by at most the events written during the copy itself.
    """
    with tempfile.TemporaryDirectory() as tmp:
        local = Path(tmp) / "events.db"
        for suffix in ("", "-wal", "-shm"):
            subprocess.run(
                ["docker", "cp", f"{container}:{db_path + suffix}", str(local) + suffix],
                capture_output=True,
                timeout=30,
            )
        if not local.exists():
            raise RuntimeError(f"could not copy {db_path} out of {container}")
        connection = sqlite3.connect(local)
        try:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            connection.close()
        return local.stat().st_size


def get_event_count(container: str, db_path: str = "/var/lib/vigilo/events.db") -> int:
    """Rows in the events table, read from a checkpointed copy.

    Counting rows directly is the honest denominator for bytes-per-event. The
    alternative -- trusting the number of triggers the harness fired -- misses
    events the daemon generated on its own and events a suppression rule
    dropped.
    """
    with tempfile.TemporaryDirectory() as tmp:
        local = Path(tmp) / "events.db"
        for suffix in ("", "-wal", "-shm"):
            subprocess.run(
                ["docker", "cp", f"{container}:{db_path + suffix}", str(local) + suffix],
                capture_output=True,
                timeout=30,
            )
        if not local.exists():
            raise RuntimeError(f"could not copy {db_path} out of {container}")
        connection = sqlite3.connect(local)
        try:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            return int(connection.execute("SELECT count(*) FROM events").fetchone()[0])
        finally:
            connection.close()


def compute_overhead_report(
    idle_samples: list[ResourceSample],
    load_samples: list[ResourceSample],
    db_bytes_before: int,
    db_bytes_after: int,
    n_events: int,
) -> OverheadReport:
    delta_bytes = db_bytes_after - db_bytes_before
    bytes_per_event = (delta_bytes / n_events) if n_events > 0 and delta_bytes > 0 else None
    return OverheadReport(
        idle_cpu_pct_median=_median([s.cpu_pct for s in idle_samples]),
        idle_mem_mib_median=_median([s.mem_mib for s in idle_samples]),
        load_cpu_pct_median=_median([s.cpu_pct for s in load_samples]),
        load_mem_mib_median=_median([s.mem_mib for s in load_samples]),
        bytes_per_event=bytes_per_event,
    )
