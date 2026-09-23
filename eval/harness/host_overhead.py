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


def _copy_store(container: str, db_path: str, dest: Path) -> None:
    """Copies the event store and its WAL out of the container, failing loudly.

    `-shm` is deliberately not copied: SQLite rebuilds it from the WAL, and a
    stale one buys nothing. The WAL is not optional -- if it fails to copy
    while the main file succeeds, the checkpoint becomes a no-op and the
    measurement silently returns the un-checkpointed main-file size, which is
    the original zero-growth bug wearing a different hat.
    """
    for suffix in ("", "-wal"):
        result = subprocess.run(
            ["docker", "cp", f"{container}:{db_path + suffix}", str(dest) + suffix],
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"docker cp {db_path + suffix} from {container} failed: "
                f"{result.stderr.decode(errors='replace').strip()}"
            )


def snapshot_store(container: str, db_path: str = "/var/lib/vigilo/events.db") -> tuple[int, int]:
    """Steady-state on-disk bytes and row count, from a single checkpointed copy.

    Both values come from one snapshot on purpose. Taking them separately meant
    two copy-and-checkpoint round trips up to half a second apart, and the
    collectors are poll-based, so an event landing in that gap inflated the
    denominator and deflated bytes-per-event.

    Counting rows directly is the honest denominator: trusting the number of
    triggers the harness fired misses events the daemon generated on its own
    and events a suppression rule dropped.

    Reads the file after `PRAGMA wal_checkpoint(TRUNCATE)`, because SQLite in
    WAL mode holds the main file near-fixed and writes into the WAL until a
    checkpoint. Measuring the main file alone reported zero growth across 15
    real events; summing `.db` + `.db-wal` + `.db-shm` then overcorrected,
    because the WAL is write-ahead churn whose size tracks write traffic and
    checkpoint timing rather than retained data. Measured live at 40 events,
    that sum reported 22,758 B/event against a checkpointed 819 B/event.

    Checkpointing both snapshots also makes the delta immune to a live
    auto-checkpoint firing between them, which would have corrupted any
    sum-the-files approach.

    The live daemon is never written to and never paused. Copying a database
    under concurrent writes can capture a torn WAL tail; the checkpoint then
    recovers the last consistent commit, so the result can undercount by at
    most the events written during the copy itself.
    """
    with tempfile.TemporaryDirectory() as tmp:
        local = Path(tmp) / "events.db"
        _copy_store(container, db_path, local)
        connection = sqlite3.connect(local)
        try:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            count = int(connection.execute("SELECT count(*) FROM events").fetchone()[0])
        finally:
            connection.close()
        return local.stat().st_size, count


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
