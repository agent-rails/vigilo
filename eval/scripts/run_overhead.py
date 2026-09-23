"""Runs the real V4 (host overhead) pass against the isolated eval compose
stack. Assumes `docker compose up -d` has already been run in eval/docker/ --
this script doesn't manage the container lifecycle, matching run_evaluation.py's
separation of "build/start infra" from "run the measurement".

V4 previously had no runner in the repo at all: `harness/host_overhead.py` is a
library module with no entry point, so the committed `v4_host_overhead.json` was
produced by something that was never checked in and could not be reproduced or
audited. This script is that missing entry point.

Idle is sampled before any trigger load so the baseline is not contaminated by
the load window's own tail.
"""

from __future__ import annotations

import json
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from harness.host_overhead import (
    compute_overhead_report,
    get_db_size_bytes,
    get_event_count,
    sample_over_window,
)
from harness.trigger import DAEMON_CONTAINER, run_all_chains

IDLE_WINDOW_S = 30.0
LISTENER_HOST = "webhook-listener"
SAMPLE_INTERVAL_S = 1.0
N_LOAD_REPEATS = 10


def run_v4_overhead() -> dict:
    print(f"V4: sampling {IDLE_WINDOW_S:.0f}s idle baseline...")
    idle_samples = sample_over_window(DAEMON_CONTAINER, IDLE_WINDOW_S, SAMPLE_INTERVAL_S)

    db_bytes_before = get_db_size_bytes(DAEMON_CONTAINER)
    events_before = get_event_count(DAEMON_CONTAINER)

    print(f"V4: sampling under {N_LOAD_REPEATS} trigger repeats...")
    load_samples: list = []
    triggers = threading.Thread(
        target=run_all_chains, args=(DAEMON_CONTAINER, N_LOAD_REPEATS, LISTENER_HOST), daemon=True
    )
    triggers.start()
    while triggers.is_alive():
        load_samples.extend(sample_over_window(DAEMON_CONTAINER, SAMPLE_INTERVAL_S, SAMPLE_INTERVAL_S))
    triggers.join()
    if not load_samples:
        raise RuntimeError("trigger load finished before a single resource sample landed")

    db_bytes_after = get_db_size_bytes(DAEMON_CONTAINER)
    events_after = get_event_count(DAEMON_CONTAINER)
    n_events = events_after - events_before

    report = compute_overhead_report(
        idle_samples=idle_samples,
        load_samples=load_samples,
        db_bytes_before=db_bytes_before,
        db_bytes_after=db_bytes_after,
        n_events=n_events,
    )

    print(
        f"V4 result: idle cpu={report.idle_cpu_pct_median}% mem={report.idle_mem_mib_median}MiB | "
        f"load cpu={report.load_cpu_pct_median}% mem={report.load_mem_mib_median}MiB"
    )
    print(f"  events recorded during load: {n_events}")
    print(f"  steady-state bytes/event: {report.bytes_per_event}")

    return {
        "state": "reported",
        "idle_cpu_pct_median": report.idle_cpu_pct_median,
        "idle_mem_mib_median": report.idle_mem_mib_median,
        "load_cpu_pct_median": report.load_cpu_pct_median,
        "load_mem_mib_median": report.load_mem_mib_median,
        "bytes_per_event": report.bytes_per_event,
        "n_events": n_events,
        "db_bytes_before": db_bytes_before,
        "db_bytes_after": db_bytes_after,
        "measurement": "post-wal-checkpoint",
        "idle_window_s": IDLE_WINDOW_S,
        "sample_interval_s": SAMPLE_INTERVAL_S,
        "throughput_ceiling": "not measured -- disclosed gap, same as the V1/V3 scope limits",
    }


def main() -> int:
    v4 = run_v4_overhead()

    results_dir = Path(__file__).parent.parent / "results"
    results_dir.mkdir(exist_ok=True)
    out_path = results_dir / f"overhead_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
    out_path.write_text(json.dumps({"v4_host_overhead": v4}, indent=2), encoding="utf-8")
    print(f"\nwrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
