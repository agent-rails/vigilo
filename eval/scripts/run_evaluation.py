"""Runs the real V1 (detection latency) + V3 (false-positive rate) pass
against the isolated eval compose stack. Assumes `docker compose up -d`
has already been run in eval/docker/ -- this script doesn't manage the
container lifecycle, matching memkit-eval's separation of "build/start
infra" from "run the measurement" (docker compose down is a human action,
not automated here, so a failed run doesn't silently tear down a stack
someone might want to inspect)."""

from __future__ import annotations

import json
import sys
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from harness.benign_activity import run_benign_activity
from harness.false_positive import FalsePositiveWindow, compute_fp_rate
from harness.latency import aggregate_latencies, compute_latency
from harness.trigger import DAEMON_CONTAINER, run_all_chains
from harness.webhook_listener import AlertReceived

WEBHOOK_LISTENER_URL = "http://127.0.0.1:8090"
POLL_INTERVAL_MS = 1000.0  # matches docker/config.eval.yaml's poll_interval: 1s
N_LATENCY_REPEATS = 10
FP_WINDOW_DURATION_S = 60.0  # bounded -- V3's own documented design assumes a
# multi-week window (Step 0.5), infeasible here; disclosed honestly, not
# silently presented as equivalent to a production-scale measurement.


def _fetch_alerts() -> list[dict]:
    import httpx

    resp = httpx.get(f"{WEBHOOK_LISTENER_URL}/alerts", timeout=5.0)
    resp.raise_for_status()
    return resp.json()


def run_v1_latency() -> dict:
    """CORRECTED (live run found a real bug): the first version matched each
    trigger against ALL new alerts sharing a loose resource fragment and
    always picked the globally-earliest one -- for env_write specifically
    (identical resource every repeat), every one of the 10 triggers matched
    the SAME first alert. Repeats after the first then had a t0 LATER than
    that reused alert's t1, so compute_latency's negative-latency guard
    (working exactly as designed) correctly rejected them -- collapsing
    what should have been n=10 down to n=1 per chain. Fixed with proper
    one-to-one pairing: alerts are consumed once matched, in chronological
    trigger order, keyed by each TriggerResult's own `resource`."""
    print(f"V1: running {N_LATENCY_REPEATS} repeats of each immediate-tier chain...")
    before_count = len(_fetch_alerts())

    triggers = run_all_chains(DAEMON_CONTAINER, N_LATENCY_REPEATS, "webhook-listener")
    time.sleep(3.0)  # let the last poll-based trigger's alert land

    after_alerts = _fetch_alerts()
    available = list(after_alerts[before_count:])  # consume-once pool

    metrics = []
    for trigger in sorted(triggers, key=lambda t: t.t0):
        candidates = [a for a in available if _alert_matches_trigger(a, trigger)]
        if not candidates:
            continue
        alert = min(candidates, key=lambda a: a["t1"])
        available.remove(alert)  # never matched again by a later trigger
        metric = compute_latency(trigger, AlertReceived(t1=alert["t1"], payload=alert["payload"]))
        if metric is not None:
            metrics.append(metric)

    _validate_latency_sample_count(metrics, N_LATENCY_REPEATS)

    report = aggregate_latencies(metrics, poll_interval_ms=POLL_INTERVAL_MS)
    print(f"V1 result: state={report.state}")
    for chain, stats in report.per_chain.items():
        print(f"  {chain}: n={stats['n']} median={stats['median_ms']:.1f}ms p95={stats['p95_ms']:.1f}ms")
    return {"state": report.state, "per_chain": report.per_chain}


def _alert_matches_trigger(alert: dict, trigger) -> bool:
    resource = alert["payload"].get("resource", "")
    if trigger.chain_name == "suspicious_outbound":
        return alert["payload"].get("source") == "network" and resource.endswith(trigger.resource)
    return resource == trigger.resource


def _validate_latency_sample_count(metrics, expected_repeats: int) -> None:
    expected = {
        "keystore_write": expected_repeats,
        "env_write": expected_repeats,
        "suspicious_outbound": expected_repeats,
    }
    observed = Counter(metric.chain_name for metric in metrics)
    incomplete = {chain: (observed[chain], n) for chain, n in expected.items() if observed[chain] != n}
    if incomplete:
        raise RuntimeError(
            f"latency run incomplete (observed, expected) samples by chain: {incomplete}; refusing to report medians"
        )


def run_v3_false_positive() -> dict:
    print(f"V3: running a {FP_WINDOW_DURATION_S:.0f}s bounded benign-activity window...")
    before_count = len(_fetch_alerts())

    start = time.time()
    i = 0
    while time.time() - start < FP_WINDOW_DURATION_S:
        run_benign_activity(DAEMON_CONTAINER, i)
        i += 1
        time.sleep(2.0)

    after_alerts = _fetch_alerts()
    new_alert_count = len(after_alerts) - before_count

    window = FalsePositiveWindow(
        duration_s=FP_WINDOW_DURATION_S, benign_events_observed=i > 0, alert_count=new_alert_count
    )
    report = compute_fp_rate(window)
    print(f"V3 result: state={report.state} fp_count={report.fp_count} fp_rate_per_day={report.fp_rate_per_day}")
    return {
        "state": report.state,
        "fp_count": report.fp_count,
        "fp_rate_per_day": report.fp_rate_per_day,
        "workload_qualifier": report.workload_qualifier,
    }


def main() -> int:
    v1 = run_v1_latency()
    v3 = run_v3_false_positive()

    results_dir = Path(__file__).parent.parent / "results"
    results_dir.mkdir(exist_ok=True)
    out_path = results_dir / f"run_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
    out_path.write_text(json.dumps({"v1_latency": v1, "v3_false_positive": v3}, indent=2), encoding="utf-8")
    print(f"\nwrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
