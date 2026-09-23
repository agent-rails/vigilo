"""Regression: the first version of run_v1_latency's alert-matching always
picked the globally-earliest candidate alert for every trigger sharing a
resource, instead of pairing one-to-one -- collapsing what should have been
n=10 down to n=1 per chain (the negative-latency guard correctly rejected
the resulting nonsense pairings, silently masking the real bug upstream of
it). Live-reproduced against a real 10-repeat env_write run."""

import pytest

from harness.latency import LatencyMetric
from harness.trigger import TriggerResult
from scripts.run_evaluation import N_LATENCY_REPEATS, _alert_matches_trigger, _validate_latency_sample_count


def _alert(t1: float, resource: str, source: str = "file_access") -> dict:
    return {"t1": t1, "payload": {"resource": resource, "source": source}}


def test_exact_resource_matches_only_its_own_alert():
    trigger = TriggerResult(
        chain_name="keystore_write", t0=0.0, mechanism="fsnotify", resource="/app/keystore/id_eval_3"
    )
    assert _alert_matches_trigger(_alert(1.0, "/app/keystore/id_eval_3"), trigger)
    assert not _alert_matches_trigger(_alert(1.0, "/app/keystore/id_eval_4"), trigger)


def test_suspicious_outbound_matches_by_port_suffix():
    trigger = TriggerResult(chain_name="suspicious_outbound", t0=0.0, mechanism="poll", resource=":4444")
    assert _alert_matches_trigger(_alert(1.0, "172.18.0.2:4444", source="network"), trigger)
    assert not _alert_matches_trigger(_alert(1.0, "172.18.0.2:4445", source="network"), trigger)
    # right port, wrong source -- must not match a coincidental file event
    assert not _alert_matches_trigger(_alert(1.0, "x:4444", source="file_access"), trigger)


def test_one_to_one_pairing_consumes_alerts():
    """Ten env_write triggers sharing an identical resource must each pair
    with a DIFFERENT alert, not all collapse onto the first."""
    triggers = [
        TriggerResult(chain_name="env_write", t0=float(i), mechanism="fsnotify", resource="/app/.env")
        for i in range(10)
    ]
    alerts = [_alert(float(i) + 0.05, "/app/.env") for i in range(10)]

    available = list(alerts)
    paired = []
    for trigger in sorted(triggers, key=lambda t: t.t0):
        candidates = [a for a in available if _alert_matches_trigger(a, trigger)]
        assert candidates, f"no candidates left for {trigger}"
        alert = min(candidates, key=lambda a: a["t1"])
        available.remove(alert)
        paired.append((trigger, alert))

    assert len(paired) == 10
    assert len({id(a) for _, a in paired}) == 10  # each alert used exactly once
    for trigger, alert in paired:
        assert alert["t1"] > trigger.t0  # each trigger paired with ITS OWN later alert, not an earlier one


def test_incomplete_sample_gate_rejects_well_formed_partial_results():
    """A partial set of matches must not be presented as a complete median."""
    expected = N_LATENCY_REPEATS
    metrics = [LatencyMetric(chain, float(i), float(i + 1), 1000.0, "fsnotify")
        for chain in ("keystore_write", "env_write", "suspicious_outbound")
        for i in range(expected)]
    _validate_latency_sample_count(metrics, expected)

    with pytest.raises(RuntimeError, match="refusing to report medians"):
        _validate_latency_sample_count(metrics[:-1], expected)
