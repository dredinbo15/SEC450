"""REQ-11: detection accuracy on the scripted attack scenario set (AC-28)."""
from datetime import timedelta

import pytest

from .conftest import T0
from .scenarios import ATTACK_RULES, LabTraffic, play, score

ATTACKS_PER_RULE = 7


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_detection_accuracy(cfg, conn, clock, seed):  # AC-28
    """At least 28 attacks (7 per rule) in 60 minutes of baseline traffic, ground truth logged:
    detection rate >= 90% and false alarms (clusters matching no attack / all clusters) <= 10%."""
    traffic = LabTraffic(cfg, seed=seed, start=T0)
    traffic.baseline(minutes=60)
    rng = traffic.rng
    kinds = ["scan_404", "injection", "large_transfer"] * ATTACKS_PER_RULE
    kinds += [rng.choice(["ssh_bruteforce", "app_bruteforce"]) for _ in range(ATTACKS_PER_RULE)]
    for kind in kinds:
        traffic.attack(kind, at=rng.uniform(30, 60 * 60 - 700))   # leaves R4's 10-minute window inside the hour
    play(traffic, cfg, conn, clock, until=T0 + timedelta(minutes=63))

    per_rule = {r: sum(a.rule == r for a in traffic.attacks) for r in sorted(set(ATTACK_RULES.values()))}
    assert len(traffic.attacks) >= 28 and min(per_rule.values()) >= ATTACKS_PER_RULE, per_rule
    # Every generated line must parse; quarantined baseline would make false alarms trivially zero.
    assert conn.execute("SELECT COUNT(*) FROM raw_line WHERE status = 'quarantined'").fetchone()[0] == 0
    for a in traffic.attacks:
        print(a.as_json())
    result = score(conn, traffic.attacks)
    print(f"seed {seed}: {result.detected}/{result.attacks} attacks detected ({result.detection_rate:.0%}), "
          f"{len(result.false_alarms)}/{result.clusters} clusters false alarms ({result.false_alarm_rate:.0%})")
    assert result.detection_rate >= 0.90, [a.as_json() for a in result.missed]
    assert result.false_alarm_rate <= 0.10, result.false_alarms
