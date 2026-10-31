"""REQ-10: queries spanning up to 7 days answer within 2 s at p95 with 100,000 stored events (AC-27).

The store is seeded the way the collector fills it: one hash-chained batch per
source per hour over 30 days, with attack bursts grouped into clusters and a
report for every high or critical one. Queries go through the full /v1 stack
(authentication, validation, the query, the audit write) in process, so TLS
setup is not included. Run with -s to see the timing summary for the manual
outlier review.
"""
import json
import math
import random
import time
from datetime import timedelta

from fastapi.testclient import TestClient

from sec450 import hashchain
from sec450.db import transaction
from sec450.keys import create_key
from sec450.timeutil import iso

from .conftest import T0

EVENTS = 100_000
DAYS = 30
QUERIES = 200
SOURCES = {"nginx_access": "web01", "nginx_error": "web01", "ssh_auth": "ssh01", "app": "app01"}
RULES = [("R1", "high"), ("R2", "medium"), ("R3", "high"), ("R4", "critical")]


def seed_store(conn, rng: random.Random) -> tuple[list[str], list[str]]:
    """EVENTS events over DAYS days ending at T0. Returns the client IPs and usernames used."""
    ips = [f"198.51.{100 + i // 250}.{i % 250 + 1}" for i in range(2000)]
    hot = ips[:20]
    users = [f"user{i:03d}" for i in range(200)]
    hours = DAYS * 24
    per_batch = math.ceil(EVENTS / (hours * len(SOURCES)))
    start = T0 - timedelta(days=DAYS)
    event_id = raw_id = cluster_id = 0
    with transaction(conn) as c:
        prev = hashchain.last_hash(c, "batch")
        batches, raws, events, clusters, members, reports = [], [], [], [], [], []
        for h in range(hours):
            collected = start + timedelta(hours=h + 1)
            for source, host in SOURCES.items():
                batch_id = len(batches) + 1
                burst = rng.random() < 0.15        # an attack burst from one address in this batch
                attacker = rng.choice(ips)
                ids, lines = [], []
                for seq in range(per_batch):
                    raw_id += 1
                    event_id += 1
                    ts = collected - timedelta(seconds=rng.uniform(0, 3600))
                    in_burst = burst and seq < 12
                    ip = attacker if in_burst else (rng.choice(hot) if rng.random() < 0.2 else rng.choice(ips))
                    user = rng.choice(users) if rng.random() < 0.25 else None
                    status = 404 if in_burst else rng.choice([200, 200, 200, 304, 404, 401])
                    target = f"/page/{rng.randint(1, 500)}"
                    text = (f'{ip} - {user or "-"} [{ts:%d/%b/%Y:%H:%M:%S} +0000] "GET {target} HTTP/1.1" '
                            f'{status} {rng.randint(100, 90_000)} "-" "Mozilla/5.0" "-"')
                    lines.append(text)
                    raws.append((raw_id, batch_id, seq, text))
                    events.append((event_id, raw_id, iso(ts), source, host, ip, user, "GET", target,
                                   "failure" if status >= 400 else "success", status, rng.randint(100, 90_000)))
                    if in_burst:
                        ids.append((event_id, iso(ts)))
                h_ = hashchain.batch_hash(prev, source, iso(collected), lines)
                batches.append((batch_id, source, iso(collected), len(lines), prev, h_))
                prev = h_
                if ids:
                    cluster_id += 1
                    rule, severity = rng.choice(RULES)
                    first, last = min(t for _, t in ids), max(t for _, t in ids)
                    reported = severity in ("high", "critical")
                    clusters.append((cluster_id, rule, severity, attacker, first, last,
                                     "REPORTED" if reported else "DONE", iso(collected)))
                    members += [(cluster_id, eid) for eid, _ in ids]
                    if reported:
                        body = {"summary": f"{rule} {severity} from {attacker}", "requester": {"client_ip": attacker},
                                "raw_log_lines": lines[:12], "timeline": [t for _, t in ids]}
                        reports.append((cluster_id, iso(collected + timedelta(minutes=3)), json.dumps(body)))
        c.executemany("INSERT INTO batch VALUES (?, ?, ?, ?, ?, ?)", batches)
        c.executemany("INSERT INTO raw_line (raw_id, batch_id, seq, text, status) VALUES (?, ?, ?, ?, 'parsed')",
                      raws)
        c.executemany("INSERT INTO event (event_id, raw_id, ts, source, host, client_ip, username, action, target, "
                      "outcome, status_code, bytes_sent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", events)
        c.executemany("INSERT INTO cluster (cluster_id, rule_id, severity, group_key, window_start, window_end, "
                      "state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", clusters)
        c.executemany("INSERT INTO cluster_event (cluster_id, event_id) VALUES (?, ?)", members)
        c.executemany("INSERT INTO report (cluster_id, generated_at, body_json) VALUES (?, ?, ?)", reports)
        c.execute("INSERT INTO gap (source, start, \"end\", reason) VALUES ('ssh_auth', ?, ?, 'unreadable')",
                  (iso(T0 - timedelta(days=3)), iso(T0 - timedelta(days=3) + timedelta(minutes=5))))
    conn.execute("ANALYZE")
    return ips, users


def random_query(rng: random.Random, ips: list[str], users: list[str]) -> str:
    span = timedelta(days=rng.uniform(1, 7))
    end = T0 - timedelta(seconds=rng.uniform(0, (timedelta(days=DAYS) - span).total_seconds()))
    params = {"start": iso(end - span), "end": iso(end)}
    if rng.random() < 0.3:
        params["source_ip"] = rng.choice(ips[:20] if rng.random() < 0.5 else ips)
    if rng.random() < 0.2:
        params["user"] = rng.choice(users)
    if rng.random() < 0.25:
        params["severity"] = rng.choice(["medium", "high", "critical"])
    limit = rng.choice([None, 10, 1000])
    if limit:
        params["limit"] = str(limit)
    endpoint = rng.choices(["events", "logs", "clusters", "reports"], weights=[4, 2, 2, 2])[0]
    return f"/v1/{endpoint}?" + "&".join(f"{k}={v}" for k, v in params.items())


def test_query_performance(cfg, conn, clock):  # AC-27
    rng = random.Random(27)
    ips, users = seed_store(conn, rng)
    assert conn.execute("SELECT COUNT(*) FROM event").fetchone()[0] >= EVENTS

    # AC-25 covers the rate limit; lift it so 200 queries measure query time, not 429s.
    cfg.api.rate_limit_per_minute = 10_000
    from sec450.api.app import create_app
    _, key = create_key(conn, clock)
    client = TestClient(create_app(cfg, clock))
    client.headers["Authorization"] = f"Bearer {key}"

    timings: list[tuple[float, str, int]] = []
    for _ in range(QUERIES):
        url = random_query(rng, ips, users)
        started = time.perf_counter()
        r = client.get(url.replace("+", "%2B"))
        timings.append((time.perf_counter() - started, url, r.status_code))

    errors = [(url, status) for _, url, status in timings if status != 200]
    seconds = sorted(t for t, _, _ in timings)
    p95 = seconds[math.ceil(0.95 * len(seconds)) - 1]
    print(f"\nAC-27: {len(seconds)} queries, p50 {seconds[len(seconds) // 2] * 1000:.0f} ms, "
          f"p95 {p95 * 1000:.0f} ms, max {seconds[-1] * 1000:.0f} ms; slowest:")
    for t, url, _ in sorted(timings, reverse=True)[:5]:
        print(f"  {t * 1000:7.0f} ms  {url}")
    assert errors == []
    assert p95 <= 2.0
