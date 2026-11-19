"""Configurable threshold rules that group events into clusters (REQ-03, DD-01, DD-09).

Every rule groups events by client IP and slides a window over them in time
order. A window qualifies when its metric meets the rule's threshold; every
event inside a qualifying window joins the rule's FLAGGED cluster for that IP.
Windows are inclusive: events exactly window_seconds apart share a window.
"""
from __future__ import annotations

import logging
import re
from collections import Counter, defaultdict
from datetime import timedelta
from urllib.parse import unquote_plus

from .config import Config, RuleConfig
from .db import Connection, Row, one, transaction
from .models import LOGIN_ACTIONS
from .timeutil import Clock, iso, parse_iso

log = logging.getLogger(__name__)

CANDIDATE_SQL = {
    "failed_login_count": "outcome = 'failure' AND action IN ({})".format(", ".join(["%s"] * len(LOGIN_ACTIONS))),
    "distinct_404": "status_code = 404",
    "pattern": "target != ''",
    "bytes_sum": "bytes_sent > 0",
}


def _candidates(conn: Connection, rule: RuleConfig, since: str) -> dict[str, list[Row]]:
    params: list = [since]
    if rule.kind == "failed_login_count":
        params += LOGIN_ACTIONS
    rows = conn.execute(
        f"SELECT event_id, ts, client_ip, target, bytes_sent FROM event "
        f"WHERE ts >= %s AND client_ip IS NOT NULL AND {CANDIDATE_SQL[rule.kind]} ORDER BY ts, event_id",
        params,
    ).fetchall()
    groups: dict[str, list[Row]] = defaultdict(list)
    for r in rows:
        groups[r["client_ip"]].append(r)
    return groups


def _pattern_hit(patterns: list[re.Pattern[str]], target: str) -> bool:
    decoded = unquote_plus(target)
    return any(p.search(target) or p.search(decoded) for p in patterns)


def qualifying_events(rule: RuleConfig, events: list[Row]) -> set[int]:
    """Event ids that fall inside at least one window meeting the threshold."""
    if rule.kind == "pattern":
        compiled = [re.compile(p) for p in rule.patterns]
        return {e["event_id"] for e in events if _pattern_hit(compiled, e["target"])}

    times = [parse_iso(e["ts"]) for e in events]
    window = timedelta(seconds=rule.window_seconds)
    hits: set[int] = set()
    targets: Counter[str] = Counter()
    total = 0
    i = 0
    marked = 0  # events before this index are already in `hits`
    for j, ev in enumerate(events):
        targets[ev["target"]] += 1
        total += ev["bytes_sent"]
        while times[j] - times[i] > window:
            old = events[i]
            targets[old["target"]] -= 1
            if not targets[old["target"]]:
                del targets[old["target"]]
            total -= old["bytes_sent"]
            i += 1
        if rule.kind == "failed_login_count":
            met = j - i + 1 >= rule.threshold
        elif rule.kind == "distinct_404":
            met = len(targets) >= rule.threshold
        else:  # bytes_sum: strictly more than the threshold
            met = total > rule.threshold
        if met:
            for k in range(max(i, marked), j + 1):
                hits.add(events[k]["event_id"])
            marked = j + 1
    return hits


def run_detection(conn: Connection, cfg: Config, clock: Clock) -> list[int]:
    """Evaluate every enabled rule; returns ids of clusters created or extended."""
    now = clock.now()
    touched: list[int] = []
    for rule in cfg.detection.rules:
        if not rule.enabled:
            continue
        since = iso(now - timedelta(seconds=rule.window_seconds + cfg.detection.lookback_seconds))
        for group_key, events in _candidates(conn, rule, since).items():
            hits = qualifying_events(rule, events)
            if hits:
                cid = _assign(conn, rule, group_key, hits, now)
                if cid is not None:
                    touched.append(cid)
    return touched


def _assign(conn: Connection, rule: RuleConfig, group_key: str, hits: set[int], now) -> int | None:
    with transaction(conn) as c:
        already = {r[0] for r in c.execute(
            "SELECT ce.event_id FROM cluster_event ce JOIN cluster cl USING (cluster_id) "
            "WHERE cl.rule_id = %s AND cl.group_key = %s", (rule.id, group_key))}
        new = sorted(hits - already)
        if not new:
            return None
        open_row = c.execute(
            "SELECT cluster_id FROM cluster WHERE rule_id = %s AND group_key = %s AND state = 'FLAGGED' "
            "ORDER BY cluster_id DESC LIMIT 1", (rule.id, group_key)).fetchone()
        if open_row:
            cid = open_row["cluster_id"]
        else:
            # Frozen clusters take no new events (DD-09): start a linked one.
            prev = c.execute(
                "SELECT cluster_id FROM cluster WHERE rule_id = %s AND group_key = %s "
                "ORDER BY cluster_id DESC LIMIT 1", (rule.id, group_key)).fetchone()
            placeholder = iso(now)
            cid = one(c.execute(
                "INSERT INTO cluster (rule_id, severity, group_key, window_start, window_end, state, "
                "prev_cluster_id, created_at) VALUES (%s, %s, %s, %s, %s, 'FLAGGED', %s, %s) RETURNING cluster_id",
                (rule.id, rule.severity, group_key, placeholder, placeholder,
                 prev["cluster_id"] if prev else None, iso(now))))[0]
            log.info("cluster flagged: rule %s, %s, severity %s", rule.id, group_key, rule.severity,
                     extra={"cluster_id": cid})
        c.cursor().executemany("INSERT INTO cluster_event (cluster_id, event_id) VALUES (%s, %s) "
                               "ON CONFLICT DO NOTHING", [(cid, eid) for eid in new])
        c.execute(
            "UPDATE cluster SET window_start = (SELECT MIN(e.ts) FROM event e JOIN cluster_event ce "
            "USING (event_id) WHERE ce.cluster_id = %(c)s), window_end = (SELECT MAX(e.ts) FROM event e "
            "JOIN cluster_event ce USING (event_id) WHERE ce.cluster_id = %(c)s) WHERE cluster_id = %(c)s",
            {"c": cid})
    return cid
