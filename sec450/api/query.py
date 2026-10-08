"""Query parameter validation and filtered reads (REQ-05, REQ-10, AC-13, AC-14)."""
from __future__ import annotations

import ipaddress
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta

from starlette.datastructures import QueryParams

from ..config import SEVERITY_ORDER, ApiConfig
from ..reports import overlapping_gaps
from ..timeutil import iso, parse_iso

ALLOWED_PARAMS = {"start", "end", "source_ip", "user", "severity", "limit"}


class QueryError(ValueError):
    pass


@dataclass
class Query:
    start: str
    end: str
    source_ip: str | None
    user: str | None
    severity: str | None
    limit: int


def parse_query(params: QueryParams, cfg: ApiConfig, now: datetime) -> Query:
    unknown = set(params.keys()) - ALLOWED_PARAMS
    if unknown:
        raise QueryError(f"unknown parameter(s): {', '.join(sorted(unknown))}")
    for key in params.keys():
        if len(params.getlist(key)) > 1:
            raise QueryError(f"parameter {key!r} given more than once")
        if params[key] == "":
            raise QueryError(f"parameter {key!r} is empty")

    def ts(name: str) -> datetime | None:
        if name not in params:
            return None
        try:
            return parse_iso(params[name])
        except ValueError:
            raise QueryError(f"{name} must be an ISO 8601 timestamp with a UTC offset") from None

    start, end = ts("start"), ts("end")
    if end is None:
        end = now
    if start is None:
        start = end - timedelta(hours=cfg.default_span_hours)
    if start >= end:
        raise QueryError("start must be before end")
    if end - start > timedelta(days=cfg.max_span_days):
        raise QueryError(f"time range may not exceed {cfg.max_span_days} days")

    source_ip = None
    if "source_ip" in params:
        try:
            source_ip = str(ipaddress.ip_address(params["source_ip"]))
        except ValueError:
            raise QueryError("source_ip is not a valid IPv4 or IPv6 address") from None

    severity = params.get("severity")
    if severity is not None and severity not in SEVERITY_ORDER:
        raise QueryError(f"severity must be one of {', '.join(SEVERITY_ORDER)}")

    limit = cfg.default_limit
    if "limit" in params:
        try:
            limit = int(params["limit"])
        except ValueError:
            raise QueryError("limit must be an integer") from None
        if not 1 <= limit <= cfg.max_limit:
            raise QueryError(f"limit must be between 1 and {cfg.max_limit}")

    return Query(iso(start), iso(end), source_ip, params.get("user"), severity, limit)


def _envelope(conn: sqlite3.Connection, q: Query, key: str, items: list) -> dict:
    return {
        "query": {"start": q.start, "end": q.end, "source_ip": q.source_ip, "user": q.user,
                  "severity": q.severity, "limit": q.limit},
        "count": len(items),
        "collection_gaps": overlapping_gaps(conn, q.start, q.end),
        key: items,
    }


def query_events(conn: sqlite3.Connection, q: Query) -> dict:
    sql = ["SELECT * FROM event e WHERE e.ts >= ? AND e.ts <= ?"]
    args: list = [q.start, q.end]
    if q.source_ip:
        sql.append("AND e.client_ip = ?")
        args.append(q.source_ip)
    if q.user:
        sql.append("AND e.username = ?")
        args.append(q.user)
    if q.severity:
        sql.append("AND EXISTS (SELECT 1 FROM cluster_event ce JOIN cluster c USING (cluster_id) "
                   "WHERE ce.event_id = e.event_id AND c.severity = ?)")
        args.append(q.severity)
    sql.append("ORDER BY e.ts DESC, e.event_id DESC LIMIT ?")
    args.append(q.limit)
    rows = [dict(r) for r in conn.execute(" ".join(sql), args)]
    for r in rows:
        r["clock_anomaly"] = bool(r["clock_anomaly"])
    return _envelope(conn, q, "events", rows)


def _cluster_filters(q: Query) -> tuple[str, list]:
    sql = ["c.window_start <= ? AND c.window_end >= ?"]
    args: list = [q.end, q.start]
    if q.source_ip:
        sql.append("AND c.group_key = ?")
        args.append(q.source_ip)
    if q.user:
        sql.append("AND EXISTS (SELECT 1 FROM cluster_event ce JOIN event e USING (event_id) "
                   "WHERE ce.cluster_id = c.cluster_id AND e.username = ?)")
        args.append(q.user)
    if q.severity:
        sql.append("AND c.severity = ?")
        args.append(q.severity)
    return " ".join(sql), args


def query_clusters(conn: sqlite3.Connection, q: Query) -> dict:
    where, args = _cluster_filters(q)
    rows = conn.execute(
        f"SELECT c.*, (SELECT COUNT(*) FROM cluster_event ce WHERE ce.cluster_id = c.cluster_id) AS event_count "
        f"FROM cluster c WHERE {where} ORDER BY c.window_end DESC, c.cluster_id DESC LIMIT ?",
        [*args, q.limit]).fetchall()
    items = []
    for r in rows:
        item = {k: r[k] for k in ("cluster_id", "rule_id", "severity", "group_key", "window_start",
                                  "window_end", "state", "prev_cluster_id", "created_at", "event_count")}
        item["ai_assessment"] = None if r["ai_classification"] is None else {
            "label": "AI-generated, advisory only", "classification": r["ai_classification"],
            "recommended_severity": r["ai_recommended_severity"], "explanation": r["ai_explanation"],
            "model": r["ai_model"], "received_at": r["ai_received_at"]}
        items.append(item)
    return _envelope(conn, q, "clusters", items)


def query_reports(conn: sqlite3.Connection, q: Query) -> dict:
    where, args = _cluster_filters(q)
    rows = conn.execute(
        f"SELECT r.report_id, r.cluster_id, r.generated_at, r.body_json FROM report r "
        f"JOIN cluster c USING (cluster_id) WHERE {where} ORDER BY r.generated_at DESC LIMIT ?",
        [*args, q.limit]).fetchall()
    items = [{"report_id": r["report_id"], "cluster_id": r["cluster_id"],
              "generated_at": r["generated_at"], "body": json.loads(r["body_json"])} for r in rows]
    return _envelope(conn, q, "reports", items)
