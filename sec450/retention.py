"""Retention: delete expired batches and reports, record each deletion, move the chain anchor
(REQ-08, DD-08, AC-22)."""
from __future__ import annotations

import logging
from datetime import timedelta

from .config import Config
from .db import Connection, Row, one, transaction
from .timeutil import Clock, iso

log = logging.getLogger(__name__)


def _record(c: Connection, now: str, object_type: str, row: Row) -> None:
    if row["n"]:
        c.execute(
            "INSERT INTO deletion_record (deleted_at, object_type, oldest_deleted, newest_deleted, count) "
            "VALUES (%s, %s, %s, %s, %s)", (now, object_type, row["oldest"], row["newest"], row["n"]))


def run_retention(conn: Connection, cfg: Config, clock: Clock) -> None:
    now_dt = clock.now()
    now = iso(now_dt)
    event_cutoff = iso(now_dt - timedelta(days=cfg.retention.event_days))
    report_cutoff = iso(now_dt - timedelta(days=cfg.retention.report_days))

    with transaction(conn) as c:
        expired = "SELECT batch_id FROM batch WHERE collected_at < %(cut)s"
        last = c.execute(
            f"SELECT batch_id, hash FROM batch WHERE batch_id IN ({expired}) ORDER BY batch_id DESC LIMIT 1",
            {"cut": event_cutoff}).fetchone()
        if last:
            _record(c, now, "event", one(c.execute(
                f"SELECT COUNT(*) n, MIN(ts) oldest, MAX(ts) newest FROM event e JOIN raw_line r USING (raw_id) "
                f"WHERE r.batch_id IN ({expired})", {"cut": event_cutoff})))
            _record(c, now, "raw_line", one(c.execute(
                f"SELECT COUNT(*) n, MIN(b.collected_at) oldest, MAX(b.collected_at) newest FROM raw_line r "
                f"JOIN batch b USING (batch_id) WHERE r.batch_id IN ({expired})", {"cut": event_cutoff})))
            _record(c, now, "batch", one(c.execute(
                "SELECT COUNT(*) n, MIN(collected_at) oldest, MAX(collected_at) newest FROM batch "
                "WHERE collected_at < %s", (event_cutoff,))))
            # Cascades remove raw lines, events and cluster memberships.
            c.execute("DELETE FROM batch WHERE batch_id <= %s", (last["batch_id"],))
            # The next retained batch must chain from the last deleted hash (DD-08).
            c.execute(
                "INSERT INTO chain_anchor (chain, first_retained_id, anchor_hash) VALUES ('batch', %s, %s) "
                "ON CONFLICT (chain) DO UPDATE SET first_retained_id = excluded.first_retained_id, "
                "anchor_hash = excluded.anchor_hash", (last["batch_id"] + 1, last["hash"]))
            log.info("retention deleted batches up to %s", last["batch_id"])

        reports = one(c.execute("SELECT COUNT(*) n, MIN(generated_at) oldest, MAX(generated_at) newest "
                                "FROM report WHERE generated_at < %s", (report_cutoff,)))
        if reports["n"]:
            _record(c, now, "report", reports)
            c.execute("DELETE FROM report WHERE generated_at < %s", (report_cutoff,))
            log.info("retention deleted %d reports", reports["n"])
