import json
from datetime import timedelta
from pathlib import Path

import pytest

from sec450.collector import Collector
from sec450.config import Config
from sec450.geoip import GeoIP
from sec450.hashchain import verify_batches
from sec450.retention import run_retention
from sec450.timeutil import iso

from .conftest import T0, insert_events


def app_line(i: int, ts: str = "2026-10-08T14:00:00Z") -> str:
    return json.dumps({"ts": ts, "event": "view", "outcome": "success", "path": f"/p/{i}"}) + "\n"


def app_source(cfg: Config):
    return next(s for s in cfg.sources if s.name == "app")


def test_quarantine_and_health_warning(cfg, conn, clock):  # AC-17
    src = app_source(cfg)
    collector = Collector(cfg, conn, clock, GeoIP())
    for bad in (4, 5, 6):
        with Path(src.path).open("a", encoding="utf-8") as fh:
            for i in range(100):
                fh.write("{broken\n" if i < bad else app_line(i))
        collector.collect_source(src)
    assert conn.execute("SELECT COUNT(*) FROM raw_line WHERE status = 'quarantined'").fetchone()[0] == 15
    assert [w["quarantined"] for w in collector.health_warnings] == [6]


def test_clock_anomaly_boundary(cfg, conn, clock):  # AC-19
    src = app_source(cfg)
    with Path(src.path).open("a", encoding="utf-8") as fh:
        fh.write(app_line(1, iso(T0 + timedelta(minutes=4, seconds=59))))
        fh.write(app_line(2, iso(T0 + timedelta(minutes=5, seconds=1))))
    Collector(cfg, conn, clock, GeoIP()).collect_source(src)
    assert [r[0] for r in conn.execute("SELECT clock_anomaly FROM event ORDER BY event_id")] == [0, 1]


def test_gap_opens_after_retries_and_closes(cfg, conn, clock):  # AC-18
    src = app_source(cfg)
    collector = Collector(cfg, conn, clock, GeoIP())
    collector.collect_source(src)  # file missing
    assert conn.execute('SELECT COUNT(*) FROM gap WHERE "end" IS NULL').fetchone()[0] == 1
    Path(src.path).write_text(app_line(0), encoding="utf-8")
    clock.advance(60)
    collector.collect_source(src)
    assert conn.execute('SELECT COUNT(*) FROM gap WHERE "end" IS NOT NULL').fetchone()[0] == 1


def test_raw_line_update_rejected(conn):  # AC-20
    insert_events(conn, [{}])
    with pytest.raises(Exception, match="immutable"):
        conn.execute("UPDATE raw_line SET text = 'x'")


def test_tamper_detection(conn):  # AC-21
    for _ in range(50):
        insert_events(conn, [{}])
    assert verify_batches(conn)["status"] == "intact"

    conn.execute("DROP TRIGGER raw_line_no_update")
    original = conn.execute("SELECT text FROM raw_line WHERE batch_id = 23").fetchone()[0]
    conn.execute("UPDATE raw_line SET text = ? WHERE batch_id = 23", ("X" + original[1:],))
    assert verify_batches(conn) == {"status": "broken", "batch_id": 23, "reason": "content hash mismatch"}

    conn.execute("UPDATE raw_line SET text = ? WHERE batch_id = 23", (original,))
    conn.execute("DELETE FROM batch WHERE batch_id = 30")
    assert verify_batches(conn)["batch_id"] in (30, 31)


def test_retention_boundaries(cfg, conn, clock):  # AC-22
    old = insert_events(conn, [{"ts": "x"}], collected_at=iso(T0 - timedelta(days=30, hours=1)))
    insert_events(conn, [{"ts": "y"}], collected_at=iso(T0 - timedelta(days=29, hours=23)))
    conn.execute("INSERT INTO cluster (rule_id, severity, group_key, window_start, window_end, state, created_at) "
                 "VALUES ('R1','high','ip','a','b','REPORTED','c'), ('R1','high','ip2','a','b','REPORTED','c')")
    conn.execute("INSERT INTO report (cluster_id, generated_at, body_json) VALUES (1, ?, '{}'), (2, ?, '{}')",
                 (iso(T0 - timedelta(days=90, hours=1)), iso(T0 - timedelta(days=89, hours=23))))
    run_retention(conn, cfg, clock)
    assert [r[0] for r in conn.execute("SELECT batch_id FROM batch")] == [old + 1]
    assert conn.execute("SELECT COUNT(*) FROM report").fetchone()[0] == 1
    types = sorted(r[0] for r in conn.execute("SELECT object_type FROM deletion_record"))
    assert types == ["batch", "event", "raw_line", "report"]
    assert verify_batches(conn)["status"] == "intact"
