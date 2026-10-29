import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest
import yaml

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


def test_ac21_batch_hash_matches_design_formula(conn):
    """DD-07: hash = SHA-256(prev_hash | source | collected_at | SHA-256(lines)), recomputed by hand."""
    insert_events(conn, [{}, {}], source="ssh_auth")
    b = conn.execute("SELECT * FROM batch").fetchone()
    lines = [r[0] for r in conn.execute("SELECT text FROM raw_line WHERE batch_id = ? ORDER BY seq", (b["batch_id"],))]
    lines_hash = hashlib.sha256("\n".join(lines).encode()).hexdigest()
    expected = hashlib.sha256(f"{'0' * 64}|ssh_auth|{b['collected_at']}|{lines_hash}".encode()).hexdigest()
    assert b["prev_hash"] == "0" * 64 and b["hash"] == expected


def test_ac21_source_name_cannot_contain_separator(cfg):
    data = cfg.model_dump(mode="json")
    data["sources"][0]["name"] = "bad|name"
    with pytest.raises(ValueError, match="source name"):
        Config.model_validate(data)


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


def test_ac21_verify_command(cfg, conn, tmp_path, capsys):
    """`python -m sec450.verify` exits 0 when intact and 1 with the broken batch id when not."""
    from sec450 import verify
    config_file = tmp_path / "config.yaml"
    config_file.write_text(yaml.safe_dump(cfg.model_dump(mode="json")), encoding="utf-8")
    for _ in range(3):
        insert_events(conn, [{}])
    assert verify.main(["--config", str(config_file)]) == 0

    conn.execute("DROP TRIGGER raw_line_no_update")
    conn.execute("UPDATE raw_line SET text = 'tampered' WHERE batch_id = 2")
    capsys.readouterr()
    assert verify.main(["--config", str(config_file)]) == 1
    assert json.loads(capsys.readouterr().out)["batches"]["batch_id"] == 2


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


def test_invalid_utf8_is_kept_byte_for_byte(cfg, conn, clock):  # REQ-08
    src = app_source(cfg)
    bad = app_line(1).encode().replace(b"/p/1", b"/p/\xff\xfe").rstrip(b"\n")
    Path(src.path).write_bytes(bad + b"\n" + app_line(2).encode())
    Collector(cfg, conn, clock, GeoIP()).collect_source(src)
    rows = conn.execute("SELECT text, raw_bytes FROM raw_line ORDER BY seq").fetchall()
    assert rows[0]["raw_bytes"] == bad and "�" in rows[0]["text"]
    assert rows[1]["raw_bytes"] is None                                  # valid UTF-8: text alone is exact
    assert verify_batches(conn)["status"] == "intact"

    conn.execute("DROP TRIGGER raw_line_no_update")
    conn.execute("UPDATE raw_line SET raw_bytes = ? WHERE seq = 0", (bad.replace(b"\xff", b"\xfd"),))
    assert verify_batches(conn)["reason"] == "content hash mismatch"     # the hash covers the bytes as read


def test_report_integrity_rehashes_only_its_own_batches(conn):  # REQ-06, REQ-08
    from sec450.reports import integrity
    a = insert_events(conn, [{}])
    b = insert_events(conn, [{}])
    conn.execute("DROP TRIGGER raw_line_no_update")
    conn.execute("UPDATE raw_line SET text = 'tampered' WHERE batch_id = ?", (a,))
    assert integrity(conn, {b})["status"] == "intact"                    # another batch's lines: not this report's
    broken = integrity(conn, {a})
    assert (broken["status"], broken["batch_id"]) == ("broken", a)
    conn.execute("UPDATE batch SET lines_hash = ? WHERE batch_id = ?", ("0" * 64, a))
    assert integrity(conn, {b})["status"] == "broken"                    # a forged lines_hash breaks the chain


def test_database_from_before_lines_hash_is_migrated(tmp_path):
    """init_db adds the new columns to an older database; its batches still verify from their lines."""
    import sqlite3

    from sec450 import hashchain
    from sec450.db import connect, init_db
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.executescript(
        "CREATE TABLE batch (batch_id INTEGER PRIMARY KEY, source TEXT NOT NULL, collected_at TEXT NOT NULL, "
        "line_count INTEGER NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL UNIQUE);"
        "CREATE TABLE raw_line (raw_id INTEGER PRIMARY KEY, batch_id INTEGER NOT NULL, seq INTEGER NOT NULL, "
        "text TEXT NOT NULL, status TEXT NOT NULL, quarantine_reason TEXT, UNIQUE (batch_id, seq));")
    digest = hashchain.batch_hash(hashchain.GENESIS, "app", iso(T0), ["a", "b"])
    old.execute("INSERT INTO batch VALUES (1, 'app', ?, 2, ?, ?)", (iso(T0), hashchain.GENESIS, digest))
    old.executemany("INSERT INTO raw_line (batch_id, seq, text, status) VALUES (1, ?, ?, 'parsed')",
                    [(0, "a"), (1, "b")])
    old.commit()
    old.close()

    conn = connect(path)
    init_db(conn)
    init_db(conn)                                                        # a second start is a no-op
    assert {"lines_hash"} <= {r["name"] for r in conn.execute("PRAGMA table_info(batch)")}
    assert {"raw_bytes"} <= {r["name"] for r in conn.execute("PRAGMA table_info(raw_line)")}
    assert verify_batches(conn, content_ids=set()) == {"status": "intact", "batches": 1}
    conn.close()
