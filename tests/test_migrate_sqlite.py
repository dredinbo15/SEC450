"""DD-06: the one-time SQLite -> PostgreSQL copy keeps ids, text and both hash chains."""
import json
import sqlite3

import pytest
import yaml

from sec450 import hashchain
from sec450.api.audit import write_audit
from sec450.db import connect
from sec450.keys import create_key, hash_key, lookup_key
from sec450.migrate_sqlite import main

from .conftest import ROOT

KEY = "sec450_migrated-key"


def _audit_row(prev: str, i: int) -> tuple:
    fields = {"ts": f"2026-10-08T14:00:{i:02d}.000000Z", "key_id": "k_old" if i % 2 else None, "method": "GET",
              "path": "/v1/events", "params_json": json.dumps({"user": f"ü{i}"}, ensure_ascii=False),
              "status_code": 200, "result_count": i}
    return (*fields.values(), prev, hashchain.audit_hash(prev, fields))


@pytest.fixture
def legacy(tmp_path):
    """A SQLite file in the old schema: retention already moved the batch anchor past batch 1."""
    path = tmp_path / "sec450.db"
    db = sqlite3.connect(path)
    db.executescript((ROOT / "tests" / "fixtures" / "sqlite_schema.sql").read_text(encoding="utf-8"))
    prev = "a" * 64                                        # hash of the deleted batch 1
    db.execute("INSERT INTO chain_anchor VALUES ('batch', 2, ?)", (prev,))
    raw_id = 10
    for batch_id in (2, 3, 4):
        at = f"2026-10-08T14:0{batch_id}:00.000000Z"
        lines = [f"line {batch_id}.{seq} ünïcode" for seq in range(3)]
        digest = hashchain.batch_hash(prev, "ssh_auth", at, lines)
        db.execute("INSERT INTO batch VALUES (?, 'ssh_auth', ?, 3, ?, ?)", (batch_id, at, prev, digest))
        prev = digest
        for seq, text in enumerate(lines):
            raw_id += 1
            db.execute("INSERT INTO raw_line VALUES (?, ?, ?, ?, 'parsed', NULL)", (raw_id, batch_id, seq, text))
            db.execute("INSERT INTO event (event_id, raw_id, ts, source, host, client_ip, action, target, outcome, "
                       "status_code, bytes_sent) VALUES (?, ?, ?, 'ssh_auth', 'ssh01', '203.0.113.5', 'ssh_login', "
                       "'sshd', 'failure', NULL, 0)", (raw_id + 100, raw_id, at))
    db.execute("INSERT INTO cluster (cluster_id, rule_id, severity, group_key, window_start, window_end, state, "
               "created_at) VALUES (7, 'R1', 'high', '203.0.113.5', 'a', 'b', 'REPORTED', 'c')")
    db.execute("INSERT INTO cluster (cluster_id, rule_id, severity, group_key, window_start, window_end, state, "
               "prev_cluster_id, created_at) VALUES (9, 'R1', 'high', '203.0.113.5', 'a', 'b', 'FLAGGED', 7, 'd')")
    db.execute("INSERT INTO cluster_event SELECT 7, event_id FROM event")
    db.execute("INSERT INTO report VALUES (5, 7, '2026-10-08T14:10:00.000000Z', '{\"summary\": \"x\"}')")
    db.execute("INSERT INTO triage_budget VALUES (7, '2026-10-08', 'called')")
    db.execute("INSERT INTO siem_delivery VALUES (5, 'e')")
    db.execute("INSERT INTO source_cursor VALUES ('ssh_auth', 154011418, 4096, 'f')")
    db.execute("INSERT INTO api_key VALUES ('k_old', ?, 0, '2026-10-01T00:00:00.000000Z')", (hash_key(KEY),))
    db.execute("INSERT INTO gap VALUES (3, 'app', 'g', NULL, 'unreadable')")
    db.execute("INSERT INTO deletion_record VALUES (4, 'h', 'batch', 'i', 'j', 1)")
    prev = hashchain.GENESIS
    for i in range(1, 6):
        row = _audit_row(prev, i)
        db.execute("INSERT INTO audit_entry (entry_id, ts, key_id, method, path, params_json, status_code, "
                   "result_count, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (i * 2, *row))
        prev = row[-1]
    db.commit()
    db.close()
    return path


@pytest.fixture
def config_file(cfg, tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(cfg.model_dump(mode="json")), encoding="utf-8")
    return path


def test_migration_keeps_rows_and_chains(cfg, config_file, legacy, capsys):
    assert main(["--config", str(config_file), str(legacy)]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["ok"] and summary["differences"] == {}
    assert summary["rows"]["event"] == 9 and summary["rows"]["audit_entry"] == 5
    assert summary["chains"] == {"batches": {"status": "intact", "batches": 3},
                                 "audit": {"status": "intact", "entries": 5}}

    conn = connect(cfg.database)
    assert lookup_key(conn, KEY) == "k_old"                # existing keys keep working
    # Identity columns continue after the copied ids; the chains continue too.
    write_audit(conn, "2026-10-08T15:00:00.000000Z", None, "GET", "/v1/reports", {}, 401, 0)
    assert conn.execute("SELECT MAX(entry_id) FROM audit_entry").fetchone()[0] == 11
    create_key(conn)
    cid = conn.execute("INSERT INTO cluster (rule_id, severity, group_key, window_start, window_end, state, "
                       "created_at) VALUES ('R2', 'medium', 'x', 'a', 'b', 'FLAGGED', 'c') RETURNING cluster_id"
                       ).fetchone()[0]
    assert cid == 10
    assert hashchain.verify_audit(conn)["status"] == "intact"


def test_migration_refuses_a_non_empty_target(cfg, config_file, legacy, capsys):
    assert main(["--config", str(config_file), str(legacy)]) == 0
    with pytest.raises(SystemExit, match="not empty"):
        main(["--config", str(config_file), str(legacy)])
    assert main(["--config", str(config_file), "--replace", str(legacy)]) == 0


def test_migration_reports_a_broken_source_chain(cfg, config_file, legacy, capsys):
    db = sqlite3.connect(legacy)
    db.execute("DROP TRIGGER raw_line_no_update")
    db.execute("UPDATE raw_line SET text = 'tampered' WHERE raw_id = 14")
    db.commit()
    db.close()
    assert main(["--config", str(config_file), str(legacy)]) == 1
    summary = json.loads(capsys.readouterr().out)
    assert summary["chains"]["batches"] == {"status": "broken", "batch_id": 3, "reason": "content hash mismatch"}
