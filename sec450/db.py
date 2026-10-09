"""SQLite schema (docs/images/data_diagram_schema.jpg) and connection helpers (DD-06)."""
from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS source_cursor (
    source        TEXT PRIMARY KEY,
    inode         INTEGER,
    byte_offset   INTEGER NOT NULL DEFAULT 0,
    last_read_at  TEXT
);

CREATE TABLE IF NOT EXISTS batch (
    batch_id      INTEGER PRIMARY KEY,
    source        TEXT NOT NULL,
    collected_at  TEXT NOT NULL,
    line_count    INTEGER NOT NULL CHECK (line_count >= 1),
    prev_hash     TEXT NOT NULL,
    hash          TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS raw_line (
    raw_id             INTEGER PRIMARY KEY,
    batch_id           INTEGER NOT NULL REFERENCES batch(batch_id) ON DELETE CASCADE,
    seq                INTEGER NOT NULL,
    text               TEXT NOT NULL,
    status             TEXT NOT NULL CHECK (status IN ('parsed', 'quarantined')),
    quarantine_reason  TEXT,
    UNIQUE (batch_id, seq)
);

-- Raw lines are evidence: never modified after insert (REQ-08, AC-20).
CREATE TRIGGER IF NOT EXISTS raw_line_no_update
BEFORE UPDATE ON raw_line
BEGIN
    SELECT RAISE(ABORT, 'raw_line is immutable');
END;

CREATE TABLE IF NOT EXISTS event (
    event_id       INTEGER PRIMARY KEY,
    raw_id         INTEGER NOT NULL UNIQUE REFERENCES raw_line(raw_id) ON DELETE CASCADE,
    ts             TEXT NOT NULL,
    source         TEXT NOT NULL,
    host           TEXT NOT NULL,
    client_ip      TEXT,
    username       TEXT,
    api_key_id     TEXT,
    asn            INTEGER,
    country        TEXT,
    action         TEXT NOT NULL,
    target         TEXT NOT NULL,
    outcome        TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'unknown')),
    status_code    INTEGER,
    bytes_sent     INTEGER NOT NULL DEFAULT 0,
    clock_anomaly  INTEGER NOT NULL DEFAULT 0 CHECK (clock_anomaly IN (0, 1))
);
CREATE INDEX IF NOT EXISTS ix_event_ts ON event(ts);
CREATE INDEX IF NOT EXISTS ix_event_ip_ts ON event(client_ip, ts);
CREATE INDEX IF NOT EXISTS ix_event_user_ts ON event(username, ts);

CREATE TABLE IF NOT EXISTS cluster (
    cluster_id               INTEGER PRIMARY KEY,
    rule_id                  TEXT NOT NULL,
    severity                 TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    group_key                TEXT NOT NULL,
    window_start             TEXT NOT NULL,
    window_end               TEXT NOT NULL,
    -- Lifecycle diagram: sec450/models.py CLUSTER_STATES
    state                    TEXT NOT NULL CHECK (state IN ('FLAGGED', 'TRIAGE_PENDING', 'TRIAGED',
                                 'TRIAGE_UNAVAILABLE', 'DONE', 'REPORTED')),
    prev_cluster_id          INTEGER REFERENCES cluster(cluster_id),
    ai_classification        TEXT,
    ai_recommended_severity  TEXT,
    ai_explanation           TEXT CHECK (ai_explanation IS NULL OR length(ai_explanation) <= 500),
    ai_model                 TEXT,
    ai_received_at           TEXT,
    created_at               TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_cluster_rule ON cluster(rule_id, group_key, state);
CREATE INDEX IF NOT EXISTS ix_cluster_sev ON cluster(severity, created_at);

CREATE TABLE IF NOT EXISTS cluster_event (
    cluster_id  INTEGER NOT NULL REFERENCES cluster(cluster_id) ON DELETE CASCADE,
    event_id    INTEGER NOT NULL REFERENCES event(event_id) ON DELETE CASCADE,
    PRIMARY KEY (cluster_id, event_id)
);
CREATE INDEX IF NOT EXISTS ix_cluster_event_event ON cluster_event(event_id);

CREATE TABLE IF NOT EXISTS report (
    report_id     INTEGER PRIMARY KEY,
    cluster_id    INTEGER NOT NULL UNIQUE REFERENCES cluster(cluster_id),
    generated_at  TEXT NOT NULL,
    body_json     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_key (
    key_id      TEXT PRIMARY KEY,
    key_hash    TEXT NOT NULL UNIQUE,
    revoked     INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_entry (
    entry_id      INTEGER PRIMARY KEY,
    ts            TEXT NOT NULL,
    key_id        TEXT REFERENCES api_key(key_id),
    method        TEXT NOT NULL,
    path          TEXT NOT NULL,
    params_json   TEXT NOT NULL,
    status_code   INTEGER NOT NULL,
    result_count  INTEGER NOT NULL,
    prev_hash     TEXT NOT NULL,
    hash          TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS gap (
    gap_id  INTEGER PRIMARY KEY,
    source  TEXT NOT NULL,
    start   TEXT NOT NULL,
    "end"   TEXT,
    reason  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS deletion_record (
    deletion_id     INTEGER PRIMARY KEY,
    deleted_at      TEXT NOT NULL,
    object_type     TEXT NOT NULL,
    oldest_deleted  TEXT,
    newest_deleted  TEXT,
    count           INTEGER NOT NULL
);

-- Where hash-chain verification starts after retention deletes old rows (DD-08).
CREATE TABLE IF NOT EXISTS chain_anchor (
    chain              TEXT PRIMARY KEY CHECK (chain IN ('batch', 'audit')),
    first_retained_id  INTEGER,
    anchor_hash        TEXT NOT NULL
);
"""


def connect(path: str | Path) -> sqlite3.Connection:
    """Open a connection in autocommit mode; use transaction() for writes."""
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """BEGIN IMMEDIATE ... COMMIT, rolling back on any exception.

    A failed COMMIT (e.g. SQLITE_BUSY) leaves SQLite's transaction open, so it
    is rolled back too; otherwise every later BEGIN would fail (AC-03).
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
