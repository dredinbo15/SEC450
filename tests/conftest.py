from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from sec450 import hashchain
from sec450.config import Config
from sec450.db import connect, init_db, transaction
from sec450.timeutil import FixedClock, iso

ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 10, 8, 14, 0, 0, tzinfo=UTC)


@pytest.fixture
def cfg(tmp_path: Path) -> Config:
    data = yaml.safe_load((ROOT / "config.example.yaml").read_text(encoding="utf-8"))
    data["database_path"] = str(tmp_path / "test.db")
    for src in data["sources"]:
        src["path"] = str(tmp_path / f"{src['name']}.log")
    data["geoip"] = {}
    data["collector"]["retry_delay_seconds"] = 0
    return Config.model_validate(data)


@pytest.fixture
def conn(cfg: Config):
    c = connect(cfg.database_path)
    init_db(c)
    yield c
    c.close()


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(T0)


def insert_events(conn, events: list[dict], source: str = "app", collected_at: str | None = None) -> int:
    """Store events as one hash-chained batch, bypassing the parsers."""
    collected_at = collected_at or iso(T0)
    lines = [f"line {i} {e}" for i, e in enumerate(events)]
    with transaction(conn) as c:
        first_id, _ = hashchain.anchor(c, "batch")
        batch_id = max(c.execute("SELECT COALESCE(MAX(batch_id), 0) FROM batch").fetchone()[0] + 1, first_id or 1)
        prev = hashchain.last_hash(c, "batch")
        c.execute("INSERT INTO batch VALUES (?, ?, ?, ?, ?, ?)",
                  (batch_id, source, collected_at, len(lines), prev,
                   hashchain.batch_hash(prev, batch_id, source, collected_at, lines)))
        for seq, (text, e) in enumerate(zip(lines, events, strict=True)):
            raw_id = c.execute("INSERT INTO raw_line (batch_id, seq, text, status) VALUES (?, ?, ?, 'parsed')",
                               (batch_id, seq, text)).lastrowid
            row = {"ts": collected_at, "source": source, "host": "h", "client_ip": "203.0.113.5", "action": "GET",
                   "target": "/", "outcome": "success", "bytes_sent": 0, **e, "raw_id": raw_id}
            cols = ", ".join(row)
            c.execute(f"INSERT INTO event ({cols}) VALUES ({', '.join('?' * len(row))})", list(row.values()))
    return batch_id
