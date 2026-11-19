from __future__ import annotations

import os
import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import pytest
import yaml
from psycopg.conninfo import conninfo_to_dict

from sec450 import hashchain
from sec450.config import Config
from sec450.db import SCHEMA, connect, init_db, transaction
from sec450.timeutil import FixedClock, iso

ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 10, 8, 14, 0, 0, tzinfo=UTC)

# A PostgreSQL server the tests may create and drop databases on. The default matches
# the throwaway container in README.md ("Running the tests"); CI sets its service here.
TEST_SERVER = os.environ.get("SEC450_TEST_DATABASE_URL", "postgresql://postgres:test@127.0.0.1:55432/postgres")
TEMPLATE = "sec450_test_template"


def _admin() -> psycopg.Connection:
    return psycopg.connect(TEST_SERVER, autocommit=True)


@pytest.fixture(scope="session")
def _template_db():
    """A database holding the schema; every test gets a fresh copy of it (CREATE DATABASE ... TEMPLATE)."""
    with _admin() as admin:
        admin.execute(f"DROP DATABASE IF EXISTS {TEMPLATE} WITH (FORCE)")
        admin.execute(f"CREATE DATABASE {TEMPLATE} TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'")
    with psycopg.connect(TEST_SERVER, dbname=TEMPLATE, autocommit=True) as c:
        c.execute(SCHEMA)
    yield
    with _admin() as admin:
        admin.execute(f"DROP DATABASE IF EXISTS {TEMPLATE} WITH (FORCE)")


@pytest.fixture
def database(_template_db) -> dict:
    """Connection settings (config.yaml's database section) for a new, empty database."""
    name = f"sec450_test_{uuid.uuid4().hex[:12]}"
    with _admin() as admin:
        admin.execute(f"CREATE DATABASE {name} TEMPLATE {TEMPLATE}")
    server = conninfo_to_dict(TEST_SERVER)
    os.environ["SEC450_TEST_DB_PASSWORD"] = str(server.get("password", ""))
    yield {"host": server.get("host", "localhost"), "port": int(server.get("port", 5432)), "name": name,
           "user": server.get("user", "postgres"), "password_env": "SEC450_TEST_DB_PASSWORD"}
    with _admin() as admin:
        admin.execute(f"DROP DATABASE {name} WITH (FORCE)")


@pytest.fixture
def cfg(tmp_path: Path, database: dict) -> Config:
    data = yaml.safe_load((ROOT / "config.example.yaml").read_text(encoding="utf-8"))
    data["database"] = database
    for src in data["sources"]:
        src["path"] = str(tmp_path / f"{src['name']}.log")
    data["geoip"] = {}
    data["collector"]["retry_delay_seconds"] = 0
    return Config.model_validate(data)


@pytest.fixture
def slice_cfg(cfg: Config) -> Config:
    """Only the SSH source, fed from the brute-force fixture (other sources would just open gaps)."""
    ssh = next(s for s in cfg.sources if s.kind == "ssh_auth")
    shutil.copyfile(ROOT / "tests" / "fixtures" / "logs" / "ssh_bruteforce.log", ssh.path)
    cfg.sources = [ssh]
    return cfg


@pytest.fixture
def conn(cfg: Config):
    c = connect(cfg.database)
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
        c.execute("INSERT INTO batch VALUES (%s, %s, %s, %s, %s, %s)",
                  (batch_id, source, collected_at, len(lines), prev,
                   hashchain.batch_hash(prev, source, collected_at, lines)))
        for seq, (text, e) in enumerate(zip(lines, events, strict=True)):
            raw_id = c.execute("INSERT INTO raw_line (batch_id, seq, text, status) VALUES (%s, %s, %s, 'parsed') "
                               "RETURNING raw_id", (batch_id, seq, text)).fetchone()[0]
            row = {"ts": collected_at, "source": source, "host": "h", "client_ip": "203.0.113.5", "action": "GET",
                   "target": "/", "outcome": "success", "bytes_sent": 0, **e, "raw_id": raw_id}
            cols = ", ".join(row)
            c.execute(f"INSERT INTO event ({cols}) VALUES ({', '.join(['%s'] * len(row))})", list(row.values()))
    return batch_id
