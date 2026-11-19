"""DD-06: the PostgreSQL helpers in sec450/db.py."""
import psycopg
import pytest

from sec450.db import Pool, connect, in_transaction, init_db, transaction
from sec450.worker import reconnect_if_closed

from .conftest import _admin


def test_row_reads_by_position_and_name(conn):
    row = conn.execute("SELECT 1 AS a, 'x' AS b").fetchone()
    assert row[0] == 1 and row["b"] == "x" and tuple(row) == (1, "x")
    assert dict(row) == {"a": 1, "b": "x"} and row.keys() == ["a", "b"]


def test_transaction_rolls_back_on_error(conn):
    with pytest.raises(psycopg.errors.UniqueViolation), transaction(conn) as c:
        c.execute("INSERT INTO api_key VALUES ('k1', 'h', 0, 't')")
        c.execute("INSERT INTO api_key VALUES ('k2', 'h', 0, 't')")   # same key_hash
    assert not in_transaction(conn)
    assert conn.execute("SELECT COUNT(*) FROM api_key").fetchone()[0] == 0


def _terminate(conn) -> None:
    pid = conn.info.backend_pid
    with _admin() as admin:
        admin.execute("SELECT pg_terminate_backend(%s)", (pid,))


def test_pool_reuses_and_replaces_dropped_connections(cfg):
    pool = Pool(cfg.database)
    with pool.connection() as first:
        pid = first.info.backend_pid
    with pool.connection() as again:
        assert again.info.backend_pid == pid             # reused, no new connection
        _terminate(again)
    with pool.connection() as fresh:                     # e.g. after a PostgreSQL restart
        assert fresh.info.backend_pid != pid
        assert fresh.execute("SELECT 1").fetchone()[0] == 1


def test_worker_reconnects_after_a_dropped_connection(cfg, conn):
    _terminate(conn)
    with pytest.raises(psycopg.OperationalError):
        conn.execute("SELECT 1")
    new = reconnect_if_closed(conn, cfg)
    assert new is not conn and new.execute("SELECT 1").fetchone()[0] == 1
    assert reconnect_if_closed(new, cfg) is new


def test_init_db_requires_c_collation(cfg):
    name = cfg.database.name + "_en"
    with _admin() as admin:
        admin.execute(f"CREATE DATABASE {name} TEMPLATE template0 LC_COLLATE 'en_US.utf8' LC_CTYPE 'en_US.utf8'")
    try:
        with connect(cfg.database.model_copy(update={"name": name})) as other:
            with pytest.raises(RuntimeError, match="collation"):
                init_db(other)
    finally:
        with _admin() as admin:
            admin.execute(f"DROP DATABASE {name} WITH (FORCE)")
