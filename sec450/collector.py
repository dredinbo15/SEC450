"""Batch collection from shared log folders (REQ-01, REQ-07, REQ-08, DD-04, DD-05).

Each cycle reads the complete new lines of every source, stores them as one
hash-chained batch, parses each line into an event or quarantines it, and
advances the source cursor -- all in a single transaction, so a crash or
commit failure never loses or duplicates a line.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from . import hashchain
from .config import Config, SourceConfig
from .db import transaction
from .geoip import GeoIP
from .models import ParsedEvent, ParseError
from .parsers import PARSERS, ParseContext
from .timeutil import Clock, iso

log = logging.getLogger(__name__)


@dataclass
class ReadResult:
    lines: list[str]
    inode: int
    offset: int


def _read_from(path: Path, offset: int, include_partial: bool = False) -> tuple[list[str], int]:
    with path.open("rb") as fh:
        fh.seek(offset)
        data = fh.read()
    end = len(data) if include_partial else data.rfind(b"\n") + 1
    chunk = data[:end]
    lines = [ln.rstrip(b"\r").decode("utf-8", errors="replace") for ln in chunk.split(b"\n")]
    return [ln for ln in lines if ln], offset + end


def read_new_lines(path: Path, inode: int | None, offset: int) -> ReadResult:
    """Read complete lines appended since (inode, offset), following one rotation (file -> file.1)."""
    st = os.stat(path)
    lines: list[str] = []
    if inode is not None and st.st_ino != inode:
        rotated = path.with_name(path.name + ".1")
        if rotated.exists() and os.stat(rotated).st_ino == inode:
            lines, _ = _read_from(rotated, offset, include_partial=True)
        offset = 0
    elif st.st_size < offset:  # truncated in place
        offset = 0
    new, offset = _read_from(path, offset)
    return ReadResult(lines + new, st.st_ino, offset)


class Collector:
    def __init__(self, cfg: Config, conn: sqlite3.Connection, clock: Clock, geoip: GeoIP,
                 sleep: Callable[[float], None] = time.sleep):
        self.cfg = cfg
        self.conn = conn
        self.clock = clock
        self.geoip = geoip
        self.sleep = sleep
        self.health_warnings: list[dict] = []

    def run_cycle(self) -> None:
        """Collect every source; one source failing never blocks the others (REQ-01)."""
        for source in self.cfg.sources:
            try:
                self.collect_source(source)
            except Exception:
                log.exception("collection failed for %s; will retry next cycle", source.name)

    def collect_source(self, source: SourceConfig) -> int | None:
        """Collect one source; returns the new batch_id, or None if nothing was stored."""
        cursor = self.conn.execute(
            "SELECT inode, byte_offset FROM source_cursor WHERE source = ?", (source.name,)
        ).fetchone()
        inode, offset = (cursor["inode"], cursor["byte_offset"]) if cursor else (None, 0)

        result, error = None, None
        for attempt in range(self.cfg.collector.read_retries + 1):
            try:
                result = read_new_lines(Path(source.path), inode, offset)
                break
            except OSError as exc:
                error = exc
                if attempt < self.cfg.collector.read_retries:
                    self.sleep(self.cfg.collector.retry_delay_seconds)
        if result is None:
            self._open_gap(source.name, f"unreadable after {self.cfg.collector.read_retries} retries: {error}")
            return None
        self._close_gap(source.name)

        if not result.lines:
            with transaction(self.conn):
                self._save_cursor(source.name, result.inode, result.offset)
            return None
        return self._store_batch(source, result)

    def _store_batch(self, source: SourceConfig, result: ReadResult) -> int:
        now = self.clock.now()
        collected_at = iso(now)
        ctx = ParseContext(tz=source.timezone, now=now, trusted_proxies=self.cfg.collector.proxy_networks())
        parse = PARSERS[source.kind]
        skew = timedelta(seconds=self.cfg.collector.clock_skew_seconds)
        quarantined = 0

        with transaction(self.conn) as c:
            first_id, _ = hashchain.anchor(c, "batch")
            max_id = c.execute("SELECT COALESCE(MAX(batch_id), 0) FROM batch").fetchone()[0]
            batch_id = max(max_id + 1, first_id or 1)
            prev = hashchain.last_hash(c, "batch")
            digest = hashchain.batch_hash(prev, batch_id, source.name, collected_at, result.lines)
            c.execute(
                "INSERT INTO batch (batch_id, source, collected_at, line_count, prev_hash, hash) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (batch_id, source.name, collected_at, len(result.lines), prev, digest),
            )
            for seq, text in enumerate(result.lines):
                reason: str | None  # None = stored as an event; text = quarantine reason
                try:
                    ev = parse(text, ctx)
                except ParseError as exc:
                    reason = str(exc)
                except Exception as exc:  # a parser bug must not stall the source on this line forever
                    log.exception("parser %s crashed on batch %s line %s", source.kind, batch_id, seq)
                    reason = f"parser error: {type(exc).__name__}: {exc}"
                else:
                    reason = self._insert_event(c, source, batch_id, seq, text, ev, now + skew)
                    if reason is None:
                        continue
                quarantined += 1
                c.execute(
                    "INSERT INTO raw_line (batch_id, seq, text, status, quarantine_reason) "
                    "VALUES (?, ?, ?, 'quarantined', ?)", (batch_id, seq, text, reason))
            self._save_cursor(source.name, result.inode, result.offset)

        if quarantined / len(result.lines) > self.cfg.collector.quarantine_warn_ratio:
            warning = {"source": source.name, "batch_id": batch_id, "quarantined": quarantined,
                       "lines": len(result.lines), "at": collected_at}
            self.health_warnings.append(warning)
            log.warning("high quarantine rate: %s", warning)
        return batch_id

    def _insert_event(self, c: sqlite3.Connection, source: SourceConfig, batch_id: int, seq: int,
                      text: str, ev: ParsedEvent, anomaly_after: datetime) -> str | None:
        """Store a parsed line and its event; returns a quarantine reason if the event is unstorable.

        Runs in a savepoint so a bad value (e.g. an integer too large for SQLite) undoes only
        this line. Operational errors (locked, disk full) still propagate and retry the batch.
        """
        c.execute("SAVEPOINT line")
        try:
            raw_id = c.execute(
                "INSERT INTO raw_line (batch_id, seq, text, status) VALUES (?, ?, ?, 'parsed')",
                (batch_id, seq, text)).lastrowid
            asn, country = self.geoip.lookup(ev.client_ip)
            c.execute(
                "INSERT INTO event (raw_id, ts, source, host, client_ip, username, api_key_id, asn, "
                "country, action, target, outcome, status_code, bytes_sent, clock_anomaly) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (raw_id, iso(ev.ts), source.name, source.host, ev.client_ip, ev.username,
                 ev.api_key_id, asn, country, ev.action, ev.target, ev.outcome, ev.status_code,
                 ev.bytes_sent, int(ev.ts > anomaly_after)),
            )
        except (sqlite3.InterfaceError, sqlite3.IntegrityError, sqlite3.ProgrammingError,
                OverflowError, TypeError, ValueError) as exc:
            c.execute("ROLLBACK TO line")
            c.execute("RELEASE line")
            log.warning("unstorable event in batch %s line %s: %s", batch_id, seq, exc)
            return f"unstorable event: {type(exc).__name__}: {exc}"
        c.execute("RELEASE line")
        return None

    def _save_cursor(self, source: str, inode: int, offset: int) -> None:
        self.conn.execute(
            "INSERT INTO source_cursor (source, inode, byte_offset, last_read_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(source) DO UPDATE SET inode = excluded.inode, byte_offset = excluded.byte_offset, "
            "last_read_at = excluded.last_read_at",
            (source, inode, offset, iso(self.clock.now())),
        )

    def _open_gap(self, source: str, reason: str) -> None:
        with transaction(self.conn) as c:
            if not c.execute('SELECT 1 FROM gap WHERE source = ? AND "end" IS NULL', (source,)).fetchone():
                c.execute("INSERT INTO gap (source, start, reason) VALUES (?, ?, ?)",
                          (source, iso(self.clock.now()), reason))
                log.error("collection gap opened for %s: %s", source, reason)

    def _close_gap(self, source: str) -> None:
        with transaction(self.conn) as c:
            n = c.execute('UPDATE gap SET "end" = ? WHERE source = ? AND "end" IS NULL',
                          (iso(self.clock.now()), source)).rowcount
        if n:
            log.info("collection gap closed for %s", source)
