"""Collector service: `python -m sec450.worker`.

The main loop collects and runs detection every interval. Triage, reports
and retention run on a second thread with their own connection, so a slow
LLM call never delays collection.

The work of one cycle lives in collection_cycle() and analysis_cycle() so
tests can drive exactly what the service runs, one step at a time.
"""
from __future__ import annotations

import logging
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

from .collector import Collector
from .config import Config, load_config
from .db import connect, init_db
from .detection import run_detection
from .geoip import GeoIP
from .logjson import setup_logging
from .mock_llm import MockLLMClient
from .reports import generate_pending_reports
from .retention import run_retention
from .timeutil import Clock
from .triage import ClaudeTriageClient, LLMClient, run_triage

log = logging.getLogger("sec450.worker")

# Touched after every collection cycle; the Docker healthcheck fails if it gets stale.
HEARTBEAT = Path(tempfile.gettempdir()) / "sec450-collector.heartbeat"


def make_triage_client(cfg: Config) -> LLMClient | None:
    """The configured LLM client, or None (clusters then go to TRIAGE_UNAVAILABLE)."""
    if not cfg.triage.enabled:
        return None
    if cfg.triage.client == "mock":
        log.warning("triage uses the MOCK LLM; AI assessments are placeholders")
        return MockLLMClient()
    if not cfg.triage.resolved_api_key():
        log.warning("no Claude API key configured; clusters will be marked TRIAGE_UNAVAILABLE")
        return None
    return ClaudeTriageClient(cfg.triage)


def collection_cycle(collector: Collector, conn: sqlite3.Connection, cfg: Config, clock: Clock) -> None:
    """Read new lines from every source, then evaluate the rules (REQ-01, REQ-03)."""
    collector.run_cycle()
    run_detection(conn, cfg, clock)


def analysis_cycle(conn: sqlite3.Connection, cfg: Config, clock: Clock, client: LLMClient | None) -> None:
    """Triage settled clusters, then write reports for finished high/critical ones (REQ-04, REQ-06)."""
    run_triage(conn, cfg, clock, client)
    generate_pending_reports(conn, cfg, clock)


def analysis_loop(cfg: Config, clock: Clock, stop: threading.Event) -> None:
    conn = connect(cfg.database_path)
    client = make_triage_client(cfg)
    last_retention = 0.0
    while not stop.is_set():
        try:
            analysis_cycle(conn, cfg, clock, client)
            if time.monotonic() - last_retention >= cfg.retention.run_every_seconds:
                run_retention(conn, cfg, clock)
                last_retention = time.monotonic()
        except Exception:
            log.exception("analysis cycle failed")
        stop.wait(cfg.triage.worker_interval_seconds)


def main() -> None:
    setup_logging()
    cfg = load_config()
    clock = Clock()
    conn = connect(cfg.database_path)
    init_db(conn)
    collector = Collector(cfg, conn, clock, GeoIP.from_config(cfg.geoip))

    stop = threading.Event()
    threading.Thread(target=analysis_loop, args=(cfg, clock, stop), daemon=True, name="analysis").start()
    interval = cfg.collector.interval_seconds
    log.info("collecting %d sources every %ds", len(cfg.sources), interval)
    try:
        while True:
            started = time.monotonic()
            try:
                collection_cycle(collector, conn, cfg, clock)
                HEARTBEAT.touch()
            except Exception:
                log.exception("collection cycle failed")
            time.sleep(max(0.0, interval - (time.monotonic() - started)))
    except KeyboardInterrupt:
        stop.set()


if __name__ == "__main__":
    main()
