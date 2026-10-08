"""Collector service: `python -m sec450.worker`.

The main loop collects and runs detection every interval. Triage, reports
and retention run on a second thread with their own connection, so a slow
LLM call never delays collection.
"""
from __future__ import annotations

import logging
import threading
import time

from .collector import Collector
from .config import Config, load_config
from .db import connect, init_db
from .detection import run_detection
from .geoip import GeoIP
from .reports import generate_pending_reports
from .retention import run_retention
from .timeutil import Clock
from .triage import ClaudeTriageClient, run_triage

log = logging.getLogger("sec450.worker")


def analysis_loop(cfg: Config, clock: Clock, stop: threading.Event) -> None:
    conn = connect(cfg.database_path)
    client = ClaudeTriageClient(cfg.triage) if cfg.triage.enabled and cfg.triage.resolved_api_key() else None
    if cfg.triage.enabled and client is None:
        log.warning("no Claude API key configured; clusters will be marked triage_unavailable")
    last_retention = 0.0
    while not stop.is_set():
        try:
            run_triage(conn, cfg, clock, client)
            generate_pending_reports(conn, cfg, clock)
            if time.monotonic() - last_retention >= cfg.retention.run_every_seconds:
                run_retention(conn, cfg, clock)
                last_retention = time.monotonic()
        except Exception:
            log.exception("analysis cycle failed")
        stop.wait(cfg.triage.worker_interval_seconds)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
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
                collector.run_cycle()
                run_detection(conn, cfg, clock)
            except Exception:
                log.exception("collection cycle failed")
            time.sleep(max(0.0, interval - (time.monotonic() - started)))
    except KeyboardInterrupt:
        stop.set()


if __name__ == "__main__":
    main()
