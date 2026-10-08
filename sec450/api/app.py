"""HTTPS query endpoint (REQ-05, REQ-09, DD-10, DD-12).

Every /v1 request passes through one middleware that authenticates the key,
applies the rate limit, runs the handler, and writes a hash-chained audit
entry. If the audit entry cannot be written the client gets a 500 with no data.
"""
from __future__ import annotations

import logging
import sqlite3
from typing import Iterator

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from .. import hashchain
from ..config import Config
from ..db import connect, init_db
from ..keys import lookup_key
from ..timeutil import Clock, iso
from .audit import write_audit
from .query import QueryError, parse_query, query_clusters, query_events, query_reports
from .ratelimit import RateLimiter

log = logging.getLogger(__name__)


def create_app(cfg: Config, clock: Clock | None = None) -> FastAPI:
    clock = clock or Clock()
    limiter = RateLimiter(cfg.api.rate_limit_per_minute, clock)
    init_db(connect(cfg.database_path))

    app = FastAPI(title="SEC450 log analysis API", docs_url=None, redoc_url=None, openapi_url=None)

    def get_conn() -> Iterator[sqlite3.Connection]:
        conn = connect(cfg.database_path)
        try:
            yield conn
        finally:
            conn.close()

    def _authenticate(request: Request) -> str | None:
        auth = request.headers.get("authorization", "")
        key = auth[7:].strip() if auth.lower().startswith("bearer ") else request.headers.get("x-api-key")
        if not key:
            return None
        conn = connect(cfg.database_path)
        try:
            return lookup_key(conn, key)
        finally:
            conn.close()

    def _audit(key_id: str | None, request: Request, status: int, count: int) -> None:
        conn = connect(cfg.database_path)
        try:
            write_audit(conn, iso(clock.now()), key_id, request.method, request.url.path,
                        dict(request.query_params.multi_items()), status, count)
        finally:
            conn.close()

    @app.middleware("http")
    async def security(request: Request, call_next):
        if not request.url.path.startswith("/v1/"):
            return await call_next(request)
        key_id = await run_in_threadpool(_authenticate, request)
        if key_id is None:
            response = JSONResponse({"error": "missing, invalid or revoked API key"}, status_code=401,
                                    headers={"WWW-Authenticate": "Bearer"})
        elif (retry_after := limiter.check(key_id)) is not None:
            response = JSONResponse({"error": "rate limit exceeded"}, status_code=429,
                                    headers={"Retry-After": str(retry_after)})
        else:
            request.state.result_count = 0
            try:
                response = await call_next(request)
            except Exception:
                log.exception("unhandled error serving %s", request.url.path)
                response = JSONResponse({"error": "internal error"}, status_code=500)
        count = getattr(request.state, "result_count", 0) if response.status_code == 200 else 0
        try:
            await run_in_threadpool(_audit, key_id, request, response.status_code, count)
        except Exception:
            log.exception("audit write failed; failing closed")
            return JSONResponse({"error": "audit log unavailable"}, status_code=500)
        return response

    @app.exception_handler(QueryError)
    async def bad_query(_: Request, exc: QueryError) -> JSONResponse:
        return JSONResponse({"error": str(exc)}, status_code=400)

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/v1/events")
    def events(request: Request, conn: sqlite3.Connection = Depends(get_conn)) -> dict:
        result = query_events(conn, parse_query(request.query_params, cfg.api, clock.now()))
        request.state.result_count = result["count"]
        return result

    @app.get("/v1/clusters")
    def clusters(request: Request, conn: sqlite3.Connection = Depends(get_conn)) -> dict:
        result = query_clusters(conn, parse_query(request.query_params, cfg.api, clock.now()))
        request.state.result_count = result["count"]
        return result

    @app.get("/v1/reports")
    def reports(request: Request, conn: sqlite3.Connection = Depends(get_conn)) -> dict:
        result = query_reports(conn, parse_query(request.query_params, cfg.api, clock.now()))
        request.state.result_count = result["count"]
        return result

    @app.get("/v1/integrity")
    def integrity(request: Request, conn: sqlite3.Connection = Depends(get_conn)) -> dict:
        if request.query_params:
            raise QueryError("this endpoint takes no parameters")
        request.state.result_count = 1
        return {"batches": hashchain.verify_batches(conn), "audit": hashchain.verify_audit(conn)}

    return app
