"""Course testing interface: the system and tester /test endpoints (docs/testing-interface.md).

System (base URL https://seclog.redinbo.win):
    POST /test/setup   {session_id, setup}  -> 201 {session_id}
    GET  /test/report?session_id=...        -> 200 {session_id, coverage: {code}}
Tester (base URL https://seclog.redinbo.win/tester):
    POST /test/setup   {target_url}         -> 201 {session_id}, after the target's setup confirms it
    POST /test/run     {session_id}         -> 200 suite report (runs once per session)
    GET  /test/report?session_id=...        -> 200 the stored suite report

Errors on these endpoints are {"message", "source"}. None of them need an API key: system setup
only registers the session (it never deletes collected logs, which REQ-08 keeps immutable), and
when the tester targets this deployment it creates a read-only key for the run and revokes it
afterwards, so every /v1 call it makes is authenticated, rate limited and audited like any other.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import ssl
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Any
from urllib.parse import urlsplit

import certifi
import httpcore
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from ..config import Config
from ..db import connect
from ..keys import create_key, revoke_key
from ..timeutil import Clock
from .ratelimit import RateLimiter

log = logging.getLogger(__name__)

# The operations of our interface (README REQ-05, REQ-09 and this module) the suite can exercise.
OPERATIONS = ("GET /health", "GET /v1/events", "GET /v1/clusters", "GET /v1/reports",
              "GET /v1/reports/{id}", "GET /v1/integrity", "POST /test/setup", "GET /test/report")
ACCEPTANCE_CRITERIA = 30          # AC-01 to AC-30 in README.md
REPORT_FIELDS = ("summary", "matched_rule", "requester", "data_destination", "timeline",
                 "ai_assessment", "raw_lines", "integrity")       # REQ-06
MAX_SESSIONS = 500                # oldest sessions are forgotten past this (memory bound)
REQUEST_TIMEOUT = 20.0
# These endpoints need no credentials and share the API's worker threads, so their cost is
# bounded: at most this many setups or runs at once, a time budget per run (checks still
# pending are skipped), and a limit on setups (each of which can lead to one run).
MAX_CONCURRENT = 2
RUN_BUDGET_SECONDS = 120.0
SETUPS_PER_MINUTE = 10
SOURCES = ("tester", "system", "communication", "unknown")

ClientFactory = Callable[[str, bool], httpx.Client]   # (target_url, target_is_this_deployment)
TargetGuard = Callable[[str], str | None]             # returns why a target is refused, or None
TlsProbe = Callable[[], list[tuple[str, str, str]]]   # [(test_id, outcome, message)]


def problem(status: int, message: str, source: str) -> JSONResponse:
    return JSONResponse({"message": message, "source": source}, status_code=status)


def busy(status: int, message: str, retry_after: int) -> JSONResponse:
    response = problem(status, message, "tester")
    response.headers["Retry-After"] = str(retry_after)
    return response


async def _json_object(request: Request) -> dict[str, Any] | None:
    try:
        body = await request.json()
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


def _session_id(value: Any) -> str | None:
    return value if isinstance(value, str) and 0 < len(value) <= 128 else None


@dataclass
class TesterSession:
    target_url: str
    is_self: bool
    state: str = "ready"            # ready -> running -> done
    report: dict[str, Any] | None = None


@dataclass
class Registry:
    system: OrderedDict[str, str] = field(default_factory=OrderedDict)          # session_id -> created
    tester: OrderedDict[str, TesterSession] = field(default_factory=OrderedDict)
    lock: threading.Lock = field(default_factory=threading.Lock)
    slots: threading.BoundedSemaphore = field(default_factory=lambda: threading.BoundedSemaphore(MAX_CONCURRENT))
    setups: RateLimiter = field(default_factory=lambda: RateLimiter(SETUPS_PER_MINUTE, Clock()))

    @staticmethod
    def trim(d: OrderedDict) -> None:
        while len(d) > MAX_SESSIONS:
            d.popitem(last=False)


class NotPublicError(Exception):
    pass


def public_address(host: str, port: int) -> str:
    """An address for host, provided every address it resolves to is public; else NotPublicError."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        raise NotPublicError(f"cannot resolve {host}") from None
    addresses = [str(info[4][0]) for info in infos]
    # A scoped IPv6 address ("fe80::1%eth0") is link-local, so never public.
    if not addresses or not all(ipaddress.ip_address(a.split("%")[0]).is_global for a in addresses):
        raise NotPublicError(f"{host} must resolve to public addresses only")
    return addresses[0]


def public_target_guard(target_url: str) -> str | None:
    """Refuse targets that are not public HTTPS hosts, so the tester can't be aimed inward (SSRF).

    This gives a clear error at setup. The connection itself is checked again by
    PublicOnlyBackend, since a hostname can resolve differently a moment later.
    """
    parts = urlsplit(target_url)
    if parts.scheme != "https" or not parts.hostname:
        return "target_url must be an https:// URL"
    if parts.username or parts.password or parts.query or parts.fragment:
        return "target_url must not contain credentials, a query or a fragment"
    try:
        public_address(parts.hostname, parts.port or 443)
    except NotPublicError as exc:
        return str(exc)
    return None


class PublicOnlyBackend(httpcore.SyncBackend):
    """Resolves the host once per connection, refuses non-public addresses and connects to the
    address it checked, so DNS rebinding can't swap in an internal one after the check.
    TLS still verifies the certificate against the hostname (httpcore sends it as SNI)."""

    def connect_tcp(self, host: str, port: int, timeout: float | None = None,
                    local_address: str | None = None,
                    socket_options: Iterable[Any] | None = None) -> httpcore.NetworkStream:
        try:
            address = public_address(host, port)
        except NotPublicError as exc:
            raise httpcore.ConnectError(str(exc)) from None
        return super().connect_tcp(address, port, timeout, local_address, socket_options)


class PublicOnlyTransport(httpx.HTTPTransport):
    def __init__(self) -> None:
        super().__init__()
        # httpx has no public option for the network backend, so its pool is replaced by one
        # built the same way (certifi's CAs, as httpx uses by default) with PublicOnlyBackend.
        self._pool = httpcore.ConnectionPool(ssl_context=ssl.create_default_context(cafile=certifi.where()),
                                             network_backend=PublicOnlyBackend())


def default_client_factory(cfg: Config) -> ClientFactory:
    def make(target_url: str, is_self: bool) -> httpx.Client:
        if is_self:
            # This deployment: go straight to the api on localhost and verify its own certificate
            # (issued to localhost by docker/entrypoint.sh) instead of hairpinning through Cloudflare.
            ctx = ssl.create_default_context(cafile=str(cfg.api.tls_cert))
            return httpx.Client(base_url=f"https://localhost:{cfg.api.port}", verify=ctx,
                                timeout=REQUEST_TIMEOUT, trust_env=False)
        # trust_env=False: a proxy from the environment would be an internal hop the check can't see.
        return httpx.Client(base_url=target_url, timeout=REQUEST_TIMEOUT, transport=PublicOnlyTransport(),
                            trust_env=False)
    return make


def default_tls_probe(cfg: Config) -> TlsProbe:
    """AC-23 against this deployment: plain HTTP is refused, TLS 1.2 and 1.3 are accepted."""
    def probe() -> list[tuple[str, str, str]]:
        out: list[tuple[str, str, str]] = []
        try:
            r = httpx.get(f"http://localhost:{cfg.api.port}/health", timeout=5, trust_env=False)
            out.append(("tls-plain-http-refused", "fail" if r.status_code == 200 else "pass",
                        f"plain HTTP got HTTP {r.status_code}"))
        except httpx.TransportError:
            out.append(("tls-plain-http-refused", "pass", "plain HTTP connection was closed without a response"))
        for name, version in (("1.2", ssl.TLSVersion.TLSv1_2), ("1.3", ssl.TLSVersion.TLSv1_3)):
            ctx = ssl.create_default_context(cafile=str(cfg.api.tls_cert))
            ctx.minimum_version = ctx.maximum_version = version
            try:
                with socket.create_connection(("localhost", cfg.api.port), timeout=5) as sock, \
                        ctx.wrap_socket(sock, server_hostname="localhost") as tls:
                    out.append((f"tls-{name}-accepted", "pass", f"handshake completed with {tls.version()}"))
            except (OSError, ssl.SSLError) as exc:
                out.append((f"tls-{name}-accepted", "fail", f"TLS {name} handshake failed: {exc}"))
        return out
    return probe


class _ServerError(Exception):
    pass


def _fixed(outcome: str, message: str) -> tuple[str, str]:
    return outcome, message


class Suite:
    """One run of the checks against a target system base URL."""

    def __init__(self, http: httpx.Client, session_id: str, key: str | None,
                 tls_probe: TlsProbe | None, now: datetime, budget_seconds: float = RUN_BUDGET_SECONDS) -> None:
        self.http, self.session_id, self.key, self.tls_probe, self.now = http, session_id, key, tls_probe, now
        self.budget_seconds = budget_seconds
        self.deadline = time.monotonic() + budget_seconds
        self.results: list[dict[str, Any]] = []
        self.ops: set[str] = {"POST /test/setup"}   # the target's setup confirmed this session
        self.acs: set[str] = set()
        self.code_coverage: dict[str, Any] = {
            "covered": None, "total": None, "basis": "the target's system report gave no code coverage"}

    # -- helpers -----------------------------------------------------------------------------
    def get(self, path: str, params: dict[str, str] | None = None,
            auth: str | None = "key") -> httpx.Response:
        headers = {}
        if auth == "key" and self.key:
            headers["Authorization"] = f"Bearer {self.key}"
        elif auth not in (None, "key"):
            headers["Authorization"] = auth
        r = self.http.get(path, params=params, headers=headers)
        if r.status_code >= 500:
            raise _ServerError(f"GET {path} returned HTTP {r.status_code}: {r.text[:200]}")
        return r

    @staticmethod
    def ts(dt: datetime) -> str:
        return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    def check(self, test_id: str, ops: tuple[str, ...], acs: tuple[str, ...],
              fn: Callable[[], tuple[str, str]], needs_key: bool = False) -> None:
        source = None
        if time.monotonic() > self.deadline:
            outcome, message = "skip", f"the run's time budget of {self.budget_seconds:g} s was used up"
        elif needs_key and not self.key:
            outcome, message = "skip", "the tester holds no API key for this target"
        else:
            try:
                outcome, message = fn()
            except _ServerError as exc:
                outcome, message, source = "error", str(exc), "system"
            except httpx.TimeoutException:
                outcome, message, source = "error", "request timed out", "communication"
            except httpx.TransportError as exc:
                outcome, message, source = "error", f"connection failed: {exc}", "communication"
            except Exception as exc:   # a bug in a check must not abort the suite
                log.exception("tester check %s failed", test_id)
                outcome, message, source = "error", f"tester error: {type(exc).__name__}: {exc}", "tester"
        row: dict[str, Any] = {"test_id": test_id, "outcome": outcome, "message": message or outcome}
        if source:
            row["source"] = source
        self.results.append(row)
        if outcome != "skip":
            self.ops.update(ops)
            self.acs.update(acs)

    @staticmethod
    def expect(r: httpx.Response, status: int, what: str) -> tuple[str, str]:
        if r.status_code == status:
            return "pass", f"{what}: HTTP {status}"
        return "fail", f"{what}: expected HTTP {status}, got {r.status_code}: {r.text[:200]}"

    def expect_400(self, what: str, params: dict[str, str]) -> tuple[str, str]:
        r = self.get("/v1/events", params)
        if r.status_code != 400:
            return "fail", f"{what}: expected HTTP 400, got {r.status_code}"
        body = r.json()
        if "error" not in body or "events" in body:
            return "fail", f"{what}: 400 body must have an error and no data, got {r.text[:200]}"
        return "pass", f"{what}: HTTP 400 with an error body and no data"

    # -- checks ------------------------------------------------------------------------------
    def run(self) -> None:
        now = self.now
        self.check("health", ("GET /health",), (), self._health)
        self.check("system-test-report", ("GET /test/report",), (), self._system_report)
        self.check("auth-missing-key", ("GET /v1/events",), ("AC-24",), lambda: self._auth(None))
        self.check("auth-wrong-key", ("GET /v1/events",), ("AC-24",),
                   lambda: self._auth("Bearer sec450_not_a_real_key"))
        self.check("auth-valid-key", ("GET /v1/events",), ("AC-24",), self._valid_key, needs_key=True)

        invalid = [
            ("param-start-after-end", {"start": self.ts(now), "end": self.ts(now - timedelta(hours=1))}),
            ("param-span-31-days-plus-1s", {"start": self.ts(now - timedelta(days=31, seconds=1)),
                                            "end": self.ts(now)}),
            ("param-malformed-timestamp", {"start": "yesterday"}),
            ("param-invalid-ip", {"source_ip": "999.1.1.1"}),
            ("param-bad-severity", {"severity": "urgent"}),
            ("param-limit-0", {"limit": "0"}),
            ("param-limit-1001", {"limit": "1001"}),
            ("param-unknown", {"foo": "bar"}),
        ]
        for test_id, params in invalid:
            self.check(test_id, ("GET /v1/events",), ("AC-14",),
                       partial(self.expect_400, test_id, params), needs_key=True)
        valid = [
            ("param-span-31-days", {"start": self.ts(now - timedelta(days=31)), "end": self.ts(now)}),
            ("param-ipv6", {"source_ip": "2001:db8::1"}),
            ("param-limit-1", {"limit": "1"}),
            ("param-limit-1000", {"limit": "1000"}),
        ]
        for test_id, params in valid:
            self.check(test_id, ("GET /v1/events",), ("AC-14",),
                       partial(self._expect_events_200, test_id, params), needs_key=True)

        self.check("events-collected", ("GET /v1/events",), (), self._events_collected, needs_key=True)
        self.check("filter-source-ip", ("GET /v1/events",), ("AC-13",), self._filter_source_ip, needs_key=True)
        self.check("clusters-list", ("GET /v1/clusters",), ("AC-13",), self._clusters, needs_key=True)
        self.check("filter-severity", ("GET /v1/clusters",), ("AC-13",), self._filter_severity, needs_key=True)
        self.check("reports-list", ("GET /v1/reports",), ("AC-13",), self._reports, needs_key=True)
        self.check("report-bad-id", ("GET /v1/reports/{id}",), ("AC-14",), self._report_bad_id, needs_key=True)
        self.check("report-content", ("GET /v1/reports/{id}",), ("AC-15",), self._report_content, needs_key=True)
        if self.tls_probe is None:
            self.check("tls-versions", (), ("AC-23",),
                       lambda: ("skip", "TLS versions are only probed when the tester runs beside the target"))
        else:
            for test_id, outcome, message in self._tls():
                self.check(test_id, (), ("AC-23",), partial(_fixed, outcome, message))
        # Last, so the audit chain it verifies includes this run's requests.
        self.check("integrity-chains", ("GET /v1/integrity",), ("AC-21", "AC-26"), self._integrity, needs_key=True)

    def _expect_events_200(self, what: str, params: dict[str, str]) -> tuple[str, str]:
        return self.expect(self.get("/v1/events", params), 200, what)

    def _tls(self) -> list[tuple[str, str, str]]:
        try:
            return self.tls_probe() if self.tls_probe else []
        except Exception as exc:   # report it as a tester error rather than abort
            log.exception("TLS probe failed")
            return [("tls-versions", "error", f"tester error: {exc}")]

    def _health(self) -> tuple[str, str]:
        r = self.get("/health", auth=None)
        if r.status_code == 200 and r.json().get("status") == "ok":
            return "pass", "GET /health returned 200 {status: ok}"
        return "fail", f"GET /health returned {r.status_code}: {r.text[:200]}"

    def _system_report(self) -> tuple[str, str]:
        r = self.get("/test/report", {"session_id": self.session_id}, auth=None)
        if r.status_code != 200:
            return "fail", f"system /test/report returned {r.status_code}: {r.text[:200]}"
        code = (r.json().get("coverage") or {}).get("code")
        if not isinstance(code, dict) or not code.get("basis"):
            return "fail", "system report has no coverage.code with a basis"
        self.code_coverage = {"covered": code.get("covered"), "total": code.get("total"), "basis": code["basis"]}
        return "pass", "system report returned coverage.code"

    def _auth(self, header: str | None) -> tuple[str, str]:
        r = self.get("/v1/events", auth=header or None)
        if r.status_code != 401:
            return "fail", f"expected HTTP 401, got {r.status_code}"
        if "bearer" not in r.headers.get("www-authenticate", "").lower():
            return "fail", "401 without a WWW-Authenticate: Bearer header"
        if "events" in r.json():
            return "fail", "401 response contained data"
        return "pass", "HTTP 401 with WWW-Authenticate: Bearer and no data"

    def _valid_key(self) -> tuple[str, str]:
        r = self.get("/v1/events")
        if r.status_code != 200:
            return "fail", f"valid key: expected 200, got {r.status_code}"
        body = r.json()
        if not isinstance(body.get("events"), list) or not isinstance(body.get("count"), int):
            return "fail", "200 response lacks an events list and a count"
        return "pass", f"valid key: HTTP 200 with {body['count']} events"

    def _events_collected(self) -> tuple[str, str]:
        r = self.get("/v1/events", {"limit": "1"})
        if r.status_code != 200:
            return "fail", f"expected 200, got {r.status_code}"
        if r.json()["count"] < 1:
            return "fail", "no events collected in the last 24 hours (is the lab running?)"
        return "pass", f"latest event at {r.json()['events'][0].get('ts')}"

    def _filter_source_ip(self) -> tuple[str, str]:
        latest = self.get("/v1/events", {"limit": "1"}).json().get("events") or []
        ip = latest[0].get("client_ip") if latest else None
        if not ip:
            return "skip", "no recent event with a client IP to filter on"
        r = self.get("/v1/events", {"source_ip": ip, "limit": "1000"})
        events = r.json().get("events", []) if r.status_code == 200 else []
        if r.status_code != 200 or not events:
            return "fail", f"source_ip={ip}: expected 200 with that event, got {r.status_code}, {len(events)} events"
        wrong = [e for e in events if e.get("client_ip") != ip]
        if wrong:
            return "fail", f"source_ip={ip} returned {len(wrong)} events from other IPs"
        return "pass", f"source_ip={ip} returned {len(events)} events, all from that IP"

    def _clusters(self) -> tuple[str, str]:
        r = self.get("/v1/clusters")
        if r.status_code != 200 or not isinstance(r.json().get("clusters"), list):
            return "fail", f"expected 200 with a clusters list, got {r.status_code}"
        return "pass", f"HTTP 200 with {r.json()['count']} clusters in the last 24 hours"

    def _filter_severity(self) -> tuple[str, str]:
        r = self.get("/v1/clusters", {"severity": "high", "limit": "1000"})
        if r.status_code != 200:
            return "fail", f"expected 200, got {r.status_code}"
        clusters = r.json().get("clusters", [])
        wrong = [c for c in clusters if c.get("severity") != "high"]
        if wrong:
            return "fail", f"severity=high returned {len(wrong)} clusters of other severities"
        return "pass", f"severity=high returned {len(clusters)} clusters, all high"

    def _reports(self) -> tuple[str, str]:
        r = self.get("/v1/reports")
        if r.status_code != 200 or not isinstance(r.json().get("reports"), list):
            return "fail", f"expected 200 with a reports list, got {r.status_code}"
        return "pass", f"HTTP 200 with {r.json()['count']} reports in the last 24 hours"

    def _report_bad_id(self) -> tuple[str, str]:
        for path, status in (("/v1/reports/abc", 400), ("/v1/reports/0", 400), ("/v1/reports/999999999999", 404)):
            r = self.get(path)
            if r.status_code != status:
                return "fail", f"GET {path}: expected {status}, got {r.status_code}"
        return "pass", "non-numeric and zero ids get 400, an unknown id gets 404"

    def _report_content(self) -> tuple[str, str]:
        start = self.ts(self.now - timedelta(days=7))
        listed = self.get("/v1/reports", {"start": start, "limit": "1"}).json().get("reports") or []
        if not listed:
            return "skip", "no report generated in the last 7 days"
        report_id = listed[0]["report_id"]
        r = self.get(f"/v1/reports/{report_id}")
        if r.status_code != 200:
            return "fail", f"GET /v1/reports/{report_id}: expected 200, got {r.status_code}"
        body = r.json().get("body", {})
        missing = [f for f in REPORT_FIELDS if f not in body]
        if missing:
            return "fail", f"report {report_id} is missing {', '.join(missing)}"
        if not body["raw_lines"] or not all(line.get("text") for line in body["raw_lines"]):
            return "fail", f"report {report_id} has no raw log lines"
        if body["integrity"].get("status") not in ("intact", "broken"):
            return "fail", f"report {report_id} has no integrity result"
        return "pass", f"report {report_id} has all REQ-06 fields and {len(body['raw_lines'])} raw lines"

    def _integrity(self) -> tuple[str, str]:
        r = self.get("/v1/integrity")
        if r.status_code != 200:
            return "fail", f"expected 200, got {r.status_code}"
        body = r.json()
        batches, audit = body.get("batches", {}), body.get("audit", {})
        if batches.get("status") != "intact" or audit.get("status") != "intact":
            return "fail", f"hash chains not intact: batches {batches}, audit {audit}"
        return "pass", (f"batch chain intact ({batches.get('batches')} batches), "
                        f"audit chain intact ({audit.get('entries')} entries)")

    def report(self, target_url: str) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target_url": target_url,
            "results": self.results,
            "coverage": {
                "code": self.code_coverage,
                "component": {"covered": len(self.ops), "total": len(OPERATIONS),
                              "basis": "operations of the SEC450 interface (" + ", ".join(OPERATIONS)
                                       + ") exercised by an executed test"},
                "system": {"covered": len(self.acs), "total": ACCEPTANCE_CRITERIA,
                           "basis": "acceptance criteria AC-01 to AC-30 (README.md) exercised by an executed test: "
                                    + (", ".join(sorted(self.acs)) or "none")},
            },
        }


def install(app: FastAPI, cfg: Config) -> None:
    """Add the system and tester /test endpoints. Hooks on app.state let tests swap the network."""
    reg = Registry()
    app.state.testing_registry = reg
    app.state.tester_client_factory = default_client_factory(cfg)
    app.state.tester_target_guard = public_target_guard
    app.state.tester_tls_probe = default_tls_probe(cfg)
    app.state.tester_now = lambda: datetime.now(UTC)
    app.state.tester_run_budget = RUN_BUDGET_SECONDS

    endpoints = {"system": ["POST /test/setup", "GET /test/report"],
                 "tester": ["POST /tester/test/setup", "POST /tester/test/run", "GET /tester/test/report"],
                 "spec": "https://github.com/dredinbo15/sec450/blob/main/docs/testing-interface.md"}

    @app.get("/test")
    @app.get("/tester/test")
    def index() -> dict:
        return endpoints

    # -- system --------------------------------------------------------------------------------
    @app.post("/test/setup")
    async def system_setup(request: Request) -> JSONResponse:
        body = await _json_object(request) or {}
        sid = _session_id(body.get("session_id"))
        if sid is None:
            return problem(400, "body must be a JSON object with a session_id string (1-128 chars)", "system")
        if "setup" in body and not isinstance(body["setup"], dict):
            return problem(400, "setup must be a JSON object", "system")
        with reg.lock:
            if sid in reg.system:
                return problem(409, "session_id already used", "system")
            reg.system[sid] = datetime.now(UTC).isoformat()
            reg.trim(reg.system)
        log.info("test session %s set up", sid)
        return JSONResponse({"session_id": sid}, status_code=201)

    @app.get("/test/report")
    def system_report(session_id: str | None = None) -> JSONResponse:
        if not session_id:
            return problem(400, "session_id query parameter is required", "system")
        with reg.lock:
            known = session_id in reg.system
        if not known:
            return problem(404, "unknown session_id", "system")
        return JSONResponse({"session_id": session_id, "coverage": {"code": {
            "covered": None, "total": None,
            "basis": "line coverage is not instrumented in the deployed service; "
                     "CI runs the pytest suite (tests/) on every push"}}})

    # -- tester --------------------------------------------------------------------------------
    @app.post("/tester/test/setup")
    async def tester_setup(request: Request) -> JSONResponse:
        body = await _json_object(request)
        target = body.get("target_url") if body is not None else None
        if not isinstance(target, str) or not target.strip():
            return problem(400, "body must be a JSON object with a target_url string", "tester")
        target = target.strip().rstrip("/")
        parts = urlsplit(target)
        is_self = parts.netloc.lower() == request.headers.get("host", "").lower() and parts.path in ("", "/")
        if not is_self:
            refused = await run_in_threadpool(app.state.tester_target_guard, target)
            if refused:
                return problem(400, refused, "tester")
        if (retry_after := reg.setups.check("tester")) is not None:
            return busy(429, f"at most {SETUPS_PER_MINUTE} tester sessions are set up per minute", retry_after)
        if not reg.slots.acquire(blocking=False):
            return busy(503, "the tester is busy with other sessions; try again shortly", 30)
        sid = str(uuid.uuid4())
        try:
            with app.state.tester_client_factory(target, is_self) as http:
                r = await run_in_threadpool(http.post, "/test/setup", json={"session_id": sid, "setup": {}})
        except httpx.TimeoutException:
            return problem(504, "target /test/setup timed out", "communication")
        except httpx.TransportError as exc:
            return problem(502, f"cannot reach target: {exc}", "communication")
        finally:
            reg.slots.release()
        try:
            confirmed = r.status_code == 201 and r.json().get("session_id") == sid
        except ValueError:
            confirmed = False
        if not confirmed:
            try:
                rb = r.json()
                message = rb.get("message") or rb.get("error") or r.text[:200]
                source = rb.get("source") if rb.get("source") in SOURCES else "system"
            except ValueError:
                message, source = r.text[:200] or "no body", "system"
            status = r.status_code if r.status_code >= 400 else 502
            return problem(status, f"target setup did not confirm the session: {message}", source)
        with reg.lock:
            reg.tester[sid] = TesterSession(target, is_self)
            reg.trim(reg.tester)
        return JSONResponse({"session_id": sid}, status_code=201)

    @app.post("/tester/test/run")
    async def tester_run(request: Request) -> JSONResponse:
        body = await _json_object(request)
        sid = _session_id(body.get("session_id")) if body is not None else None
        if sid is None:
            return problem(400, "body must be a JSON object with a session_id string", "tester")
        with reg.lock:
            session = reg.tester.get(sid)
            if session is None:
                return problem(404, "unknown session_id", "tester")
            if session.state != "ready":
                return problem(409, f"session already {session.state}; each session runs once", "tester")
            if not reg.slots.acquire(blocking=False):
                return busy(503, "the tester is busy with other runs; try again shortly", 30)
            session.state = "running"
        try:
            report = await run_in_threadpool(_run_suite, app, cfg, sid, session)
        except Exception:
            log.exception("tester run %s aborted", sid)
            session.report = {"session_id": sid, "target_url": session.target_url, "results": [
                {"test_id": "suite", "outcome": "error", "source": "tester", "message": "tester aborted"}],
                "coverage": {m: {"covered": None, "total": None, "basis": "run aborted"}
                             for m in ("code", "component", "system")}}
            session.state = "done"
            return problem(500, "tester aborted; the stored report is available", "tester")
        finally:
            reg.slots.release()
        session.report, session.state = report, "done"
        return JSONResponse(report)

    @app.get("/tester/test/report")
    def tester_report(session_id: str | None = None) -> JSONResponse:
        if not session_id:
            return problem(400, "session_id query parameter is required", "tester")
        with reg.lock:
            session = reg.tester.get(session_id)
        if session is None:
            return problem(404, "unknown session_id", "tester")
        if session.state != "done" or session.report is None:
            return problem(409, "the suite has not finished for this session", "tester")
        return JSONResponse(session.report)


def _run_suite(app: FastAPI, cfg: Config, sid: str, session: TesterSession) -> dict[str, Any]:
    key_id = key = None
    if session.is_self:
        # A fresh read-only key per run (so repeated runs never share a rate-limit bucket),
        # revoked when the run ends; only its hash is ever stored (DD-11).
        conn = connect(cfg.database_path)
        try:
            key_id, key = create_key(conn)
        finally:
            conn.close()
    try:
        with app.state.tester_client_factory(session.target_url, session.is_self) as http:
            suite = Suite(http, sid, key, app.state.tester_tls_probe if session.is_self else None,
                          app.state.tester_now(), app.state.tester_run_budget)
            suite.run()
            return suite.report(session.target_url)
    finally:
        if key_id:
            conn = connect(cfg.database_path)
            try:
                revoke_key(conn, key_id)
            finally:
                conn.close()
