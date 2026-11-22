"""Fixtures for the Team 105 incident API suite. Standalone: no database, no imports from our system or tests/.

Every write goes to an isolated course session store under /system. A request hook refuses anything else
before it leaves the machine (see _guard), so a mistake in a test can't touch their production store.
"""
from __future__ import annotations

import os
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
import pytest

BASE_URL = os.environ.get("POD105_BASE_URL", "https://sec450-incident-api.onrender.com/system").rstrip("/")
# Their production API, the same host without /system. Only read-only GETs go there (isolation check).
PRODUCTION_URL = os.environ.get("POD105_PRODUCTION_URL", BASE_URL.removesuffix("/system"))
# Free-tier Render host: the first request after an idle spell can take about a minute.
TIMEOUT = float(os.environ.get("POD105_TIMEOUT", "90"))
WAKE_DEADLINE = float(os.environ.get("POD105_WAKE_SECONDS", "180"))

SESSION_HEADER = "X-Test-Session-Id"
MAX_SESSIONS = 2   # the shared store + one for the isolation test; see open_session
# Reuse a store prepared earlier (sessions are kept) instead of opening a new one for the shared store.
REUSE_SESSION_ID = os.environ.get("POD105_SESSION_ID", "")
SYSTEM_PATH = urlsplit(BASE_URL).path   # "/system"


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "finding: a security finding; fails while the weakness is present")


def _guard(request: httpx.Request) -> None:
    """Refuse requests that could change their production store or land in another team's session."""
    path = request.url.path
    if path.rstrip("/").endswith("/test/reset"):
        raise RuntimeError(f"refusing {request.method} {path}: the suite never resets a store")
    if not path.startswith(SYSTEM_PATH + "/") and request.method != "GET":
        raise RuntimeError(f"refusing {request.method} {request.url}: only GETs may go outside {SYSTEM_PATH}")
    if path.startswith(SYSTEM_PATH + "/api/") and SESSION_HEADER not in request.headers:
        # Headerless /system requests go to whichever session was created last, possibly someone else's.
        raise RuntimeError(f"refusing {request.method} {path} without {SESSION_HEADER}")


def _client(base_url: str, headers: dict[str, str] | None = None) -> httpx.Client:
    return httpx.Client(base_url=base_url, headers=headers, timeout=TIMEOUT, event_hooks={"request": [_guard]})


@pytest.fixture(scope="session", autouse=True)
def _awake() -> None:
    """Wake the host once before the first test so per-test timeouts measure the API, not a cold start."""
    deadline = time.monotonic() + WAKE_DEADLINE
    last = "no response"
    with _client(BASE_URL) as c:
        while time.monotonic() < deadline:
            try:
                r = c.get("/health")
                if r.status_code == 200:
                    return
                last = f"HTTP {r.status_code}"
            except httpx.HTTPError as e:
                last = repr(e)
            time.sleep(5)
    pytest.exit(f"Team 105 API at {BASE_URL} did not become healthy within {WAKE_DEADLINE:.0f} s ({last})", 2)


@pytest.fixture(scope="session")
def system() -> Iterator[httpx.Client]:
    """The course interface (/system/test/...); carries no session header."""
    with _client(BASE_URL) as c:
        yield c


@pytest.fixture(scope="session")
def production() -> Iterator[httpx.Client]:
    """Their production API. _guard lets only GETs through."""
    with _client(PRODUCTION_URL) as c:
        yield c


def new_session_id() -> str:
    return f"team102-pytest-{uuid.uuid4().hex}"


@dataclass
class PodSession:
    id: str
    setup_response: httpx.Response | None   # kept for the course interface test; None for a reused store
    client: httpx.Client             # /system/api/v1 with the session header always set


@pytest.fixture(scope="session")
def open_session(system: httpx.Client) -> Iterator[Callable[[], PodSession]]:
    """Factory: prepare a fresh session store. A run may open at most MAX_SESSIONS.

    Their host keeps every session and has no way to delete one; once its capacity is used up,
    setup answers 503 for everyone (us, Team 105, the graders). So the suite shares one store
    and opens a second only where isolation itself is under test.
    """
    sessions: list[PodSession] = []

    def open_() -> PodSession:
        if len(sessions) >= MAX_SESSIONS:
            raise RuntimeError(f"refusing to open more than {MAX_SESSIONS} course sessions in one run")
        sid = new_session_id()
        r = system.post("/test/setup", json={"session_id": sid, "setup": {}})
        if r.status_code == 503:
            msg = f"Team 105 refused a new course session (503): {r.text[:300]}"
            if not sessions and not REUSE_SESSION_ID:   # no shared store, so nothing can run
                pytest.exit(msg + " -- set POD105_SESSION_ID to reuse a store prepared earlier", 2)
            pytest.fail(msg)
        assert r.status_code == 201, f"POST /test/setup returned {r.status_code}: {r.text[:300]}"
        sessions.append(PodSession(sid, r, _client(BASE_URL + "/api/v1", headers={SESSION_HEADER: sid})))
        return sessions[-1]

    yield open_
    for s in sessions:
        s.client.close()


@pytest.fixture(scope="session")
def store(system: httpx.Client, open_session: Callable[[], PodSession]) -> Iterator[PodSession]:
    """The run's shared session store. Tests make their own incidents in it and don't rely on its size."""
    if not REUSE_SESSION_ID:
        yield open_session()
        return
    r = system.get("/test/report", params={"session_id": REUSE_SESSION_ID})
    if r.status_code != 200:
        pytest.exit(f"POD105_SESSION_ID={REUSE_SESSION_ID!r} is not a prepared session: {r.status_code}", 2)
    with _client(BASE_URL + "/api/v1", headers={SESSION_HEADER: REUSE_SESSION_ID}) as c:
        yield PodSession(REUSE_SESSION_ID, None, c)


@pytest.fixture
def api(store: PodSession) -> httpx.Client:
    """A client for the shared, isolated session store."""
    return store.client
