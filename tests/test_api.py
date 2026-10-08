import pytest
from fastapi.testclient import TestClient

from sec450.hashchain import verify_audit
from sec450.keys import create_key, revoke_key

from .conftest import insert_events


@pytest.fixture
def api(cfg, conn, clock):
    from sec450.api.app import create_app
    key_id, key = create_key(conn, clock)
    client = TestClient(create_app(cfg, clock))
    client.headers["Authorization"] = f"Bearer {key}"
    return client, key_id


@pytest.mark.parametrize("query,status", [
    ("", 200),
    ("start=2026-10-08T00:00:00Z&end=2026-10-07T00:00:00Z", 400),
    ("start=2026-09-07T00:00:00Z&end=2026-10-08T00:00:00Z", 200),   # 31 days
    ("start=2026-09-07T00:00:00Z&end=2026-10-08T00:00:01Z", 400),   # 31 days + 1 s
    ("start=yesterday", 400),
    ("source_ip=999.1.1.1", 400),
    ("source_ip=2001:db8::1", 200),
    ("severity=urgent", 400),
    ("limit=0", 400), ("limit=1", 200), ("limit=1000", 200), ("limit=1001", 400),
    ("foo=bar", 400),
])
def test_parameter_validation(api, query, status):  # AC-14
    client, _ = api
    r = client.get(f"/v1/events?{query}")
    assert r.status_code == status
    if status == 400:
        assert "error" in r.json() and "events" not in r.json()


def test_filters(api, conn):  # AC-13
    insert_events(conn, [{"ts": "2026-10-08T13:00:00.000000Z", "client_ip": "198.51.100.1", "username": "a"},
                         {"ts": "2026-10-08T13:01:00.000000Z", "client_ip": "198.51.100.2", "username": "b"}])
    client, _ = api
    assert client.get("/v1/events").json()["count"] == 2
    assert client.get("/v1/events?source_ip=198.51.100.1").json()["count"] == 1
    assert client.get("/v1/events?user=b").json()["events"][0]["client_ip"] == "198.51.100.2"


def test_auth(api, conn):  # AC-24
    client, key_id = api
    assert client.get("/v1/events", headers={"Authorization": ""}).status_code == 401
    assert client.get("/v1/events", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.get("/v1/events").status_code == 200
    revoke_key(conn, key_id)
    assert client.get("/v1/events").status_code == 401
    assert conn.execute("SELECT COUNT(*) FROM api_key WHERE key_hash LIKE 'sec450_%'").fetchone()[0] == 0


def test_rate_limit(api, clock):  # AC-25
    client, _ = api
    for _ in range(60):
        assert client.get("/v1/events").status_code == 200
        clock.advance(50 / 60)
    r = client.get("/v1/events")
    assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1
    clock.advance(61 - 50)
    assert client.get("/v1/events").status_code == 200


def test_audit_chain_and_fail_closed(api, conn):  # AC-26
    client, _ = api
    client.get("/v1/events")
    client.get("/v1/events?limit=0")
    client.get("/v1/events", headers={"Authorization": "Bearer bad"})
    statuses = [r[0] for r in conn.execute("SELECT status_code FROM audit_entry ORDER BY entry_id")]
    assert statuses == [200, 400, 401]
    assert verify_audit(conn)["status"] == "intact"

    conn.execute("CREATE TRIGGER block_audit BEFORE INSERT ON audit_entry BEGIN SELECT RAISE(ABORT, 'no'); END")
    r = client.get("/v1/events")
    assert r.status_code == 500 and "events" not in r.json()
