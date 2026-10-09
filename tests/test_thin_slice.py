"""Thin slice, end to end: SSH log -> collector -> event -> R1 -> cluster -> report -> GET /v1/reports/{id}.

The test drives the same cycle functions the collector service runs
(sec450/worker.py), with the injectable clock and the mock LLM.
"""
import json
import logging
import shutil
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sec450.api.app import create_app
from sec450.collector import Collector
from sec450.geoip import GeoIP
from sec450.keys import create_key
from sec450.logjson import JsonFormatter
from sec450.mock_llm import MockLLMClient
from sec450.worker import analysis_cycle, collection_cycle, make_triage_client

from .conftest import T0

FIXTURE = Path(__file__).parent / "fixtures" / "logs" / "ssh_bruteforce.log"
ATTACKER = "203.0.113.50"


@pytest.fixture
def slice_cfg(cfg):
    """Only the SSH source, fed from the fixture file (other sources would just open gaps)."""
    ssh = next(s for s in cfg.sources if s.kind == "ssh_auth")
    shutil.copyfile(FIXTURE, ssh.path)
    cfg.sources = [ssh]
    return cfg


def _run_pipeline(cfg, conn, clock, llm):
    """One collection cycle, then one analysis cycle once the cluster has settled."""
    clock.set(T0 + timedelta(minutes=2))          # fixture lines span 14:00:00Z-14:00:55Z
    collection_cycle(Collector(cfg, conn, clock, GeoIP()), conn, cfg, clock)
    clock.advance(cfg.triage.settle_seconds)
    analysis_cycle(conn, cfg, clock, llm)


def test_ac15_thin_slice_ssh_bruteforce_to_report(slice_cfg, conn, clock):
    llm = MockLLMClient("ok")
    _run_pipeline(slice_cfg, conn, clock, llm)

    # Collector: every line stored unmodified, parsed into events with UTC times (REQ-01, REQ-08).
    fixture_lines = FIXTURE.read_bytes().decode("utf-8").splitlines()
    stored = [r[0] for r in conn.execute("SELECT text FROM raw_line ORDER BY raw_id")]
    assert stored == fixture_lines
    assert conn.execute("SELECT COUNT(*) FROM event").fetchone()[0] == len(fixture_lines)
    assert conn.execute("SELECT MIN(ts) FROM event").fetchone()[0] == "2026-10-08T14:00:00.000000Z"

    # R1 fired once, high severity, holding exactly the six failed logins; mock LLM was called once.
    clusters = conn.execute("SELECT * FROM cluster").fetchall()
    assert len(clusters) == 1
    c = clusters[0]
    assert (c["rule_id"], c["severity"], c["group_key"], c["state"]) == ("R1", "high", ATTACKER, "REPORTED")
    assert conn.execute("SELECT COUNT(*) FROM cluster_event").fetchone()[0] == 6
    assert llm.calls == 1

    # Report is retrievable through the API with a key (REQ-05, REQ-06, REQ-09).
    key_id, key = create_key(conn, clock)
    client = TestClient(create_app(slice_cfg, clock))
    report_id = conn.execute("SELECT report_id FROM report").fetchone()[0]
    r = client.get(f"/v1/reports/{report_id}", headers={"Authorization": f"Bearer {key}"})
    assert r.status_code == 200
    assert r.headers["X-Request-ID"]
    body = r.json()["body"]

    for field in ("summary", "requester", "data_destination", "timeline", "matched_rule",
                  "ai_assessment", "raw_lines", "integrity"):
        assert field in body, field
    assert body["matched_rule"]["id"] == "R1"
    assert body["requester"]["client_ip"] == ATTACKER
    assert body["requester"]["usernames"] == ["admin", "root"]
    assert body["data_destination"] == {"client_ip": ATTACKER, "bytes_sent": 0}
    assert len(body["timeline"]) == 6
    assert [x["text"] for x in body["raw_lines"]] == [ln for ln in fixture_lines if "Failed password" in ln]
    assert body["integrity"]["status"] == "intact"
    # AI is advisory only: it recommended "critical", the rule's "high" stands (DD-01).
    assert body["ai_assessment"]["status"] == "available"
    assert body["ai_assessment"]["recommended_severity"] == "critical"
    assert body["matched_rule"]["severity"] == "high"

    # The read was audited under the key's id, never the key itself (REQ-09).
    audit = conn.execute("SELECT key_id, path, status_code, result_count FROM audit_entry").fetchall()
    assert [tuple(a) for a in audit] == [(key_id, f"/v1/reports/{report_id}", 200, 1)]


@pytest.mark.parametrize("path,headers,status", [
    ("/v1/reports/1", {}, 401),                       # no key
    ("/v1/reports/1", {"Authorization": "Bearer wrong"}, 401),
    ("/v1/reports/999", None, 404),                   # valid key, no such report
    ("/v1/reports/abc", None, 400),                   # malformed id -> 400, not 422
    ("/v1/reports/0", None, 400),
    ("/v1/reports/1?limit=5", None, 400),             # this endpoint takes no parameters
])
def test_ac14_report_by_id_errors(slice_cfg, conn, clock, path, headers, status):
    _run_pipeline(slice_cfg, conn, clock, MockLLMClient("ok"))
    _, key = create_key(conn, clock)
    client = TestClient(create_app(slice_cfg, clock))
    r = client.get(path, headers={"Authorization": f"Bearer {key}"} if headers is None else headers)
    assert r.status_code == status
    assert "error" in r.json() and "body" not in r.json()


def test_mock_client_selected_from_config(slice_cfg):
    slice_cfg.triage.client = "mock"
    assert isinstance(make_triage_client(slice_cfg), MockLLMClient)


def test_json_log_line_carries_context():
    record = logging.LogRecord("sec450.test", logging.INFO, __file__, 1, "cluster %s", (7,), None)
    record.cluster_id = 7
    entry = json.loads(JsonFormatter().format(record))
    assert entry["msg"] == "cluster 7" and entry["cluster_id"] == 7 and entry["level"] == "INFO"
