"""DD-17: reports are pushed to the SIEM once each, and an outage delays them instead of losing them."""
import json
import socket
import threading

import pytest

from sec450.mock_llm import MockLLMClient
from sec450.siem import forward_pending_reports
from sec450.worker import analysis_cycle

from .test_thin_slice import ATTACKER, _run_pipeline


class SyslogServer:
    """Accepts TCP connections on a free local port and keeps every newline-framed line."""

    def __init__(self) -> None:
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.lines: list[bytes] = []
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                data = b""
                while chunk := conn.recv(65536):
                    data += chunk
                self.lines += data.splitlines()

    def close(self) -> None:
        self.sock.close()


@pytest.fixture
def siem_cfg(slice_cfg):
    slice_cfg.siem.enabled = True
    slice_cfg.siem.host = "127.0.0.1"
    slice_cfg.siem.report_url = "https://seclog.example/v1/reports/"
    return slice_cfg


@pytest.fixture
def server():
    s = SyslogServer()
    yield s
    s.close()


def _delivered(conn) -> list[int]:
    return [r[0] for r in conn.execute("SELECT report_id FROM siem_delivery ORDER BY report_id")]


def _wait_for(server: SyslogServer, n: int) -> None:
    for _ in range(200):
        if len(server.lines) >= n:
            return
        threading.Event().wait(0.01)


def test_report_pushed_once_with_triage_fields(siem_cfg, conn, clock, server):
    siem_cfg.siem.port = server.port
    _run_pipeline(siem_cfg, conn, clock, MockLLMClient("ok"))   # analysis_cycle forwards the new report
    _wait_for(server, 1)

    report_id = conn.execute("SELECT report_id FROM report").fetchone()[0]
    assert _delivered(conn) == [report_id]
    assert len(server.lines) == 1
    alert = json.loads(server.lines[0])
    assert alert["srcip"] == ATTACKER
    s = alert["sec450"]
    assert (s["report_id"], s["severity"], s["rule"]["id"]) == (report_id, "high", "R1")
    assert s["usernames"] == ["admin", "root"] and s["event_count"] == 6
    assert s["ai"]["status"] == "available" and s["ai"]["recommended_severity"] == "critical"
    assert s["integrity"] == "intact"
    assert s["report_url"] == f"https://seclog.example/v1/reports/{report_id}"
    assert "raw_lines" not in s           # the full report stays behind the authenticated API

    analysis_cycle(conn, siem_cfg, clock, None)   # nothing new: nothing sent again
    assert len(server.lines) == 1


def test_outage_delays_delivery_without_losing_reports(siem_cfg, conn, clock):
    dead = socket.create_server(("127.0.0.1", 0))
    siem_cfg.siem.port = dead.getsockname()[1]
    dead.close()                                    # nothing listens on this port now
    _run_pipeline(siem_cfg, conn, clock, MockLLMClient("ok"))
    assert conn.execute("SELECT COUNT(*) FROM report").fetchone()[0] == 1
    assert _delivered(conn) == []

    server = SyslogServer()                         # the SIEM comes back
    try:
        siem_cfg.siem.port = server.port
        assert forward_pending_reports(conn, siem_cfg, clock) == _delivered(conn) != []
        _wait_for(server, 1)
        assert len(server.lines) == 1
    finally:
        server.close()


def test_disabled_sends_nothing(slice_cfg, conn, clock):
    sent: list = []
    _run_pipeline(slice_cfg, conn, clock, MockLLMClient("ok"))
    assert forward_pending_reports(conn, slice_cfg, clock, send=lambda cfg, lines: sent.append(lines)) == []
    assert sent == [] and _delivered(conn) == []


def test_batches_and_retention_cleanup(siem_cfg, conn, clock):
    _run_pipeline(siem_cfg, conn, clock, MockLLMClient("ok"))
    conn.execute("DELETE FROM siem_delivery")       # pretend nothing was delivered yet
    body = conn.execute("SELECT body_json FROM report").fetchone()[0]
    cluster_id = conn.execute("SELECT cluster_id FROM cluster").fetchone()[0]
    for i in range(2):                              # two more reports for copies of the cluster
        cid = conn.execute("INSERT INTO cluster (rule_id, severity, group_key, window_start, window_end, state, "
                           "created_at) SELECT rule_id, severity, group_key, window_start, window_end, state, "
                           "created_at FROM cluster WHERE cluster_id = ?", (cluster_id,)).lastrowid
        conn.execute("INSERT INTO report (cluster_id, generated_at, body_json) VALUES (?, ?, ?)",
                     (cid, f"2026-10-08T15:0{i}:00.000000Z", body))

    siem_cfg.siem.batch_size = 2
    batches: list[int] = []
    send = lambda cfg, lines: batches.append(len(lines))  # noqa: E731
    first = forward_pending_reports(conn, siem_cfg, clock, send=send)
    second = forward_pending_reports(conn, siem_cfg, clock, send=send)
    assert batches == [2, 1] and len(set(first + second)) == 3

    conn.execute("DELETE FROM report WHERE report_id = ?", (first[0],))   # what retention does
    assert first[0] not in _delivered(conn)
