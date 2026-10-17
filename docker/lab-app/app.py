"""Lab application (DD-03): a tiny JSON API behind the lab nginx, standard library only.

Writes one JSON object per request to /var/log/app/app.log, in the format
sec450/parsers/app.py parses (ts, event, outcome, peer_ip, x_forwarded_for,
user, api_key_id, path, status, bytes). Times are UTC.

The account and API keys below are made up for the lab: they protect nothing and
exist only so logins and key use show up in the logs. Lab use only.
"""
from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock

LOG_PATH = "/var/log/app/app.log"
USERS = {"alice": "lab-only-pass-1"}                     # the one account that can log in
API_KEYS = {"lab-key-reporting": "k_lab_reporting",      # key -> key id (only the id is logged)
            "lab-key-sync": "k_lab_sync"}
RECORDS = [{"id": i, "name": f"asset-{i:03d}", "owner": "it-ops", "site": "lab"} for i in range(1, 41)]

_log_lock = Lock()
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
_log = open(LOG_PATH, "a", buffering=1, encoding="utf-8")   # noqa: SIM115 - kept open for the process
os.chmod(LOG_PATH, 0o644)                                   # the collector reads it as another user


class Handler(BaseHTTPRequestHandler):
    server_version = "lab-app"

    def _send(self, status: int, body: dict, event: str, outcome: str, user: str | None = None,
              api_key_id: str | None = None) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        entry = {"ts": datetime.now(UTC).isoformat().replace("+00:00", "Z"), "event": event,
                 "outcome": outcome, "peer_ip": self.client_address[0],
                 "x_forwarded_for": self.headers.get("X-Forwarded-For"), "user": user,
                 "api_key_id": api_key_id, "path": self.path, "status": status, "bytes": len(data)}
        with _log_lock:
            _log.write(json.dumps(entry) + "\n")

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        if self.path == "/api/health":
            self._send(200, {"status": "ok"}, "health_check", "success")
        elif self.path.startswith("/api/records"):
            key = self.headers.get("X-API-Key", "")
            key_id = API_KEYS.get(key)
            if key_id:
                self._send(200, {"records": RECORDS}, "api_request", "success", api_key_id=key_id)
            else:
                self._send(401, {"error": "invalid API key"}, "api_request", "failure")
        else:
            self._send(404, {"error": "not found"}, "http_request", "failure")

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        length = min(int(self.headers.get("Content-Length") or 0), 4096)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            body = {}
        if self.path != "/api/login":
            self._send(404, {"error": "not found"}, "http_request", "failure")
            return
        user = str(body.get("user", ""))[:64] or None
        ok = user in USERS and body.get("password") == USERS[user]
        self._send(200 if ok else 401, {"ok": ok}, "login", "success" if ok else "failure", user=user)

    def log_message(self, *args: object) -> None:   # the JSON log above replaces stderr access logs
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()  # noqa: S104  # nosec B104 - lab container
