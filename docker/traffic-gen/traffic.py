"""Lab traffic generator (DD-03): normal and attack traffic for the SSH, web and app lab servers.

Each cycle runs one attack, then normal browsing halfway to the next attack.
Attacks rotate so every detection rule fires in turn:

  ssh_bruteforce  R1  8 failed SSH logins
  scan_404        R2  25 requests for distinct missing paths within a few seconds
  injection       R3  path traversal, SQL injection, XSS and command injection probes
  large_transfer  R4  three 4 MB downloads (12 MB, over the 10 MB threshold)
  app_bruteforce  R1  8 failed logins to the lab app's /api/login

Baseline traffic (page views, a successful app login, an API call with a valid
key, one mistyped password each on SSH and the app, one missing favicon) stays
below every rule's threshold. QUIET_GAP is longer than the longest rule window
(R4, 600 s), so baseline events never fall in an attack's window, where they
would join its cluster or start a linked follow-up cluster (DD-09).

Each attack is printed as a JSON "ground_truth" line so detection accuracy
(REQ-11) can be scored against `docker compose logs traffic-gen`.

Note: all traffic comes from this container's single IP, so baseline and attack
traffic share a source address. REQ-11 scoring will need separate source IPs.
"""
from __future__ import annotations

import http.client
import json
import logging
import socket
import time
from collections.abc import Callable
from datetime import UTC, datetime

import paramiko

SSH_HOST = "lab-ssh"
WEB_HOST = "lab-nginx"
QUIET_GAP = 660           # seconds between an attack and baseline traffic (> R4 window of 600 s)
BURST_SIZE = 8            # failed logins per brute-force burst (R1 threshold is 5)
USERNAMES = ["admin", "root", "oracle", "test"]
# Throwaway guesses sent to lab servers that have no such accounts; not real credentials.
PASSWORDS = ["123456", "password", "admin", "letmein", "qwerty", "welcome", "root", "changeme"]
LAB_KEY = "lab-key-reporting"                      # made-up key the lab app accepts
LAB_USER, LAB_PASSWORD = "alice", "lab-only-pass-1"   # made-up lab account

SCAN_PATHS = ["admin", "wp-login.php", ".env", ".git/config", "backup.zip", "phpmyadmin", "config.php",
              "server-status", "login.jsp", "console", "cgi-bin/test.cgi", "db.sql", "old", "test",
              "api/v1/users", "uploads", "shell.php", "xmlrpc.php", "admin.php", "debug", "actuator",
              "vendor/phpunit", "manager/html", "install.php", "web.config"]
INJECTION_PATHS = [
    "/../../../../etc/passwd",
    "/files/..%2f..%2f..%2fetc%2fshadow",
    "/index.html?id=1%27%20OR%201=1--",
    "/search?q=1+UNION+SELECT+username,password+FROM+users",
    "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
    "/api/records?filter=x;cat%20/etc/passwd",
]

logging.getLogger("paramiko").setLevel(logging.CRITICAL)   # failed logins are expected; keep output clean


def emit(kind: str, **fields: object) -> None:
    print(json.dumps({"ts": datetime.now(UTC).isoformat(), "kind": kind, **fields}), flush=True)


def wait_for(host: str, port: int) -> None:
    while True:
        try:
            socket.create_connection((host, port), timeout=3).close()
            return
        except OSError:
            time.sleep(2)


def failed_ssh_login(username: str, password: str) -> None:
    """One password attempt that the lab server will reject (it logs 'Failed password ...')."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # noqa: S507  # nosec B507 - lab host
    try:
        client.connect(SSH_HOST, username=username, password=password, timeout=10,
                       allow_agent=False, look_for_keys=False)
    except (paramiko.AuthenticationException, paramiko.SSHException, OSError):
        pass
    finally:
        client.close()


def web(method: str, path: str, body: dict | None = None, headers: dict | None = None) -> int:
    """One request to the lab web server; the path is sent exactly as given. Returns bytes received."""
    conn = http.client.HTTPConnection(WEB_HOST, 80, timeout=30)
    try:
        data = json.dumps(body).encode() if body is not None else None
        hdrs = {"User-Agent": "Mozilla/5.0 (lab traffic-gen)", **(headers or {})}
        if data is not None:
            hdrs["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=hdrs)
        return len(conn.getresponse().read())
    except OSError:
        return 0
    finally:
        conn.close()


def ssh_bruteforce() -> int:
    for i in range(BURST_SIZE):
        failed_ssh_login(USERNAMES[i % len(USERNAMES)], PASSWORDS[i % len(PASSWORDS)])
        time.sleep(1)
    return BURST_SIZE


def app_bruteforce() -> int:
    for i in range(BURST_SIZE):
        web("POST", "/api/login", {"user": USERNAMES[i % len(USERNAMES)], "password": PASSWORDS[i]})
        time.sleep(1)
    return BURST_SIZE


def scan_404() -> int:
    for p in SCAN_PATHS:
        web("GET", f"/{p}")
        time.sleep(0.2)
    return len(SCAN_PATHS)


def injection() -> int:
    for p in INJECTION_PATHS:
        web("GET", p)
        time.sleep(1)
    return len(INJECTION_PATHS)


def large_transfer() -> int:
    for _ in range(3):
        web("GET", "/files/dataset-2026.bin")
        time.sleep(2)
    return 3


ATTACKS: list[tuple[str, str, Callable[[], int]]] = [
    ("ssh_bruteforce", "R1", ssh_bruteforce),
    ("scan_404", "R2", scan_404),
    ("injection", "R3", injection),
    ("large_transfer", "R4", large_transfer),
    ("app_bruteforce", "R1", app_bruteforce),
]


def baseline() -> None:
    for page in ("/", "/about.html", "/docs/handbook.html", "/files/"):
        web("GET", page)
        time.sleep(3)
    web("GET", "/favicon.ico")                                        # one ordinary 404
    web("POST", "/api/login", {"user": LAB_USER, "password": "lab-only-pass-l"})  # nosec B105 - lab typo
    time.sleep(4)
    web("POST", "/api/login", {"user": LAB_USER, "password": LAB_PASSWORD})
    web("GET", "/api/records", headers={"X-API-Key": LAB_KEY})
    failed_ssh_login(LAB_USER, "wrong-password")
    emit("baseline", actions=["page_views", "favicon_404", "app_login_typo", "app_login", "api_request",
                              "ssh_failed_login"])


def main() -> None:
    wait_for(SSH_HOST, 22)
    wait_for(WEB_HOST, 80)
    emit("started", targets=[SSH_HOST, WEB_HOST])
    time.sleep(15)                     # give the collector a moment to start
    n = 0
    while True:                        # one cycle is about 22 minutes
        attack, rule, run = ATTACKS[n % len(ATTACKS)]
        n += 1
        start = datetime.now(UTC).isoformat()
        count = run()
        emit("ground_truth", attack=attack, rule=rule, burst=n, requests=count,
             start=start, end=datetime.now(UTC).isoformat())
        time.sleep(QUIET_GAP)
        baseline()
        time.sleep(QUIET_GAP)


if __name__ == "__main__":
    main()
