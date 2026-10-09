"""Lab traffic generator (DD-03). Thin-slice version: SSH only.

- Attack: a burst of BURST_SIZE failed logins (brute force), which R1 should flag.
- Baseline: one failed login halfway between bursts, like a user mistyping a
  password. It is kept QUIET_GAP seconds (more than R1's 5-minute window) away
  from every burst, so it never lands in an attack cluster or starts a linked
  follow-up cluster after the attack cluster is frozen (DD-09).

Each attack is printed as a JSON "ground_truth" line so detection accuracy
(REQ-11) can later be scored against `docker compose logs traffic-gen`.

Note: every request comes from this container's single IP, so baseline and
attack traffic share a source address. Fine for the slice; REQ-11 scoring
will need separate source IPs.
"""
from __future__ import annotations

import json
import logging
import socket
import time
from datetime import UTC, datetime

import paramiko

SSH_HOST = "lab-ssh"
QUIET_GAP = 450           # seconds between a burst and a baseline login (> R1 window of 300 s)
BURST_SIZE = 8            # failed logins per burst (R1 threshold is 5)
USERNAMES = ["admin", "root", "oracle", "test"]
# Throwaway guesses sent to the lab server, which has no accounts; not real credentials.
PASSWORDS = ["123456", "password", "admin", "letmein", "qwerty", "welcome", "root", "changeme"]

logging.getLogger("paramiko").setLevel(logging.CRITICAL)   # failed logins are expected; keep output clean


def emit(kind: str, **fields: object) -> None:
    print(json.dumps({"ts": datetime.now(UTC).isoformat(), "kind": kind, **fields}), flush=True)


def wait_for_ssh() -> None:
    while True:
        try:
            socket.create_connection((SSH_HOST, 22), timeout=3).close()
            return
        except OSError:
            time.sleep(2)


def failed_login(username: str, password: str) -> None:
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


def attack_burst(n: int) -> None:
    start = datetime.now(UTC).isoformat()
    for i in range(BURST_SIZE):
        failed_login(USERNAMES[i % len(USERNAMES)], PASSWORDS[i % len(PASSWORDS)])
        time.sleep(1)
    emit("ground_truth", attack="ssh_bruteforce", rule="R1", burst=n, attempts=BURST_SIZE,
         start=start, end=datetime.now(UTC).isoformat())


def main() -> None:
    wait_for_ssh()
    emit("started", target=SSH_HOST)
    time.sleep(15)                     # give the collector a moment to start
    bursts = 0
    while True:                        # one cycle is about 15 minutes
        bursts += 1
        attack_burst(bursts)
        time.sleep(QUIET_GAP)
        failed_login("alice", "wrong-password")
        emit("baseline", action="ssh_failed_login")
        time.sleep(QUIET_GAP)


if __name__ == "__main__":
    main()
