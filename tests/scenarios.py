"""Seeded lab scenarios for detection latency (AC-07) and accuracy (AC-28).

Attack and baseline traffic are written as log lines in the formats the lab
servers produce (docker/lab-ssh, docker/lab-nginx, docker/lab-app) into the
test config's source files, and collected by the cycle the collector service
runs (worker.collection_cycle), with the clock stepped one interval at a time.
Parsing, storage and detection are the production code; only the servers and
the wall clock are simulated.

Unlike the live traffic generator, every attack comes from its own address, so
ground truth can be matched to clusters by (rule, client IP). Baseline clients
include near misses: a user who mistypes a password a few times, a crawler
following a dozen dead links, and a client who downloads two large files.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from sec450.collector import Collector
from sec450.config import Config
from sec450.geoip import GeoIP
from sec450.timeutil import FixedClock, iso, parse_iso
from sec450.worker import collection_cycle

LAB_TZ = ZoneInfo("America/Indiana/Indianapolis")   # the nginx and SSH lab servers' zone
PROXY = "172.20.0.10"                                # nginx, the trusted proxy in front of the app

PAGES = ["/", "/about.html", "/docs/handbook.html", "/files/", "/blog/2026/10/select-the-right-tool",
         "/search?q=union+station", "/search?q=rock+and+roll", "/products?sort=price&order=asc"]
DEAD_LINKS = ["/favicon.ico", "/old/index.html", "/blog/draft", "/img/logo.png", "/apple-touch-icon.png",
              "/robots.txt", "/sitemap.xml", "/docs/v1/", "/docs/v2/", "/team.html", "/careers",
              "/press", "/feed", "/rss.xml", "/archive/2024"]
SCAN_PATHS = ["/admin", "/wp-login.php", "/.env", "/.git/config", "/backup.zip", "/phpmyadmin", "/config.php",
              "/server-status", "/login.jsp", "/console", "/cgi-bin/test.cgi", "/db.sql", "/old", "/test",
              "/api/v1/users", "/uploads", "/shell.php", "/xmlrpc.php", "/admin.php", "/debug", "/actuator",
              "/vendor/phpunit", "/manager/html", "/install.php", "/web.config", "/.htaccess", "/.svn/entries",
              "/wp-admin/", "/administrator/", "/solr/", "/jenkins/", "/.DS_Store", "/id_rsa", "/dump.sql",
              "/info.php", "/status"]
INJECTION_PATHS = ["/../../../../etc/passwd", "/files/..%2f..%2f..%2fetc%2fshadow",
                   "/index.html?id=1%27%20OR%201=1--", "/search?q=1+UNION+SELECT+username,password+FROM+users",
                   "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
                   "/api/records?filter=x;cat%20/etc/passwd", "/item?id=1;%20DROP%20TABLE%20users",
                   "/search?q=$(id)"]
GUESSED_USERS = ["admin", "root", "oracle", "test", "ubuntu", "postgres"]
LAB_USERS = ["alice", "bob", "carol", "dave"]
BIG_FILE = 4_194_304                                 # /files/dataset-2026.bin on the lab nginx

# Attack kinds and the rule each one should trip.
ATTACK_RULES = {"ssh_bruteforce": "R1", "app_bruteforce": "R1", "scan_404": "R2",
                "injection": "R3", "large_transfer": "R4"}


@dataclass
class Line:
    ts: datetime
    source: str
    text: str


@dataclass
class Attack:
    """Ground truth for one injected attack."""
    kind: str
    rule: str
    ip: str
    start: datetime
    end: datetime
    trigger: datetime   # when the line completing the rule's condition was written

    def as_json(self) -> str:
        return json.dumps({"kind": "ground_truth", "attack": self.kind, "rule": self.rule, "ip": self.ip,
                           "start": iso(self.start), "end": iso(self.end), "trigger": iso(self.trigger)})


@dataclass
class Score:
    attacks: int
    detected: int
    clusters: int
    false_alarms: list[dict] = field(default_factory=list)
    missed: list[Attack] = field(default_factory=list)

    @property
    def detection_rate(self) -> float:
        return self.detected / self.attacks

    @property
    def false_alarm_rate(self) -> float:
        return len(self.false_alarms) / self.clusters if self.clusters else 0.0


class LabTraffic:
    """Builds a timeline of lab log lines plus the ground truth of the attacks in it."""

    def __init__(self, cfg: Config, seed: int, start: datetime):
        self.cfg = cfg
        self.rng = random.Random(seed)
        self.start = start
        self.lines: list[Line] = []
        self.attacks: list[Attack] = []
        self._next_attacker = 1
        self._rules = {r.id: r for r in cfg.detection.rules}

    # -- log lines in the lab servers' formats -----------------------------------------------
    def _access(self, ts: datetime, ip: str, method: str, path: str, status: int, size: int) -> None:
        self.lines.append(Line(ts, "nginx_access",
                               f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" '
                               f'{status} {size} "-" "Mozilla/5.0 (lab)" "-"'))
        if status == 404:
            local = ts.astimezone(LAB_TZ)
            self.lines.append(Line(ts, "nginx_error",
                                   f'{local:%Y/%m/%d %H:%M:%S} [error] 12#12: *1 open() '
                                   f'"/usr/share/nginx/lab{path.split("?")[0]}" failed (2: No such file or '
                                   f'directory), client: {ip}, server: web01, request: "{method} {path} '
                                   f'HTTP/1.1", host: "web01"'))

    def _ssh(self, ts: datetime, ip: str, user: str, ok: bool) -> None:
        local = ts.astimezone(LAB_TZ)
        verb = "Accepted password" if ok else "Failed password"
        port = self.rng.randint(1024, 65535)
        self.lines.append(Line(ts, "ssh_auth", f"{local:%b} {local.day:>2} {local:%H:%M:%S} ssh01 sshd[42]: "
                                               f"{verb} for {user} from {ip} port {port} ssh2"))

    def _app_login(self, ts: datetime, ip: str, user: str, ok: bool) -> None:
        """A login through nginx: one access line, and the app's JSON line with nginx as the peer."""
        status = 200 if ok else 401
        self._access(ts, ip, "POST", "/api/login", status, 12)
        self.lines.append(Line(ts, "app", json.dumps({
            "ts": iso(ts), "event": "login", "outcome": "success" if ok else "failure", "peer_ip": PROXY,
            "x_forwarded_for": ip, "user": user, "api_key_id": None, "path": "/api/login",
            "status": status, "bytes": 12})))

    def _api_request(self, ts: datetime, ip: str) -> None:
        self._access(ts, ip, "GET", "/api/records", 200, 220)
        self.lines.append(Line(ts, "app", json.dumps({
            "ts": iso(ts), "event": "api_request", "outcome": "success", "peer_ip": PROXY,
            "x_forwarded_for": ip, "user": None, "api_key_id": "k_lab_reporting", "path": "/api/records",
            "status": 200, "bytes": 220})))

    # -- attacks -----------------------------------------------------------------------------
    def attacker_ip(self) -> str:
        n = self._next_attacker
        self._next_attacker += 1
        return f"203.0.{113 + n // 250}.{n % 250 + 1}"

    def attack(self, kind: str, at: float) -> Attack:
        """Add one attack starting `at` seconds after the scenario start."""
        rng, ip, rule = self.rng, self.attacker_ip(), self._rules[ATTACK_RULES[kind]]
        t = self.start + timedelta(seconds=at)
        times: list[datetime] = []
        trigger_index = 0
        if kind in ("ssh_bruteforce", "app_bruteforce"):
            for _ in range(rng.randint(rule.threshold + 1, rule.threshold + 7)):
                user = rng.choice(GUESSED_USERS)
                (self._ssh if kind == "ssh_bruteforce" else self._app_login)(t, ip, user, False)
                times.append(t)
                t += timedelta(seconds=rng.uniform(1, 3))
            trigger_index = rule.threshold - 1
        elif kind == "scan_404":
            for path in rng.sample(SCAN_PATHS, rng.randint(rule.threshold + 2, len(SCAN_PATHS))):
                self._access(t, ip, "GET", path, 404, 153)
                times.append(t)
                t += timedelta(seconds=rng.uniform(0.2, 1.4))
            trigger_index = rule.threshold - 1
        elif kind == "injection":
            for path in rng.sample(INJECTION_PATHS, rng.randint(1, 6)):
                self._access(t, ip, "GET", path, rng.choice([400, 404, 200]), 153)
                times.append(t)
                t += timedelta(seconds=rng.uniform(1, 5))
        elif kind == "large_transfer":
            total = 0
            for i in range(rng.randint(3, 6)):
                self._access(t, ip, "GET", "/files/dataset-2026.bin", 200, BIG_FILE)
                times.append(t)
                total += BIG_FILE
                if total <= rule.threshold:
                    trigger_index = i + 1
                t += timedelta(seconds=rng.uniform(5, 90))
        else:
            raise ValueError(kind)
        a = Attack(kind, rule.id, ip, times[0], times[-1], times[trigger_index])
        self.attacks.append(a)
        return a

    # -- baseline ----------------------------------------------------------------------------
    def baseline(self, minutes: int, clients: int = 60) -> None:
        """Ordinary browsing, logins and API use, plus near misses that stay under every threshold."""
        rng = self.rng
        pool = [f"198.51.100.{i}" for i in range(1, clients + 1)] + ["2001:db8::17", "2001:db8::42"]
        for minute in range(minutes):
            for _ in range(rng.randint(6, 14)):
                ip = rng.choice(pool)
                t = self.start + timedelta(seconds=minute * 60 + rng.uniform(0, 50))
                for page in rng.sample(PAGES, rng.randint(1, 4)):
                    self._access(t, ip, "GET", page, 200, rng.randint(400, 60_000))
                    t += timedelta(seconds=rng.uniform(0.5, 3))
                roll = rng.random()
                if roll < 0.08:
                    self._access(t, ip, "GET", rng.choice(DEAD_LINKS), 404, 153)
                elif roll < 0.12:
                    user = rng.choice(LAB_USERS)
                    self._app_login(t, ip, user, False)                    # one typo, then in
                    self._app_login(t + timedelta(seconds=4), ip, user, True)
                elif roll < 0.15:
                    self._ssh(t, ip, rng.choice(LAB_USERS), True)
                elif roll < 0.20:
                    self._api_request(t, ip)
                elif roll < 0.21:
                    self._access(t, ip, "GET", "/files/dataset-2026.bin", 200, BIG_FILE)
        self._near_misses(minutes)

    def _near_misses(self, minutes: int) -> None:
        rng, span = self.rng, max(60, minutes * 60 - 700)
        r1, r2, r4 = (self._rules[r] for r in ("R1", "R2", "R4"))
        for i in range(3):
            ip, t = f"192.0.2.{10 + i}", self.start + timedelta(seconds=rng.uniform(0, span))
            for _ in range(r1.threshold - 1):                               # forgetful user
                (self._ssh if i % 2 else self._app_login)(t, ip, LAB_USERS[i], False)
                t += timedelta(seconds=rng.uniform(5, 30))
            ip, t = f"192.0.2.{20 + i}", self.start + timedelta(seconds=rng.uniform(0, span))
            for path in rng.sample(DEAD_LINKS, min(len(DEAD_LINKS), r2.threshold - 5)):   # dead-link crawler
                self._access(t, ip, "GET", path, 404, 153)
                t += timedelta(seconds=rng.uniform(0.5, 2))
            ip, t = f"192.0.2.{30 + i}", self.start + timedelta(seconds=rng.uniform(0, span))
            for _ in range(r4.threshold // BIG_FILE):                       # two big downloads, under 10 MB
                self._access(t, ip, "GET", "/files/dataset-2026.bin", 200, BIG_FILE)
                t += timedelta(seconds=rng.uniform(30, 240))


def play(traffic: LabTraffic, cfg: Config, conn, clock: FixedClock, until: datetime) -> None:
    """Write each line before the first collection cycle after its timestamp, one interval at a time."""
    paths = {s.name: s.path for s in cfg.sources}
    for p in paths.values():
        p.touch()
    lines = sorted(traffic.lines, key=lambda ln: ln.ts)
    collector = Collector(cfg, conn, clock, GeoIP(), sleep=lambda _: None)
    step = timedelta(seconds=cfg.collector.interval_seconds)
    t, i = traffic.start + step, 0
    while t <= until:
        chunk: dict[str, list[str]] = {}
        while i < len(lines) and lines[i].ts < t:
            chunk.setdefault(lines[i].source, []).append(lines[i].text)
            i += 1
        for source, texts in chunk.items():
            with paths[source].open("a", encoding="utf-8") as fh:
                fh.write("".join(text + "\n" for text in texts))
        clock.set(t)
        collection_cycle(collector, conn, cfg, clock)
        t += step


def first_cluster(conn, attack: Attack):
    return conn.execute("SELECT cluster_id, created_at FROM cluster WHERE rule_id = ? AND group_key = ? "
                        "ORDER BY created_at, cluster_id LIMIT 1", (attack.rule, attack.ip)).fetchone()


def score(conn, attacks: list[Attack]) -> Score:
    """Detected: a cluster of the attack's rule for its address. False alarm: a cluster for an
    address that sent no attack (linked follow-up clusters of an attack count as that attack)."""
    attack_ips = {a.ip for a in attacks}
    clusters = [dict(r) for r in conn.execute("SELECT cluster_id, rule_id, severity, group_key, window_start, "
                                              "window_end FROM cluster ORDER BY cluster_id")]
    missed = [a for a in attacks if first_cluster(conn, a) is None]
    return Score(attacks=len(attacks), detected=len(attacks) - len(missed), clusters=len(clusters),
                 false_alarms=[c for c in clusters if c["group_key"] not in attack_ips], missed=missed)


def latency_seconds(conn, attack: Attack) -> float | None:
    row = first_cluster(conn, attack)
    return None if row is None else (parse_iso(row["created_at"]) - attack.trigger).total_seconds()
