"""Helpers shared by the source parsers."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime

from ..models import ParseError

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclass
class ParseContext:
    tz: str
    now: datetime                                   # collector clock, UTC
    trusted_proxies: list[Network] = field(default_factory=list)


def normalize_ip(value: str | None) -> str | None:
    """Canonical text form of an IP, or None for '-'/empty. Raises ParseError if invalid."""
    if value is None or value in ("", "-"):
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ParseError(f"invalid IP address {value!r}") from exc


def is_trusted(ip: str | None, trusted: list[Network]) -> bool:
    if ip is None:
        return False
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in trusted)


def resolve_client_ip(peer: str | None, forwarded_for: str | None, trusted: list[Network]) -> str | None:
    """Honor X-Forwarded-For only when the connecting peer is a trusted proxy.

    Walks the header right to left and returns the first hop that is not
    itself a trusted proxy, so a client cannot spoof the leftmost entry.
    """
    peer = normalize_ip(peer)
    if not forwarded_for or forwarded_for == "-" or not is_trusted(peer, trusted):
        return peer
    hops = [h.strip() for h in forwarded_for.split(",") if h.strip()]
    for hop in reversed(hops):
        try:
            ip = normalize_ip(hop)
        except ParseError:
            return peer
        if not is_trusted(ip, trusted):
            return ip
    return peer


def split_request(request: str) -> tuple[str, str]:
    """'GET /path HTTP/1.1' -> ('GET', '/path'); malformed request lines keep their text."""
    parts = request.split(" ")
    if len(parts) == 3 and parts[2].startswith("HTTP/"):
        return parts[0], parts[1]
    return "INVALID", request
