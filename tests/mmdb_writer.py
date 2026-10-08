"""Minimal MaxMind DB (.mmdb) writer for building the AC-04 test GeoIP databases.

Implements just enough of the MaxMind DB format 2.0 spec (IPv6 tree, 24-bit records,
IPv4 networks under ::/96) for geoip2/maxminddb to read the result. Networks must not
overlap. Spec: https://maxmind.github.io/MaxMind-DB/
"""
from __future__ import annotations

import ipaddress
import time
from pathlib import Path

METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"


class Uint16(int): ...
class Uint32(int): ...
class Uint64(int): ...


def _control(type_: int, size: int) -> bytes:
    if size < 29:
        low, ext = size, b""
    elif size < 285:
        low, ext = 29, bytes([size - 29])
    elif size < 65821:
        low, ext = 30, (size - 285).to_bytes(2, "big")
    else:
        low, ext = 31, (size - 65821).to_bytes(3, "big")
    if type_ <= 7:
        return bytes([(type_ << 5) | low]) + ext
    return bytes([low, type_ - 7]) + ext


def _uint(type_: int, value: int, width: int) -> bytes:
    payload = value.to_bytes(width, "big").lstrip(b"\x00")
    return _control(type_, len(payload)) + payload


def encode(value) -> bytes:
    if isinstance(value, bool):
        return _control(14, int(value))
    if isinstance(value, Uint16):
        return _uint(5, value, 2)
    if isinstance(value, Uint64):
        return _uint(9, value, 8)
    if isinstance(value, int):
        return _uint(6, value, 4)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _control(2, len(raw)) + raw
    if isinstance(value, dict):
        return _control(7, len(value)) + b"".join(encode(k) + encode(v) for k, v in value.items())
    if isinstance(value, list):
        return _control(11, len(value)) + b"".join(encode(v) for v in value)
    raise TypeError(f"cannot encode {type(value).__name__}")


def write_mmdb(path: Path, database_type: str, networks: dict[str, dict]) -> Path:
    """Write networks ({'8.8.8.0/24': record, ...}) to an IPv6 database at path."""
    data, offsets, root = b"", [], [None, None]
    for cidr, record in networks.items():
        net = ipaddress.ip_network(cidr)
        bits = int(net.network_address)
        prefix = net.prefixlen + (96 if net.version == 4 else 0)  # IPv4 lives under ::/96
        offsets.append(len(data))
        data += encode(record)
        node = root
        for i in range(prefix):
            bit = (bits >> (127 - i)) & 1
            if i == prefix - 1:
                node[bit] = ("data", offsets[-1])
            else:
                if not isinstance(node[bit], list):
                    node[bit] = [None, None]
                node = node[bit]

    order, queue = [], [root]  # breadth-first numbering, root is node 0
    while queue:
        node = queue.pop(0)
        order.append(node)
        queue.extend(c for c in node if isinstance(c, list))
    number = {id(n): i for i, n in enumerate(order)}
    count = len(order)

    def record(child) -> int:
        if child is None:
            return count                       # "not found"
        if isinstance(child, list):
            return number[id(child)]
        return count + 16 + child[1]          # data section pointer

    tree = b"".join(record(n[0]).to_bytes(3, "big") + record(n[1]).to_bytes(3, "big") for n in order)
    metadata = {
        "binary_format_major_version": Uint16(2),
        "binary_format_minor_version": Uint16(0),
        "build_epoch": Uint64(int(time.time())),
        "database_type": database_type,
        "description": {"en": "SEC450 test database"},
        "ip_version": Uint16(6),
        "languages": ["en"],
        "node_count": Uint32(count),
        "record_size": Uint16(24),
    }
    path.write_bytes(tree + b"\x00" * 16 + data + METADATA_MARKER + encode(metadata))
    return path
