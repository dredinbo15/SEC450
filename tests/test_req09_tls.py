"""REQ-09: the query endpoint accepts only TLS 1.2 or later (AC-23).

Serves the API with the service's own uvicorn config (sec450.api.__main__) on a
local port and connects with each protocol version. A control server that does
accept TLS 1.0 and 1.1 proves this client can still offer them, so a refusal
comes from the API, not from the local OpenSSL build.
"""
import shutil
import socket
import ssl
import subprocess
import threading
import time

import httpx
import pytest
import uvicorn

from sec450.api.__main__ import server_config
from sec450.keys import create_key

OLD_VERSIONS = {"1.0": ssl.TLSVersion.TLSv1, "1.1": ssl.TLSVersion.TLSv1_1}
NEW_VERSIONS = {"1.2": ssl.TLSVersion.TLSv1_2, "1.3": ssl.TLSVersion.TLSv1_3}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def certs(tmp_path):
    if shutil.which("openssl") is None:
        pytest.skip("openssl command not available")
    cert, key = tmp_path / "server.crt", tmp_path / "server.key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",  # noqa: S603,S607
                    "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    return cert, key


@pytest.fixture
def server(cfg, conn, certs):
    cfg.api.host, cfg.api.port = "127.0.0.1", free_port()
    cfg.api.tls_cert, cfg.api.tls_key = certs
    srv = uvicorn.Server(server_config(cfg))
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not srv.started:
        assert time.monotonic() < deadline and thread.is_alive(), "API did not start"
        time.sleep(0.05)
    yield cfg
    srv.should_exit = True
    thread.join(10)


def legacy_client(version: ssl.TLSVersion) -> ssl.SSLContext:
    """A client pinned to one version, allowed to use the old ciphers that version needs."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    ctx.minimum_version = ctx.maximum_version = version
    return ctx


def handshake(port: int, ctx: ssl.SSLContext) -> str | None:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock, ctx.wrap_socket(sock) as tls:
        return tls.version()


def client_can_offer(version: ssl.TLSVersion, certs) -> bool:
    """Handshake against a server that accepts every version, to see if this OpenSSL allows `version`."""
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(*certs)
    server_ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    server_ctx.minimum_version = ssl.TLSVersion.TLSv1
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def accept() -> None:
            conn, _ = listener.accept()
            try:
                server_ctx.wrap_socket(conn, server_side=True).close()
            except (OSError, ssl.SSLError):
                conn.close()

        t = threading.Thread(target=accept, daemon=True)
        t.start()
        try:
            return handshake(listener.getsockname()[1], legacy_client(version)) is not None
        except (OSError, ssl.SSLError):
            return False
        finally:
            t.join(5)


def audit_count(conn) -> int:
    return conn.execute("SELECT COUNT(*) FROM audit_entry").fetchone()[0]


@pytest.mark.filterwarnings("ignore:ssl.TLSVersion.TLSv1:DeprecationWarning")
def test_tls_enforcement(server, conn, certs):  # AC-23
    port = server.api.port
    _, key = create_key(conn)

    with pytest.raises(httpx.TransportError):
        httpx.get(f"http://127.0.0.1:{port}/v1/events", headers={"Authorization": f"Bearer {key}"},
                  timeout=5, trust_env=False)
    for name, version in OLD_VERSIONS.items():
        if not client_can_offer(version, certs):
            pytest.skip(f"this OpenSSL build cannot offer TLS {name}, so its refusal cannot be shown")
        with pytest.raises(ssl.SSLError):
            handshake(port, legacy_client(version))
    assert audit_count(conn) == 0          # refused connections never reach the audited handler

    for name, version in NEW_VERSIONS.items():
        ctx = ssl.create_default_context(cafile=str(certs[0]))
        ctx.minimum_version = ctx.maximum_version = version
        with httpx.Client(verify=ctx, trust_env=False, timeout=5) as client:
            r = client.get(f"https://127.0.0.1:{port}/v1/events", headers={"Authorization": f"Bearer {key}"})
        assert r.status_code == 200, (name, r.text)
    assert audit_count(conn) == 2
