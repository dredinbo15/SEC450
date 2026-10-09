"""Run the API over HTTPS with TLS 1.2 as the floor: `python -m sec450.api` (REQ-09, AC-23)."""
from __future__ import annotations

import ssl

import uvicorn

from ..config import load_config
from ..logjson import setup_logging
from .app import create_app


def main() -> None:
    setup_logging()
    cfg = load_config()
    config = uvicorn.Config(
        create_app(cfg), host=cfg.api.host, port=cfg.api.port,
        ssl_certfile=str(cfg.api.tls_cert), ssl_keyfile=str(cfg.api.tls_key),
        proxy_headers=False, server_header=False,
        log_config=None,    # keep our JSON handler instead of uvicorn's text format
        access_log=False,   # the app logs each request itself, with a request_id
    )
    config.load()
    if config.ssl is None:  # uvicorn builds this from the cert/key above
        raise RuntimeError("TLS is not configured; refusing to serve plain HTTP")
    config.ssl.minimum_version = ssl.TLSVersion.TLSv1_2
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
