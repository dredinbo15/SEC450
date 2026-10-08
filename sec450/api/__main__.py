"""Run the API over HTTPS with TLS 1.2 as the floor: `python -m sec450.api` (REQ-09, AC-23)."""
from __future__ import annotations

import logging
import ssl

import uvicorn

from ..config import load_config
from .app import create_app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load_config()
    config = uvicorn.Config(
        create_app(cfg), host=cfg.api.host, port=cfg.api.port,
        ssl_certfile=str(cfg.api.tls_cert), ssl_keyfile=str(cfg.api.tls_key),
        proxy_headers=False, server_header=False,
    )
    config.load()
    config.ssl.minimum_version = ssl.TLSVersion.TLSv1_2
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
