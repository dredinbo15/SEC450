"""Check both hash chains: `python -m sec450.verify` (REQ-08, REQ-09, AC-21).

Prints the result as JSON and exits 0 when both chains are intact, 1 when
either is broken (so scripts and CI can use the exit code). In Docker:

    docker compose exec collector python -m sec450.verify
"""
from __future__ import annotations

import argparse
import json

from .config import load_config
from .db import connect, init_db
from .hashchain import verify_audit, verify_batches


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sec450.verify")
    parser.add_argument("--config", help="path to config.yaml (default: $SEC450_CONFIG or ./config.yaml)")
    args = parser.parse_args(argv)

    conn = connect(load_config(args.config).database_path)
    init_db(conn)
    result = {"batches": verify_batches(conn), "audit": verify_audit(conn)}
    print(json.dumps(result, indent=2))
    return 0 if all(chain["status"] == "intact" for chain in result.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
