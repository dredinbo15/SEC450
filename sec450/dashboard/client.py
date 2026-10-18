"""Minimal client for the /v1 query API."""
from __future__ import annotations

import httpx

from ..config import DashboardConfig


class ApiError(RuntimeError):
    pass


class ApiClient:
    def __init__(self, cfg: DashboardConfig, transport: httpx.BaseTransport | None = None):
        key = cfg.resolved_api_key()
        if not key:
            raise ApiError("no API key: set dashboard.api_key in config.yaml or SEC450_API_KEY")
        self._http = httpx.Client(
            base_url=cfg.api_url, headers={"Authorization": f"Bearer {key}"}, timeout=10,
            verify=str(cfg.ca_cert) if cfg.ca_cert else True, transport=transport)

    def get(self, path: str, **params) -> dict:
        params = {k: v for k, v in params.items() if v not in (None, "")}
        try:
            r = self._http.get(path, params=params)
        except httpx.HTTPError as exc:
            raise ApiError(f"cannot reach the API: {exc}") from exc
        if r.status_code != 200:
            try:
                detail = r.json().get("error", r.text)
            except ValueError:
                detail = r.text
            raise ApiError(f"{path} returned {r.status_code}: {detail}")
        return r.json()
