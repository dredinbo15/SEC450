"""Loads and validates config.yaml, the single configuration file (REQ-12)."""
from __future__ import annotations

import ipaddress
import os
import re
from pathlib import Path
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

Severity = Literal["low", "medium", "high", "critical"]
SEVERITY_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SourceKind = Literal["nginx_access", "nginx_error", "ssh_auth", "app"]
RuleKind = Literal["failed_login_count", "distinct_404", "pattern", "bytes_sum"]


class SourceConfig(BaseModel):
    name: str
    kind: SourceKind
    host: str
    path: Path
    timezone: str = "UTC"

    @field_validator("name")
    @classmethod
    def _safe_name(cls, v: str) -> str:
        # Letters, digits, "_", "-", "." only: the name is part of the batch hash,
        # where "|" separates fields (hashchain.batch_hash).
        if not re.fullmatch(r"[A-Za-z0-9_.\-]+", v):
            raise ValueError(f"source name {v!r} may contain only letters, digits, '_', '-' and '.'")
        return v

    @field_validator("timezone")
    @classmethod
    def _valid_tz(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"unknown time zone {v!r}") from exc
        return v


class CollectorConfig(BaseModel):
    interval_seconds: int = Field(60, ge=1, le=300)
    read_retries: int = Field(3, ge=0)
    retry_delay_seconds: float = Field(2.0, ge=0)
    clock_skew_seconds: int = 300
    quarantine_warn_ratio: float = 0.05
    trusted_proxies: list[str] = []

    @field_validator("trusted_proxies")
    @classmethod
    def _valid_networks(cls, v: list[str]) -> list[str]:
        for net in v:
            ipaddress.ip_network(net, strict=False)
        return v

    def proxy_networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_network(n, strict=False) for n in self.trusted_proxies]


class RuleConfig(BaseModel):
    id: str
    name: str
    kind: RuleKind
    severity: Severity
    threshold: int = Field(ge=1)
    window_seconds: int = Field(ge=1)
    enabled: bool = True
    patterns: list[str] = []

    @field_validator("patterns")
    @classmethod
    def _valid_patterns(cls, v: list[str]) -> list[str]:
        for p in v:
            try:
                re.compile(p)
            except re.error as exc:
                raise ValueError(f"invalid pattern {p!r}: {exc}") from exc
        return v

    @model_validator(mode="after")
    def _pattern_rule_has_patterns(self) -> RuleConfig:
        if self.kind == "pattern" and not self.patterns:
            raise ValueError(f"rule {self.id}: a pattern rule needs at least one pattern")
        return self


class DetectionConfig(BaseModel):
    lookback_seconds: int = 900
    rules: list[RuleConfig]

    @model_validator(mode="after")
    def _unique_ids(self) -> DetectionConfig:
        ids = [r.id for r in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("rule ids must be unique")
        return self


class GeoIPConfig(BaseModel):
    asn_db: Path | None = None
    country_db: Path | None = None


class TriageConfig(BaseModel):
    enabled: bool = True
    api_key: str | None = None
    model: str = "claude-opus-5-5"
    effort: Literal["low", "medium", "high", "xhigh", "max"] = "low"
    server_fallbacks: bool = True
    timeout_seconds: float = 30
    retries: int = 2
    max_events: int = Field(50, ge=1, le=50)
    settle_seconds: int = 60
    max_wait_seconds: int = 180
    worker_interval_seconds: int = 15

    def resolved_api_key(self) -> str | None:
        return self.api_key or os.environ.get("ANTHROPIC_API_KEY")


class RetentionConfig(BaseModel):
    event_days: int = Field(30, ge=1)
    report_days: int = Field(90, ge=1)
    run_every_seconds: int = 3600


class ApiConfig(BaseModel):
    # Inside its container; only Docker's published port reaches it.
    host: str = "0.0.0.0"  # noqa: S104  # nosec B104
    port: int = 8443
    tls_cert: Path = Path("certs/server.crt")
    tls_key: Path = Path("certs/server.key")
    rate_limit_per_minute: int = 60
    max_span_days: int = 31
    default_span_hours: int = 24
    default_limit: int = 100
    max_limit: int = 1000


class Config(BaseModel):
    database_path: Path = Path("data/sec450.db")
    sources: list[SourceConfig]
    collector: CollectorConfig = CollectorConfig()
    detection: DetectionConfig
    geoip: GeoIPConfig = GeoIPConfig()
    triage: TriageConfig = TriageConfig()
    retention: RetentionConfig = RetentionConfig()
    api: ApiConfig = ApiConfig()

    @model_validator(mode="after")
    def _unique_sources(self) -> Config:
        names = [s.name for s in self.sources]
        if len(names) != len(set(names)):
            raise ValueError("source names must be unique")
        return self


def load_config(path: str | Path | None = None) -> Config:
    path = Path(path or os.environ.get("SEC450_CONFIG", "config.yaml"))
    with path.open(encoding="utf-8") as fh:
        return Config.model_validate(yaml.safe_load(fh))
