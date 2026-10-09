"""Offline ASN/country enrichment from local GeoLite2 databases (DD-13)."""
from __future__ import annotations

import ipaddress
import logging
from pathlib import Path

import geoip2.database
import geoip2.errors

from .config import GeoIPConfig

log = logging.getLogger(__name__)


class GeoIP:
    def __init__(self, asn_db: Path | None = None, country_db: Path | None = None):
        self._asn = self._open(asn_db)
        self._country = self._open(country_db)

    @classmethod
    def from_config(cls, cfg: GeoIPConfig) -> GeoIP:
        return cls(cfg.asn_db, cfg.country_db)

    @staticmethod
    def _open(path: Path | None) -> geoip2.database.Reader | None:
        if path is None:
            return None
        if not Path(path).exists():
            log.warning("GeoIP database %s not found; lookups will return null", path)
            return None
        return geoip2.database.Reader(str(path))

    def lookup(self, ip: str | None) -> tuple[int | None, str | None]:
        """Return (asn, ISO country code). Private/reserved IPs give (None, None)."""
        if ip is None or not ipaddress.ip_address(ip).is_global:
            return None, None
        asn = country = None
        try:
            if self._asn:
                asn = self._asn.asn(ip).autonomous_system_number
        except geoip2.errors.AddressNotFoundError:
            pass
        try:
            if self._country:
                country = self._country.country(ip).country.iso_code
        except geoip2.errors.AddressNotFoundError:
            pass
        return asn, country

    def close(self) -> None:
        for reader in (self._asn, self._country):
            if reader:
                reader.close()
