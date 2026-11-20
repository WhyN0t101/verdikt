"""Local GeoLite2 lookups: no quota, and no IOC ever leaves the machine."""

from __future__ import annotations

import logging
from pathlib import Path

import maxminddb

from verdikt.jsonutil import obj
from verdikt.models import GeoPoint

log = logging.getLogger(__name__)


def _open(path: Path) -> maxminddb.Reader | None:
    if not path.is_file():
        return None
    try:
        return maxminddb.open_database(path)
    except (OSError, ValueError, maxminddb.InvalidDatabaseError):
        log.warning("cannot open %s", path.name)
        return None


class GeoLookup:
    def __init__(self, directory: Path | None) -> None:
        self._city = _open(directory / "GeoLite2-City.mmdb") if directory else None
        self._asn = _open(directory / "GeoLite2-ASN.mmdb") if directory else None

    @property
    def available(self) -> bool:
        return self._city is not None

    def asn(self, ip: str) -> tuple[int, str] | None:
        if self._asn is None:
            return None
        rec = obj(self._asn.get(ip))
        if "autonomous_system_number" not in rec:
            return None
        return int(rec["autonomous_system_number"]), str(
            rec.get("autonomous_system_organization", "")
        )

    def lookup(self, ip: str, role: str = "ioc") -> GeoPoint | None:
        if self._city is None:
            return None
        try:
            rec = obj(self._city.get(ip))
        except (ValueError, maxminddb.InvalidDatabaseError):
            return None
        loc = obj(rec.get("location"))
        if "latitude" not in loc or "longitude" not in loc:
            return None
        asn = self.asn(ip)
        return GeoPoint(
            ip=ip,
            lat=float(loc["latitude"]),
            lon=float(loc["longitude"]),
            country=obj(rec.get("country")).get("iso_code"),
            city=obj(obj(rec.get("city")).get("names")).get("en"),
            asn=asn[0] if asn else None,
            as_org=asn[1] if asn else None,
            role=role,
        )
