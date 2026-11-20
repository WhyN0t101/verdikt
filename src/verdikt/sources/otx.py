"""AlienVault OTX (key optional)."""

from __future__ import annotations

import ipaddress
from datetime import timedelta
from urllib.parse import quote

from verdikt.models import IOC, IOCType, SourceResult, Status
from verdikt.sources.base import BaseSource, Gate, json_object

API = "https://otx.alienvault.com/api/v1/indicators"


def _kind(ioc: IOC) -> tuple[str, str]:
    """(API section, web section)."""
    match ioc.type:
        case IOCType.IP:
            v6 = ipaddress.ip_address(ioc.value).version == 6
            return ("IPv6" if v6 else "IPv4"), "ip"
        case IOCType.DOMAIN:
            return "domain", "domain"
        case IOCType.URL:
            return "url", "url"
        case _:
            return "file", "file"


class OTX(BaseSource):
    name = "otx"
    supports = frozenset(IOCType)
    requires_key = False
    rate = (2, 1.0)
    ttl = timedelta(hours=24)

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        section, web = _kind(ioc)
        headers = {"X-OTX-API-KEY": self._key} if self._key else {}
        resp = await http.get(
            f"{API}/{section}/{quote(ioc.value, safe='')}/general", headers=headers
        )
        if (err := self.from_status(resp)) is not None:
            return err
        body = json_object(resp)
        info = body.get("pulse_info", {})
        pulses = int(info.get("count", 0))
        tags: list[str] = []
        for pulse in info.get("pulses", [])[:10]:
            for t in pulse.get("tags", []):
                if str(t) not in tags and len(tags) < 10:
                    tags.append(str(t))
        return self.result(
            Status.OK,
            f"{pulses} pulse{'s' if pulses != 1 else ''}",
            metrics={"pulses": pulses},
            tags=tags,
            link=f"https://otx.alienvault.com/indicator/{web}/{quote(ioc.value, safe='')}",
            raw=body,
        )
