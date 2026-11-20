"""GreyNoise Community. Context only: acts through `benign_override` in rules.yaml."""

from __future__ import annotations

from datetime import timedelta

from verdikt.models import IOC, IOCType, SourceResult, Status
from verdikt.sources.base import BaseSource, Gate, json_object

API = "https://api.greynoise.io/v3/community"


class GreyNoise(BaseSource):
    name = "greynoise"
    supports = frozenset({IOCType.IP})
    requires_key = False
    rate = (1, 2.0)
    ttl = timedelta(hours=24)

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        headers = {"key": self._key} if self._key else {}
        resp = await http.get(f"{API}/{ioc.value}", headers=headers)
        if (err := self.from_status(resp)) is not None:
            if err.status is Status.NOT_FOUND:
                return self.result(Status.NOT_FOUND, "not observed scanning")
            return err
        body = json_object(resp)
        noise = bool(body.get("noise", False))
        riot = bool(body.get("riot", False))
        cls = str(body.get("classification") or "")
        name = str(body.get("name") or "")
        tags = [t for t in (cls, name) if t and t != "unknown"]
        if riot:
            summary = f"known benign service{': ' + name if name else ''}"
        elif noise:
            summary = f"internet scanner ({cls or 'unclassified'})"
        else:
            summary = "not a known scanner"
        link = f"https://viz.greynoise.io/ip/{ioc.value}"
        return self.result(
            Status.OK,
            summary,
            metrics={"noise": noise, "riot": riot},
            tags=tags,
            link=link,
            raw=body,
        )
