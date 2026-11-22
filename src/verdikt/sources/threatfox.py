"""abuse.ch ThreatFox (v1 API, Auth-Key header)."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any
from urllib.parse import quote

from verdikt.jsonutil import arr, obj
from verdikt.models import IOC, IOCType, RelatedIOC, SourceResult, Status
from verdikt.sources.base import BaseSource, Gate, json_object

API = "https://threatfox-api.abuse.ch/api/v1/"
_PORT_SUFFIX = re.compile(r":\d{1,5}$")


def _is_exact(entry: dict[str, Any], ioc: IOC) -> bool:
    """True when the entry's `ioc` is the value itself, or an IP with a port (`1.2.3.4:80`)."""
    found = str(entry.get("ioc", "")).lower()
    if found == ioc.value.lower():
        return True
    return (
        ioc.type is IOCType.IP
        and _PORT_SUFFIX.sub("", found) == ioc.value.lower()
        and ":" not in ioc.value
    )


class ThreatFox(BaseSource):
    name = "threatfox"
    # its API rejects SHA-1 (`illegal_hash`: "must be MD5 or SHA256")
    supports = frozenset(IOCType) - {IOCType.SHA1}
    requires_key = True
    rate = (1, 1.0)
    ttl = timedelta(hours=6)

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        if ioc.type.is_hash:
            payload: dict[str, Any] = {"query": "search_hash", "hash": ioc.value}
        else:
            payload = {"query": "search_ioc", "search_term": ioc.value, "exact_match": False}
        resp = await http.post(API, json=payload, headers={"Auth-Key": self._key or ""})
        if (err := self.from_status(resp)) is not None:
            return err
        body = json_object(resp)
        status = body.get("query_status")
        link = f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{quote(ioc.value, safe='')}"
        if status == "no_result":
            return self.result(
                Status.OK,
                "no match",
                metrics={"match": False, "entries": 0},
                link=link,
                raw=body,
            )
        if status != "ok" or not isinstance(body.get("data"), list):
            return self.result(Status.ERROR, "unexpected response")
        # exact_match=false is a substring search: keep only entries that are this IOC
        entries = [e for e in arr(body["data"]) if _is_exact(obj(e), ioc)]
        if not entries:
            return self.result(
                Status.OK,
                "no exact match",
                metrics={"match": False, "entries": 0},
                link=link,
                raw=body,
            )
        families = sorted(
            {str(e["malware_printable"]) for e in entries if e.get("malware_printable")}
        )
        related = [RelatedIOC(value=f, type="malware", relation="belongs_to") for f in families[:5]]
        threat = next((str(e["threat_type"]) for e in entries if e.get("threat_type")), "")
        return self.result(
            Status.OK,
            f"{len(entries)} match(es){': ' + threat if threat else ''}",
            metrics={"match": True, "entries": len(entries)},
            tags=families[:10],
            related=related,
            link=link,
            raw=body,
        )
