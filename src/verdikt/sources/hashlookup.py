"""CIRCL hashlookup: is this file hash in known-good sets (NSRL and others)? Keyless."""

from __future__ import annotations

from datetime import timedelta

from verdikt.models import IOC, IOCType, SourceResult, Status
from verdikt.sources.base import BaseSource, Gate, json_object

API = "https://hashlookup.circl.lu/lookup"
_KIND = {IOCType.MD5: "md5", IOCType.SHA1: "sha1", IOCType.SHA256: "sha256"}


class Hashlookup(BaseSource):
    """A hit means "known file", not "benign": it only softens SUSPICIOUS (see rules.yaml).
    A hit flagged `KnownMalicious` is the opposite and counts as suspicious."""

    name = "hashlookup"
    supports = frozenset(_KIND)
    requires_key = False
    rate = (2, 1.0)
    ttl = timedelta(days=7)

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        resp = await http.get(f"{API}/{_KIND[ioc.type]}/{ioc.value}")
        if resp.status_code == 404:
            return self.result(Status.NOT_FOUND, "not in known-file sets")
        if (err := self.from_status(resp)) is not None:
            return err
        body = json_object(resp)
        # EICAR is in these sets with trust 100 *and* a KnownMalicious flag: only that flag says bad
        bad = body.get("KnownMalicious")
        name = str(body.get("FileName") or "")
        return self.result(
            Status.OK,
            f"known malicious ({bad})" if bad else f"known file{': ' + name if name else ''}",
            metrics={"known_good": not bad, "known_malicious": bool(bad)},
            tags=[f"known-malicious:{bad}"] if bad else [],
            link=f"https://hashlookup.circl.lu/lookup/{_KIND[ioc.type]}/{ioc.value}",
            raw=body,
        )
