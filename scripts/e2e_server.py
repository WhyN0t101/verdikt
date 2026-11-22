"""Backend for the Playwright e2e run: the real API and built SPA over deterministic fake sources.

No network, no keys, no history on disk. `cd web && npm run e2e` starts this itself.
"""

import json
import os
import tempfile
from pathlib import Path

import httpx
import uvicorn

from verdikt.api.app import create_app
from verdikt.cache import Cache
from verdikt.config import Settings, load_rules
from verdikt.engine import Engine
from verdikt.models import IOC, IOCType, RelatedIOC, SourceResult, Status
from verdikt.sources import feeds
from verdikt.sources.base import BaseSource, Gate, Source
from verdikt.sources.feeds import LocalFeeds

PORT = int(os.environ.get("VERDIKT_E2E_PORT", "8768"))
TOKEN = "e2e-token"  # noqa: S105
BAD = {"185.220.101.4", "evil.example"}
# Any indicator under BAD_PREFIX is malicious at once (a fresh one per test attempt gives a live,
# uncached answer); any under FLIP_PREFIX is clean on its first lookup and malicious after that.
# State is per indicator and per server start, so a retried test can use a new indicator.
BAD_PREFIX = "185.220.101."
FLIP_PREFIX = "9.9.9."
SAMPLES = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "feeds"
KEV_ID = next(iter(feeds.parse_kev((SAMPLES / "kev.json").read_bytes())))


def is_bad(value: str) -> bool:
    return value in BAD or value.startswith(BAD_PREFIX)


class FakeVirusTotal(BaseSource):
    name = "virustotal"
    supports = frozenset(IOCType)
    rate = (1000, 1.0)

    def __init__(self) -> None:
        super().__init__()
        self._flip_seen: set[str] = set()  # per server process: the suite's one server starts clean

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        flips = ioc.value.startswith(FLIP_PREFIX)
        bad = is_bad(ioc.value) or (flips and ioc.value in self._flip_seen)
        if flips:
            self._flip_seen.add(ioc.value)
        related = (
            [
                RelatedIOC(
                    value="evil.example", type=IOCType.DOMAIN, relation="resolves_to", inbound=True
                ),
                RelatedIOC(value="Cobalt Strike", type="malware", relation="belongs_to"),
            ]
            if ioc.value == "185.220.101.4"
            else []
        )
        return self.result(
            Status.OK,
            "20/92 engines malicious" if bad else "0/92 engines malicious",
            metrics={"malicious": 20 if bad else 0, "suspicious": 0, "total": 92},
            related=related,
            link=f"https://example.invalid/vt/{ioc.value}",
            raw={"fake": "virustotal"},
        )


class FakeAbuseIPDB(BaseSource):
    name = "abuseipdb"
    supports = frozenset({IOCType.IP})
    rate = (1000, 1.0)

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        score = 100 if is_bad(ioc.value) else 0
        return self.result(
            Status.OK,
            f"{score}% confidence",
            metrics={"score": score, "reports": score * 4, "tor": False},
            link=f"https://example.invalid/abuseipdb/{ioc.value}",
            raw={"fake": "abuseipdb"},
        )


class FakeFeed(BaseSource):
    name = "threatfox"
    supports = frozenset(IOCType)
    rate = (1000, 1.0)

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        return self.result(
            Status.OK,
            "no match",
            metrics={"match": False, "entries": 0},
            link=f"https://example.invalid/threatfox/{ioc.value}",
            raw={"fake": "threatfox"},
        )


class FakeInternetDB(BaseSource):
    """Context row that reports two CVEs: one in the KEV sample, one with an EPSS score."""

    name = "internetdb"
    supports = frozenset({IOCType.IP})
    rate = (1000, 1.0)

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        return self.result(
            Status.OK,
            "2 open port(s), 2 CVE(s)",
            metrics={"ports": 2, "vulns": 2},
            link=f"https://example.invalid/internetdb/{ioc.value}",
            raw={"vulns": [KEV_ID, "CVE-1999-0001"]},
        )


def feeds_dir() -> Path:
    """KEV and EPSS data from the fixtures; no meta.json, so the UI shows 'no feeds yet'."""
    d = Path(tempfile.mkdtemp(prefix="verdikt-e2e-feeds-"))
    (d / "kev.json").write_text(
        json.dumps(feeds.parse_kev((SAMPLES / "kev.json").read_bytes())), encoding="utf-8"
    )
    feeds._build_epss(d, feeds.parse_epss((SAMPLES / "epss.csv.gz").read_bytes()))
    return d


def main() -> None:
    fd = feeds_dir()
    sources: list[Source] = [
        FakeVirusTotal(),
        FakeAbuseIPDB(),
        FakeFeed(),
        FakeInternetDB(),
        LocalFeeds(fd),  # disabled until a feed (here: an imported MISP file) exists
    ]
    engine = Engine(
        Settings(_env_file=None, feeds_dir=fd),  # pyright: ignore[reportCallIssue]
        load_rules(),
        Cache(":memory:"),
        httpx.AsyncClient(),
        sources=sources,
    )
    app = create_app(engine, port=PORT, token=TOKEN)
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
