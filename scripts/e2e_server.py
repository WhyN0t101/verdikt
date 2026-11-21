"""Backend for the Playwright e2e run: the real API and built SPA over deterministic fake sources.

No network, no keys, no history on disk. `cd web && npm run e2e` starts this itself.
"""

import os

import httpx
import uvicorn

from verdikt.api.app import create_app
from verdikt.cache import Cache
from verdikt.config import Settings, load_rules
from verdikt.engine import Engine
from verdikt.models import IOC, IOCType, RelatedIOC, SourceResult, Status
from verdikt.sources.base import BaseSource, Gate, Source

PORT = int(os.environ.get("VERDIKT_E2E_PORT", "8768"))
TOKEN = "e2e-token"  # noqa: S105
BAD = {"185.220.101.4", "evil.example"}


class FakeVirusTotal(BaseSource):
    name = "virustotal"
    supports = frozenset(IOCType)
    rate = (1000, 1.0)

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        bad = ioc.value in BAD
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
        score = 100 if ioc.value in BAD else 0
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


def main() -> None:
    sources: list[Source] = [FakeVirusTotal(), FakeAbuseIPDB(), FakeFeed()]
    engine = Engine(
        Settings(_env_file=None),  # pyright: ignore[reportCallIssue]
        load_rules(),
        Cache(":memory:"),
        httpx.AsyncClient(),
        sources=sources,
    )
    app = create_app(engine, port=PORT, token=TOKEN)
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
