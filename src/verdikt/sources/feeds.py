"""Public data feeds downloaded once and matched locally: no quota, no indicator ever leaves.

`verdikt feeds update` (or the UI button) fetches them; lookups read files from the feeds dir.
Feeds are plain data (text, JSON, CSV, zip): they are parsed, never executed.
"""

from __future__ import annotations

import asyncio
import csv
import gzip
import io
import ipaddress
import json
import logging
import sqlite3
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from verdikt.jsonutil import arr, obj
from verdikt.models import IOC, IOCType, SourceResult, Status
from verdikt.sources.base import BaseSource, Gate

log = logging.getLogger(__name__)

FEODO = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
DROP = "https://www.spamhaus.org/drop/drop_v4.json"
TOR = "https://check.torproject.org/torbulkexitlist"
TRANCO = "https://tranco-list.eu/top-1m.csv.zip"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS = "https://epss.cyentia.com/epss_scores-current.csv.gz"

MAX_BYTES = 40 * 1024 * 1024  # a feed bigger than this is not what we think it is
DEFAULT_TOP = 100_000  # Tranco ranks kept; the full list is 1M domains
META = "meta.json"


@dataclass(frozen=True)
class FeedResult:
    name: str
    ok: bool
    count: int
    detail: str


# --- parsers (pure) -----------------------------------------------------------------------


def parse_ip_list(text: str) -> set[str]:
    """One IP per line; `#` comments and anything that is not an IP are skipped."""
    found: set[str] = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        try:
            found.add(ipaddress.ip_address(line).compressed)
        except ValueError:
            continue
    return found


def parse_drop(text: str) -> list[str]:
    """Spamhaus DROP JSON lines: `{"cidr": "1.10.16.0/20", ...}`; the metadata line has no cidr."""
    cidrs: list[str] = []
    for line in text.splitlines():
        try:
            cidr = obj(json.loads(line)).get("cidr")
            if cidr:
                cidrs.append(str(ipaddress.ip_network(cidr, strict=False)))
        except ValueError:
            continue
    return cidrs


def parse_tranco(data: bytes, top: int) -> list[str]:
    """Tranco zip with `top-1m.csv` (`rank,domain`), best rank first. Keeps `top` domains."""
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        name = next(n for n in zf.namelist() if n.endswith(".csv"))
        rows = csv.reader(io.TextIOWrapper(zf.open(name), encoding="utf-8"))
        return [row[1].lower() for _, row in zip(range(top), rows, strict=False) if len(row) > 1]


def parse_kev(data: bytes) -> dict[str, dict[str, Any]]:
    """CISA KEV catalog -> {CVE id: {name, added, ransomware}}."""
    out: dict[str, dict[str, Any]] = {}
    for v in arr(obj(json.loads(data)).get("vulnerabilities")):
        v = obj(v)
        if cve := v.get("cveID"):
            out[str(cve).upper()] = {
                "name": str(v.get("vulnerabilityName", "")),
                "added": str(v.get("dateAdded", "")),
                "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
            }
    return out


def parse_epss(data: bytes) -> list[tuple[str, float, float]]:
    """EPSS gzip CSV: a `#model_version` comment, a header, then `cve,epss,percentile`."""
    text = gzip.decompress(data).decode("utf-8")
    rows = csv.reader(line for line in text.splitlines() if not line.startswith("#"))
    next(rows, None)  # header
    out: list[tuple[str, float, float]] = []
    for row in rows:
        try:
            out.append((row[0].upper(), float(row[1]), float(row[2])))
        except (ValueError, IndexError):
            continue
    return out


# --- store --------------------------------------------------------------------------------


def _atomic_write(path: Path, data: bytes | str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    if isinstance(data, str):
        tmp.write_text(data, encoding="utf-8")
    else:
        tmp.write_bytes(data)
    tmp.replace(path)


def _read_meta(directory: Path) -> dict[str, Any]:
    try:
        return obj(json.loads((directory / META).read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return {}


def feeds_status(directory: Path) -> dict[str, dict[str, Any]]:
    """Per feed: `fetched_at` (ISO) and `count`. Empty when nothing was downloaded."""
    return {k: obj(v) for k, v in _read_meta(directory).items()}


async def _download(http: httpx.AsyncClient, url: str) -> bytes:
    async with http.stream("GET", url, timeout=60, follow_redirects=True) as resp:
        resp.raise_for_status()
        chunks: list[bytes] = []
        size = 0
        async for chunk in resp.aiter_bytes():
            size += len(chunk)
            if size > MAX_BYTES:
                raise ValueError("feed larger than the size cap")
            chunks.append(chunk)
    return b"".join(chunks)


def _build_epss(directory: Path, rows: list[tuple[str, float, float]]) -> None:
    tmp = directory / "epss.sqlite.tmp"
    tmp.unlink(missing_ok=True)
    db = sqlite3.connect(tmp)
    try:
        db.execute("CREATE TABLE epss (cve TEXT PRIMARY KEY, score REAL, pct REAL) WITHOUT ROWID")
        db.executemany("INSERT OR REPLACE INTO epss VALUES (?,?,?)", rows)
        db.commit()
    finally:
        db.close()
    tmp.replace(directory / "epss.sqlite")


async def update_feeds(
    http: httpx.AsyncClient, directory: Path, top: int = DEFAULT_TOP
) -> list[FeedResult]:
    """Download every feed. One failing feed never stops the others or deletes its old copy."""
    await asyncio.to_thread(directory.mkdir, parents=True, exist_ok=True)
    meta = await asyncio.to_thread(_read_meta, directory)
    results: list[FeedResult] = []

    async def run(name: str, url: str, save: Callable[[bytes], int]) -> None:
        try:
            # parsing and writing are blocking (EPSS is 400k rows): keep them off the event loop
            count = int(await asyncio.to_thread(save, await _download(http, url)))
        except (
            httpx.HTTPError,
            ValueError,
            OSError,
            KeyError,
            StopIteration,
            zipfile.BadZipFile,
        ) as exc:
            log.warning("feed %s failed (%s)", name, type(exc).__name__)
            results.append(FeedResult(name, False, 0, f"failed: {type(exc).__name__}"))
            return
        meta[name] = {"fetched_at": datetime.now(UTC).isoformat(), "count": count}
        results.append(FeedResult(name, True, count, "updated"))

    def save_ips(name: str) -> Callable[[bytes], int]:
        def inner(data: bytes) -> int:
            ips = parse_ip_list(data.decode("utf-8", "replace"))
            _atomic_write(directory / f"{name}.txt", "\n".join(sorted(ips)))
            return len(ips)

        return inner

    def save_drop(data: bytes) -> int:
        cidrs = parse_drop(data.decode("utf-8", "replace"))
        if not cidrs:
            raise ValueError("no networks found")
        _atomic_write(directory / "drop.txt", "\n".join(cidrs))
        return len(cidrs)

    def save_tranco(data: bytes) -> int:
        domains = parse_tranco(data, top)
        _atomic_write(directory / "tranco.txt", "\n".join(domains))
        return len(domains)

    def save_kev(data: bytes) -> int:
        kev = parse_kev(data)
        if not kev:
            raise ValueError("no vulnerabilities found")
        _atomic_write(directory / "kev.json", json.dumps(kev))
        return len(kev)

    def save_epss(data: bytes) -> int:
        rows = parse_epss(data)
        if not rows:
            raise ValueError("no scores found")
        _build_epss(directory, rows)
        return len(rows)

    await run("feodo", FEODO, save_ips("feodo"))
    await run("spamhaus_drop", DROP, save_drop)
    await run("tor_exits", TOR, save_ips("tor"))
    await run("tranco", TRANCO, save_tranco)
    await run("cisa_kev", KEV, save_kev)
    await run("epss", EPSS, save_epss)
    await asyncio.to_thread(_atomic_write, directory / META, json.dumps(meta, indent=1))
    return results


class FeedStore:
    """Lazy, reloading view of the downloaded feeds (reloads when `meta.json` changes)."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self._stamp: float | None = None
        self._feodo: set[str] = set()
        self._tor: set[str] = set()
        self._drop: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._rank: dict[str, int] = {}

    def _lines(self, name: str) -> list[str]:
        try:
            return (self.directory / name).read_text(encoding="utf-8").split()
        except OSError:
            return []

    def _reload(self) -> None:
        try:
            stamp = (self.directory / META).stat().st_mtime
        except OSError:
            self._stamp = None
            self._feodo = self._tor = set()
            self._drop, self._rank = [], {}
            return
        if stamp == self._stamp:
            return
        self._stamp = stamp
        self._feodo = set(self._lines("feodo.txt"))
        self._tor = set(self._lines("tor.txt"))
        self._drop = [ipaddress.ip_network(c) for c in self._lines("drop.txt")]
        self._rank = {d: i + 1 for i, d in enumerate(self._lines("tranco.txt"))}

    @property
    def available(self) -> bool:
        self._reload()
        return self._stamp is not None

    def ip(self, value: str) -> tuple[bool, bool, str | None]:
        """(blocklisted, tor_exit, which blocklist)."""
        self._reload()
        addr = ipaddress.ip_address(value)
        if value in self._feodo:
            return True, value in self._tor, "Feodo Tracker C2"
        if any(addr in net for net in self._drop if net.version == addr.version):
            return True, value in self._tor, "Spamhaus DROP"
        return False, value in self._tor, None

    def top_rank(self, domain: str) -> int | None:
        """Exact match only: `evil.github.io` must not inherit `github.io`'s reputation."""
        self._reload()
        return self._rank.get(domain)


class LocalFeeds(BaseSource):
    """Blocklists (Feodo C2, Spamhaus DROP), Tor exit nodes and the Tranco top sites."""

    name = "localfeeds"
    supports = frozenset({IOCType.IP, IOCType.DOMAIN})
    requires_key = False
    ttl = timedelta(0)  # local data: never serve a cached answer across a feed update

    def __init__(self, directory: Path) -> None:
        super().__init__()
        self._store = FeedStore(directory)

    @property
    def enabled(self) -> bool:
        return self._store.available

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        if ioc.type is IOCType.IP:
            listed, tor, which = self._store.ip(ioc.value)
            tags = [t for t in (which, "tor-exit" if tor else None) if t]
            summary = (
                f"listed: {which}" if listed else "Tor exit node" if tor else "not on local lists"
            )
            return self.result(
                Status.OK,
                summary,
                metrics={"blocklisted": listed, "tor_exit": tor, "top_site": False},
                tags=tags,
                link=f"https://metrics.torproject.org/exonerator.html?ip={ioc.value}"
                if tor and not listed
                else "https://feodotracker.abuse.ch/blocklist/",
            )
        rank = self._store.top_rank(ioc.value)
        return self.result(
            Status.OK,
            f"Tranco top-site rank {rank:,}" if rank else "not in the Tranco top sites",
            metrics={"blocklisted": False, "tor_exit": False, "top_site": rank is not None},
            tags=["tranco-top"] if rank else [],
            link=f"https://tranco-list.eu/query/{ioc.value}",
        )
