"""The e2e fake server: FLIP is clean once, then malicious (the Playwright diff test)."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import httpx

from tests.conftest import CountingLimiter
from verdikt.cache import Cache
from verdikt.config import Settings, load_rules
from verdikt.engine import Engine
from verdikt.models import Level
from verdikt.sources.base import Source

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "e2e_server.py"


def load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("e2e_server", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def test_each_flip_indicator_flips_on_its_own() -> None:
    e2e = load()
    sources: list[Source] = [e2e.FakeVirusTotal(), e2e.FakeAbuseIPDB(), e2e.FakeFeed()]
    async with httpx.AsyncClient() as http:
        engine = Engine(
            Settings(_env_file=None),  # pyright: ignore[reportCallIssue]
            load_rules(),
            Cache(":memory:"),
            http,
            sources=sources,
            limiter_factory=CountingLimiter,
        )

        async def level(ioc: str) -> Level:
            return (await engine.check(ioc, no_cache=True)).level

        one, two = f"{e2e.FLIP_PREFIX}10", f"{e2e.FLIP_PREFIX}11"
        assert [await level(one), await level(one), await level(one)] == [
            Level.SAFE,
            Level.MALICIOUS,
            Level.MALICIOUS,
        ]
        # a second indicator under the prefix starts clean: a retry can use a fresh one
        assert [await level(two), await level(two)] == [Level.SAFE, Level.MALICIOUS]


async def test_other_indicators_keep_their_behaviour() -> None:
    e2e = load()
    sources: list[Source] = [e2e.FakeVirusTotal(), e2e.FakeAbuseIPDB(), e2e.FakeFeed()]
    async with httpx.AsyncClient() as http:
        engine = Engine(
            Settings(_env_file=None),  # pyright: ignore[reportCallIssue]
            load_rules(),
            Cache(":memory:"),
            http,
            sources=sources,
            limiter_factory=CountingLimiter,
        )
        assert (await engine.check("8.8.8.8", no_cache=True)).level is Level.SAFE
        for bad in ("185.220.101.4", f"{e2e.BAD_PREFIX}77", "evil.example"):  # malicious at once
            assert (await engine.check(bad, no_cache=True)).level is Level.MALICIOUS
        assert (await engine.check("9.9.8.8", no_cache=True)).level is Level.SAFE  # not the prefix


def test_each_server_start_resets_the_flips() -> None:
    assert load().FakeVirusTotal()._flip_seen == set()  # pyright: ignore[reportPrivateUsage]
