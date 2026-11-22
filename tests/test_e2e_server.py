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


async def test_flip_is_safe_first_and_malicious_after() -> None:
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
        levels = [(await engine.check(e2e.FLIP, no_cache=True)).level for _ in range(3)]
        assert levels == [Level.SAFE, Level.MALICIOUS, Level.MALICIOUS]
        # other indicators keep their behaviour
        assert (await engine.check("8.8.8.8", no_cache=True)).level is Level.SAFE
        assert (await engine.check("185.220.101.4", no_cache=True)).level is Level.MALICIOUS


def test_each_server_start_resets_the_flip() -> None:
    assert load().FakeVirusTotal()._flip_seen is False  # pyright: ignore[reportPrivateUsage]
