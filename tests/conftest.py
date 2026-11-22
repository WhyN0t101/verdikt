from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from types import TracebackType
from typing import Any

import httpx
import pytest
import respx

from verdikt.cache import Cache
from verdikt.config import Settings, load_rules
from verdikt.engine import Engine
from verdikt.models import IOC, IOCType, SourceResult, Status
from verdikt.sources.base import BaseSource, Gate, Source

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(source: str, name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / source / f"{name}.json").read_text(encoding="utf-8"))


class CountingLimiter:
    """Stands in for AsyncLimiter: no waiting, counts slots taken."""

    def __init__(self, *_: object) -> None:
        self.acquired = 0

    async def __aenter__(self) -> None:
        self.acquired += 1

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None


class Sleeps:
    """Records sleeps instead of waiting."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


class Fake(BaseSource):
    """Canned source: returns a result with the given metrics, or raises."""

    supports = frozenset(IOCType)

    def __init__(
        self,
        name: str,
        metrics: dict[str, int | bool] | None = None,
        status: Status = Status.OK,
        raises: bool = False,
        summary: str = "fake",
    ) -> None:
        super().__init__("key")
        self.name = name
        self.metrics = metrics or {}
        self._status = status
        self._raises = raises
        self._summary = summary
        self.calls = 0

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        self.calls += 1
        if self._raises:
            raise RuntimeError("boom")
        return self.result(self._status, self._summary, metrics=self.metrics, raw={"fake": True})

    async def query(self, ioc: IOC, http: Gate) -> SourceResult:
        # raise through on purpose: the engine must survive a misbehaving source
        return await self.lookup(ioc, http)


@pytest.fixture
def router() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_called=False) as r:
        yield r


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient() as c:
        yield c


@pytest.fixture
def sleeps() -> Sleeps:
    return Sleeps()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    # an empty feeds dir keeps tests independent of feeds downloaded on this machine
    return Settings(
        _env_file=None,  # pyright: ignore[reportCallIssue]
        internal_domains="corp.example.com",
        feeds_dir=tmp_path / "feeds",
    )


@pytest.fixture
def cache() -> Iterator[Cache]:
    c = Cache(":memory:")
    yield c
    c.close()


@pytest.fixture
def gate(client: httpx.AsyncClient, sleeps: Sleeps) -> Gate:
    return Gate("test", client, CountingLimiter(), sleep=sleeps, backoff=0)


def make_engine(
    settings: Settings,
    cache: Cache,
    client: httpx.AsyncClient,
    sources: list[Source],
    **kw: Any,
) -> Engine:
    return Engine(settings, load_rules(), cache, client, sources=sources, **kw)
