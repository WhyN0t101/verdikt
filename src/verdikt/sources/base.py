"""Source protocol, throttled HTTP gate, and the shared error-mapping base class."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from types import TracebackType
from typing import Any, Protocol

import httpx
from pydantic import HttpUrl, TypeAdapter, ValidationError
from tenacity import AsyncRetrying, RetryCallState, retry_if_result, stop_after_attempt

from verdikt.cache import Cache
from verdikt.models import IOC, IOCType, SourceResult, Status

log = logging.getLogger(__name__)

TIMEOUT = 10.0
MAX_ATTEMPTS = 3
BACKOFF = 1.0
_URL = TypeAdapter(HttpUrl)


class RateLimitedError(Exception):
    """Daily budget exhausted or Retry-After longer than the timeout."""


class Limiter(Protocol):
    async def __aenter__(self) -> Any: ...
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> Any: ...


def retry_after(resp: httpx.Response) -> float | None:
    value = resp.headers.get("retry-after")
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        pass
    try:  # HTTP-date form
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, (when - datetime.now(UTC)).total_seconds())


class Gate:
    """Per-source HTTP access over the one shared client.

    Every attempt (including retries) charges the daily budget and takes a limiter slot.
    A 429 whose Retry-After exceeds the timeout is returned at once, never waited on.
    """

    def __init__(
        self,
        source: str,
        client: httpx.AsyncClient,
        limiter: Limiter,
        cache: Cache | None = None,
        daily_budget: int | None = None,
        timeout: float = TIMEOUT,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        backoff: float = BACKOFF,
    ) -> None:
        self.source = source
        self._client = client
        self._limiter = limiter
        self._cache = cache
        self._budget = daily_budget
        self.timeout = timeout
        self._sleep = sleep
        self._backoff = backoff

    async def _once(self, method: str, url: str, **kw: Any) -> httpx.Response:
        if self._cache is not None and not self._cache.charge(self.source, self._budget):
            raise RateLimitedError("daily budget exhausted")
        async with self._limiter:
            return await self._client.request(method, url, timeout=self.timeout, **kw)

    def _should_retry(self, resp: httpx.Response) -> bool:
        if resp.status_code == 429:
            wait = retry_after(resp)
            return wait is None or wait <= self.timeout
        return resp.status_code >= 500

    def _wait(self, state: RetryCallState) -> float:
        assert state.outcome is not None
        resp: httpx.Response = state.outcome.result()
        wait = retry_after(resp) if resp.status_code == 429 else None
        return wait if wait is not None else self._backoff * 2 ** (state.attempt_number - 1)

    async def request(self, method: str, url: str, **kw: Any) -> httpx.Response:
        retrying = AsyncRetrying(
            stop=stop_after_attempt(MAX_ATTEMPTS),
            retry=retry_if_result(self._should_retry),
            wait=self._wait,
            sleep=self._sleep,
            retry_error_callback=lambda s: s.outcome.result() if s.outcome else None,
        )
        return await retrying(self._once, method, url, **kw)

    async def get(self, url: str, **kw: Any) -> httpx.Response:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw: Any) -> httpx.Response:
        return await self.request("POST", url, **kw)


class Source(Protocol):
    # read-only properties so plain class attributes satisfy the protocol
    @property
    def name(self) -> str: ...
    @property
    def supports(self) -> frozenset[IOCType]: ...
    @property
    def requires_key(self) -> bool: ...
    @property
    def rate(self) -> tuple[int, float]: ...  # calls, seconds
    @property
    def ttl(self) -> timedelta: ...
    @property
    def daily_budget(self) -> int | None: ...
    @property
    def timeout(self) -> float: ...
    @property
    def quota_group(self) -> str | None: ...  # share another source's limiter and budget
    @property
    def enabled(self) -> bool: ...

    async def query(self, ioc: IOC, http: Gate) -> SourceResult: ...


class BaseSource:
    """Implements `query` once: subclasses write `lookup` and never raise out of `query`."""

    name: str
    supports: frozenset[IOCType]
    requires_key: bool = False
    rate: tuple[int, float] = (1, 1.0)
    ttl: timedelta = timedelta(hours=6)
    daily_budget: int | None = None
    timeout: float = TIMEOUT
    quota_group: str | None = None

    def __init__(self, api_key: str | None = None) -> None:
        self._key = api_key

    @property
    def enabled(self) -> bool:
        return bool(self._key) or not self.requires_key

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        raise NotImplementedError

    def result(
        self, status: Status, summary: str = "", link: str | None = None, **kw: Any
    ) -> SourceResult:
        return SourceResult(
            source=self.name,
            status=status,
            summary=summary,
            link=_URL.validate_python(link) if link else None,
            **kw,
        )

    def from_status(self, resp: httpx.Response) -> SourceResult | None:
        """Map non-success HTTP outcomes; None means the body should be parsed."""
        code = resp.status_code
        if code == 429:
            return self.result(Status.RATE_LIMITED, "rate limited")
        if code == 404:
            return self.result(Status.NOT_FOUND, "not found")
        if code >= 400:
            return self.result(Status.ERROR, f"HTTP {code}")
        return None

    async def query(self, ioc: IOC, http: Gate) -> SourceResult:
        try:
            return await self.lookup(ioc, http)
        except RateLimitedError as exc:
            return self.result(Status.RATE_LIMITED, str(exc))
        except httpx.TimeoutException:
            return self.result(Status.ERROR, "timeout")
        except httpx.HTTPError as exc:
            return self.result(Status.ERROR, f"network error: {type(exc).__name__}")
        except (
            ValueError,
            KeyError,
            IndexError,
            TypeError,
            AttributeError,
            ArithmeticError,
            ValidationError,
        ) as exc:
            # malformed vendor response; message omitted: it may echo attacker-controlled data
            log.warning("%s: malformed response (%s)", self.name, type(exc).__name__)
            return self.result(Status.ERROR, "malformed response")


def json_object(resp: httpx.Response) -> dict[str, Any]:
    data = resp.json()
    if not isinstance(data, dict):
        raise ValueError("expected JSON object")
    return data  # pyright: ignore[reportUnknownVariableType]
