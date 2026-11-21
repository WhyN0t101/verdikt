"""Small HTTP helpers shared by the source layer and alert delivery (neither imports the other)."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

import httpx

MAX_WAIT = (
    86_400.0  # a day: far above any timeout, so callers treat it as "too long", never as "none"
)


def retry_after(resp: httpx.Response) -> float | None:
    """Seconds to wait from a `Retry-After` header (seconds or HTTP date), or None.

    `nan`, a negative number or junk is treated as absent. An enormous value (`inf`, `1e999`) is a
    real request to wait a long time, so it is clamped to `MAX_WAIT` rather than dropped.
    """
    value = resp.headers.get("retry-after")
    if value is None:
        return None
    try:
        seconds = float(value)
    except ValueError:
        try:  # HTTP-date form
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        seconds = (when - datetime.now(UTC)).total_seconds()
        seconds = max(0.0, seconds)
    return None if math.isnan(seconds) or seconds < 0 else min(seconds, MAX_WAIT)
