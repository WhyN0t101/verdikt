"""Small HTTP helpers shared by the source layer and alert delivery (neither imports the other)."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

import httpx


def retry_after(resp: httpx.Response) -> float | None:
    """Seconds to wait from a `Retry-After` header (seconds or HTTP date), or None.

    A value that is not a finite, non-negative wait (`nan`, `inf`, `-5`, junk) is treated as
    absent, so callers never sleep on it or print it.
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
    return seconds if math.isfinite(seconds) and seconds >= 0 else None
