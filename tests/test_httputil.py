"""`retry_after`: a Retry-After header becomes a usable wait or nothing."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest

from verdikt.httputil import MAX_WAIT, retry_after


def resp(value: str | None) -> httpx.Response:
    return httpx.Response(429, headers={} if value is None else {"Retry-After": value})


@pytest.mark.parametrize(
    ("header", "want"),
    [("0", 0.0), ("3", 3.0), ("1.5", 1.5), (" 7 ", 7.0), ("120", 120.0)],
)
def test_seconds(header: str, want: float) -> None:
    assert retry_after(resp(header)) == want


@pytest.mark.parametrize("header", [None, "", "abc", "nan", "NaN", "-inf", "-5", "-0.5"])
def test_unusable_values_are_no_wait_at_all(header: str | None) -> None:
    assert retry_after(resp(header)) is None


def test_http_date_in_the_future_and_in_the_past() -> None:
    future = format_datetime(datetime.now(UTC) + timedelta(seconds=90), usegmt=True)
    assert 80 <= (retry_after(resp(future)) or 0) <= 90
    past = format_datetime(datetime.now(UTC) - timedelta(hours=1), usegmt=True)
    assert retry_after(resp(past)) == 0.0


@pytest.mark.parametrize("header", ["inf", "Infinity", "1e999", "999999999"])
def test_a_huge_wait_is_clamped_not_dropped(header: str) -> None:
    # "wait forever" must stay a long wait, or callers would read it as "no Retry-After" and retry
    assert retry_after(resp(header)) == MAX_WAIT
