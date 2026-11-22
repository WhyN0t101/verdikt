"""`clean_text` and where it is applied: models (so stored and cached rows load clean), sources."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tests.conftest import Fake
from verdikt.cache import Cache
from verdikt.models import IOCType, RelatedIOC, SourceResult, Status
from verdikt.textutil import clean_text

ESC, BEL = "\x1b", "\x07"


@pytest.mark.parametrize(
    ("raw", "want"),
    [
        (f"a{ESC}[31mred", "a[31mred"),  # the ESC byte goes; harmless printable text stays
        (f"x{ESC}]0;title{BEL}y", "x]0;titley"),
        ("a\u202eb\u202ac\u2066d\u2069e", "abcde"),  # bidi controls
        ("a\u200bb\u200dc\ufeffd\u2060e\u00adf", "abcdef"),  # zero-width, BOM, joiner, soft hyphen
        ("a\u2028b\u2029c", "abc"),  # line and paragraph separators
        ("a\U000e0041b\U000e007fc", "abc"),  # tag characters ("ASCII smuggling")
        ("a\tb\nc\rd", "a b c d"),  # whitespace controls become a space
        ("a\x00b\x7fc\x85d", "abcd"),
        ("büchers 中文 \U0001f600", "büchers 中文 \U0001f600"),  # normal
        ("", ""),
    ],
)
def test_clean_text(raw: str, want: str) -> None:
    assert clean_text(raw) == want


def test_models_clean_summary_tags_and_related_values() -> None:
    r = SourceResult(
        source="x",
        status=Status.OK,
        summary="a\u202eb\nc",
        tags=["t\u200b1", f"t{ESC}2"],
        raw={"k": "a\u202eb"},
    )
    assert (r.summary, r.tags) == ("ab c", ["t1", "t2"])
    assert r.raw == {"k": "a\u202eb"}  # the vendor payload is kept as received
    related = RelatedIOC(value="1.2.3.4\u202e", type=IOCType.IP, relation="resolves_to")
    assert related.value == "1.2.3.4"


def test_a_source_result_is_clean_when_built() -> None:
    result = Fake("virustotal").result(Status.OK, f"{ESC}[31mhi\u202e", tags=["a\u200b"])
    assert (result.summary, result.tags) == ("[31mhi", ["a"])


def test_cached_rows_written_before_the_fix_load_clean() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    cache = Cache(":memory:", clock=lambda: now)
    ok = SourceResult(source="vt", status=Status.OK, summary="ok", fetched_at=now)
    cache.put("vt", "8.8.8.8", ok)
    poisoned = ok.model_dump_json().replace('"summary":"ok"', '"summary":"a\\u202e\\u001bb"')
    assert "\\u202e" in poisoned  # a JSON escape: it only becomes a character on load
    with cache._lock, cache._db:  # pyright: ignore[reportPrivateUsage]
        cache._db.execute("UPDATE source_cache SET result=?", (poisoned,))  # pyright: ignore[reportPrivateUsage]
    got = cache.get("vt", "8.8.8.8", timedelta(hours=1))
    assert got is not None
    assert got.summary == "ab"
    cache.close()


def test_a_cache_hit_keeps_the_original_fetch_time() -> None:
    fetched = datetime(2026, 1, 1, 12, tzinfo=UTC)
    cache = Cache(":memory:", clock=lambda: fetched + timedelta(hours=5))
    cache.put("vt", "8.8.8.8", SourceResult(source="vt", status=Status.OK, fetched_at=fetched))
    got = cache.get("vt", "8.8.8.8", timedelta(days=1))
    assert got is not None
    assert (got.cached, got.fetched_at) == (True, fetched)  # the UI shows "cached, 5 h ago"
    cache.close()
