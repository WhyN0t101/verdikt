"""Investigations (cases), exports, retention interplay and the new API routes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from tests.conftest import CountingLimiter, Fake
from verdikt.api.app import create_app
from verdikt.cache import CASE_MAX_TAGS, Cache, CaseError, clean_tags
from verdikt.config import Settings, load_rules
from verdikt.engine import Engine
from verdikt.export import case_html, case_markdown, report_html, report_markdown
from verdikt.models import (
    Confidence,
    CveInfo,
    IOCType,
    Level,
    Report,
    SeenBefore,
    SourceResult,
    Status,
)
from verdikt.sources.base import Source

T0 = datetime(2026, 1, 10, 12, tzinfo=UTC)

HOSTILE = "<script>alert(1)</script> | `x` [click](http://evil.example) \n# heading"


def report(rid: str = "r1", ioc: str = "evil.example", created: datetime = T0) -> Report:
    return Report(
        id=rid,
        ioc=ioc,
        ioc_type=IOCType.DOMAIN,
        level=Level.MALICIOUS,
        confidence=Confidence.HIGH,
        agreeing=2,
        total=2,
        reasons=["virustotal: malicious 9 >= 5 -> malicious", HOSTILE],
        results=[
            SourceResult(
                source="virustotal",
                status=Status.OK,
                level=Level.MALICIOUS,
                summary=HOSTILE,
                fired=["malicious 9 >= 5 -> malicious"],
                weight=3,
                role="strong",
            )
        ],
        cves=[CveInfo(id="CVE-2021-44228", kev=True, epss=0.97)],
        seen_before=[
            SeenBefore(
                report_id="x",
                ioc="1.2.3.4",
                level=Level.SAFE,
                created_at=T0,
                shared=["evil.example"],
            )
        ],
        created_at=created,
    )


# --- cases --------------------------------------------------------------------------------


def test_case_lifecycle() -> None:
    c = Cache(":memory:", clock=lambda: T0)
    c.save_report(report("a"))
    cid = c.case_create("Invoice phish", "first notes", ["Phishing", "q4"])
    assert c.case_add_report(cid, "a")
    assert c.case_add_report(cid, "a")  # idempotent
    case = c.case_get(cid)
    assert case is not None
    assert (case.title, case.notes, case.tags, case.report_count) == (
        "Invoice phish",
        "first notes",
        ["phishing", "q4"],
        1,
    )
    assert [r.id for r in case.reports] == ["a"]

    assert c.case_update(cid, notes="more notes", tags=["done"])
    updated = c.case_get(cid)
    assert updated is not None
    assert (updated.title, updated.notes, updated.tags) == ("Invoice phish", "more notes", ["done"])

    assert c.case_remove_report(cid, "a")
    assert c.case_get(cid).report_count == 0  # type: ignore[union-attr]
    assert c.case_delete(cid) and c.case_get(cid) is None
    assert not c.case_delete(cid)


def test_case_rejects_bad_input() -> None:
    c = Cache(":memory:")
    for title in ("", "   ", "x" * 121):
        with pytest.raises(CaseError):
            c.case_create(title)
    with pytest.raises(CaseError):
        c.case_create("ok", notes="x" * 20_001)
    for tag in ("<b>", "", "-x", "a" * 31, "x/y"):
        with pytest.raises(CaseError):
            c.case_create("ok", tags=[tag])
    with pytest.raises(CaseError):
        c.case_create("ok", tags=[f"t{i}" for i in range(CASE_MAX_TAGS + 1)])
    assert clean_tags([" A ", "a", "b:c"]) == ["a", "b:c"]


def test_case_links_need_a_real_case_and_report() -> None:
    c = Cache(":memory:")
    cid = c.case_create("x")
    assert c.case_add_report(cid, "missing") is False
    assert c.case_add_report("nope", "missing") is False
    assert c.case_update("nope", title="x") is False


def test_case_list_filters_by_tag_and_orders_by_activity() -> None:
    now = [T0]
    c = Cache(":memory:", clock=lambda: now[0])
    a = c.case_create("old", tags=["x"])
    now[0] = T0 + timedelta(hours=1)
    b = c.case_create("new", tags=["y"])
    assert [s.id for s in c.case_list()] == [b, a]
    assert [s.id for s in c.case_list("x")] == [a]
    now[0] = T0 + timedelta(hours=2)
    c.case_update(a, notes="touched")
    assert [s.id for s in c.case_list()] == [a, b]


def test_retention_never_deletes_evidence_in_a_case() -> None:
    now = [T0]
    c = Cache(":memory:", clock=lambda: now[0], report_retention=timedelta(days=1))
    c.save_report(report("kept"))
    c.save_report(report("gone", "other.example"))
    cid = c.case_create("evidence")
    c.case_add_report(cid, "kept")
    now[0] = T0 + timedelta(days=60)
    c.prune()
    assert c.get_report("kept") is not None
    assert c.get_report("gone") is None
    c.case_remove_report(cid, "kept")
    c.prune()
    assert c.get_report("kept") is None  # no longer protected


# --- exports ------------------------------------------------------------------------------


def test_markdown_report_is_defanged_and_neutralises_feed_text() -> None:
    md = report_markdown(report())
    assert "MALICIOUS: evil[.]example (domain)" in md
    assert "Confidence: **high**" in md
    assert "| virustotal | malicious | strong | 3 |" in md
    assert "CVE-2021-44228: in CISA KEV, EPSS 97.0%" in md
    assert "Seen before" in md
    # hostile feed text appears only as one-line inline code: no stray backtick, no pipe, no heading
    neutral = "`<script>alert(1)</script> / 'x' [click](http://evil.example) # heading`"
    assert md.count(neutral) == 2  # once in "Why", once in the source row
    assert not any(line.startswith("# heading") for line in md.splitlines())
    [row] = [ln for ln in md.splitlines() if ln.startswith("| virustotal")]
    assert row.count("|") == 7  # a pipe in feed text cannot add a column


def test_html_report_escapes_everything_and_has_no_script_or_external_resource() -> None:
    page = report_html(report())
    assert "<script" not in page.lower().replace("&lt;script&gt;", "")
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert "evil[.]example" in page
    assert "src=" not in page and "href=" not in page
    assert "default-src 'none'" in page
    assert "<style>" in page


def test_case_exports_include_notes_tags_and_every_report() -> None:
    c = Cache(":memory:", clock=lambda: T0)
    c.save_report(report("a"))
    c.save_report(report("b", "other.example"))
    cid = c.case_create(
        "Q4 <b>phish</b>",
        "Analyst saw it first at 09:00.\n<img src=x onerror=alert(1)>",
        ["phishing"],
    )
    c.case_add_report(cid, "a")
    c.case_add_report(cid, "b")
    case = c.case_get(cid)
    assert case is not None
    reports = [r for s in case.reports if (r := c.get_report(s.id))]

    md = case_markdown(case, reports)
    assert md.startswith("# Investigation:")
    assert "Analyst saw it first" in md
    assert "other[.]example" in md and "evil[.]example" in md
    assert "`phishing`" in md

    page = case_html(case, reports)
    assert "&lt;img src=x onerror=alert(1)&gt;" in page
    assert "<img" not in page
    assert "<b>phish</b>" not in page
    assert page.count("<h2>") >= 2


# --- API ----------------------------------------------------------------------------------

AUTH = {"x-verdikt-token": "t"}


def make_client(tmp_path: Path) -> httpx.AsyncClient:
    sources: list[Source] = [Fake("virustotal", {"malicious": 20, "suspicious": 0})]
    settings = Settings(_env_file=None, feeds_dir=tmp_path / "feeds")  # pyright: ignore[reportCallIssue]
    engine = Engine(
        settings,
        load_rules(),
        Cache(":memory:"),
        httpx.AsyncClient(),
        sources=sources,
        limiter_factory=CountingLimiter,
    )
    app = create_app(engine, port=8765, token="t", web_dist=tmp_path / "none")
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8765"
    )


async def test_api_cases_end_to_end(tmp_path: Path) -> None:
    async with make_client(tmp_path) as c:
        rid = (await c.post("/api/check", headers=AUTH, json={"ioc": "8.8.8.8"})).json()["id"]
        made = await c.post("/api/cases", headers=AUTH, json={"title": "Case A", "tags": ["Phish"]})
        assert made.status_code == 200
        cid = made.json()["id"]
        assert made.json()["tags"] == ["phish"]

        added = await c.post(f"/api/cases/{cid}/reports", headers=AUTH, json={"report_id": rid})
        assert [r["id"] for r in added.json()["reports"]] == [rid]
        assert (
            await c.post(f"/api/cases/{cid}/reports", headers=AUTH, json={"report_id": "nope"})
        ).status_code == 404

        patched = await c.patch(
            f"/api/cases/{cid}", headers=AUTH, json={"notes": "seen in the proxy logs"}
        )
        assert patched.json()["notes"] == "seen in the proxy logs"
        assert (
            await c.patch(f"/api/cases/{cid}", headers=AUTH, json={"tags": ["<x>"]})
        ).status_code == 422
        assert (
            await c.patch("/api/cases/nope", headers=AUTH, json={"notes": "x"})
        ).status_code == 404

        assert [x["title"] for x in (await c.get("/api/cases", headers=AUTH)).json()] == ["Case A"]
        assert (await c.get("/api/cases", headers=AUTH, params={"tag": "other"})).json() == []
        assert (await c.post("/api/cases", headers=AUTH, json={"title": " "})).status_code == 422

        md = await c.get(f"/api/cases/{cid}/export", headers=AUTH)
        assert md.headers["content-type"].startswith("text/markdown")
        assert "attachment" in md.headers["content-disposition"]
        assert "seen in the proxy logs" in md.text
        assert "8[.]8[.]8[.]8" in md.text
        html = await c.get(f"/api/cases/{cid}/export", headers=AUTH, params={"format": "html"})
        assert html.headers["content-type"].startswith("text/html")
        assert (
            await c.get(f"/api/cases/{cid}/export", headers=AUTH, params={"format": "pdf"})
        ).status_code == 422

        rep_md = await c.get(f"/api/reports/{rid}/export", headers=AUTH)
        assert "MALICIOUS: 8[.]8[.]8[.]8" in rep_md.text
        assert (await c.get("/api/reports/nope/export", headers=AUTH)).status_code == 404

        removed = await c.delete(f"/api/cases/{cid}/reports/{rid}", headers=AUTH)
        assert removed.json()["reports"] == []
        assert (await c.delete(f"/api/cases/{cid}", headers=AUTH)).json() == []
        assert (await c.get(f"/api/cases/{cid}", headers=AUTH)).status_code == 404


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/cases"),
        ("POST", "/api/cases"),
        ("GET", "/api/cases/x/export"),
        ("GET", "/api/reports/x/export"),
    ],
)
async def test_case_routes_need_the_token(tmp_path: Path, method: str, path: str) -> None:
    async with make_client(tmp_path) as c:
        r = await c.request(method, path, json={} if method == "POST" else None)
        assert r.status_code == 401
