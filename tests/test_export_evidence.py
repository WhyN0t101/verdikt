"""The Evidence table in the Markdown and HTML exports: where each claim came from."""

from __future__ import annotations

from datetime import UTC, datetime

from verdikt.export import report_html, report_markdown
from verdikt.models import IOCType, Level, Report, SourceResult, Status

FETCHED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def make() -> Report:
    rows = [
        SourceResult(
            source="virustotal",
            status=Status.OK,
            level=Level.MALICIOUS,
            summary="<script>alert(1)</script>",
            link="https://www.virustotal.com/gui/ip-address/1.2.3.4",  # pyright: ignore[reportArgumentType]
            fired=["malicious 7 >= 2 -> suspicious", "a|b"],
            fetched_at=FETCHED,
            raw={"secret": "VENDOR-PAYLOAD"},
        ),
        SourceResult(
            source="abuseipdb",
            status=Status.ERROR,
            cached=True,
            summary="HTTP 500",
            fetched_at=FETCHED,
        ),
    ]
    return Report(
        id="r1",
        ioc="1.2.3.4",
        ioc_type=IOCType.IP,
        level=Level.MALICIOUS,
        agreeing=1,
        total=2,
        results=rows,
    )


def test_markdown_evidence_table_lists_every_row() -> None:
    md = report_markdown(make())
    part = md[md.index("# Evidence") :]
    assert "| Source | Status | Level | Fetched | Cached | Page | Rules that fired |" in part
    assert "2026-01-02 03:04:05 UTC" in part
    row = next(line for line in part.splitlines() if line.startswith("| virustotal"))
    assert "`malicious`" in row and "`no`" in row
    assert "hxxps://www[.]virustotal[.]com/gui/ip-address/1[.]2[.]3[.]4" in row
    assert "a/b" in row  # a pipe cannot break the table cell
    err = next(line for line in part.splitlines() if line.startswith("| abuseipdb"))
    assert "`error`" in err and "`yes`" in err  # an error row is not shown as a level


def test_html_evidence_table_escapes_and_has_no_live_link() -> None:
    page = report_html(make())
    assert "<h3>Evidence</h3>" in page
    assert "2026-01-02 03:04:05 UTC" in page
    assert "hxxps://www[.]virustotal[.]com" in page
    assert "<script>" not in page.replace("<style>", "")  # escaped in the summary
    assert "&lt;script&gt;" in page
    assert "href=" not in page and "https://" not in page


def test_exports_never_carry_the_raw_vendor_payload() -> None:
    for text in (report_markdown(make()), report_html(make())):
        assert "VENDOR-PAYLOAD" not in text
