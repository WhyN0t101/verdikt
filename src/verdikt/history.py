"""Everything stored about one indicator: its reports, the cases it is in, the watch. Pure: the
cache does the reading, this only assembles and counts (no I/O, no clock, like `diff.py`)."""

from __future__ import annotations

from datetime import datetime
from itertools import pairwise

from verdikt.cache import CaseSummary, ReportSummary, WatchEntry, WatchEvent
from verdikt.models import Model

MAX_REPORTS = 50


class IocHistory(Model):
    report_id: str
    ioc: str
    reports: list[ReportSummary]  # exactly this indicator, newest first, at most MAX_REPORTS
    truncated: bool  # more than MAX_REPORTS are stored
    changes: int  # level changes over the listed reports, in time order
    cases: list[CaseSummary]  # cases holding any listed report, each once
    watched: bool
    watched_since: datetime | None
    events: list[WatchEvent]  # newest first


def build_history(
    report_id: str,
    ioc: str,
    reports: list[ReportSummary],
    cases: list[CaseSummary],
    entry: WatchEntry | None,
    events: list[WatchEvent],
) -> IocHistory:
    """`reports` is newest first; one row beyond MAX_REPORTS is the truncation probe."""
    shown = reports[:MAX_REPORTS]
    levels = [r.level for r in reversed(shown)]
    return IocHistory(
        report_id=report_id,
        ioc=ioc,
        reports=shown,
        truncated=len(reports) > MAX_REPORTS,
        changes=sum(a != b for a, b in pairwise(levels)),
        cases=cases,
        watched=entry is not None,
        watched_since=entry.added_at if entry else None,
        events=events,
    )
