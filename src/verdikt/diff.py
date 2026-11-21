"""What changed between two stored reports. Pure: no I/O, no clock; it only reads stored levels.

The diff never recomputes a verdict and never carries `raw`. Feed-derived text (summaries,
reasons, metric keys) is capped and stripped of control and bidi characters, so a spoofed line
cannot reorder what the analyst reads.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import Field

from verdikt.models import Level, Model, Report, SourceResult, Status

MAX_TEXT = 300
# C0/C1 controls, then bidi controls (embeddings, overrides, isolates, marks)
_DROP = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f؜‎‏‪-‮⁦-⁩]")
_SPACE = re.compile("[\t\n\r]")
_ANSWERED = (Status.OK, Status.NOT_FOUND)


def clean(text: str) -> str:
    return _DROP.sub("", _SPACE.sub(" ", text))[:MAX_TEXT]


class MetricChange(Model):
    # `from` is a keyword: the JSON key is "from", the attribute `from_`
    key: str
    from_: int | bool | None = Field(alias="from")
    to: int | bool | None


class SourceChange(Model):
    source: str
    change: Literal["added", "removed", "changed"]
    status_from: Status | None
    status_to: Status | None
    level_from: Level | None
    level_to: Level | None
    summary_from: str | None
    summary_to: str | None
    no_answer: bool  # the new row is an error or rate limit, not a clean result
    metrics: list[MetricChange]


class ReportDiff(Model):
    report_id: str
    previous_id: str | None
    previous_at: datetime | None
    changed: bool
    level_from: Level | None
    level_to: Level
    agreeing_from: int | None
    agreeing_to: int
    total_from: int | None
    total_to: int
    confidence_from: str | None
    confidence_to: str
    sources: list[SourceChange]
    reasons_added: list[str]
    reasons_removed: list[str]


def _metrics(old: SourceResult | None, new: SourceResult | None) -> list[MetricChange]:
    before = old.metrics if old else {}
    after = new.metrics if new else {}
    keys = sorted(before.keys() | after.keys())
    return [
        MetricChange.model_validate({"key": clean(k), "from": before.get(k), "to": after.get(k)})
        for k in keys
        if before.get(k) != after.get(k)
    ]


def _change(old: SourceResult | None, new: SourceResult | None) -> SourceChange | None:
    """The change of one source, or None when it reads the same."""
    row = new or old
    assert row is not None
    metrics = _metrics(old, new)
    same = (
        old and new and (old.status, old.level, old.summary) == (new.status, new.level, new.summary)
    )
    if same and not metrics:
        return None
    kind: Literal["added", "removed", "changed"] = (
        "added" if old is None else "removed" if new is None else "changed"
    )
    return SourceChange(
        source=clean(row.source),
        change=kind,
        status_from=old.status if old else None,
        status_to=new.status if new else None,
        level_from=old.level if old else None,
        level_to=new.level if new else None,
        summary_from=clean(old.summary) if old else None,
        summary_to=clean(new.summary) if new else None,
        no_answer=new is not None and new.status not in _ANSWERED,
        metrics=metrics,
    )


def _rank(c: SourceChange) -> int:
    if c.change == "added":
        return 3
    if c.change == "removed":
        return 4
    if c.level_from != c.level_to:
        return 0
    return 1 if c.status_from != c.status_to else 2


def diff_reports(old: Report | None, new: Report) -> ReportDiff:
    """`old` None means the first report of this indicator: nothing changed, nothing to compare."""
    sources: list[SourceChange] = []
    added: list[str] = []
    removed: list[str] = []
    if old is not None:
        before = {r.source: r for r in old.results}
        after = {r.source: r for r in new.results}
        for name in [*after, *(n for n in before if n not in after)]:
            c = _change(before.get(name), after.get(name))
            if c is not None:
                sources.append(c)
        sources.sort(key=_rank)  # stable: ties keep the report's own order
        added = [clean(r) for r in new.reasons if r not in old.reasons]
        removed = [clean(r) for r in old.reasons if r not in new.reasons]
    moved = old is not None and (
        (old.level, old.agreeing, old.total, old.confidence)
        != (new.level, new.agreeing, new.total, new.confidence)
    )
    return ReportDiff(
        report_id=new.id,
        previous_id=old.id if old else None,
        previous_at=old.created_at if old else None,
        changed=bool(sources or added or removed or moved),
        level_from=old.level if old else None,
        level_to=new.level,
        agreeing_from=old.agreeing if old else None,
        agreeing_to=new.agreeing,
        total_from=old.total if old else None,
        total_to=new.total,
        confidence_from=old.confidence.value if old else None,
        confidence_to=new.confidence.value,
        sources=sources,
        reasons_added=added,
        reasons_removed=removed,
    )
