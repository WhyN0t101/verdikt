"""Pure verdict logic: row levels and the final level come only from rules."""

from __future__ import annotations

from dataclasses import dataclass

from verdikt.config import Rules
from verdikt.models import Level, SourceResult, Status

Condition = dict[str, bool | int]


@dataclass(frozen=True)
class Decision:
    level: Level
    agreeing: int
    total: int
    reasons: list[str]
    results: list[SourceResult]


def _fired(metrics: dict[str, int | bool], condition: Condition) -> list[str]:
    """Describe each metric that satisfies `condition` (keys are OR'ed)."""
    hits: list[str] = []
    for key, want in condition.items():
        have = metrics.get(key)
        if have is None:
            continue
        if isinstance(want, bool):
            if isinstance(have, bool) and have is want:
                hits.append(f"{key} is {str(have).lower()}")
        elif not isinstance(have, bool) and have >= want:
            hits.append(f"{key} {have} >= {want}")
    return hits


def _match(rules: dict[str, Condition], row: SourceResult) -> list[str]:
    condition = rules.get(row.source)
    return _fired(row.metrics, condition) if condition else []


def decide(results: list[SourceResult], rules: Rules) -> Decision:
    """Compute every row level and the final verdict. No I/O, clock or randomness."""
    rows: list[SourceResult] = []
    reasons: list[str] = []
    malicious_rows = suspicious_rows = 0
    verdict_rows: list[SourceResult] = []

    for row in results:
        level = Level.UNKNOWN
        if row.status is Status.OK:
            if row.source in rules.context_only:
                level = Level.INFO
            else:
                mal = _match(rules.malicious, row)
                sus = _match(rules.suspicious, row)
                if mal:
                    level = Level.MALICIOUS
                    malicious_rows += 1
                    reasons.append(f"{row.source}: {'; '.join(mal)} -> malicious")
                elif sus:
                    level = Level.SUSPICIOUS
                    suspicious_rows += 1
                    reasons.append(f"{row.source}: {'; '.join(sus)} -> suspicious")
                else:
                    level = Level.SAFE
        new = row.model_copy(update={"level": level})
        rows.append(new)
        if new.status is Status.OK and level is not Level.INFO:
            verdict_rows.append(new)

    overrides = [
        f"{r.source}: {'; '.join(hit)}"
        for r in rows
        if r.status is Status.OK and (hit := _match(rules.benign_override, r))
    ]

    # A high-weight source that failed or has never seen the IOC cannot back a SAFE verdict:
    # abuse.ch feeds only list known-bad items, so "no match" there is weak evidence.
    blockers = [
        r.source
        for r in rows
        if r.source in rules.high_weight
        and r.status in (Status.ERROR, Status.RATE_LIMITED, Status.NOT_FOUND)
    ]

    final: Level
    if malicious_rows:
        final = Level.MALICIOUS
    elif suspicious_rows:
        if overrides and not blockers:
            final = Level.SAFE
            reasons.append(
                f"benign override ({'; '.join(overrides)}) downgrades suspicious -> safe"
            )
        else:
            final = Level.SUSPICIOUS
    else:
        if len(verdict_rows) >= rules.min_sources_for_safe and not blockers:
            final = Level.SAFE
            reasons.append(f"{len(verdict_rows)} sources returned no hits")
        else:
            final = Level.UNKNOWN
            if blockers:
                reasons.append(f"high-weight source gave no answer: {', '.join(blockers)}")
            if len(verdict_rows) < rules.min_sources_for_safe:
                reasons.append(
                    f"only {len(verdict_rows)} verdict-bearing source(s) answered; "
                    f"need {rules.min_sources_for_safe}"
                )

    agreeing = sum(1 for r in verdict_rows if r.level is final)
    return Decision(final, agreeing, len(verdict_rows), reasons, rows)
