"""Pure verdict logic: row levels and the final level come only from rules."""

from __future__ import annotations

from dataclasses import dataclass

from verdikt.config import Rules
from verdikt.models import Confidence, Level, SourceResult, Status

Condition = dict[str, bool | int]


@dataclass(frozen=True)
class Decision:
    level: Level
    agreeing: int
    total: int
    confidence: Confidence
    reasons: list[str]
    results: list[SourceResult]


def _fired(metrics: dict[str, int | bool], condition: Condition) -> list[str]:
    """Describe each metric that satisfies `condition` (keys are OR'ed)."""
    hits: list[str] = []
    for key, want in condition.items():
        # `metric__lt: N` means metric < N (the plain form is metric >= N)
        below = key.endswith("__lt")
        name = key.removesuffix("__lt")
        have = metrics.get(name)
        if have is None:
            continue
        if below:
            if not isinstance(have, bool) and not isinstance(want, bool) and have < want:
                hits.append(f"{name} {have} < {want}")
        elif isinstance(want, bool):
            if isinstance(have, bool) and have is want:
                hits.append(f"{key} is {str(have).lower()}")
        elif not isinstance(have, bool) and have >= want:
            hits.append(f"{key} {have} >= {want}")
    return hits


def _match(rules: dict[str, Condition], row: SourceResult) -> list[str]:
    condition = rules.get(row.source)
    return _fired(row.metrics, condition) if condition else []


def _weight(row: SourceResult, rules: Rules) -> int:
    if row.status is not Status.OK or row.level is Level.INFO:
        return 0
    if row.source in rules.listing_feeds and row.level is Level.SAFE:
        return 0  # "not listed" says nothing about an indicator that is bad but unlisted
    return rules.weights.get(row.source, rules.default_weight)


def _role(row: SourceResult, rules: Rules) -> str:
    if row.status is not Status.OK:
        return "no answer"
    if row.source in rules.context_only:
        return "context"
    if row.source in rules.listing_feeds:
        return "feed"
    return "strong" if row.source in rules.high_weight else "weak"


def _confidence(verdict_rows: list[SourceResult], final: Level, rules: Rules) -> Confidence:
    """Weighted agreement with the final level; conflicting evidence at least as heavy -> low."""
    agree = sum(_weight(r, rules) for r in verdict_rows if r.level is final)
    against = sum(_weight(r, rules) for r in verdict_rows if r.level is not final)
    if final is Level.UNKNOWN or against >= agree:
        return Confidence.LOW
    if agree >= rules.confidence_high:
        return Confidence.HIGH
    return Confidence.MEDIUM if agree >= rules.confidence_medium else Confidence.LOW


def decide(results: list[SourceResult], rules: Rules) -> Decision:
    """Compute every row level and the final verdict. No I/O, clock or randomness."""
    rows: list[SourceResult] = []
    reasons: list[str] = []
    malicious_rows = suspicious_rows = 0
    verdict_rows: list[SourceResult] = []

    for row in results:
        level = Level.UNKNOWN
        fired: list[str] = []
        if row.status is Status.OK:
            if row.source in rules.context_only:
                level = Level.INFO
            else:
                mal = _match(rules.malicious, row)
                sus = _match(rules.suspicious, row)
                if mal:
                    level = Level.MALICIOUS
                    fired = [f"{h} -> malicious" for h in mal]
                    malicious_rows += 1
                    reasons.append(f"{row.source}: {'; '.join(mal)} -> malicious")
                elif sus:
                    level = Level.SUSPICIOUS
                    fired = [f"{h} -> suspicious" for h in sus]
                    suspicious_rows += 1
                    reasons.append(f"{row.source}: {'; '.join(sus)} -> suspicious")
                else:
                    level = Level.SAFE
        new = row.model_copy(update={"level": level, "fired": fired})
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
        strong = sum(
            1
            for r in verdict_rows
            if r.source in rules.high_weight and r.source not in rules.listing_feeds
        )
        if (
            len(verdict_rows) >= rules.min_sources_for_safe
            and strong >= rules.min_high_weight_for_safe
            and not blockers
        ):
            final = Level.SAFE
            reasons.append(f"{len(verdict_rows)} sources returned no hits")
        else:
            final = Level.UNKNOWN
            if blockers:
                reasons.append(f"high-weight source gave no answer: {', '.join(blockers)}")
            if strong < rules.min_high_weight_for_safe and not blockers:
                reasons.append(
                    f"no high-weight source answered ({', '.join(rules.high_weight)}); "
                    f"need {rules.min_high_weight_for_safe}"
                )
            if len(verdict_rows) < rules.min_sources_for_safe:
                reasons.append(
                    f"only {len(verdict_rows)} verdict-bearing source(s) answered; "
                    f"need {rules.min_sources_for_safe}"
                )

    for r in rows:
        if r.status is Status.OK and (hit := _match(rules.benign_override, r)):
            r.fired = [*r.fired, *(f"{h} -> benign override (softens suspicious)" for h in hit)]
        r.weight = _weight(r, rules)
        r.role = _role(r, rules)
    agreeing = sum(1 for r in verdict_rows if r.level is final)
    confidence = _confidence(verdict_rows, final, rules)
    if rules.cap_safe_confidence_single_strong and final is Level.SAFE:
        answered = [r for r in verdict_rows if r.source in rules.high_weight]
        if sum(r.source not in rules.listing_feeds for r in answered) == 1:
            confidence = min(confidence, Confidence.MEDIUM, key=list(Confidence).index)
    return Decision(final, agreeing, len(verdict_rows), confidence, reasons, rows)
