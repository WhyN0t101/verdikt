"""Evaluate `verdict.decide()` over the labelled corpus in tests/eval/ (offline, deterministic).

    python scripts/eval_report.py                    # text report
    python scripts/eval_report.py --json             # the same numbers as JSON
    python scripts/eval_report.py --rules my.yaml    # try another rules file
    python scripts/eval_report.py --update-baseline  # accept the current outputs (review the diff)

Synthetic labels guard regressions, they do not measure accuracy. Every rate carries a Wilson
95% interval; with few samples the interval is wide, and that is the honest reading.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from verdikt.config import Rules, load_rules
from verdikt.models import Level, SourceResult, Status
from verdikt.verdict import decide

EVAL_DIR = Path(__file__).resolve().parent.parent / "tests" / "eval"
CORPUS = EVAL_DIR / "corpus.jsonl"
INDICATORS = EVAL_DIR / "indicators.jsonl"  # real-world indicators: labels, no rows
RECORDED = EVAL_DIR / "recorded.jsonl"  # rows recorded from open-licence sources (committed)
LOCAL = EVAL_DIR / "local"  # git-ignored rows from licence-restricted sources
BASELINE = EVAL_DIR / "baseline.json"
ORDER = {"safe": 0, "suspicious": 1, "malicious": 2}
GATED_SPLITS = ("synthetic", "holdout")  # outputs must match the baseline exactly
DISCLAIMER = "Synthetic labels guard regressions, they do not measure accuracy."


@dataclass(frozen=True)
class Sample:
    id: str
    split: str
    label: tuple[str, str] | None  # ordinal interval; None = unlabelled (the tool may abstain)
    rows: tuple[tuple[str, str, tuple[tuple[str, int | bool], ...]], ...]
    raw: str  # the corpus line, for the holdout checksum
    group: str = "synthetic"  # "realworld" samples are never gated in CI


@dataclass(frozen=True)
class Outcome:
    level: str
    confidence: str
    agreeing: int
    total: int


def _sample(data: dict[str, Any], rows: list[dict[str, Any]], line: str, group: str) -> Sample:
    label = data.get("label")
    return Sample(
        id=data["id"],
        split=data["split"],
        label=(label["min"], label["max"]) if label else None,
        rows=tuple(
            (r["source"], r["status"], tuple(sorted(r.get("metrics", {}).items()))) for r in rows
        ),
        raw=line,
        group=group,
    )


def _lines(path: Path) -> list[tuple[str, dict[str, Any]]]:
    if not path.exists():
        return []
    texts = (t for t in path.read_text(encoding="utf-8").splitlines() if t.strip())
    return [(t, json.loads(t)) for t in texts]


def _recorded() -> dict[str, list[dict[str, Any]]]:
    """Rows recorded by scripts/eval_record.py: committed (open licence) and local (ignored)."""
    found: dict[str, dict[str, dict[str, Any]]] = {}
    for path in [RECORDED, *sorted(LOCAL.glob("recorded*.jsonl"))]:
        for _, data in _lines(path):
            for row in data["rows"]:
                found.setdefault(data["id"], {})[row["source"]] = row
    return {sid: list(rows.values()) for sid, rows in found.items()}


def load_samples(paths: list[Path] | None = None) -> list[Sample]:
    """The inline corpus, plus (by default) the real-world indicators that have recorded rows.

    Real-world indicators are metadata only; their rows come from `recorded.jsonl` and
    `local/recorded*.jsonl`. An indicator nobody recorded yet is not evaluated.
    """
    samples = [
        _sample(data, data["rows"], line, "synthetic")
        for path in (paths if paths is not None else [CORPUS])
        for line, data in _lines(path)
    ]
    if paths is None:
        recorded = _recorded()
        samples += [
            _sample(data, recorded[data["id"]], line, "realworld")
            for line, data in _lines(INDICATORS)
            if data["id"] in recorded
        ]
    ids = [s.id for s in samples]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate sample ids in the corpus")
    return samples


def _results(sample: Sample, drop: str | None = None) -> list[SourceResult]:
    return [
        SourceResult(source=src, status=Status(status), metrics=dict(metrics))
        for src, status, metrics in sample.rows
        if src != drop
    ]


def run(sample: Sample, rules: Rules, drop: str | None = None) -> Outcome:
    d = decide(_results(sample, drop), rules)
    return Outcome(d.level.value, d.confidence.value, d.agreeing, d.total)


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for k successes in n trials."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def _rate(k: int, n: int) -> dict[str, Any]:
    low, high = wilson(k, n)
    return {
        "k": k,
        "n": n,
        "rate": round(k / n, 4) if n else None,
        "wilson95": [round(low, 4), round(high, 4)],
    }


def _blocked_high_weight(sample: Sample, rules: Rules) -> bool:
    bad = (Status.ERROR.value, Status.RATE_LIMITED.value, Status.NOT_FOUND.value)
    return any(src in rules.high_weight and status in bad for src, status, _ in sample.rows)


def evaluate(samples: list[Sample], rules: Rules) -> dict[str, Any]:
    outcomes = {s.id: run(s, rules) for s in samples}
    labelled = [s for s in samples if s.label]
    answered = [s for s in labelled if outcomes[s.id].level != Level.UNKNOWN.value]

    def inside(s: Sample) -> bool:
        assert s.label
        return ORDER[s.label[0]] <= ORDER[outcomes[s.id].level] <= ORDER[s.label[1]]

    confusion: dict[str, dict[str, int]] = {}
    for s in labelled:
        assert s.label
        row = s.label[0] if s.label[0] == s.label[1] else f"{s.label[0]}..{s.label[1]}"
        col = confusion.setdefault(row, {})
        col[outcomes[s.id].level] = col.get(outcomes[s.id].level, 0) + 1

    dangerous = [
        s.id
        for s in labelled
        if s.label and s.label[0] == "malicious" and outcomes[s.id].level == "safe"
    ]
    holdout = [s for s in labelled if s.split == "holdout"]
    safe_labelled = [s for s in holdout if s.label and s.label[1] == "safe"]
    false_alarms = [s.id for s in safe_labelled if outcomes[s.id].level == "malicious"]
    soft = [
        s.id
        for s in answered
        if not inside(s) and s.id not in dangerous and s.id not in false_alarms
    ]
    error_is_safe = [
        s.id for s in samples if _blocked_high_weight(s, rules) and outcomes[s.id].level == "safe"
    ]
    calibration: dict[str, dict[str, int]] = {}
    for s in answered:
        bucket = calibration.setdefault(outcomes[s.id].confidence, {"k": 0, "n": 0})
        bucket["n"] += 1
        bucket["k"] += inside(s)

    sources = sorted({src for s in samples for src, _, _ in s.rows})
    leave_one_out = {
        src: sum(
            run(s, rules, drop=src).level != outcomes[s.id].level
            for s in samples
            if any(r[0] == src for r in s.rows)
        )
        for src in sources
    }
    sole = {
        src: sum(
            1
            for s in samples
            if (rows := [r for r in s.rows if r[0] not in rules.context_only and r[1] == "ok"])
            and len(rows) == 1
            and rows[0][0] == src
        )
        for src in sources
    }
    return {
        "samples": len(samples),
        "labelled": len(labelled),
        "outcomes": {sid: [o.level, o.confidence] for sid, o in outcomes.items()},
        "confusion": confusion,
        "dangerous_miss": {
            "ids": dangerous,
            **_rate(
                len(dangerous), len([s for s in labelled if s.label and s.label[0] == "malicious"])
            ),
        },
        "false_alarm": {"ids": false_alarms, **_rate(len(false_alarms), len(safe_labelled))},
        "soft_error": {"ids": soft, **_rate(len(soft), len(answered))},
        "coverage": _rate(
            len([s for s in samples if outcomes[s.id].level != "unknown"]), len(samples)
        ),
        "error_is_safe": {"ids": error_is_safe, "k": len(error_is_safe)},
        "calibration": {c: {**v, **_rate(v["k"], v["n"])} for c, v in sorted(calibration.items())},
        "leave_one_out": leave_one_out,
        "sole_decider": sole,
    }


def sensitivity(samples: list[Sample], rules: Rules) -> dict[str, list[str]]:
    """Samples whose level changes when one numeric threshold moves by one step."""
    base = {s.id: run(s, rules).level for s in samples}
    flips: dict[str, list[str]] = {}
    for section in ("malicious", "suspicious"):
        for src, cond in getattr(rules, section).items():
            for key, value in cond.items():
                if isinstance(value, bool):
                    continue
                for step in (-1, 1):
                    changed = rules.model_copy(deep=True)
                    getattr(changed, section)[src][key] = value + step
                    moved = [s.id for s in samples if run(s, changed).level != base[s.id]]
                    flips[f"{section}.{src}.{key} {value}{step:+d}"] = moved
    return flips


def holdout_checksum(samples: list[Sample]) -> str:
    text = "\n".join(sorted(s.raw for s in samples if s.split == "holdout"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def baseline_of(samples: list[Sample], rules: Rules) -> dict[str, Any]:
    report = evaluate(samples, rules)
    gated = {
        sid: lv for sid, lv in report["outcomes"].items() if _split(samples, sid) in GATED_SPLITS
    }
    return {
        "note": "Accepted outputs of decide() over tests/eval/corpus.jsonl. Rewrite with "
        "`python scripts/eval_report.py --update-baseline` and review the diff.",
        "holdout_checksum": holdout_checksum(samples),
        "outcomes": dict(sorted(gated.items())),
        "dangerous_miss": report["dangerous_miss"]["k"],
        "false_alarm": report["false_alarm"]["k"],
        "coverage": {k: report["coverage"][k] for k in ("k", "n")},
        "calibration": {c: {"k": v["k"], "n": v["n"]} for c, v in report["calibration"].items()},
    }


def _split(samples: list[Sample], sid: str) -> str:
    return next(s.split for s in samples if s.id == sid)


def _fmt(rate: dict[str, Any]) -> str:
    low, high = rate["wilson95"]
    pct = "-" if rate["rate"] is None else f"{rate['rate'] * 100:.1f}%"
    return f"{rate['k']}/{rate['n']} = {pct}  (95% interval {low * 100:.1f}% to {high * 100:.1f}%)"


def text_report(report: dict[str, Any], flips: dict[str, list[str]]) -> str:
    lines = [
        f"verdikt evaluation: {report['samples']} samples ({report['labelled']} labelled)",
        DISCLAIMER,
        "",
    ]
    lines.append("confusion (label -> output):")
    for label, cols in report["confusion"].items():
        lines.append(f"  {label:<22} " + ", ".join(f"{k} {v}" for k, v in sorted(cols.items())))
    lines += ["", f"dangerous_miss (malicious label -> safe): {_fmt(report['dangerous_miss'])}"]
    lines.append(f"false_alarm (safe label -> malicious, holdout): {_fmt(report['false_alarm'])}")
    lines.append(f"soft_error (adjacent level): {_fmt(report['soft_error'])}")
    lines.append(f"coverage (output is not unknown): {_fmt(report['coverage'])}")
    lines.append(
        f"error_is_safe (must be 0): {report['error_is_safe']['k']} "
        f"{report['error_is_safe']['ids']}"
    )
    lines += ["", "calibration (share of answers inside the label interval):"]
    for conf, v in report["calibration"].items():
        lines.append(f"  {conf:<7} {_fmt(v)}")
    lines += ["", "leave-one-out (level changes when the source is removed):"]
    for src, n in report["leave_one_out"].items():
        lines.append(f"  {src:<14} {n:>3} changed, sole decider in {report['sole_decider'][src]}")
    lines += ["", "rule sensitivity (a threshold moved by one step flips these samples):"]
    for rule, moved in flips.items():
        lines.append(f"  {rule:<42} {len(moved)} flip(s)")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--rules", type=Path, help="a rules.yaml to evaluate instead of the default"
    )
    parser.add_argument("--json", action="store_true", help="print JSON instead of text")
    parser.add_argument(
        "--update-baseline", action="store_true", help="rewrite tests/eval/baseline.json"
    )
    args = parser.parse_args()
    rules = load_rules(args.rules)
    samples = load_samples()
    if args.update_baseline:
        BASELINE.write_text(
            json.dumps(baseline_of(load_samples([CORPUS]), rules), indent=1) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {BASELINE}")
        return 0
    report = evaluate(samples, rules)
    flips = sensitivity(samples, rules)
    print(
        json.dumps({**report, "sensitivity": flips}, indent=1)
        if args.json
        else text_report(report, flips)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
