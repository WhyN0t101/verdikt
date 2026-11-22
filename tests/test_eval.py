"""Regression gate over the labelled corpus in tests/eval/ (offline, deterministic, about 1 s).

The evaluation is exact: the same recorded rows and the same rules give the same outputs, so
there is no percentage slack. A deliberate change of verdict behaviour is accepted by running
`python scripts/eval_report.py --update-baseline` in the same commit (a reviewable diff).
Synthetic labels guard regressions; they do not measure accuracy.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from verdikt.config import load_rules

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "eval_report.py"


def load_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("eval_report", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up here
    spec.loader.exec_module(module)
    return module


ev = load_script()
SAMPLES = ev.load_samples([ev.CORPUS])  # the committed set: CI and a laptop agree
BASELINE: dict[str, Any] = json.loads(ev.BASELINE.read_text(encoding="utf-8"))
REPORT: dict[str, Any] = ev.evaluate(SAMPLES, load_rules())
HINT = "if this change is intended, run `python scripts/eval_report.py --update-baseline`"


def gated() -> dict[str, list[str]]:
    return {s.id: REPORT["outcomes"][s.id] for s in SAMPLES if s.split in ev.GATED_SPLITS}


def test_the_corpus_is_well_formed() -> None:
    assert len(SAMPLES) >= 80
    assert {s.split for s in SAMPLES} <= {"synthetic", "dev", "holdout"}
    for s in SAMPLES:
        if s.label:
            assert ev.ORDER[s.label[0]] <= ev.ORDER[s.label[1]], s.id


def test_every_sample_gets_the_same_level_and_confidence_as_the_baseline() -> None:
    now, before = gated(), BASELINE["outcomes"]
    assert set(now) == set(before), f"samples added or removed; {HINT}"
    changed = {sid: (before[sid], now[sid]) for sid in now if now[sid] != before[sid]}
    assert not changed, (
        f"(level, confidence) changed for {len(changed)} sample(s): {changed}; {HINT}"
    )


def test_the_holdout_set_was_not_edited_without_updating_the_baseline() -> None:
    assert ev.holdout_checksum(SAMPLES) == BASELINE["holdout_checksum"], HINT


def test_an_error_or_missing_record_is_never_safe() -> None:
    assert REPORT["error_is_safe"]["ids"] == []


def test_no_labelled_malicious_sample_comes_out_safe() -> None:
    assert REPORT["dangerous_miss"]["k"] <= BASELINE["dangerous_miss"], REPORT["dangerous_miss"][
        "ids"
    ]


def test_false_alarms_on_the_labelled_holdout_do_not_grow() -> None:
    assert REPORT["false_alarm"]["k"] <= BASELINE["false_alarm"], REPORT["false_alarm"]["ids"]


def test_coverage_does_not_fall() -> None:
    now, before = REPORT["coverage"], BASELINE["coverage"]
    assert now["k"] * before["n"] >= before["k"] * now["n"], (now, before)


@pytest.mark.parametrize("confidence", ["high", "medium", "low"])
def test_each_confidence_bucket_stays_as_right_as_before(confidence: str) -> None:
    now = REPORT["calibration"].get(confidence, {"k": 0, "n": 0})
    before = BASELINE["calibration"].get(confidence)
    if before is None or before["n"] == 0 or now["n"] == 0:
        return
    assert now["k"] * before["n"] >= before["k"] * now["n"], (confidence, now, before)


def test_the_wilson_interval_is_sane() -> None:
    low, high = ev.wilson(0, 100)
    assert (low, round(high, 3)) == (0.0, 0.037)  # "0 of 100" only supports "under about 4%"
    assert ev.wilson(0, 0) == (0.0, 1.0)
    low, high = ev.wilson(50, 100)
    assert low < 0.5 < high


def test_the_report_states_what_the_numbers_are_not() -> None:
    text = ev.text_report(REPORT, {})
    assert "do not measure accuracy" in text
    assert "95% interval" in text
