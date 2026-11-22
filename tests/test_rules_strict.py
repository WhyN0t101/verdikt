"""`Rules` refuses typos instead of silently ignoring them (a typo once meant a lower verdict)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from tests.test_sources import HITS
from verdikt.config import Rules, load_rules

SHIPPED = Path(__file__).resolve().parent.parent / "src" / "verdikt" / "rules.yaml"


def shipped() -> dict[str, Any]:
    return yaml.safe_load(SHIPPED.read_text(encoding="utf-8"))


def test_the_shipped_rules_still_load() -> None:
    rules = Rules.model_validate(shipped())
    assert rules == load_rules()
    assert rules.malicious["virustotal"] == {"malicious": 5}


def mutated(**changes: Any) -> dict[str, Any]:
    data = shipped()
    for key, value in changes.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    return data


def renamed(section: str, old: str, new: str) -> dict[str, Any]:
    data = shipped()
    data[section] = {(new if k == old else k): v for k, v in data[section].items()}
    return data


@pytest.mark.parametrize(
    ("data", "message"),
    [
        pytest.param(
            {**shipped(), "maliciuos": {"virustotal": {"malicious": 5}}},
            "maliciuos",
            id="top-level typo",
        ),
        pytest.param(
            {**shipped(), "min_source_for_safe": 5}, "min_source_for_safe", id="unknown setting"
        ),
        pytest.param(
            renamed("malicious", "virustotal", "virustotl"),
            "virustotl",
            id="source typo, malicious",
        ),
        pytest.param(
            renamed("suspicious", "abuseipdb", "abuseipbd"),
            "abuseipbd",
            id="source typo, suspicious",
        ),
        pytest.param(
            renamed("benign_override", "greynoise", "greynois"),
            "greynois",
            id="source typo, override",
        ),
        pytest.param(
            renamed("weights", "virustotal", "virustotl"), "virustotl", id="source typo, weights"
        ),
        pytest.param(
            {**shipped(), "high_weight": ["virustotl"]}, "virustotl", id="source typo, high_weight"
        ),
        pytest.param(
            {**shipped(), "context_only": ["otx", "intenetdb"]},
            "intenetdb",
            id="source typo, context",
        ),
        pytest.param(
            {**shipped(), "listing_feeds": ["threatfx"]}, "threatfx", id="source typo, feeds"
        ),
        pytest.param(
            {**shipped(), "confidence_high": 1, "confidence_medium": 9},
            "confidence_high",
            id="order",
        ),
    ],
)
def test_typos_are_errors_with_a_clear_message(data: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError) as err:
        Rules.model_validate(data)
    assert message in str(err.value)


def test_load_rules_reports_a_bad_private_file(tmp_path: Path) -> None:
    bad = tmp_path / "rules.yaml"
    bad.write_text("maliciuos:\n  virustotal: {malicious: 5}\n", encoding="utf-8")
    with pytest.raises(ValidationError, match="maliciuos"):
        load_rules(bad)


def test_equal_confidence_bands_are_allowed() -> None:
    assert Rules.model_validate({**shipped(), "confidence_high": 3, "confidence_medium": 3})


# Metric names cannot be checked at load time (a source owns them), so this guards the shipped
# file: every (source, metric) a rule reads must be one a source really produces. Sources are
# covered by tests/test_sources.py (HITS) and by the tests named here.
OTHER_TESTS = {
    "localfeeds": {"blocklisted", "tor_exit", "top_site"},  # tests/test_feeds.py
    "hashlookup": {"known_good", "known_malicious"},  # tests/test_feeds.py
    "rdap": {"age_days"},  # tests/test_verdict.py
    "greynoise": {"noise", "riot"},  # tests/test_sources.py (GreyNoise)
}


def produced() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {s: set(m) for s, m in OTHER_TESTS.items()}
    for case in HITS:
        found.setdefault(case.source.name, set()).update(case.metrics)
    return found


def test_every_metric_in_rules_yaml_is_one_a_source_produces() -> None:
    made = produced()
    problems: list[str] = []
    for section in ("malicious", "suspicious", "benign_override"):
        for source, rule in shipped()[section].items():
            for key in rule:
                metric = re.sub(r"__lt$", "", key)
                if metric not in made.get(source, set()):
                    problems.append(f"{section}: {source}.{key}")
    assert not problems, problems


# --- the opt-in cap on SAFE confidence (an experiment, off by default) ----------------------


def _safe_pair_with_one_strong_source(rules: Rules):
    from verdikt.models import SourceResult, Status
    from verdikt.verdict import decide

    rows = [
        SourceResult(source="virustotal", status=Status.OK, metrics={"malicious": 0}),
        SourceResult(source="abuseipdb", status=Status.OK, metrics={"score": 0}),
    ]
    return decide(rows, rules)


def test_safe_confidence_is_unchanged_by_default() -> None:
    d = _safe_pair_with_one_strong_source(load_rules())
    assert (d.level.value, d.confidence.value) == ("safe", "high")  # the behaviour the gate pins


def test_the_cap_limits_safe_confidence_when_one_strong_source_carries_it() -> None:
    capped = Rules.model_validate({**shipped(), "cap_safe_confidence_single_strong": True})
    d = _safe_pair_with_one_strong_source(capped)
    assert (d.level.value, d.confidence.value) == ("safe", "medium")


def test_the_cap_never_touches_other_verdicts_or_a_second_strong_source() -> None:
    from verdikt.models import SourceResult, Status
    from verdikt.verdict import decide

    capped = Rules.model_validate({**shipped(), "cap_safe_confidence_single_strong": True})
    hit = [SourceResult(source="virustotal", status=Status.OK, metrics={"malicious": 30})]
    assert decide(hit, capped).confidence == decide(hit, load_rules()).confidence
    # with a second strong source (here ThreatFox no longer a listing-only feed) the cap steps aside
    shipped_data = shipped()
    shipped_data["listing_feeds"] = [f for f in shipped_data["listing_feeds"] if f != "threatfox"]
    two = Rules.model_validate({**shipped_data, "cap_safe_confidence_single_strong": True})
    rows = [
        SourceResult(source="virustotal", status=Status.OK, metrics={"malicious": 0}),
        SourceResult(source="abuseipdb", status=Status.OK, metrics={"score": 0}),
        SourceResult(source="threatfox", status=Status.OK, metrics={"match": False}),
    ]
    assert decide(rows, two).confidence.value == "high"
