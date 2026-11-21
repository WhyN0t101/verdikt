from __future__ import annotations

import pytest

from verdikt.config import load_rules
from verdikt.models import Level, SourceResult, Status
from verdikt.verdict import decide

RULES = load_rules()
OK, ERR, RL, NF = Status.OK, Status.ERROR, Status.RATE_LIMITED, Status.NOT_FOUND


def row(source: str, status: Status = OK, **metrics: int | bool) -> SourceResult:
    return SourceResult(source=source, status=status, metrics=metrics)


def vt() -> SourceResult:
    return row("virustotal", malicious=0, suspicious=0)


CASES: list[tuple[str, list[SourceResult], Level]] = [
    ("vt malicious threshold", [row("virustotal", malicious=5)], Level.MALICIOUS),
    ("vt 1 malicious", [row("virustotal", malicious=1, suspicious=0)], Level.SUSPICIOUS),
    ("vt 1 suspicious", [row("virustotal", malicious=0, suspicious=1)], Level.SUSPICIOUS),
    ("abuseipdb 75", [row("abuseipdb", score=75)], Level.MALICIOUS),
    ("abuseipdb 25", [row("abuseipdb", score=25)], Level.SUSPICIOUS),
    ("threatfox match", [row("threatfox", match=True)], Level.MALICIOUS),
    (
        "urlhaus exact URL online",
        [row("urlhaus", match=True, online=True, url_online=True)],
        Level.MALICIOUS,
    ),
    (
        "urlhaus host online is only suspicious",
        [row("urlhaus", match=True, online=True, url_online=False)],
        Level.SUSPICIOUS,
    ),
    (
        "top site softens a host-level urlhaus listing (github.com)",
        [
            row("urlhaus", match=True, online=True, url_online=False),
            row("localfeeds", blocklisted=False, tor_exit=False, top_site=True),
            row("virustotal", malicious=0, suspicious=0),
        ],
        Level.SAFE,
    ),
    ("offline listing is not enough", [row("urlhaus", match=True, online=False), vt()], Level.SAFE),
    (
        "otx pulses never decide",
        [row("otx", pulses=50), vt(), row("threatfox", match=False)],
        Level.SAFE,
    ),
    ("two clean sources", [vt(), row("abuseipdb", score=0)], Level.SAFE),
    (
        "weak sources alone are not safe",
        [row("urlscan", malicious=False), row("otx", pulses=0)],
        Level.UNKNOWN,
    ),
    # errors are not clean
    (
        "error blocks safe",
        [row("virustotal", ERR), row("abuseipdb", score=0), row("otx", pulses=0)],
        Level.UNKNOWN,
    ),
    (
        "rate limited blocks safe",
        [row("virustotal", RL), row("abuseipdb", score=0), row("internetdb", ports=2)],
        Level.UNKNOWN,
    ),
    (
        "low-weight error does not block",
        [row("abuseipdb", ERR), vt(), row("threatfox", match=False)],
        Level.SAFE,
    ),
    # INFO rows do not count toward min_sources_for_safe
    (
        "info rows do not count",
        [row("abuseipdb", score=0), row("internetdb", ports=1), row("greynoise", riot=False)],
        Level.UNKNOWN,
    ),
    ("not found does not count", [row("virustotal", NF), row("abuseipdb", score=0)], Level.UNKNOWN),
    ("single clean source", [row("abuseipdb", score=0)], Level.UNKNOWN),
    ("no results", [], Level.UNKNOWN),
    # benign override
    (
        "riot downgrades suspicious",
        [row("virustotal", malicious=1), row("greynoise", riot=True)],
        Level.SAFE,
    ),
    (
        "riot cannot clear suspicious while a high-weight source is rate limited",
        [row("abuseipdb", score=30), row("virustotal", RL), row("greynoise", riot=True)],
        Level.SUSPICIOUS,
    ),
    (
        "high-weight not found blocks safe",
        [row("virustotal", NF), row("threatfox", match=False), row("malwarebazaar", match=False)],
        Level.UNKNOWN,
    ),
    (
        "riot cannot clear malicious",
        [row("virustotal", malicious=9), row("greynoise", riot=True)],
        Level.MALICIOUS,
    ),
    (
        "riot cannot clear malicious (threatfox)",
        [row("threatfox", match=True), row("greynoise", riot=True)],
        Level.MALICIOUS,
    ),
    (
        "malicious wins over errors",
        [row("virustotal", RL), row("threatfox", match=True)],
        Level.MALICIOUS,
    ),
]


@pytest.mark.parametrize(("name", "rows", "expected"), CASES, ids=[c[0] for c in CASES])
def test_final_level(name: str, rows: list[SourceResult], expected: Level) -> None:
    assert decide(rows, RULES).level is expected


def test_row_levels_follow_the_same_thresholds() -> None:
    rows = [
        row("virustotal", malicious=5),
        row("abuseipdb", score=30),
        row("otx", pulses=0),
        row("internetdb", ports=3),
        row("virustotal", ERR),
    ]
    levels = [r.level for r in decide(rows, RULES).results]
    assert levels == [Level.MALICIOUS, Level.SUSPICIOUS, Level.INFO, Level.INFO, Level.UNKNOWN]


def test_source_cannot_set_its_own_level() -> None:
    rows = [
        SourceResult(source="virustotal", status=OK, metrics={"malicious": 50}, level=Level.SAFE)
    ]
    assert decide(rows, RULES).results[0].level is Level.MALICIOUS


def test_agreeing_and_total_count_verdict_bearing_ok_rows() -> None:
    rows = [
        row("virustotal", malicious=9),
        row("abuseipdb", score=0),
        row("internetdb", ports=1),
        row("threatfox", ERR),
    ]
    d = decide(rows, RULES)
    assert (d.level, d.agreeing, d.total) == (Level.MALICIOUS, 1, 2)


def test_reasons_list_each_fired_rule() -> None:
    d = decide([row("virustotal", malicious=9), row("threatfox", match=True)], RULES)
    assert len(d.reasons) == 2
    assert any("virustotal" in r and "malicious 9 >= 5" in r for r in d.reasons)


def test_unknown_reason_names_the_rate_limited_source() -> None:
    d = decide([row("virustotal", RL), row("abuseipdb", score=0)], RULES)
    assert any("virustotal" in r for r in d.reasons)


def test_decide_is_pure() -> None:
    rows = [row("virustotal", malicious=2), row("abuseipdb", score=0)]
    assert decide(rows, RULES) == decide(rows, RULES)
    assert rows[0].level is Level.UNKNOWN  # input not mutated


def test_bool_metric_never_satisfies_int_threshold() -> None:
    # `True >= 1` is true in Python; a bool must not trip a numeric rule
    rows = [row("virustotal", malicious=True), row("abuseipdb", score=0)]
    assert decide(rows, RULES).results[0].level is Level.SAFE
