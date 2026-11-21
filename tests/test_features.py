"""Confidence, SAFE rule, cache lifecycle, correlation, feedback, audit log and STIX export."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI

from tests.conftest import CountingLimiter, Fake
from verdikt.api.app import create_app
from verdikt.audit import AuditLog
from verdikt.cache import Cache
from verdikt.config import Rules, Settings, load_rules
from verdikt.engine import Engine
from verdikt.models import (
    Confidence,
    Graph,
    GraphNode,
    IOCType,
    Level,
    Report,
    SourceResult,
    Status,
)
from verdikt.sources.base import Source
from verdikt.stix import pattern, to_stix
from verdikt.verdict import decide

RULES = load_rules()
T0 = datetime(2026, 1, 1, tzinfo=UTC)


def row(source: str, status: Status = Status.OK, **m: int | bool) -> SourceResult:
    return SourceResult(source=source, status=status, metrics=m)


def vt(**m: int | bool) -> SourceResult:
    return row("virustotal", malicious=m.get("malicious", 0), suspicious=0)


def report(
    rid: str = "r1",
    ioc: str = "1.2.3.4",
    ioc_type: IOCType = IOCType.IP,
    level: Level = Level.MALICIOUS,
    nodes: list[GraphNode] | None = None,
    created: datetime = T0,
) -> Report:
    return Report(
        id=rid,
        ioc=ioc,
        ioc_type=ioc_type,
        level=level,
        agreeing=1,
        total=1,
        reasons=["virustotal: malicious 9 >= 5 -> malicious"],
        graph=Graph(nodes=nodes or []),
        created_at=created,
    )


# --- SAFE needs a successful high-weight source ------------------------------------------


def test_weak_sources_alone_cannot_make_safe() -> None:
    d = decide([row("abuseipdb", score=0), row("threatfox", match=False)], RULES)
    assert d.level is Level.UNKNOWN
    assert any("no high-weight source answered" in r for r in d.reasons)


def test_one_high_weight_plus_one_other_is_safe() -> None:
    assert decide([vt(), row("abuseipdb", score=0)], RULES).level is Level.SAFE


def test_min_high_weight_is_configurable() -> None:
    loose = Rules.model_validate({**RULES.model_dump(), "min_high_weight_for_safe": 0})
    assert (
        decide([row("abuseipdb", score=0), row("threatfox", match=False)], loose).level
        is Level.SAFE
    )


# --- confidence ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "rows", "expected"),
    [
        ("two strong agree", [vt(malicious=9), row("threatfox", match=True)], Confidence.HIGH),
        ("one strong", [vt(malicious=9)], Confidence.MEDIUM),
        ("one weak", [row("otx", pulses=9)], Confidence.LOW),
        ("safe with strong+medium", [vt(), row("abuseipdb", score=0)], Confidence.HIGH),
        (
            "safe: a feed's no-match adds no weight",
            [vt(), row("threatfox", match=False)],
            Confidence.MEDIUM,
        ),
        (
            "real 185.220.101.4: bad but unlisted in feeds",
            [
                vt(malicious=13),
                row("abuseipdb", score=100),
                row("threatfox", match=False),
                row("urlhaus", match=False, online=False),
            ],
            Confidence.HIGH,
        ),
        ("unknown is always low", [row("abuseipdb", score=0)], Confidence.LOW),
        (
            "override: conflicting evidence",
            [
                row("virustotal", malicious=2),
                row("abuseipdb", score=0),
                row("greynoise", riot=True),
            ],
            Confidence.LOW,
        ),
        (
            "malicious despite a clean weak voter",
            [vt(malicious=9), row("threatfox", match=True), row("otx", pulses=0)],
            Confidence.HIGH,
        ),
    ],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_confidence(name: str, rows: list[SourceResult], expected: Confidence) -> None:
    assert decide(rows, RULES).confidence is expected


def test_confidence_never_changes_the_level() -> None:
    bumped = Rules.model_validate({**RULES.model_dump(), "weights": {"virustotal": 99}})
    rows = [vt(malicious=9)]
    assert decide(rows, bumped).level is decide(rows, RULES).level


# --- cache lifecycle ----------------------------------------------------------------------


def test_prune_drops_old_reports_cache_and_budget() -> None:
    now = [T0]
    c = Cache(":memory:", clock=lambda: now[0], report_retention=timedelta(days=90))
    c.put("vt", "x", SourceResult(source="vt", status=Status.OK, fetched_at=T0))
    c.save_report(report("old", created=T0))
    c.charge("vt", None)
    now[0] = T0 + timedelta(days=91)
    c.save_report(report("new", created=now[0]))
    counts = c.prune()
    assert counts["reports"] == 1
    assert counts["source_cache"] == 1
    assert counts["budget"] == 1
    assert c.get_report("old") is None
    assert c.get_report("new") is not None


def test_retention_none_keeps_reports_forever() -> None:
    now = [T0]
    c = Cache(":memory:", clock=lambda: now[0], report_retention=None)
    c.save_report(report("old", created=T0))
    now[0] = T0 + timedelta(days=4000)
    c.prune()
    assert c.get_report("old") is not None


def test_prune_removes_index_rows_of_deleted_reports() -> None:
    now = [T0]
    c = Cache(":memory:", clock=lambda: now[0], report_retention=timedelta(days=1))
    c.save_report(report("old", created=T0))
    now[0] = T0 + timedelta(days=5)
    c.prune()
    assert c.correlate(report("new", created=now[0])) == []


# --- correlation --------------------------------------------------------------------------


def node(kind: str, label: str) -> GraphNode:
    return GraphNode(id=f"{kind}:{label}", label=label, kind=kind)


def test_correlate_finds_shared_indicators_and_skips_asn() -> None:
    c = Cache(":memory:")
    a = report(
        "a", "evil.example", IOCType.DOMAIN, nodes=[node("ip", "9.9.9.9"), node("asn", "AS64500")]
    )
    c.save_report(a)
    b = report("b", "5.5.5.5", nodes=[node("ip", "9.9.9.9"), node("asn", "AS64500")])
    seen = c.correlate(b)
    assert [(s.report_id, s.shared) for s in seen] == [("a", ["9.9.9.9"])]  # ASN not counted


def test_correlate_matches_the_ioc_itself_and_excludes_own_report() -> None:
    c = Cache(":memory:")
    c.save_report(report("a", "1.2.3.4"))
    again = report("b", "1.2.3.4")
    assert [s.report_id for s in c.correlate(again)] == ["a"]
    assert c.correlate(report("a", "1.2.3.4")) == []


def test_correlate_is_capped_and_newest_first() -> None:
    c = Cache(":memory:")
    for i in range(15):
        c.save_report(report(f"r{i:02d}", "1.2.3.4", created=T0 + timedelta(minutes=i)))
    seen = c.correlate(report("new", "1.2.3.4", created=T0 + timedelta(days=1)))
    assert len(seen) == 10
    assert seen[0].report_id == "r14"


async def test_engine_attaches_seen_before(settings: Settings, client: httpx.AsyncClient) -> None:
    cache = Cache(":memory:")
    sources: list[Source] = [Fake("virustotal", {"malicious": 9})]
    engine = Engine(
        settings, load_rules(), cache, client, sources=sources, limiter_factory=CountingLimiter
    )
    first = await engine.check("8.8.8.8")
    second = await engine.check("8.8.8.8", no_cache=True)
    assert first.seen_before == []
    assert [s.report_id for s in second.seen_before] == [first.id]
    stored = cache.get_report(second.id)
    assert stored is not None
    assert stored.seen_before[0].shared == ["8.8.8.8"]


# --- feedback -----------------------------------------------------------------------------


def test_feedback_roundtrip_and_survives_prune() -> None:
    now = [T0]
    c = Cache(":memory:", clock=lambda: now[0], report_retention=timedelta(days=1))
    r = report("a")
    c.save_report(r)
    entry = c.add_feedback(r, "false_positive", "internal scanner")
    now[0] = T0 + timedelta(days=30)
    c.prune()
    assert c.get_report("a") is None
    [kept] = c.list_feedback()
    assert (kept.id, kept.ioc, kept.level, kept.label, kept.note) == (
        entry.id,
        "1.2.3.4",
        "malicious",
        "false_positive",
        "internal scanner",
    )


def test_feedback_rejects_unknown_label() -> None:
    c = Cache(":memory:")
    with pytest.raises(ValueError, match="label"):
        c.add_feedback(report(), "maybe")


# --- audit log ----------------------------------------------------------------------------


def full_report() -> Report:
    r = report()
    r.results.append(
        SourceResult(
            source="virustotal",
            status=Status.OK,
            level=Level.MALICIOUS,
            summary="<script>x</script> attacker text",
            raw={"api_key": "SUPERSECRET"},
        )
    )
    return r


def test_audit_event_is_defanged_and_free_of_feed_text(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "audit.jsonl"
    log = AuditLog(path)
    log.check(full_report())
    text = path.read_text(encoding="utf-8")
    event = json.loads(text.splitlines()[0])
    assert event["event"] == "check"
    assert event["ioc"] == "1[.]2[.]3[.]4"
    assert event["sources"] == [
        {"source": "virustotal", "status": "ok", "level": "malicious", "cached": False}
    ]
    assert "attacker" not in text
    assert "SUPERSECRET" not in text
    assert "T" in event["ts"]


def test_audit_appends_one_line_per_event(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    c = Cache(":memory:")
    r = full_report()
    c.save_report(r)
    log.check(r)
    log.feedback(c.add_feedback(r, "correct"))
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [e["event"] for e in events] == ["check", "feedback"]


def test_unwritable_audit_log_does_not_raise(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    AuditLog(tmp_path).check(full_report())  # a directory, not a file
    assert "audit log write failed" in caplog.text


async def test_engine_writes_audit_event(
    tmp_path: Path, settings: Settings, client: httpx.AsyncClient
) -> None:
    path = tmp_path / "audit.jsonl"
    sources: list[Source] = [Fake("virustotal", {"malicious": 9})]
    engine = Engine(
        settings,
        load_rules(),
        Cache(":memory:"),
        client,
        sources=sources,
        limiter_factory=CountingLimiter,
        audit=AuditLog(path),
    )
    await engine.check("8.8.8.8")
    [event] = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]
    assert (event["ioc"], event["level"], event["confidence"]) == (
        "8[.]8[.]8[.]8",
        "malicious",
        "medium",
    )


# --- STIX ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ioc", "kind", "want"),
    [
        ("1.2.3.4", IOCType.IP, "[ipv4-addr:value = '1.2.3.4']"),
        ("2606:4700::1111", IOCType.IP, "[ipv6-addr:value = '2606:4700::1111']"),
        ("evil.example", IOCType.DOMAIN, "[domain-name:value = 'evil.example']"),
        ("http://a.example/it's", IOCType.URL, "[url:value = 'http://a.example/it\\'s']"),
        ("a" * 64, IOCType.SHA256, f"[file:hashes.'SHA-256' = '{'a' * 64}']"),
        ("a" * 40, IOCType.SHA1, f"[file:hashes.'SHA-1' = '{'a' * 40}']"),
        ("a" * 32, IOCType.MD5, f"[file:hashes.'MD5' = '{'a' * 32}']"),
    ],
)
def test_stix_patterns(ioc: str, kind: IOCType, want: str) -> None:
    assert pattern(report(ioc=ioc, ioc_type=kind)) == want


def test_stix_bundle_shape_and_malware_relationship() -> None:
    r = report(nodes=[node("malware", "Cobalt Strike")]).model_copy(
        update={"confidence": Confidence.HIGH}
    )
    bundle = to_stix(r)
    assert bundle["type"] == "bundle"
    types = [o["type"] for o in bundle["objects"]]
    assert types == ["identity", "indicator", "malware", "relationship"]
    indicator = bundle["objects"][1]
    assert indicator["indicator_types"] == ["malicious-activity"]
    assert indicator["confidence"] == 85
    assert indicator["valid_from"] == "2026-01-01T00:00:00.000Z"
    rel = bundle["objects"][3]
    assert (rel["source_ref"], rel["relationship_type"]) == (indicator["id"], "indicates")
    assert rel["target_ref"] == bundle["objects"][2]["id"]


def test_stix_ids_are_stable_per_report() -> None:
    assert to_stix(report()) == to_stix(report())
    assert to_stix(report("a"))["id"] != to_stix(report("b"))["id"]


@pytest.mark.parametrize(
    ("level", "want"),
    [
        (Level.SAFE, "benign"),
        (Level.SUSPICIOUS, "anomalous-activity"),
        (Level.UNKNOWN, "unknown"),
    ],
)
def test_stix_indicator_type_follows_level(level: Level, want: str) -> None:
    assert to_stix(report(level=level))["objects"][1]["indicator_types"] == [want]


# --- API ----------------------------------------------------------------------------------

TOKEN = "t0ken"
PORT = 8765
AUTH = {"x-verdikt-token": TOKEN}


def make_app(tmp_path: Path) -> tuple[FastAPI, Engine]:
    sources: list[Source] = [Fake("virustotal", {"malicious": 20, "suspicious": 0})]
    engine = Engine(
        Settings(_env_file=None),  # pyright: ignore[reportCallIssue]
        load_rules(),
        Cache(":memory:"),
        httpx.AsyncClient(),
        sources=sources,
        limiter_factory=CountingLimiter,
        audit=AuditLog(tmp_path / "audit.jsonl"),
    )
    return create_app(engine, port=PORT, token=TOKEN, web_dist=tmp_path / "none"), engine


async def test_api_feedback_stix_and_audit(tmp_path: Path) -> None:
    app, _ = make_app(tmp_path)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=f"http://127.0.0.1:{PORT}") as c:
        rid = (await c.post("/api/check", headers=AUTH, json={"ioc": "8.8.8.8"})).json()["id"]
        body = (
            await c.post("/api/check", headers=AUTH, json={"ioc": "8.8.8.8", "no_cache": True})
        ).json()
        assert body["confidence"] == "medium"
        assert body["seen_before"][0]["report_id"] == rid

        ok = await c.post(
            f"/api/reports/{rid}/feedback",
            headers=AUTH,
            json={"label": "false_positive", "note": "lab host"},
        )
        assert ok.status_code == 200
        assert ok.json()["label"] == "false_positive"
        bad = await c.post(f"/api/reports/{rid}/feedback", headers=AUTH, json={"label": "maybe"})
        assert bad.status_code == 422
        long = await c.post(
            f"/api/reports/{rid}/feedback",
            headers=AUTH,
            json={"label": "correct", "note": "x" * 501},
        )
        assert long.status_code == 422
        missing = await c.post(
            "/api/reports/nope/feedback", headers=AUTH, json={"label": "correct"}
        )
        assert missing.status_code == 404
        no_token = await c.post(f"/api/reports/{rid}/feedback", json={"label": "correct"})
        assert no_token.status_code == 401
        listing = (await c.get("/api/feedback", headers=AUTH)).json()
        assert [e["label"] for e in listing] == ["false_positive"]

        stix = await c.get(f"/api/reports/{rid}/stix", headers=AUTH)
        assert stix.status_code == 200
        assert stix.headers["content-type"].startswith("application/stix+json")
        assert stix.json()["objects"][1]["pattern"] == "[ipv4-addr:value = '8.8.8.8']"
        assert (await c.get("/api/reports/nope/stix", headers=AUTH)).status_code == 404

    events = [
        json.loads(x) for x in (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert [e["event"] for e in events] == ["check", "check", "feedback"]


# --- per-source "why" ---------------------------------------------------------------------


def test_rows_explain_themselves() -> None:
    rows = [
        row("virustotal", malicious=9, suspicious=0),
        row("abuseipdb", score=0),
        row("threatfox", match=False),
        row("internetdb", ports=2),
        row("virustotal", Status.ERROR),
    ]
    got = decide(rows, RULES).results
    vt, ab, tf, idb, failed = got
    assert vt.fired == ["malicious 9 >= 5 -> malicious"]
    assert (vt.role, vt.weight) == ("strong", 3)
    assert (ab.role, ab.weight, ab.fired) == ("weak", 2, [])
    assert (tf.role, tf.weight) == ("feed", 0)  # "not listed" carries no weight
    assert (idb.role, idb.weight) == ("context", 0)
    assert (failed.role, failed.weight) == ("no answer", 0)


def test_benign_override_is_recorded_on_the_row() -> None:
    rows = [row("virustotal", malicious=2, suspicious=0), row("greynoise", riot=True)]
    vt_row, noise = decide(rows, RULES).results
    assert vt_row.fired == ["malicious 2 >= 2 -> suspicious"]
    assert noise.fired == ["riot is true -> benign override (softens suspicious)"]


def test_decide_does_not_mutate_its_input_rows() -> None:
    rows = [row("virustotal", malicious=9, suspicious=0)]
    decide(rows, RULES)
    assert (rows[0].fired, rows[0].weight, rows[0].role) == ([], 0, "")
