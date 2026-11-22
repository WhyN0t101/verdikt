"""The eval recorder with fake sources: what it saves, where, and when it stops. No network."""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest

from tests.conftest import CountingLimiter, Fake, make_engine
from verdikt.cache import Cache
from verdikt.config import Settings
from verdikt.engine import Engine
from verdikt.models import IOC, Report, SourceResult, Status
from verdikt.sources.base import Gate, Source

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "eval_record.py"
SECRET = "SECRET-SUMMARY-TEXT"


def load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("eval_record", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


rec = load()


class Charging(Fake):
    """A fake that spends one unit of daily budget per lookup, like a real source behind a Gate."""

    def __init__(self, name: str, cache: Cache, **kw: Any) -> None:
        super().__init__(name, **kw)
        self._cache = cache

    async def lookup(self, ioc: IOC, http: Gate) -> SourceResult:
        self._cache.charge(self.name, None)
        return await super().lookup(ioc, http)


@dataclass
class Env:
    http: httpx.AsyncClient
    cache: Cache
    settings: Settings
    tmp: Path

    def engine(self, sources: list[Source]) -> Engine:
        return make_engine(
            self.settings, self.cache, self.http, sources, limiter_factory=CountingLimiter
        )

    def paths(self) -> dict[str, Path]:
        return {
            "open_path": self.tmp / "open.jsonl",
            "local_path": self.tmp / "local" / "l.jsonl",
            "state_path": self.tmp / "local" / "s.json",
        }


@pytest.fixture
async def env(tmp_path: Path) -> AsyncIterator[Env]:
    async with httpx.AsyncClient() as http:
        settings = Settings(_env_file=None, feeds_dir=tmp_path / "feeds")  # pyright: ignore[reportCallIssue]
        yield Env(http, Cache(":memory:"), settings, tmp_path)


def items(*ids: str) -> list[Any]:
    return [rec.Item(i, f"{n + 1}.2.3.4", 0) for n, i in enumerate(ids)]


def read(path: Path) -> list[dict[str, Any]]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]


def quiet(_: str) -> None:
    return None


async def test_rows_split_by_licence_and_nothing_else_is_saved(env: Env) -> None:
    sources: list[Source] = [
        Charging("virustotal", env.cache, metrics={"malicious": 3}, summary=SECRET),
        Charging("threatfox", env.cache, metrics={"match": True}, summary=SECRET),
    ]
    out = await rec.record(env.engine(sources), items("a"), caps=rec.CAPS, log=quiet, **env.paths())
    assert out.recorded == ["a"] and not out.stopped
    p = env.paths()
    fox = {"source": "threatfox", "status": "ok", "metrics": {"match": True}}
    vt = {"source": "virustotal", "status": "ok", "metrics": {"malicious": 3}}
    assert read(p["open_path"]) == [{"id": "a", "rows": [fox]}]
    assert read(p["local_path"]) == [{"id": "a", "rows": [vt]}]
    for f in (p["open_path"], p["local_path"], p["state_path"]):
        text = f.read_text(encoding="utf-8")
        assert SECRET not in text and "raw" not in text and "tags" not in text


async def test_a_second_run_does_not_record_again(env: Env) -> None:
    vt = Charging("virustotal", env.cache, metrics={"malicious": 0})
    engine = env.engine([vt])
    await rec.record(engine, items("a", "b"), caps=rec.CAPS, log=quiet, **env.paths())
    calls = vt.calls
    again = await rec.record(engine, items("a", "b", "c"), caps=rec.CAPS, log=quiet, **env.paths())
    assert again.recorded == ["c"] and vt.calls == calls + 1
    assert len(read(env.paths()["local_path"])) == 3


async def test_the_virustotal_cap_stops_the_run_and_lists_what_is_left(env: Env) -> None:
    engine = env.engine([Charging("virustotal", env.cache, metrics={"malicious": 0})])
    caps = {"virustotal": 2}
    out = await rec.record(engine, items("a", "b", "c", "d"), caps=caps, log=quiet, **env.paths())
    assert out.recorded == ["a", "b"]
    assert out.not_recorded == ["c", "d"] and "cap" in out.stopped


async def test_a_smaller_source_cap_only_drops_that_source(env: Env) -> None:
    sources: list[Source] = [
        Charging("virustotal", env.cache, metrics={"malicious": 0}),
        Charging("abuseipdb", env.cache, metrics={"score": 0}),
    ]
    caps = {"virustotal": 99, "abuseipdb": 1}
    out = await rec.record(
        env.engine(sources), items("a", "b"), caps=caps, log=quiet, **env.paths()
    )
    assert out.recorded == ["a", "b"]
    rows = [{r["source"] for r in line["rows"]} for line in read(env.paths()["local_path"])]
    assert rows == [{"virustotal", "abuseipdb"}, {"virustotal"}]


@pytest.mark.parametrize("summary", ["HTTP 401", "HTTP 403"])
async def test_an_auth_error_stops_at_once_and_records_nothing(env: Env, summary: str) -> None:
    bad = Fake("virustotal", status=Status.ERROR, summary=summary)
    out = await rec.record(
        env.engine([bad]), items("a", "b"), caps=rec.CAPS, log=quiet, **env.paths()
    )
    assert out.recorded == [] and out.not_recorded == ["a", "b"]
    assert "key" in out.stopped and not env.paths()["open_path"].exists()


async def test_a_rate_limit_on_a_strict_source_stops_the_run(env: Env) -> None:
    limited = Fake("virustotal", status=Status.RATE_LIMITED, summary="daily budget exhausted")
    out = await rec.record(
        env.engine([limited]), items("a"), caps=rec.CAPS, log=quiet, **env.paths()
    )
    assert out.recorded == [] and "quota" in out.stopped


async def test_internal_indicators_are_skipped_and_a_failure_does_not_stop_the_rest(
    env: Env,
) -> None:
    engine = env.engine([Charging("virustotal", env.cache, metrics={"malicious": 0})])
    original = engine.check

    async def check(raw: str, *, no_cache: bool = False) -> Report:
        if raw == "3.2.3.4":
            raise RuntimeError("boom")
        return await original(raw, no_cache=no_cache)

    engine.check = check  # type: ignore[method-assign]
    batch = [
        rec.Item("internal", "10.0.0.1", 0),
        rec.Item("a", "1.2.3.4", 0),
        rec.Item("bad", "3.2.3.4", 0),
        rec.Item("c", "8.8.8.8", 0),
    ]
    out = await rec.record(engine, batch, caps=rec.CAPS, log=quiet, **env.paths())
    assert (out.skipped_internal, out.failed, out.recorded) == (["internal"], ["bad"], ["a", "c"])


def test_items_are_ordered_holdout_first_then_malicious_dev_then_benign_dev(tmp_path: Path) -> None:
    def line(i: str, split: str, level: str) -> str:
        label = {"min": level, "max": level}
        return json.dumps({"id": i, "ioc": "8[.]8[.]8[.]8", "split": split, "label": label})

    f = tmp_path / "i.jsonl"
    lines = [line("benign-dev", "dev", "safe"), line("mal-dev", "dev", "malicious")]
    f.write_text("\n".join([*lines, line("hold", "holdout", "safe")]), encoding="utf-8")
    got = rec.load_items(f)
    assert [i.id for i in got] == ["hold", "mal-dev", "benign-dev"]
    assert got[0].ioc == "8.8.8.8"  # refanged


def test_the_real_indicator_file_loads_and_urlscan_is_never_queried() -> None:
    assert len(rec.load_items()) == 266
    assert {"urlscan", "crtsh"} <= rec.SKIP_SOURCES
    assert rec.CAPS == {"virustotal": 250, "abuseipdb": 80, "greynoise": 50, "hybrid": 30}
