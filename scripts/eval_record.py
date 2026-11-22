"""Record real source rows for the real-world indicators in tests/eval/indicators.jsonl.

    python scripts/eval_record.py            # record (resumable); needs the keys in .env

A ONE-TIME, user-approved live run: it spends quota (VirusTotal 4/min, so about an hour). It runs
the real engine with `no_cache` against a throwaway database in a temp folder, so your own
history, cache and audit log are not touched. Only `{source, status, metrics}` are saved: never
`raw`, summaries or tags. Rows from open-licence sources (abuse.ch, local feeds) go to the
committed `tests/eval/recorded.jsonl`; rows from the others go to the git-ignored
`tests/eval/local/recorded.jsonl`. urlscan and crt.sh are never queried (and urlscan is search
only). It stops at once on an auth error (401/403) or a quota block, and never prints a key.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from verdikt.config import Settings
from verdikt.detect import DetectError, refang
from verdikt.engine import Engine, build_engine
from verdikt.models import Report, Status

EVAL_DIR = Path(__file__).resolve().parent.parent / "tests" / "eval"
INDICATORS = EVAL_DIR / "indicators.jsonl"
RECORDED = EVAL_DIR / "recorded.jsonl"  # committed: open-licence sources
LOCAL_RECORDED = EVAL_DIR / "local" / "recorded.jsonl"  # git-ignored
STATE = EVAL_DIR / "local" / "record_state.json"

OPEN_LICENCE = frozenset({"threatfox", "urlhaus", "malwarebazaar", "localfeeds"})
SKIP_SOURCES = frozenset({"urlscan", "crtsh", "passivedns"})  # no verdict value, or flaky
CAPS = {"virustotal": 250, "abuseipdb": 80, "greynoise": 50, "hybrid": 30}
STRICT = frozenset(CAPS)  # strict-quota sources: any rate limit there stops the run
AUTH_ERRORS = ("HTTP 401", "HTTP 403")


@dataclass
class Item:
    id: str
    ioc: str
    group_rank: int  # 0 holdout, 1 malicious/ambiguous dev, 2 benign dev


@dataclass
class Result:
    recorded: list[str] = field(default_factory=list[str])
    skipped_internal: list[str] = field(default_factory=list[str])
    failed: list[str] = field(default_factory=list[str])
    not_recorded: list[str] = field(default_factory=list[str])
    stopped: str = ""  # why the run stopped early, if it did


def load_items(path: Path = INDICATORS) -> list[Item]:
    """Holdout first, then malicious/ambiguous dev, then benign dev (the cap costs the least)."""
    items: list[Item] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        d = json.loads(line)
        rank = 0 if d["split"] == "holdout" else (2 if d["label"]["max"] == "safe" else 1)
        items.append(Item(d["id"], refang(d["ioc"]), rank))
    return sorted(items, key=lambda i: i.group_rank)  # stable: file order inside a group


def rows_of(report: Report) -> list[dict[str, Any]]:
    """The only thing that is ever saved: source, status and plain metrics."""
    return [
        {"source": r.source, "status": r.status.value, "metrics": dict(sorted(r.metrics.items()))}
        for r in report.results
    ]


def blocker(report: Report) -> str:
    """Why this report must not be recorded and the run must stop, or ''."""
    for r in report.results:
        if r.summary in AUTH_ERRORS:
            return f"{r.source} answered {r.summary}: check the key in .env"
        if r.status is Status.RATE_LIMITED and r.source in STRICT:
            return f"{r.source} is rate limited or out of quota ({r.summary})"
    return ""


def _append(path: Path, line: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(line, sort_keys=True) + "\n")


def load_state(path: Path) -> dict[str, Any]:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"done": [], "internal": [], "calls": {}}


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=1, sort_keys=True) + "\n", encoding="utf-8")


async def record(
    engine: Engine,
    items: list[Item],
    *,
    open_path: Path,
    local_path: Path,
    state_path: Path,
    caps: dict[str, int],
    log: Callable[[str], None] = print,
) -> Result:
    state = load_state(state_path)
    prior: dict[str, int] = dict(state["calls"])
    result = Result()
    todo = [i for i in items if i.id not in state["done"] and i.id not in state["internal"]]
    full = {s.name for s in engine.sources}  # every source we may drop when its cap is reached

    def used(name: str) -> int:
        return prior.get(name, 0) + engine.cache.budget_used(name)

    for n, item in enumerate(todo, 1):
        capped = {s for s in caps if s in full and used(s) >= caps[s]}
        if "virustotal" in capped:  # the main cap: everything after it would lack VirusTotal
            result.stopped = f"VirusTotal cap of {caps['virustotal']} calls reached"
            result.not_recorded = [i.id for i in todo[n - 1 :]]
            break
        engine.sources = [s for s in engine.sources if s.name not in capped]
        try:
            report = await engine.check(item.ioc, no_cache=True)
        except DetectError:
            state["internal"].append(item.id)
            result.skipped_internal.append(item.id)
            log(f"[{n}/{len(todo)}] {item.id} skipped: internal or unusable")
            save_state(state_path, state)
            continue
        except Exception as exc:  # fail soft per indicator; the next run retries it
            result.failed.append(item.id)
            log(f"[{n}/{len(todo)}] {item.id} failed ({type(exc).__name__})")
            continue
        if why := blocker(report):
            result.stopped = why
            result.not_recorded = [i.id for i in todo[n - 1 :]]
            break
        rows = rows_of(report)
        _append(
            open_path, {"id": item.id, "rows": [r for r in rows if r["source"] in OPEN_LICENCE]}
        )
        _append(
            local_path,
            {"id": item.id, "rows": [r for r in rows if r["source"] not in OPEN_LICENCE]},
        )
        state["done"].append(item.id)
        state["calls"] = {s: used(s) for s in CAPS}
        save_state(state_path, state)
        result.recorded.append(item.id)
        log(
            f"[{n}/{len(todo)}] {item.id} {report.ioc_type.value}: {len(rows)} rows, "
            f"vt {used('virustotal')}/{caps.get('virustotal', 0)}"
        )
    return result


async def main_async(args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory(prefix="verdikt-eval-") as tmp:
        settings = Settings(  # keys come from .env; the paths keep the real data untouched
            db_path=Path(tmp) / "eval.db",
            audit_log=Path(tmp) / "audit.jsonl",
            crtsh=False,
            vt_resolutions=False,
        )
        async with httpx.AsyncClient(follow_redirects=False) as http:
            engine = build_engine(settings, http)
            skip = SKIP_SOURCES | set(args.skip)
            engine.sources = [s for s in engine.sources if s.name not in skip]
            print(
                "sources:",
                ", ".join(f"{s.name}{'' if s.enabled else ' (no key)'}" for s in engine.sources),
            )
            try:
                result = await record(
                    engine,
                    load_items(),
                    open_path=RECORDED,
                    local_path=LOCAL_RECORDED,
                    state_path=STATE,
                    caps=CAPS,
                )
            finally:
                engine.cache.close()
    print(
        f"recorded {len(result.recorded)}, internal {len(result.skipped_internal)}, "
        f"failed {len(result.failed)}"
    )
    if result.stopped:
        print(f"STOPPED: {result.stopped}; not recorded: {len(result.not_recorded)}")
        print("not recorded ids:", ", ".join(result.not_recorded))
        return 3
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--skip", nargs="*", default=[], metavar="SOURCE", help="also leave these sources out"
    )
    return asyncio.run(main_async(parser.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
