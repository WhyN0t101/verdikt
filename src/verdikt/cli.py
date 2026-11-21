"""Typer CLI. Exit: 0 SAFE, 1 error, 2 usage, 10 SUSPICIOUS, 11 MALICIOUS, 12 UNKNOWN."""

from __future__ import annotations

import asyncio
import csv as _csv
import json as _json
import os
import secrets
import sys
import threading
import webbrowser
from collections.abc import Awaitable, Callable
from datetime import timedelta
from pathlib import Path
from typing import Annotated

import httpx
import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from verdikt.config import Settings, get_settings
from verdikt.detect import DetectError, detect
from verdikt.engine import Engine, build_engine
from verdikt.extract import MAX_ITEMS, extract_iocs
from verdikt.misp import to_misp
from verdikt.models import Level, Report, Status
from verdikt.notify import Platform, notify
from verdikt.sources.feeds import (
    DEFAULT_TOP,
    FeedResult,
    feeds_status,
    forget_import,
    register_import,
    update_feeds,
)
from verdikt.sources.importers import ImportError_, parse_any, write_import
from verdikt.stix import to_stix
from verdikt.watch import WatchChange, recheck

app = typer.Typer(add_completion=False, no_args_is_help=True, help="IOC triage.")
cache_app = typer.Typer(help="Cache maintenance.")
app.add_typer(cache_app, name="cache")
watch_app = typer.Typer(help="Watchlist: re-check indicators and report verdict changes.")
app.add_typer(watch_app, name="watch")
feeds_app = typer.Typer(help="Local data feeds: blocklists, Tor exits, top sites, KEV, EPSS.")
app.add_typer(feeds_app, name="feeds")

out = Console()
err = Console(stderr=True)

EXIT_CODES = {
    Level.SAFE: 0,
    Level.SUSPICIOUS: 10,
    Level.MALICIOUS: 11,
    Level.UNKNOWN: 12,
}
# bulk: highest severity wins
_BULK_ORDER = {0: 0, 12: 1, 10: 2, 11: 3}
LEVEL_STYLE = {
    Level.MALICIOUS: "bold red",
    Level.SUSPICIOUS: "bold yellow",
    Level.SAFE: "bold green",
    Level.UNKNOWN: "bold white",
    Level.INFO: "cyan",
}


def exit_code(level: Level) -> int:
    return EXIT_CODES[level]


def worst(codes: list[int]) -> int:
    return max(codes, key=lambda c: _BULK_ORDER[c]) if codes else 0


async def _with_engine[T](
    settings: Settings, fn: Callable[[Engine, httpx.AsyncClient], Awaitable[T]]
) -> T:
    async with httpx.AsyncClient(follow_redirects=False) as http:
        engine = build_engine(settings, http)
        try:
            return await fn(engine, http)
        finally:
            engine.cache.close()


def _render(report: Report) -> None:
    style = LEVEL_STYLE[report.level]
    out.print(
        f"[{style}]{report.level.value.upper()}[/]  [bold]{escape(report.ioc)}[/]  "
        f"({report.ioc_type.value})  {report.agreeing}/{report.total} sources · "
        f"{report.duration_ms / 1000:.1f}s",
        markup=True,
        highlight=False,
    )
    for reason in report.reasons:
        out.print(f"  - {reason}", markup=False, highlight=False)
    table = Table(show_header=True, header_style="bold")
    for col in ("source", "level", "status", "summary"):
        table.add_column(col)
    for r in report.results:
        table.add_row(
            escape(r.source),
            r.level.value + (" (cached)" if r.cached else ""),
            r.status.value,
            escape(r.summary),
        )
    out.print(table)
    if report.geo:
        geo = report.geo[0]
        out.print(
            f"geo: {geo.country or '?'} · AS{geo.asn or '?'} {geo.as_org or ''}", markup=False
        )


def _all_failed(report: Report) -> bool:
    return not report.results or all(r.status is Status.ERROR for r in report.results)


def _emit(report: Report, as_json: bool, raw: bool) -> None:
    shown = report if raw else report.without_raw()
    if as_json:
        sys.stdout.write(shown.model_dump_json(indent=2 if raw else None) + "\n")
    else:
        _render(shown)


async def _notify(
    report: Report,
    platforms: list[Platform],
    settings: Settings,
    http: httpx.AsyncClient,
    min_level: Level,
) -> None:
    for platform in platforms:
        outcome = await notify(report, platform, settings, http, min_level)
        if not outcome.sent and not outcome.detail.startswith("below min"):
            err.print(f"notify {platform}: {outcome.detail}", markup=False)
        elif outcome.sent:
            err.print(f"notify {platform}: sent", markup=False)


@app.command()
def check(
    ioc: Annotated[str, typer.Argument(help="IP, domain, URL or hash (defanged input is fine)")],
    json: Annotated[bool, typer.Option("--json", help="Print the Report as JSON")] = False,
    raw: Annotated[bool, typer.Option("--raw", help="Keep vendor `raw` payloads")] = False,
    stix: Annotated[bool, typer.Option("--stix", help="Print a STIX 2.1 bundle instead")] = False,
    misp: Annotated[bool, typer.Option("--misp", help="Print a MISP event JSON instead")] = False,
    no_cache: Annotated[bool, typer.Option("--no-cache", help="Bypass cached results")] = False,
    notify_to: Annotated[
        Platform | None, typer.Option("--notify", help="slack or telegram")
    ] = None,
    min_level: Annotated[
        Level, typer.Option("--min-level", help="Notify threshold")
    ] = Level.SUSPICIOUS,
) -> None:
    """Check one IOC."""
    settings = get_settings()

    async def run(engine: Engine, http: httpx.AsyncClient) -> Report:
        report = await engine.check(ioc, no_cache=no_cache)
        if notify_to:
            await _notify(report, [notify_to], settings, http, min_level)
        return report

    try:
        report: Report = asyncio.run(_with_engine(settings, run))
    except DetectError as exc:
        err.print(f"error: {exc}", markup=False)
        raise typer.Exit(1) from exc
    if misp:
        sys.stdout.write(_json.dumps(to_misp(report), indent=2) + "\n")
    elif stix:
        sys.stdout.write(_json.dumps(to_stix(report), indent=2) + "\n")
    else:
        _emit(report, json, raw)
    if _all_failed(report):
        err.print("error: no source answered (check keys in .env and your network)", markup=False)
        raise typer.Exit(1)
    raise typer.Exit(exit_code(report.level))


def _read_iocs(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


CSV_FIELDS = ("ioc", "type", "level", "confidence", "agreeing", "total", "report_id", "reasons")


def csv_row(report: Report) -> list[str]:
    # a spreadsheet runs cells that start with = + - @ as formulas; indicators and feed text
    # are attacker-controlled, so neutralise them
    def safe(text: str) -> str:
        return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text

    return [
        safe(report.ioc),
        report.ioc_type.value,
        report.level.value,
        report.confidence.value,
        str(report.agreeing),
        str(report.total),
        report.id,
        safe(" | ".join(report.reasons)),
    ]


@app.command()
def extract(
    source: Annotated[str, typer.Argument(help="Text file, or - for stdin")] = "-",
) -> None:
    """List every indicator found in free text (a ticket, an email). Nothing is looked up."""
    text = sys.stdin.read() if source == "-" else Path(source).read_text(encoding="utf-8")
    found = extract_iocs(text, get_settings().internal_domain_list)
    for item in found.items:
        sys.stdout.write(f"{item.type.value}\t{item.value}\n")
    for s in found.skipped:
        err.print(f"skipped {s.value}: {s.reason}", markup=False)
    if found.truncated:
        err.print(f"only the first {MAX_ITEMS} indicators are listed", markup=False)


@app.command()
def bulk(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    json: Annotated[bool, typer.Option("--json", help="One JSON report per line")] = False,
    csv_out: Annotated[bool, typer.Option("--csv", help="One CSV row per indicator")] = False,
    text: Annotated[
        bool, typer.Option("--text", help="The file is free text: extract the indicators first")
    ] = False,
    resume: Annotated[
        bool, typer.Option("--resume", help="Skip indicators already checked in the last 24 h")
    ] = False,
    notify_to: Annotated[Platform | None, typer.Option("--notify")] = None,
    min_level: Annotated[Level, typer.Option("--min-level")] = Level.SUSPICIOUS,
) -> None:
    """Check many IOCs. Sequential, so the limiters and daily budgets are respected."""
    settings = get_settings()
    if text:
        found = extract_iocs(file.read_text(encoding="utf-8"), settings.internal_domain_list)
        iocs = [i.value for i in found.items]
        for s in found.skipped:
            err.print(f"skipped {s.value}: {s.reason}", markup=False)
    else:
        iocs = _read_iocs(file)
    writer = _csv.writer(sys.stdout, lineterminator="\n") if csv_out else None
    if writer:
        writer.writerow(CSV_FIELDS)

    async def run(engine: Engine, http: httpx.AsyncClient) -> tuple[list[int], int]:
        codes: list[int] = []
        failures = 0
        done: set[str] = engine.cache.checked_since(timedelta(hours=24)) if resume else set()
        for line in iocs:
            try:
                if resume and detect(line, settings.internal_domain_list).value in done:
                    err.print(f"resume: skipping {line} (checked in the last 24 h)", markup=False)
                    continue
                report = await engine.check(line)
            except DetectError as exc:
                failures += 1
                err.print(f"skip {line!r}: {exc}", markup=False)
                continue
            if writer:
                writer.writerow(csv_row(report))
            else:
                _emit(report, json, raw=False)
            if _all_failed(report):
                failures += 1
            codes.append(exit_code(report.level))
            if notify_to:
                await _notify(report, [notify_to], settings, http, min_level)
        return codes, failures

    codes, failures = asyncio.run(_with_engine(settings, run))
    result = worst(codes)
    if failures and result == 0:
        raise typer.Exit(1)
    raise typer.Exit(result)


@app.command()
def sources() -> None:
    """List sources, whether they are enabled, and today's quota use."""
    settings = get_settings()

    async def run(engine: Engine, http: httpx.AsyncClient) -> None:
        table = Table(show_header=True, header_style="bold")
        for col in ("source", "enabled", "supports", "used today"):
            table.add_column(col)
        for s in engine.source_status():
            quota = f"{s.used_today}/{s.daily_budget}" if s.daily_budget else str(s.used_today)
            off = "no (key missing)" if s.requires_key else "no (run `verdikt feeds update`)"
            enabled = "yes" if s.enabled else off
            table.add_row(s.name, enabled, ",".join(s.supports), quota)
        out.print(table)

    asyncio.run(_with_engine(settings, run))


@feeds_app.command("update")
def feeds_update(
    top: Annotated[int, typer.Option(help="Tranco top sites to keep")] = DEFAULT_TOP,
) -> None:
    """Download the feeds (about 14 MB). Lookups then run locally with no quota."""
    directory = get_settings().resolved_feeds_dir

    async def run() -> list[FeedResult]:
        async with httpx.AsyncClient() as http:
            return await update_feeds(http, directory, top)

    results = asyncio.run(run())
    table = Table(show_header=True, header_style="bold")
    for col in ("feed", "result", "entries"):
        table.add_column(col)
    for r in results:
        table.add_row(r.name, r.detail, f"{r.count:,}" if r.ok else "-")
    out.print(table)
    if not any(r.ok for r in results):
        raise typer.Exit(1)


@feeds_app.command("import")
def feeds_import(
    file: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    name: Annotated[str, typer.Option("--name", help="Short name, e.g. misp-2026-11")],
    all_attributes: Annotated[
        bool, typer.Option("--all", help="MISP: include attributes without to_ids")
    ] = False,
) -> None:
    """Import a MISP event file or STIX 2.1 bundle as a local blocklist."""
    directory = get_settings().resolved_feeds_dir
    try:
        fmt, entries = parse_any(file.read_bytes(), all_attributes)
        count = write_import(directory, name, fmt, entries)
    except ImportError_ as exc:
        err.print(f"error: {exc}", markup=False)
        raise typer.Exit(1) from exc
    register_import(directory, name, count)
    out.print(f"imported {count:,} indicator(s) from {fmt} file as '{name}'", markup=False)


@feeds_app.command("forget")
def feeds_forget(name: Annotated[str, typer.Argument()]) -> None:
    """Remove an imported list."""
    if not forget_import(get_settings().resolved_feeds_dir, name):
        err.print("no such imported list", markup=False)
        raise typer.Exit(1)


@feeds_app.command("status")
def feeds_show() -> None:
    """Show which feeds are downloaded and when."""
    status = feeds_status(get_settings().resolved_feeds_dir)
    if not status:
        out.print("no feeds downloaded: run `verdikt feeds update`", markup=False)
        return
    for name, info in status.items():
        out.print(
            f"{name}: {info.get('count', 0):,} entries, fetched {info.get('fetched_at', '?')}",
            markup=False,
        )


@watch_app.command("add")
def watch_add(ioc: Annotated[str, typer.Argument(help="Indicator to watch")]) -> None:
    """Add an indicator. Its first `watch run` sets the baseline verdict."""
    settings = get_settings()

    async def run(engine: Engine, http: httpx.AsyncClient) -> str:
        parsed = detect(ioc, settings.internal_domain_list)
        if not engine.cache.watch_add(parsed.value, parsed.type.value):
            raise typer.Exit(1)
        return parsed.value

    try:
        value = asyncio.run(_with_engine(settings, run))
    except DetectError as exc:
        err.print(f"error: {exc}", markup=False)
        raise typer.Exit(1) from exc
    out.print(f"watching {value}", markup=False)


@watch_app.command("list")
def watch_list() -> None:
    """Show watched indicators and the latest verdict changes."""
    settings = get_settings()

    async def run(engine: Engine, http: httpx.AsyncClient) -> None:
        table = Table(show_header=True, header_style="bold")
        for col in ("indicator", "type", "last verdict", "last checked"):
            table.add_column(col)
        for e in engine.cache.watch_list():
            table.add_row(e.ioc, e.ioc_type, e.last_level or "-", str(e.last_checked_at or "-"))
        out.print(table)
        for ev in engine.cache.watch_events(10):
            out.print(
                f"{ev.at:%Y-%m-%d %H:%M}  {ev.ioc}: {ev.from_level} -> {ev.to_level}", markup=False
            )

    asyncio.run(_with_engine(settings, run))


@watch_app.command("remove")
def watch_remove(ioc: Annotated[str, typer.Argument()]) -> None:
    """Stop watching an indicator."""
    settings = get_settings()

    async def run(engine: Engine, http: httpx.AsyncClient) -> bool:
        return engine.cache.watch_remove(ioc)

    if not asyncio.run(_with_engine(settings, run)):
        err.print("not on the watchlist", markup=False)
        raise typer.Exit(1)


@watch_app.command("run")
def watch_run(
    notify_to: Annotated[Platform | None, typer.Option("--notify")] = None,
    min_level: Annotated[Level, typer.Option("--min-level")] = Level.SUSPICIOUS,
) -> None:
    """Re-check every entry (bypassing the cache) and print verdict changes. Schedule this."""
    settings = get_settings()

    async def run(engine: Engine, http: httpx.AsyncClient) -> list[WatchChange]:
        changes, reports = await recheck(engine)
        if notify_to:
            for report in reports:
                await _notify(report, [notify_to], settings, http, min_level)
        return changes

    changes = asyncio.run(_with_engine(settings, run))
    for c in changes:
        out.print(f"{c.ioc}: {c.before} -> {c.after}", markup=False)
    if not changes:
        out.print("no changes", markup=False)


@cache_app.command("clear")
def cache_clear(
    source: Annotated[str | None, typer.Option("--source", help="Only this source")] = None,
) -> None:
    """Delete cached source results (history is kept)."""
    settings = get_settings()

    async def run(engine: Engine, http: httpx.AsyncClient) -> None:
        n = engine.cache.clear(source)
        out.print(f"cleared {n} cached result(s)", markup=False)

    asyncio.run(_with_engine(settings, run))


@app.command()
def ui(
    port: Annotated[int, typer.Option(help="Port on 127.0.0.1")] = 8765,
    no_open: Annotated[bool, typer.Option("--no-open", help="Do not open a browser")] = False,
    dev: Annotated[bool, typer.Option("--dev", help="Reload on change; fixed dev token")] = False,
) -> None:
    """Start the local web UI (binds 127.0.0.1 only)."""
    import uvicorn

    # a preset token lets Shuffle/Cortex call the API; otherwise one per run
    preset = os.environ.get("VERDIKT_SESSION_TOKEN")
    token = "dev-token" if dev else preset or secrets.token_urlsafe(32)
    os.environ["VERDIKT_PORT"] = str(port)
    os.environ["VERDIKT_SESSION_TOKEN"] = token
    url = f"http://127.0.0.1:{port}/"
    if dev:
        err.print(
            "dev mode: run `npm run dev` in web/ (its proxy sends the dev token)", markup=False
        )
    elif not no_open:
        threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    err.print(f"verdikt ui on {url}", markup=False)
    uvicorn.run(
        "verdikt.api.app:create_app",
        factory=True,
        host="127.0.0.1",
        port=port,
        reload=dev,
        log_level="warning",
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
