"""FastAPI app: /api/* plus the built SPA. Loopback only; see PLAN.md section 14."""

from __future__ import annotations

import html
import mimetypes
import os
import secrets
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal

import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from verdikt.cache import (
    WATCHLIST_MAX,
    CaseDetail,
    CaseError,
    CaseSummary,
    FeedbackEntry,
    ReportSummary,
    Stats,
    WatchEntry,
    WatchEvent,
)
from verdikt.config import get_settings
from verdikt.detect import DetectError
from verdikt.engine import Engine, SourceInfo, build_engine
from verdikt.export import case_html, case_markdown, report_html, report_markdown
from verdikt.extract import Extraction, extract_iocs
from verdikt.misp import to_misp
from verdikt.models import Model, Report
from verdikt.scheduler import JOBS, JobStatus, Scheduler
from verdikt.sources.feeds import (
    feeds_status,
    forget_import,
    register_import,
    update_feeds,
)
from verdikt.sources.importers import NAME, ImportError_, parse_any, write_import
from verdikt.stix import to_stix
from verdikt.watch import WatchChange, recheck

TOKEN_HEADER = "x-verdikt-token"  # noqa: S105
TOKEN_PLACEHOLDER = "<!--VERDIKT_TOKEN-->"  # noqa: S105
WEB_DIST = Path(__file__).resolve().parent.parent / "web_dist"
# StaticFiles trusts the OS mime table; on Windows the registry can map .js/.css to the wrong
# type, which `nosniff` then turns into a blank page. Pin the types the SPA needs.
MIME_TYPES = {
    ".js": "text/javascript",
    ".mjs": "text/javascript",
    ".css": "text/css",
    ".woff2": "font/woff2",
    ".svg": "image/svg+xml",
    ".json": "application/json",
}
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


class CaseCreate(BaseModel):
    title: str
    notes: str = ""
    tags: list[str] = Field(default_factory=list[str])


class CaseUpdate(BaseModel):
    title: str | None = None
    notes: str | None = None
    tags: list[str] | None = None


class WatchRequest(BaseModel):
    report_id: str


class ExtractRequest(BaseModel):
    text: str = Field(max_length=200_000)


class WatchState(Model):
    entries: list[WatchEntry]
    events: list[WatchEvent]


class FeedInfo(Model):
    name: str
    count: int
    fetched_at: str


class FeedImportRequest(BaseModel):
    name: str
    content: str = Field(max_length=10_000_000)
    all_attributes: bool = False


class FeedImport(Model):
    name: str
    format: str
    count: int


class FeedUpdate(Model):
    name: str
    ok: bool
    count: int
    detail: str


class FeedbackRequest(BaseModel):
    label: Literal["false_positive", "false_negative", "correct"]
    note: str = Field(default="", max_length=500)


class CheckRequest(BaseModel):
    ioc: str
    no_cache: bool = False


class Health(Model):
    status: str


def _get_engine(request: Request) -> Engine:
    engine: Engine = request.app.state.engine
    return engine


EngineDep = Annotated[Engine, Depends(_get_engine)]


def create_app(
    engine: Engine | None = None,
    *,
    port: int | None = None,
    token: str | None = None,
    web_dist: Path | None = None,
) -> FastAPI:
    """Build the app. Without arguments, reads port/token from the env `verdikt ui` sets."""
    for ext, mime in MIME_TYPES.items():
        mimetypes.add_type(mime, ext)
    port = port if port is not None else int(os.environ.get("VERDIKT_PORT", "8765"))
    token = token or os.environ.get("VERDIKT_SESSION_TOKEN") or secrets.token_urlsafe(32)
    dist = web_dist if web_dist is not None else WEB_DIST
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
        if engine is not None:
            app.state.engine = engine
            async with _scheduled(app, engine):
                yield
            return
        async with httpx.AsyncClient(follow_redirects=False) as http:
            built = build_engine(get_settings(), http)
            app.state.engine = built
            try:
                async with _scheduled(app, built):
                    yield
            finally:
                built.cache.close()

    @asynccontextmanager
    async def _scheduled(app: FastAPI, eng: Engine) -> AsyncGenerator[None]:
        scheduler = Scheduler(eng, eng.settings)
        app.state.scheduler = scheduler
        scheduler.start()
        try:
            yield
        finally:
            await scheduler.stop()

    app = FastAPI(title="verdikt", lifespan=lifespan, docs_url=None, redoc_url=None)
    if engine is not None:
        app.state.engine = engine

    @app.middleware("http")
    async def guard(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # DNS rebinding: a rebound hostname arrives with the attacker's Host header.
        if request.headers.get("host", "") not in allowed_hosts:
            return JSONResponse({"detail": "bad host"}, status_code=421)
        path = request.url.path
        if path.startswith("/api") or path == "/openapi.json":
            supplied = request.headers.get(TOKEN_HEADER, "")
            if not secrets.compare_digest(supplied.encode(), token.encode()):
                return JSONResponse({"detail": "missing or invalid session token"}, status_code=401)
            # JSON-only POST: a cross-site form cannot set this without a CORS preflight.
            if (
                request.method == "POST"
                and request.headers.get("content-type", "").split(";")[0].strip().lower()
                != "application/json"
            ):
                return JSONResponse(
                    {"detail": "content-type must be application/json"}, status_code=415
                )
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/api/check", response_model=Report)
    async def check(body: CheckRequest, engine: EngineDep) -> Report:
        try:
            report = await engine.check(body.ioc, no_cache=body.no_cache)
        except DetectError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return report.without_raw()

    @app.get("/api/reports", response_model=list[ReportSummary])
    async def reports(
        engine: EngineDep,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> list[ReportSummary]:
        return engine.cache.list_reports(limit, offset)

    @app.get("/api/reports/{report_id}", response_model=Report)
    async def report(report_id: str, engine: EngineDep, raw: bool = False) -> Report:
        found = engine.cache.get_report(report_id)
        if found is None:
            raise HTTPException(status_code=404, detail="report not found")
        return found if raw else found.without_raw()

    @app.get("/api/reports/{report_id}/stix")
    async def report_stix(report_id: str, engine: EngineDep) -> JSONResponse:
        found = engine.cache.get_report(report_id)
        if found is None:
            raise HTTPException(status_code=404, detail="report not found")
        return JSONResponse(to_stix(found), media_type="application/stix+json")

    @app.get("/api/reports/{report_id}/misp")
    async def report_misp(report_id: str, engine: EngineDep) -> JSONResponse:
        found = engine.cache.get_report(report_id)
        if found is None:
            raise HTTPException(status_code=404, detail="report not found")
        return JSONResponse(to_misp(found))

    @app.post("/api/reports/{report_id}/feedback", response_model=FeedbackEntry)
    async def add_feedback(
        report_id: str, body: FeedbackRequest, engine: EngineDep
    ) -> FeedbackEntry:
        found = engine.cache.get_report(report_id)
        if found is None:
            raise HTTPException(status_code=404, detail="report not found")
        entry = engine.cache.add_feedback(found, body.label, body.note)
        if engine.audit:
            engine.audit.feedback(entry)
        return entry

    @app.get("/api/feedback", response_model=list[FeedbackEntry])
    async def feedback(engine: EngineDep) -> list[FeedbackEntry]:
        return engine.cache.list_feedback()

    def _export(kind: str, text_md: str, text_html: str, fmt: str, stem: str) -> Response:
        if fmt == "html":
            body, media, ext = text_html, "text/html; charset=utf-8", "html"
        else:
            body, media, ext = text_md, "text/markdown; charset=utf-8", "md"
        return Response(
            body,
            media_type=media,
            headers={"Content-Disposition": f'attachment; filename="verdikt-{kind}-{stem}.{ext}"'},
        )

    @app.get("/api/reports/{report_id}/export")
    async def report_export(
        report_id: str,
        engine: EngineDep,
        fmt: Annotated[Literal["md", "html"], Query(alias="format")] = "md",
    ) -> Response:
        found = engine.cache.get_report(report_id)
        if found is None:
            raise HTTPException(status_code=404, detail="report not found")
        shown = found.without_raw()
        return _export("report", report_markdown(shown), report_html(shown), fmt, report_id[:8])

    @app.get("/api/cases", response_model=list[CaseSummary])
    async def cases(engine: EngineDep, tag: str | None = None) -> list[CaseSummary]:
        return engine.cache.case_list(tag)

    @app.post("/api/cases", response_model=CaseDetail)
    async def case_create(body: CaseCreate, engine: EngineDep) -> CaseDetail:
        try:
            case_id = engine.cache.case_create(body.title, body.notes, body.tags)
        except CaseError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return _case(engine, case_id)

    def _case(engine: Engine, case_id: str) -> CaseDetail:
        found = engine.cache.case_get(case_id)
        if found is None:
            raise HTTPException(status_code=404, detail="case not found")
        return found

    @app.get("/api/cases/{case_id}", response_model=CaseDetail)
    async def case_get(case_id: str, engine: EngineDep) -> CaseDetail:
        return _case(engine, case_id)

    @app.patch("/api/cases/{case_id}", response_model=CaseDetail)
    async def case_update(case_id: str, body: CaseUpdate, engine: EngineDep) -> CaseDetail:
        try:
            ok = engine.cache.case_update(case_id, body.title, body.notes, body.tags)
        except CaseError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if not ok:
            raise HTTPException(status_code=404, detail="case not found")
        return _case(engine, case_id)

    @app.delete("/api/cases/{case_id}", response_model=list[CaseSummary])
    async def case_delete(case_id: str, engine: EngineDep) -> list[CaseSummary]:
        engine.cache.case_delete(case_id)
        return engine.cache.case_list()

    @app.post("/api/cases/{case_id}/reports", response_model=CaseDetail)
    async def case_add(case_id: str, body: WatchRequest, engine: EngineDep) -> CaseDetail:
        if not engine.cache.case_add_report(case_id, body.report_id):
            raise HTTPException(status_code=404, detail="case or report not found")
        return _case(engine, case_id)

    @app.delete("/api/cases/{case_id}/reports/{report_id}", response_model=CaseDetail)
    async def case_remove(case_id: str, report_id: str, engine: EngineDep) -> CaseDetail:
        engine.cache.case_remove_report(case_id, report_id)
        return _case(engine, case_id)

    @app.get("/api/cases/{case_id}/export")
    async def case_export(
        case_id: str,
        engine: EngineDep,
        fmt: Annotated[Literal["md", "html"], Query(alias="format")] = "md",
    ) -> Response:
        case = _case(engine, case_id)
        reports = [r.without_raw() for s in case.reports if (r := engine.cache.get_report(s.id))]
        return _export(
            "case", case_markdown(case, reports), case_html(case, reports), fmt, case_id[:8]
        )

    @app.get("/api/scheduler", response_model=list[JobStatus])
    async def scheduler_status(request: Request) -> list[JobStatus]:
        sched: Scheduler = request.app.state.scheduler
        return sched.status()

    @app.post("/api/scheduler/{name}/run", response_model=JobStatus)
    async def scheduler_run(name: str, request: Request) -> JobStatus:
        if name not in JOBS:
            raise HTTPException(status_code=404, detail="no such job")
        sched: Scheduler = request.app.state.scheduler
        return await sched.run(name)

    @app.get("/api/stats", response_model=Stats)
    async def stats(engine: EngineDep, days: Annotated[int, Query(ge=1, le=90)] = 30) -> Stats:
        return engine.cache.stats(days)

    @app.get("/api/watchlist", response_model=WatchState)
    async def watchlist(engine: EngineDep) -> WatchState:
        return WatchState(entries=engine.cache.watch_list(), events=engine.cache.watch_events())

    @app.post("/api/watchlist", response_model=WatchState)
    async def watch_add(body: WatchRequest, engine: EngineDep) -> WatchState:
        found = engine.cache.get_report(body.report_id)
        if found is None:
            raise HTTPException(status_code=404, detail="report not found")
        if not engine.cache.watch_add(found.ioc, found.ioc_type.value):
            raise HTTPException(status_code=409, detail=f"watchlist is full ({WATCHLIST_MAX})")
        engine.cache.watch_record(found)  # the report becomes the baseline
        return WatchState(entries=engine.cache.watch_list(), events=engine.cache.watch_events())

    @app.delete("/api/watchlist", response_model=WatchState)
    async def watch_remove(ioc: str, engine: EngineDep) -> WatchState:
        engine.cache.watch_remove(ioc)
        return WatchState(entries=engine.cache.watch_list(), events=engine.cache.watch_events())

    @app.post("/api/watchlist/recheck", response_model=list[WatchChange])
    async def watch_recheck(engine: EngineDep) -> list[WatchChange]:
        changes, _ = await recheck(engine)
        return changes

    @app.get("/api/feeds", response_model=list[FeedInfo])
    async def feeds_info(engine: EngineDep) -> list[FeedInfo]:
        status = feeds_status(engine.settings.resolved_feeds_dir)
        return [
            FeedInfo(name=n, count=int(i.get("count", 0)), fetched_at=str(i.get("fetched_at", "")))
            for n, i in status.items()
        ]

    @app.post("/api/feeds/update", response_model=list[FeedUpdate])
    async def feeds_refresh(engine: EngineDep) -> list[FeedUpdate]:
        results = await update_feeds(engine.http, engine.settings.resolved_feeds_dir)
        return [FeedUpdate(name=r.name, ok=r.ok, count=r.count, detail=r.detail) for r in results]

    @app.post("/api/feeds/import", response_model=FeedImport)
    async def feeds_import(body: FeedImportRequest, engine: EngineDep) -> FeedImport:
        directory = engine.settings.resolved_feeds_dir
        try:
            fmt, entries = parse_any(body.content.encode("utf-8"), body.all_attributes)
            count = write_import(directory, body.name, fmt, entries)
        except ImportError_ as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        register_import(directory, body.name, count)
        return FeedImport(name=body.name, format=fmt, count=count)

    @app.delete("/api/feeds/import", response_model=list[FeedInfo])
    async def feeds_forget(name: str, engine: EngineDep) -> list[FeedInfo]:
        if not NAME.match(name):
            raise HTTPException(status_code=422, detail="invalid list name")
        forget_import(engine.settings.resolved_feeds_dir, name)
        return await feeds_info(engine)

    @app.post("/api/extract", response_model=Extraction)
    async def extract(body: ExtractRequest, engine: EngineDep) -> Extraction:
        return extract_iocs(body.text, engine.settings.internal_domain_list)

    @app.get("/api/sources", response_model=list[SourceInfo])
    async def sources(engine: EngineDep) -> list[SourceInfo]:
        return engine.source_status()

    @app.get("/api/health", response_model=Health)
    async def health() -> Health:
        return Health(status="ok")

    index = dist / "index.html"
    if index.is_file():
        page = index.read_text(encoding="utf-8")
        injected = f'<meta name="verdikt-token" content="{html.escape(token, quote=True)}">'
        page = page.replace(TOKEN_PLACEHOLDER, injected)

        @app.get("/", include_in_schema=False)
        async def spa_root() -> HTMLResponse:
            return HTMLResponse(page, headers={"Cache-Control": "no-store"})

        assets = dist / "assets"
        if assets.is_dir():
            app.mount("/assets", StaticFiles(directory=assets), name="assets")
    else:

        @app.get("/", include_in_schema=False)
        async def no_ui() -> HTMLResponse:
            return HTMLResponse(
                "<!doctype html><title>verdikt</title><p>UI not built. "
                "Run <code>cd web &amp;&amp; npm run build</code>.</p>"
            )

    return app
