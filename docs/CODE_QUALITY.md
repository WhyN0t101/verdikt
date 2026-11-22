# Code quality audit

A checklist for finding dead code, duplicated code, slow code and best-practice violations in verdikt. A person or a coding agent runs it top to bottom and produces a findings report. It is tuned to this codebase: the checks that earn their place here are listed, and the generic ones that produced only noise are left out on purpose.

## 1. Rules of the run

- **Report first.** An audit changes no code. It produces the report in section 10. Fixes happen afterwards, one finding at a time, and a bug fix starts with a failing test (CLAUDE.md).
- **Exclude generated and third-party trees from every command:** `.venv/`, `web/node_modules/`, `src/verdikt/web_dist/` (the built SPA, minified, sits inside `src/` and drowns most tools), `web/src/types.ts` (generated), `web/src/data/land.json` (generated), `tests/fixtures/`, `uv.lock`, `web/package-lock.json`.
- **Do not add dependencies for an audit.** CLAUDE.md says to ask first. One-off tools are run through `uvx` or `npx`, which download code, so record the exact version used in the report and pin it (for example `uvx vulture@<version>`).
- **Triage every finding into exactly one bucket:**
  - **Fix now:** correctness, security, a failing gate, or a rule from CLAUDE.md that is broken.
  - **Log:** real but not urgent. Add it to `docs/DEBT.md` with the path, the evidence and why it was deferred.
  - **Accept:** deliberate. Write the reason next to the code (a `shortcut:` or why-comment), not just in the report.
- **Measure before optimizing.** A performance finding needs a number (time, size, count). Without one it is logged, not fixed.

## 2. Baseline gates

Any failure here is fix now.

```bash
uv run ruff check . && uv run ruff format --check .
uv run pyright
uv run pytest
cd web && npm run lint && npm run typecheck && npm test && npm run build
```

`npm run e2e` runs in CI (the `e2e` job). Locally it needs a browser: `PW_CHANNEL=msedge npm run e2e`, or `npx playwright install chromium` once.

## 3. Security invariants

These come straight from CLAUDE.md. Any hit is fix now.

| Check | Command or place to look | Expected |
|---|---|---|
| No HTML injection in the SPA | `grep -rnE "dangerouslySetInnerHTML\|innerHTML\|eval\(" web/src` | no hits (eslint already blocks the first) |
| Notifications escape feed text | read `src/verdikt/notify/format.py` | one line and every dot defanged on every feed-derived string; `html.escape` for Telegram, `&`, `<`, `>` (backtick, `*`, `~` removed) for Slack, `(` `)` swapped for `{` `}` for Discord and Teams |
| Feed text is cleaned at the model boundary | `grep -n clean_text src/verdikt/models.py` | validators on `SourceResult.summary`, `tags`, `RelatedIOC.value`, `SeenBefore.shared`, `CveInfo.kev_*` and `GeoPoint` names; `raw` is the only field kept as received. No `model_copy(update=...)` sets one of those fields (it skips validators) |
| Keys never reach logs, errors or URLs | `grep -rnE "api_key\|apikey\|x-apikey\|Auth-Key\|Authorization\|token" src/verdikt` and inspect each hit near `log`, `print`, `raise`, f-strings and `params=` | keys only in headers; no key in any message |
| Exception text never carries a URL | every `except httpx.HTTPError` branch | message uses the exception class name only (httpx messages include the URL) |
| API guard intact | read `src/verdikt/api/app.py` | Host check, constant-time token compare, JSON-only POST, no CORS headers, `127.0.0.1` bind |
| Internal targets never leave the machine | trace every outbound call in `sources/*`, `enrich/dns.py`, `notify/*` | indicators pass `detect()` first; no source builds a request from related indicators or from URLs found in feed data |
| urlscan is search only | `grep -rn "urlscan" src/verdikt` | no scan submission, no `visibility` parameter needed |
| DNS stays off | `grep -rn "dns_resolve" src/verdikt` | default `False`, only `engine.py` reads it |
| Map makes no requests | read `web/src/components/MapView.tsx` | no `fetch`, no remote tile or image URL |
| Level never colour alone | every use of `LevelBadge` and level colour tokens | icon and text always present |
| No hardcoded colours | `grep -rnE "#[0-9a-fA-F]{3,8}\b\|rgb\(" web/src --include=*.tsx` | only token references; `tokens.css` is the one place for values |

## 4. Dead code

```bash
uv run ruff check . --select F,ARG,RUF100            # unused imports, variables, arguments, stale noqa
uvx vulture@<version> src --min-confidence 80 --exclude "src/verdikt/web_dist"
cd web && npx knip@<version>                         # unused files, exports, dependencies
cd web && npx tsc --noEmit                           # noUnusedLocals and noUnusedParameters are already on
```

vulture is low-yield on pydantic models, FastAPI handlers and typer commands because they look unused to it. Keep `--min-confidence 80` and review hits by hand, or keep a whitelist file in the report.

Cross-checks that no tool does, worth a small script or a careful manual pass:

- Every key under `source:` in `src/verdikt/rules.yaml` is a metric some source actually emits (compare with the `metrics=` dictionaries in `src/verdikt/sources/*.py`), and every emitted metric that no rule uses is deliberate (display only).
- Every variable in `.env.example` is a field in `src/verdikt/config.py`, and the reverse.
- Every route in `src/verdikt/api/app.py` is called by `web/src/api.ts` or documented in `docs/API.md` as external (for example Shuffle).
- Every exported symbol in `web/src/lib/` is used.

Triage: delete code with no caller and no test. Keep code that is a documented seam (PLAN.md section 17) and say so in a comment.

## 5. Duplicate code

```bash
npx jscpd@<version> src/verdikt/sources web/src/components --min-tokens 50 --ignore "**/web_dist/**"
```

Run it on sources and components only. `tests/test_sources.py` is repetitive on purpose (one fixture-driven case per source and outcome, per the testing rules), so test duplication is accepted. The likely real hotspots are the per-source `lookup` boilerplate and the repeated level-colour maps in the UI. Triage: extract only when there are three or more copies, and only if the extraction does not blur the rule that a source holds no thresholds and sets no level.

## 6. Async correctness and performance

- **Sync I/O inside `async def`.** `Engine._query`, `Engine.check` and `Gate._once` call the synchronous sqlite `Cache` (guarded by a `threading.Lock`) on the event loop. At about ten sources this is fine; check that no query inside the lock can become slow (history listing with large raw payloads is the one to measure). `uv run ruff check . --select ASYNC` is already clean; add `grep -n "cache\." src/verdikt/engine.py src/verdikt/sources/base.py` and review each call.
- **Swallowed failures.** `Engine.check` turns any exception from a source into an `ERROR` row with the summary "source failed" and no log. That hides bugs in a source. Expected: log the exception class name (never a URL or key) before converting it.
- **Parallelism.** Sources run under `asyncio.gather`; confirm no new code awaits sources one by one.
- **Cache.** A repeated check of the same indicator must make no HTTP call (covered by `tests/test_engine.py`); confirm errors are never cached and `raw` is always stored.
- **Frontend.** Measure the initial JavaScript chunk from `npm run build`, not the lazy `GraphView` chunk (Cytoscape is already split out). Profile the map in the React profiler before touching its roughly 3,800 land dots. Check for needless re-renders in `App.tsx` and that no effect re-creates the Cytoscape instance without need.
- **Triage:** fix only with a measurement showing user-visible cost; otherwise log.

## 7. Test quality

- A test that cannot fail is worse than none. `grep -L "assert" tests/test_*.py` lists test files with no assert; also look for tests whose only assertion is that nothing raised.
- Mocked routes must be asserted: a `respx` route that is never called means the test did not test the HTTP path. Prefer `assert route.called` or `call_count` where the call is the point.
- `tests/test_verdict.py` must keep the four mandatory cases from CLAUDE.md: errors are not clean, a rate-limited high-weight source blocks SAFE, INFO rows do not count towards `min_sources_for_safe`, a benign override cannot clear MALICIOUS.
- Mutation check by hand: change one threshold in `rules.yaml` (for example `virustotal: {malicious: 5}` to 6) and confirm a test fails; revert after.
- No test makes a live network call. `grep -rn "http" tests/*.py` should show only fixture and mock URLs.
- Fixtures contain no keys, emails or account IDs, and are trimmed to the fields read.

## 8. Drift

- **Types.** Regenerate to a temporary file and diff: `cd web && npm run gen:types` rewrites `web/src/types.ts`, so run it and check `git diff web/src/types.ts` is empty. Any difference means the backend model changed; check `schema_version` was bumped if the change was breaking.
- **Docs.** The sources table in `PLAN.md`, the registry in `src/verdikt/sources/__init__.py` and `docs/SOURCES.md` must agree. Exit codes in `src/verdikt/cli.py`, `PLAN.md` section 10, `README.md` and `docs/INTEGRATIONS.md` must agree. Routes in `src/verdikt/api/app.py` and `docs/API.md` must agree.
- **Plan versus code.** If code and `PLAN.md` disagree, the rule in CLAUDE.md applies: stop, decide, and update `PLAN.md` in the same change.
- **Suppressions.** `grep -rnE "noqa\|type: ignore\|pyright: ignore\|eslint-disable" src web/src tests`. Each needs a rule code and, for anything in `src/`, a reason. A bare `type: ignore` or a `pyright: ignore` that lets an `Any` escape breaks the rule that only `SourceResult.raw` may be `Any`.

## 9. Dependencies, licences and accessibility

- **Python dependencies.** `uv pip check`. For each runtime dependency in `pyproject.toml`, confirm it is imported: `grep -rn "^import <name>\|^from <name>" src`. The ones most worth checking are `tenacity`, `aiolimiter`, `dnspython`, `maxminddb` and `ioc-fanger`. Run an advisory scan (`uvx pip-audit@<version>`) and record the result.
- **Frontend dependencies.** `npx knip` covers unused packages; check `topojson-client` and `world-atlas` are devDependencies used only by `npm run gen:land`, and that each `@fontsource-variable` font is actually used.
- **No SDKs.** `requests`, `aiohttp` and vendor SDKs such as `vt-py` must not appear in `pyproject.toml` or imports.
- **Licences.** The notes in `README.md` still hold: VirusTotal public API and Shodan InternetDB forbid commercial use, IPinfo Lite needs attribution, GeoLite2 files are never committed.
- **Accessibility.** Keyboard focus is visible and reachable on the command bar, history list, tabs and map markers; every control has an accessible name; the SVG map has a role and label; text contrast is at least 4.5:1 in both themes; motion respects `prefers-reduced-motion`.

## 10. Report template

One entry per finding. Order by severity, then by area.

```
[severity: high | medium | low] path:line
Area: security | dead code | duplicate | async/perf | tests | drift | deps | a11y
Evidence: command output, a measurement, or the exact code
Why it matters: one sentence
Triage: fix now | log in docs/DEBT.md | accept (reason)
Proposed change: one sentence, no code changes made in the audit
```

End the report with the commands that were run, the tool versions, and what was not checked, so the next run can start from the same baseline.

## Known findings at the time of writing

Found while preparing this document; confirm and triage them on the first run.

- urlscan search rows often carry no verdict data, so that source contributes context only (scan count, related IPs and domains), never a verdict (see `docs/SOURCES.md`).
