# verdikt

IOC triage tool. Takes an IP, domain, URL or hash, queries threat-intel sources in parallel, returns a verdict, optionally notifies Slack, Telegram, Discord, Teams or email, and shows results in a local browser UI (map + graph).

**`PLAN.md` is the spec.** Read the relevant section before starting a milestone. If code and plan disagree, stop and ask; update `PLAN.md` in the same change when a decision changes.

## Status

M0–M9 implemented, plus the post-M9 batches in `PLAN.md` §19 (all committed on `main`). Update this file when a command or path changes. Frontend types: `npm run gen:types` dumps the schema offline via `scripts/dump_openapi.py` (the runtime `/openapi.json` needs the session token).

## Commands

```bash
uv sync                                   # install backend deps
uv run pytest                             # backend tests
uv run pytest tests/test_verdict.py -q    # single file
uv run ruff check . && uv run ruff format --check .
uv run pyright
uv run verdikt check 8.8.8.8              # CLI
uv run verdikt ui --dev                   # API with reload; run Vite separately
cd web && npm ci && npm run dev           # frontend dev server (proxies /api)
cd web && npm run build                   # outputs to src/verdikt/web_dist/
cd web && npm run lint && npm run typecheck && npm test
```

**Definition of done for any change:** `ruff check`, `ruff format --check`, `pyright`, `pytest` all pass; for frontend changes also `npm run lint`, `typecheck`, `test`, `build`. Report real output on failure.

## Architecture rules

- The core library (`src/verdikt/`) returns one `Report` pydantic model. CLI, API, UI and SOAR glue only consume it. Nothing outside `sources/` calls a threat-intel API.
- `Report` has `schema_version`. Bump it on any breaking field change and regenerate frontend types (`npm run gen:types` from `/openapi.json`). Never hand-edit generated types.
- One shared `httpx.AsyncClient`. No `requests`, no `aiohttp`, no vendor SDKs (`vt-py` etc.).
- `verdict.decide()` is a pure function: no I/O, no clock, no randomness. It sets every row `level` and the final verdict. Sources never set `level`.
- Context-only sources (the `context_only` list in `rules.yaml`: `internetdb`, `greynoise`, `otx`, `urlscan`, `crtsh`, `passivedns`) get row level INFO and never count toward `min_sources_for_safe`. `benign_override` (greynoise `riot`, hashlookup `known_good`, localfeeds `top_site`) only downgrades SUSPICIOUS to SAFE and never touches MALICIOUS.
- `rules.yaml` is plain YAML structure validated by pydantic. Never add a string expression parser or `eval`.
- Exit codes: 0 SAFE, 1 error, 2 usage (Click), 10 SUSPICIOUS, 11 MALICIOUS, 12 UNKNOWN. Don't reuse 1 or 2 for verdicts.
- Config: secrets via `pydantic-settings` from `.env`; thresholds in `rules.yaml`. No magic numbers for thresholds in code.

## Adding a source

1. One file in `src/verdikt/sources/<name>.py` implementing the `Source` protocol (`name`, `supports`, `requires_key`, `rate`, `ttl`, `daily_budget`, `timeout`, `quota_group`, `enabled`, `async query`); subclass `BaseSource`, which maps timeouts, network errors and malformed bodies to `ERROR`.
2. Map raw response to `SourceResult` and fill `metrics` (plain counts/scores/booleans). No thresholds and no `level` in the source; add rules to `rules.yaml`.
3. Handle every outcome explicitly: hit, not found (`NOT_FOUND`), 429 (`RATE_LIMITED`), 4xx/5xx/timeout (`ERROR`). Never raise out of `query`.
4. Set `link` to the source's web page for the IOC.
5. Register it, add the key to `.env.example` (empty value), add a row to the sources table in `PLAN.md`.
6. Tests with fixtures for hit, miss, error and 429.

## Security rules (non-negotiable)

- API keys only in `.env` (git-ignored). Never log, print, return from the API, put in URLs where avoidable, or commit them. Fixtures must be scrubbed of keys and account data.
- API binds to `127.0.0.1` only. Keep the `Host` header check, the per-run session token, and JSON-only POST. Never add CORS headers.
- Never send internal targets to any third party: private IPs (`not ip.is_global`), IPv6 addresses that carry a non-global IPv4 (mapped, NAT64 `64:ff9b::/96`, 6to4, Teredo, IPv4-compatible `::/96`, IPv4-translated `::ffff:0:0:0/96`) and the site-local range `fec0::/10`, URLs whose host is private/internal, `localhost`, single-label names, `.local`/`.internal`/`.lan`/`.corp`/`.home.arpa`/`.intranet`/`.private`/`.home`/`.localdomain`, and `VERDIKT_INTERNAL_DOMAINS` suffixes.
- Escape feed-derived text in notifications. It is single-lined and every dot is defanged. Telegram: `html.escape()`. Slack: `&`/`<`/`>` escaped, backtick becomes `'`, `*` and `~` removed. Discord and Teams: `(` `)` become `{` `}` and Discord sends `allowed_mentions: {parse: []}`. Email is plain text.
- Source retries obey the limiter and daily budget on every attempt. Alert delivery retries once, only when the wait is within the timeout. `Retry-After` longer than the timeout → `RATE_LIMITED`, no waiting.
- The map must make no remote request (no tiles, no third-party fonts or images): a request would reveal what you investigate.
- urlscan: search only. No scan submission unless explicitly added, and then `visibility=private` by default.
- DNS resolution of IOCs is off by default.
- Treat all source data as attacker-controlled: render as text in the UI (no `dangerouslySetInnerHTML`, no markdown rendering of feed data), defang IOCs in notifications and copy buttons. Control, bidi and invisible characters (Unicode categories Cc, Cf, Zl, Zp) are stripped from feed-derived text (summary, tags, related values) by `clean_text` when a `SourceResult` or `RelatedIOC` is built or loaded; `raw` is the only field kept as received; other feed-derived strings (summary, tags, related values, KEV names, shared indicators, GeoIP names) are cleaned the same way.
- An error or rate limit never produces a `SAFE` verdict.

## Testing rules

- TDD for logic: write the failing test first for `detect`, `verdict`, `engine`, each source, `notify`.
- **No live network calls in tests.** Use `respx` with recorded fixtures in `tests/fixtures/<source>/`. A test that hits the network is a bug.
- Recording fixtures: one manual live call, save JSON, scrub keys/emails/account IDs, trim to the fields used.
- `verdict` tests are table-driven and must cover: errors-are-not-clean, high-weight `RATE_LIMITED` blocks `SAFE`, INFO rows don't count toward `min_sources_for_safe`, benign override cannot clear `MALICIOUS`.
- Tests are deterministic: freeze time where TTL/caching matters, no sleeps (patch the limiter).
- Bug fix = regression test first.

## Code style (project-specific)

- Python 3.12+, `pyright` strict. `Any` only where untyped vendor JSON enters (`raw: dict[str, Any]` on `SourceResult`, `jsonutil`, `json_object`, JSON-shaped dicts) and in `**kw` pass-through. Narrow it at that boundary.
- `ruff` is the formatter and linter; don't argue with it.
- Async all the way in core; CLI calls `asyncio.run` once.
- Frontend: TypeScript strict, Tailwind with tokens from `web/src/styles/tokens.css`. No hardcoded colors. Verdict level is always shown with text/icon, never color alone.
- **Design source of truth: `docs/DESIGN.md`** (references in `docs/design/`). Violet is the only accent; red/amber/teal/grey are reserved for verdict levels.
- **Skills:** invoke `frontend-design` before any UI work. Invoke `dataviz` before building the map, graph, source waterfall or any chart.
- IOCs, hashes and numbers use the monospace font.

## Workflow

- Work one milestone at a time (M0 → M9 in `PLAN.md`). A milestone is done only when its acceptance check in `PLAN.md` passes and is shown.
- Before a milestone: re-read its `PLAN.md` section, list files to touch, then implement.
- Don't start the next milestone without asking.
- Don't add dependencies beyond `PLAN.md` without asking.
- Live API calls during development cost quota (VT: 4/min, 500/day). Ask before running anything that makes more than a few.
- Code audits (dead code, duplicates, performance, best practices): follow `docs/CODE_QUALITY.md`. Report findings first; change nothing until approved.

## Git

- Repo lives on `main`; CI is `.github/workflows/ci.yml`.
- Commit only when asked. Message format: `TYPE: summary` (`ADD`, `FIX`, `UPDATE`, `REMOVE`, `REFACTOR`, `DOCS`, `TEST`, `CHORE`), imperative, ≤72 chars.
- Branches: `type/short-description`. One milestone = one branch.
- `.gitignore` must include `.env`, `*.db`, `src/verdikt/web_dist/`, `web/node_modules/`, `*.mmdb`, `.codegraph/`.

## Data files

- GeoLite2 `.mmdb` files live outside the repo (path in `.env`, `VERDIKT_GEOIP_DIR`). Never commit them (MaxMind license).
- SQLite cache/history path from `.env` (`VERDIKT_DB_PATH`), default under the user data dir, not the repo.

## Licensing notes

VirusTotal public API and Shodan InternetDB forbid commercial products. IPinfo Lite requires attribution if used. Keep these notes in the README.
