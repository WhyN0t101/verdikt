# verdikt — Implementation Plan

verdikt takes an IOC (IP, domain, URL or hash), queries several threat-intelligence sources in parallel, returns a short verdict, optionally notifies Slack, Telegram, Discord, Microsoft Teams or email, and shows the result in a local browser UI with a map and a relationship graph.

Guiding rule: the core is a Python library that returns one JSON model. The CLI, the API, the UI and any later SOAR integration all consume that model. Nothing else talks to threat-intel APIs.

---

## 1. Architecture

```
            ┌──────────── verdikt core (Python library) ────────────┐
 CLI ──────►│ detect ─► engine ─► sources/* (async, rate-limited)   │
 (typer)    │                 └─► enrich (geo, dns)                 │
            │                 └─► verdict (rules.yaml)              │
 API ──────►│                 └─► cache (sqlite)                    │
 (FastAPI)  │ ──► Report (pydantic JSON)  ──► notify (slack/tg)     │
   ▲        └───────────────────────────────────────────────────────┘
   │ JSON
 Browser UI (React SPA, served by FastAPI on 127.0.0.1)
```

- One process. `verdikt ui` starts FastAPI and opens a browser tab.
- The frontend never sees API keys and never calls third-party intel APIs.

---

## 2. Tech stack

### Backend (Python 3.12+)

| Concern | Choice | Notes |
|---|---|---|
| Packaging | `uv`, `pyproject.toml` | Single `verdikt` console script |
| HTTP | `httpx.AsyncClient` (one shared client) | Per-source timeout 10 s |
| Rate limiting | `aiolimiter` (one limiter per source) | VT: 4/min |
| Retries | `tenacity` | Retry on 429/5xx, max 3. Every attempt takes a limiter slot and is charged to the daily budget. `Retry-After` longer than the source timeout → return `RATE_LIMITED`, don't wait |
| Models | `pydantic` v2 | `Report` is the contract for CLI, API, UI |
| Config | `pydantic-settings` (`.env`) + `rules.yaml` (parsed with `pyyaml`) | Missing key disables that source, never crashes |
| IOC refang | `ioc-fanger` | `ioc-finder` later for "paste a whole ticket" mode |
| Geo/ASN | MaxMind GeoLite2 City + ASN (`maxminddb`) | Local lookups: no quota, no IOC leak. IPinfo Lite optional |
| DNS | `dnspython` | Off by default (see Security) |
| Cache/history | `sqlite3` (stdlib) | Own table, because abuse.ch APIs use POST and HTTP caches skip POST. Always stores `raw`; output strips it unless `--raw` |
| IDs | `uuid.uuid4().hex` (stdlib) | No ULID dependency; history sorts by `created_at` |
| CLI | `typer` + `rich` | |
| API | `fastapi` + `uvicorn` | Serves `/api/*` and the built SPA |
| Lint/type | `ruff`, `pyright` (strict) | |
| Tests | `pytest`, `pytest-asyncio`, `respx` | Recorded JSON fixtures, no live calls in CI |

### Frontend (`web/`)

| Concern | Choice |
|---|---|
| Build | Vite + React + TypeScript (SPA, no SSR) |
| Styling | Tailwind CSS (plain components in `components/ui`, no shadcn/ui), design tokens as CSS variables |
| Data fetching | TanStack Query |
| Map | Dot-matrix world map drawn on a canvas from a bundled land outline; arcs are great-circle points computed in a small helper. No map library, no deck.gl |
| Basemap | None: no tiles, so the map makes no remote request and cannot reveal what you investigate |
| Graph | Cytoscape.js + `cytoscape-fcose` layout |
| Fonts | Familjen Grotesk Variable (UI), Martian Mono Variable (IOCs, hashes, JSON), self-hosted |
| Land data | `web/src/data/land.json`: Natural Earth land rasterised to a 2° dot grid by `npm run gen:land` (devDependencies `world-atlas`, `topojson-client`, used only by that script) |
| Tests | Vitest for utilities, one Playwright smoke test |

---

## 3. Sources

| Source | IP | Domain | URL | Hash | Key | Cache TTL | Weight |
|---|---|---|---|---|---|---|---|
| VirusTotal v3 | ✓ | ✓ | ✓ | ✓ | yes | 24 h | high |
| AbuseIPDB v2 | ✓ | | | | yes | 6 h | medium |
| urlscan.io (search only) | ✓ | ✓ | ✓ | sha256 | optional | 12 h | context only |
| ThreatFox | ✓ | ✓ | ✓ | ✓ | abuse.ch | 6 h | high |
| URLhaus | ✓ (host) | ✓ | ✓ | | abuse.ch | 6 h | high |
| MalwareBazaar | | | | ✓ | abuse.ch | 7 d | high |
| AlienVault OTX | ✓ | ✓ | ✓ | ✓ | optional | 24 h | context only |
| GreyNoise Community | ✓ | | | | optional | 24 h | benign override |
| Shodan InternetDB | ✓ | | | | no | 7 d | context only |
| Hybrid Analysis | | | | ✓ | yes | 7 d | medium |
| `hashlookup` (CIRCL) | | | | ✓ | no | 7 d | softens SUSPICIOUS / flags `KnownMalicious` |
| `rdap` (domain age) | | ✓ | | | no | 7 d | low (suspicious when under 30 days) |
| `crtsh` (certificate transparency) | | ✓ | | | no, opt-in `VERDIKT_CRTSH` | 24 h | context only |
| `passivedns` (VirusTotal resolutions) | ✓ | ✓ | | | VT key, opt-in `VERDIKT_VT_RESOLUTIONS` | 24 h | context only |
| `localfeeds` (Feodo, Spamhaus DROP, Tor exits, Tranco, OpenPhish, imported MISP/STIX) | ✓ | ✓ | ✓ | ✓ | no, `verdikt feeds update` | local | blocklist (malicious) / top site (softens SUSPICIOUS) |

"Context only" sources add data (ports, CVEs, ASN) but never change the verdict.

Every source name above (`virustotal`, `abuseipdb`, `urlscan`, `threatfox`, `urlhaus`, `malwarebazaar`, `otx`, `greynoise`, `internetdb`, `hybrid`, `hashlookup`, `rdap`, `crtsh`, `passivedns`, `localfeeds`) is registered in `sources/__init__.py`; `tests/test_plan_sync.py` fails if a source is missing from this section.

**VirusTotal metrics.** Besides the engine counts (`malicious`, `suspicious`, `harmless`, `undetected`, `total`) the VT source reports `last_analysis_age_days` (whole days since `last_analysis_date`, never negative, omitted when the field is missing or not a JSON integer) and `reputation` (integer, may be negative, omitted when absent). No default rule reads them: they are shown in the UI "Why" panel and can be used in a private `rules.yaml` (rule keys are OR'ed, so a lone `last_analysis_age_days__lt` rule would flag every fresh scan: pair it with care). One engine hit on a months-old scan is weaker than one on a fresh scan, which is why the age is exposed.

---

## 4. Repository layout

```
verdikt/
├── pyproject.toml
├── .env.example                 # every key and setting, empty values
├── README.md
├── src/verdikt/
│   ├── models.py                # IOCType, IOC, SourceResult, Report, Graph, GeoPoint, CveInfo, SeenBefore
│   ├── detect.py                # refang, normalize, classify, reject private/internal targets
│   ├── extract.py               # indicators from free text (ioc-finder + detect)
│   ├── config.py                # Settings (pydantic-settings), Rules, load rules.yaml
│   ├── rules.yaml               # default thresholds and weights
│   ├── engine.py                # fan-out, timeouts, cache, enrichment, assemble Report
│   ├── verdict.py               # pure function: results + rules -> verdict, confidence, why
│   ├── cache.py                 # sqlite: source cache, reports, budget, stats, watchlist, cases,
│   │                            #   feedback, ioc index, kv (scheduler last_run, notify cooldown)
│   ├── watch.py                 # watchlist re-checks (4 at a time, errors are not changes)
│   ├── scheduler.py             # in-process jobs for verdikt ui (watch, feeds), off by default
│   ├── audit.py                 # JSON-lines audit log, rotates at 10 MB
│   ├── stix.py  misp.py         # STIX 2.1 bundle and MISP event export
│   ├── export.py                # Markdown / HTML report and case export
│   ├── jsonutil.py              # typed accessors for untyped vendor JSON
│   ├── httputil.py              # Retry-After parsing shared by sources and notifiers
│   ├── sources/
│   │   ├── base.py              # Source protocol, Gate (limiter, budget, retries), BaseSource
│   │   ├── virustotal.py  abuseipdb.py  urlscan.py  hybrid.py
│   │   ├── threatfox.py   urlhaus.py    malwarebazaar.py
│   │   ├── otx.py  greynoise.py  internetdb.py  hashlookup.py
│   │   ├── rdap.py  crtsh.py  passivedns.py
│   │   ├── feeds.py             # local feeds: download, parse, match (LocalFeeds source)
│   │   └── importers.py         # MISP event / STIX bundle -> local list
│   ├── enrich/
│   │   ├── geo.py               # GeoLite2 lookups
│   │   ├── dns.py               # optional resolution
│   │   └── cve.py               # CISA KEV and EPSS for the CVEs InternetDB reports
│   ├── notify/
│   │   ├── __init__.py          # Slack, Telegram, Discord, Teams, email; Retry-After; cooldown
│   │   └── format.py            # defang, escaping, message text
│   ├── cli.py                   # typer app
│   ├── api/app.py               # FastAPI routes + static mount
│   └── web_dist/                # built SPA (generated, git-ignored)
├── web/                         # React app source
│   ├── src/
│   │   ├── api.ts  model.ts  types.ts   # types.ts is generated from OpenAPI
│   │   ├── components/          # command bar, verdict panel, source table, map, graph, overview,
│   │   │                        #   batch, cases, history, raw JSON (shared UI in components/ui)
│   │   └── styles/tokens.css
│   └── e2e/                     # Playwright, against scripts/e2e_server.py
├── scripts/                     # dump_openapi.py, e2e_server.py
├── integrations/                # Cortex analyzer, Shuffle app
├── docs/                        # DESIGN, API, SOURCES, INTEGRATIONS, CODE_QUALITY
└── tests/
    ├── fixtures/<source>/*.json # recorded or hand-made responses (see fixtures/README.md)
    ├── test_detect.py  test_verdict.py  test_engine.py  test_cache.py
    ├── test_sources*.py  test_feeds.py  test_cve.py  test_notify.py
    ├── test_api.py  test_cli.py  test_dashboard.py  test_cases.py  test_scheduler.py
    ├── test_features.py  test_hardening.py  test_plan_sync.py
```

---

## 5. Core data model

```python
class IOCType(StrEnum):
    IP, DOMAIN, URL, MD5, SHA1, SHA256


class Status(StrEnum):
    OK, NOT_FOUND, ERROR, RATE_LIMITED, SKIPPED


class Level(StrEnum):  # matches Cortex taxonomy levels
    MALICIOUS, SUSPICIOUS, SAFE, INFO, UNKNOWN
    # INFO is a row level only (context sources). A Report never has level INFO.


class SourceResult(BaseModel):
    source: str
    status: Status
    metrics: dict[str, int | bool]  # always filled: {"malicious": 12, "match": True, ...}
    level: Level  # set by verdict.py from rules.yaml, never by the source
    summary: str  # "12/94 engines malicious"
    tags: list[str]  # malware families, "tor", "scanner"
    link: HttpUrl | None  # permalink to the source's web UI
    related: list[RelatedIOC]  # feeds the graph
    cached: bool
    fetched_at: datetime
    raw: dict[str, Any] | None  # always cached; stripped from output unless --raw / raw tab


class Report(BaseModel):
    schema_version: int  # bump on breaking change
    id: str  # uuid4 hex
    ioc: str
    ioc_type: IOCType
    level: Level  # MALICIOUS | SUSPICIOUS | SAFE | UNKNOWN
    agreeing: int  # verdict-bearing sources agreeing with level
    total: int  # verdict-bearing sources that returned OK; UI formats "4/6"
    confidence: Confidence  # low | medium | high, from rules.yaml weights
    reasons: list[str]  # why this verdict, human readable
    results: list[SourceResult]
    geo: list[GeoPoint]
    graph: Graph  # nodes + edges
    seen_before: list[
        SeenBefore
    ]  # earlier reports sharing the IOC or related indicators (ASNs excluded)
    duration_ms: int
    created_at: datetime
```

The model is versioned (`schema_version`) because the UI and later SOAR glue depend on it.

---

## 6. Source plugin interface

```python
class Source(Protocol):
    name: str
    supports: frozenset[IOCType]
    requires_key: bool
    rate: tuple[int, float]  # calls, seconds
    ttl: timedelta
    daily_budget: int | None  # requests/day; None = uncapped (usage still counted)
    timeout: float  # per-request seconds (crt.sh needs more than the default)
    quota_group: (
        str | None
    )  # share another source's limiter and budget (passive DNS uses VirusTotal's)
    enabled: bool  # property: key present or key not required

    async def query(self, ioc: IOC, http: Gate) -> SourceResult: ...
```

`Gate` is a thin per-source wrapper over the one shared `httpx.AsyncClient`: every attempt (retries included) charges the daily budget and takes a limiter slot; 429/5xx are retried up to 3 times; a `Retry-After` (seconds or HTTP-date) longer than the timeout returns the 429 at once. Sources subclass `BaseSource`, which maps timeouts, network errors, malformed bodies and budget exhaustion to `ERROR` / `RATE_LIMITED` so `query` never raises.

- Built-in sources register in `sources/__init__.py`.
- Later: third-party sources via the `verdikt.sources` entry-point group. Adding a feed is then one file and no core change.
- Each source maps its raw response to a `SourceResult` and fills `metrics` with plain facts (counts, scores, booleans). It never sets `level` and holds no thresholds; `verdict.py` computes every row level and the final verdict from `rules.yaml`.

---

## 7. IOC detection and normalization (`detect.py`)

1. Strip whitespace, refang (`hxxp`, `[.]`, `(.)`, `[:]`).
2. Classify: `ipaddress` → IP; hex length 32/40/64 → MD5/SHA1/SHA256; contains scheme → URL; else domain regex.
3. Normalize: lowercase domains and hashes, IDNA encode, strip trailing dot, canonical URL.
4. Reject internal targets with a clear message, for every IOC type:
   - IPs, and IP-literal hosts inside URLs, where `not ip.is_global`.
   - Hostnames (domain IOCs and URL hosts) that are `localhost`, single-label (`intranet`), or end in `.local`, `.internal`, `.lan`, `.corp`, `.home.arpa`.
   - Hostnames ending in any suffix from the `VERDIKT_INTERNAL_DOMAINS` setting (your company domains).
5. Unknown input exits with code 1 (the §10 "any error" code; 4 is not used) and a message. No API call is made.
6. Domains whose last label is all digits or `0x` hex (`127.1`, `0x7f.0.0.1`) are rejected: browsers read them as IPs, so they are not public names.
7. Input longer than 2048 characters is rejected before any parsing. A suffix in the internal list also matches the bare apex (`corp.example.com`, not only `*.corp.example.com`).

---

## 8. Engine (`engine.py`)

1. Detect IOC.
2. Pick sources that support the type and have keys.
3. For each source: cache hit within TTL → use it; else, per attempt (including retries): check daily budget → acquire limiter → query with timeout.
   - shortcut: limiter and budget are per process; `verdikt ui` + `verdikt bulk` at once double the rate. Move budget/limiter state to sqlite if that becomes normal.
4. `asyncio.gather(..., return_exceptions=True)`: one failing source yields `Status.ERROR`, never a failed report.
5. Enrich: geo for every IP in the IOC and in `related`; DNS only if enabled.
6. Build the graph from `related`.
7. Run `verdict.decide()`.
8. Save the report to history. Return it.

---

## 9. Verdict rules (`verdict.py` + `rules.yaml`)

Rules are plain YAML structure validated by pydantic. No string expressions, no parser, no `eval`.
Integer value = "metric ≥ value". Boolean value = "metric is that value". A key ending in `__lt` flips the integer comparison: `age_days__lt: 30` means `age_days < 30`.

```yaml
# Integer value = "metric >= value". Boolean value = "metric is that value".
# Inside one source, keys are OR'ed.
malicious:                      # any match -> MALICIOUS
  virustotal: {malicious: 5}
  localfeeds: {blocklisted: true}      # Feodo C2 or Spamhaus DROP, matched locally
  abuseipdb: {score: 75}
  threatfox: {match: true}
  malwarebazaar: {match: true}
  urlhaus: {url_online: true}          # the exact URL is listed and online
suspicious:                     # any match -> SUSPICIOUS
  virustotal: {malicious: 2, suspicious: 1}   # one malicious engine alone is usually a false positive
  abuseipdb: {score: 25}
  hybrid: {malicious: true}
  hashlookup: {known_malicious: true}
  urlhaus: {online: true}              # a host with an online listed URL: popular hosts have some
  rdap: {age_days__lt: 30}            # registered in the last 30 days: weak, so weight 1
benign_override:                # downgrade SUSPICIOUS -> SAFE; never touches MALICIOUS
  greynoise: {riot: true}
  hashlookup: {known_good: true}       # known file with no malicious flag
  localfeeds: {top_site: true}         # exact Tranco top-site match only
# rows get INFO, never count toward min_sources_for_safe. OTX counts every pulse that merely
# mentions an indicator (50 for example.com) and urlscan search carries no verdicts on the free plan.
context_only: [internetdb, greynoise, otx, urlscan, crtsh, passivedns]
high_weight: [virustotal, threatfox, urlhaus, malwarebazaar]
min_sources_for_safe: 2
# feeds that only list known-bad items: "no match" is absence of evidence, not evidence of safety
listing_feeds: [threatfox, urlhaus, malwarebazaar, localfeeds]
min_high_weight_for_safe: 1     # SAFE needs this many successful high-weight non-feed sources
weights:                        # evidence weight per source -> Report.confidence (never the level)
  virustotal: 3
  threatfox: 3
  urlhaus: 3
  malwarebazaar: 3
  abuseipdb: 2
  hybrid: 2
  hashlookup: 2
  localfeeds: 3
default_weight: 1
confidence_high: 5              # agreeing weight >= this -> high
confidence_medium: 3            # agreeing weight >= this -> medium, below -> low
```

Inside one source, keys are OR'ed (VT malicious ≥ 2 **or** suspicious ≥ 1). `tests/test_plan_sync.py` fails if the yaml block above differs from `src/verdikt/rules.yaml`.

Decision order in `decide()`:
1. Row levels: each OK row gets MALICIOUS / SUSPICIOUS / SAFE from the same rules. Context-only sources (InternetDB, GreyNoise, geo) get INFO.
2. Any MALICIOUS row → MALICIOUS.
3. Any SUSPICIOUS row → SUSPICIOUS, unless a `benign_override` matches **and** no high-weight source is blocking (see 4) → SAFE.
4. Otherwise SAFE only if **both**:
   - at least `min_sources_for_safe` **verdict-bearing** sources returned OK (INFO rows don't count),
   - at least `min_high_weight_for_safe` of them are high-weight sources (weak sources alone never give SAFE), and
   - no high-weight source that supports this IOC type returned ERROR, RATE_LIMITED or NOT_FOUND.
5. Otherwise UNKNOWN.

- `Report.confidence` (low / medium / high) is the summed `weights` of the verdict rows that agree with the final level, against `confidence_high` / `confidence_medium`. Conflicting evidence at least as heavy as the agreeing evidence, or an UNKNOWN verdict, gives low. Weights never change the level.
- `decide()` is a pure function, fully unit-tested with table-driven cases.
- Every rule that fires adds a line to `Report.reasons`.
- `agreeing` / `total` count verdict-bearing OK rows only.
- `NOT_FOUND` (no record at the source, e.g. VT 404, GreyNoise not observed) is neither clean nor an error: it does not count toward `min_sources_for_safe`. From a high-weight source (VT) it blocks SAFE, because abuse.ch feeds only list known-bad items and an unseen IOC is not a clean one. Feeds that answered "no match" (ThreatFox, URLhaus, MalwareBazaar) return `OK` with `match: false`. urlscan and OTX are context only (INFO rows).
- ThreatFox search is a substring search: only entries whose `ioc` equals the IOC (or `ip:port`) count as a match.
- Errors and rate limits never count as clean. Example that must give UNKNOWN: VT RATE_LIMITED, AbuseIPDB score 0, InternetDB OK.

---

## 10. CLI (`cli.py`)

```
verdikt check <ioc> [--json] [--raw] [--stix] [--misp] [--no-cache] [--notify slack|telegram|discord|teams|email] [--min-level suspicious]
verdikt extract [FILE|-]                         # list the indicators in free text, nothing is looked up
verdikt bulk <file> [--json] [--csv] [--text] [--resume] [--notify ...] [--min-level suspicious]
verdikt sources                                  # list sources, enabled/disabled, quota left
verdikt doctor                                   # what is configured and what is missing
verdikt ui [--port 8765] [--no-open] [--dev]
verdikt cache clear [--source NAME]
verdikt feeds update [--top N]                   # download blocklists, Tor exits, Tranco, OpenPhish, KEV, EPSS
verdikt feeds import <file> --name NAME [--all]  # MISP event or STIX bundle as a local blocklist
verdikt feeds forget NAME
verdikt feeds status
verdikt watch add <ioc>
verdikt watch list
verdikt watch remove <ioc>
verdikt watch run [--notify ...] [--min-level suspicious]   # re-check every entry, bypassing the cache
```

`bulk` reads one IOC per line, or free text with `--text`; `--csv` prints one row per indicator (cells that start with `= + - @` get a leading apostrophe), `--resume` skips indicators checked in the last 24 hours. Cases have no CLI: they live in the UI and API (§12).

Exit codes (kept off 1 and 2, which Python crashes and Click usage errors already use):

| Code | Meaning |
|---|---|
| 0 | SAFE |
| 1 | any error (crash, bad input, all sources failed) |
| 2 | usage error (Click) |
| 10 | SUSPICIOUS |
| 11 | MALICIOUS |
| 12 | UNKNOWN |

`bulk` exits with the highest-severity code across all IOCs (MALICIOUS > SUSPICIOUS > UNKNOWN > SAFE).

---

## 11. Notifications (`notify/`)

- Platforms: Slack (incoming webhook), Telegram (Bot API `sendMessage`, `parse_mode=HTML`), Discord (webhook; always `allowed_mentions: {parse: []}` so feed text cannot ping `@everyone`), Microsoft Teams (webhook), and email (stdlib `smtplib`: STARTTLS, or implicit TLS on port 465; login only after the channel is encrypted).
- Send only at or above `--min-level` (default `suspicious`). `VERDIKT_NOTIFY_COOLDOWN_HOURS` (default 0 = off) skips a repeat alert for the same indicator at the same level.
- Always defang IOCs in messages.
- Escape all feed-derived text (tags, family names, summaries) before sending. Every channel first puts it on one line and defangs every dot. Telegram then goes through `html.escape()`; Slack replaces `&` `<` `>` with `&amp;` `&lt;` `&gt;` and drops backticks, `*` and `~`; Discord and Teams replace `(` and `)` with `{` and `}`. Otherwise `a<b` makes Telegram return 400 (alert lost) and `<https://evil|Open report>` renders as a fake Slack link.
- **Rate limits.** Webhooks answer HTTP 429 under bursts (bulk runs, a big watch re-check). A 429 whose `Retry-After` (seconds or an HTTP date) is at most the notify timeout (10 s) is waited out and retried once; a longer one, a missing header, or a second 429 is reported as `rate limited (HTTP 429), retry after N s`. Nothing waits longer than the timeout. Other HTTP errors are not retried.
- A failed send is logged and reported in the CLI output, never swallowed; the report never contains the webhook URL or bot token.
- Message: level emoji + IOC + type, one line per source that hit, link to the VT/urlscan page.
- Credentials live in `.env` only: `VERDIKT_SLACK_WEBHOOK_URL`, `VERDIKT_TELEGRAM_BOT_TOKEN` + `VERDIKT_TELEGRAM_CHAT_ID`, `VERDIKT_DISCORD_WEBHOOK_URL`, `VERDIKT_TEAMS_WEBHOOK_URL`, `VERDIKT_SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_FROM` / `_TO`.

---

## 12. API (`api/app.py`)

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/check` | Body `{ioc, no_cache}` → `Report` |
| GET | `/api/reports` | History list (paged) |
| GET | `/api/reports/{report_id}` | One stored report (`?raw=true` keeps vendor payloads) |
| GET | `/api/reports/{report_id}/stix` | The report as a STIX 2.1 bundle (`application/stix+json`) |
| GET | `/api/reports/{report_id}/misp` | The report as a MISP event JSON |
| GET | `/api/reports/{report_id}/export` | `?format=md\|html`: shareable, defanged, escaped document |
| POST | `/api/reports/{report_id}/feedback` | Body `{label: false_positive\|false_negative\|correct, note?}` → recorded entry |
| GET | `/api/feedback` | Recorded analyst feedback, newest first |
| GET | `/api/sources` | Source status, quota left |
| GET | `/api/health` | Liveness |
| GET | `/api/stats` | Dashboard data: checks per day, source health, recurring infrastructure, feedback counts |
| GET, POST, DELETE | `/api/watchlist` | List with recent changes; watch a report's indicator (`{report_id}`); stop watching (`?ioc=`) |
| POST | `/api/watchlist/recheck` | Re-check every entry now (bypasses the cache); returns the verdict changes |
| GET | `/api/feeds` | Downloaded and imported feeds with entry counts |
| POST | `/api/feeds/update` | Download the feeds |
| POST, DELETE | `/api/feeds/import` | Import a MISP event or STIX bundle as a local list (`{name, content}`); remove one (`?name=`) |
| POST | `/api/extract` | `{text}` → indicators found and skipped (internal targets); nothing is looked up |
| GET, POST | `/api/cases` | List cases (`?tag=`); create one (`{title, notes?, tags?}`) |
| GET, PATCH, DELETE | `/api/cases/{case_id}` | Read, update, delete a case |
| POST | `/api/cases/{case_id}/reports` | Add a report (`{report_id}`); reports in a case survive retention |
| DELETE | `/api/cases/{case_id}/reports/{report_id}` | Remove a report from the case |
| GET | `/api/cases/{case_id}/export` | `?format=md\|html`: the whole case as one document |
| GET | `/api/scheduler` | Jobs `watch` and `feeds`: interval, `running`, `progress` ("3/50"), last run and result |
| POST | `/api/scheduler/{name}/run` | Run a job now and wait for it |
| POST | `/api/scheduler/{name}/start` | Start a job in the background; poll `GET /api/scheduler` |
| GET | `/*` | Built SPA (`web_dist/`) |

`tests/test_plan_sync.py` fails if a route or method in the API schema is missing from this table, or a route here does not exist.

Frontend TypeScript types are generated with `openapi-typescript` from the schema dumped offline by `scripts/dump_openapi.py` (`cd web && npm run gen:types`), because `/openapi.json` is token-gated at runtime. Backend and UI never drift.

All `/api/*` routes and `/openapi.json` require the `X-Verdikt-Token` header. `verdikt ui` uses a fresh token per run unless `VERDIKT_SESSION_TOKEN` is set (for Shuffle/Cortex calling a long-running instance). `--dev` uses the fixed token `dev-token`, which Vite's proxy sends.

---

## 13. UI

**Visual direction, palette and layout mapping live in `docs/DESIGN.md`** (references in `docs/design/`). That file wins over the wireframe and token list below where they differ. The map is a dot-matrix canvas with no remote tiles and no map library (so there is no zoom cap to keep). shadcn/ui is not used: plain Tailwind components, to avoid the Radix dependency tree. Fonts (Familjen Grotesk, Martian Mono) are self-hosted via `@fontsource-variable/*`.

### Layout

```
┌────────────────────────────────────────────────────────────────┐
│ verdikt   [ ⌘K  Paste IP, domain, URL or hash…          ] [▶] │
├───────────────┬────────────────────────────────────────────────┤
│ HISTORY       │ ┌ VERDICT CARD ─────────────────────────────┐  │
│ 185.220.101.4 │ │ ● MALICIOUS   185.220.101.4  IP           │  │
│ evil.com      │ │ 4/6 sources · AS4224 · DE · 1.2 s         │  │
│ 44d88…        │ │ Reasons: ThreatFox C2 match; VT 12/94 …   │  │
│               │ └───────────────────────────────────────────┘  │
│               │ ┌ SOURCES ──────────────────────────────────┐  │
│               │ │ VirusTotal   ● 12/94 malicious       ↗    │  │
│               │ │ AbuseIPDB    ● 100% · 2,341 reports  ↗    │  │
│               │ │ GreyNoise    ○ not a known scanner        │  │
│               │ └───────────────────────────────────────────┘  │
│               │ [ Map ] [ Graph ] [ Raw JSON ]                 │
│               │ ┌──────────────────────────────────────────┐   │
│               │ │   dot-matrix map, arcs, pulsing dots     │   │
│               │ └──────────────────────────────────────────┘   │
└───────────────┴────────────────────────────────────────────────┘
```

### Design

- Dark theme first, light theme via the same tokens.
- Tokens in `tokens.css`: `--bg`, `--panel`, `--border`, `--text`, `--muted`, `--accent`, `--lvl-malicious`, `--lvl-suspicious`, `--lvl-safe`, `--lvl-unknown`.
- Monospace for every IOC, hash and number. Copy button on each IOC (copies defanged by default).
- Keyboard first: `⌘K`/`Ctrl+K` focus search, `Enter` run, `1/2/3` switch tabs, `Esc` clear.
- Skeleton loaders per source row while results stream in.
- Accessible: level is shown with text and icon, never colour alone. Contrast ≥ 4.5:1.

### Map

- Markers for the IOC IP and every related IP, coloured by level.
- Arcs from the IOC to related infrastructure (resolved IPs, C2 peers).
- Hover: IP, ASN, country, level. Click: pivot.
- Geo is approximate. The tooltip says so for cloud/VPN ASNs.
- The map has no tiles, so it makes no request (see stack table).

### Graph

- Node types: ip, domain, url, hash, malware family, ASN. Shape per type, colour per level.
- Edges labelled: `resolves_to`, `hosted_on`, `drops`, `contacts`, `belongs_to`.
- Click a node → "Check this IOC" (pivot). Pivots respect quota and show remaining budget.

---

## 14. Security

- **Bind to `127.0.0.1` only.** The process holds your API keys.
- **CSRF and DNS rebinding:** any web page you visit can send requests to `localhost`. Mitigations:
  - Reject requests whose `Host` header is not `127.0.0.1:<port>` or `localhost:<port>`.
  - Require `Content-Type: application/json` on POST (forces a CORS preflight) and send no CORS headers.
  - Generate a per-run session token, inject it into the served page, require it on `/api/*`.
- Keys only in `.env`, which is git-ignored. `.env.example` has empty values. Keys are never logged or returned by the API.
- **Do not submit scans to urlscan by default.** Submissions are public unless set private, and make urlscan visit the target.
- **DNS resolution is off by default.** Resolving a domain can reach the attacker's authoritative name server. Prefer passive DNS from VT/OTX.
- Internal targets are never sent to third parties: private IPs, URLs with private/internal hosts, internal hostnames (§7 step 4).
- Render source text as text, never as HTML: threat-feed data is attacker-controlled. Same for notifications: escape before sending (§11).
- Map tiles would be a lookup leak too: the map uses none and must make no remote request.

---

## 15. Testing

- `test_detect.py`: refang, classification, normalization, internal-target rejection (`192.168.1.10`, `http://192.168.1.10/admin`, `http://localhost:8080/`, `intranet`, `intranet.corp`, `host.local`, a `VERDIKT_INTERNAL_DOMAINS` suffix).
- `test_verdict.py`: table-driven rules, including: errors-are-not-clean, high-weight RATE_LIMITED blocks SAFE (VT rate-limited + AbuseIPDB 0 + InternetDB OK → UNKNOWN), INFO rows don't count toward `min_sources_for_safe`, benign override cannot clear MALICIOUS, row levels match final thresholds.
- `test_engine.py` also: retries take a limiter slot and budget each; `Retry-After` > timeout → RATE_LIMITED without waiting; cache hit still has `raw` for `--raw`.
- `test_cli.py`: exit codes 0/1/10/11/12, bulk highest-severity code.
- `test_sources_*.py`: each source against recorded hit/miss/error/429 fixtures (`respx`).
- `test_engine.py`: one source raising still yields a report; cache hit skips the HTTP call; budget exhausted yields `RATE_LIMITED`.
- `test_api.py`: Host header check, token check, `/api/check` happy path.
- `test_notify.py`: defanging, min-level filter, Telegram HTML escaping (`a<b`), Slack escaping (`<https://evil|Open report>`).
- Frontend: Vitest for formatting helpers; one Playwright smoke test (search → verdict card visible).
- CI (GitHub Actions): ruff, pyright, pytest, frontend build. No live API calls in CI.

---

## 16. Milestones

Each milestone ends with tests passing and an acceptance check.

| # | Scope | Done when |
|---|---|---|
| M0 | Scaffold: uv project, ruff, pyright, pytest, `.env.example`, CI | `uv run pytest` green on an empty suite |
| M1 | `models`, `detect`, VirusTotal, `engine`, `verdikt check` | `verdikt check 8.8.8.8` prints a VT result |
| M2 | AbuseIPDB, urlscan, abuse.ch ×3, OTX, GreyNoise, InternetDB, Hybrid Analysis; `verdict.py`; cache; `--json`; exit codes | IP, domain and hash each return a full report; second run is served from cache |
| M3 | Slack + Telegram notify (Discord, Teams and email came in 19c) | A malicious test IOC posts a defanged message |
| M4 | FastAPI: routes, security checks, `verdikt ui` | `curl` with token returns a Report; without token returns 401 |
| M5 | Frontend: command bar, verdict card, source table, raw JSON, history | Search in browser shows a live result |
| M6 | GeoLite2 enrich + map view | IP IOC shows a marker and arcs to related IPs |
| M7 | Graph view + pivot | Clicking a node runs a new check |
| M8 | `verdikt bulk`, daily budgets, quota display | 50-IOC file finishes without a 429 failure |
| M9 | SOAR prep: Cortex analyzer wrapper and Shuffle app calling `/api/check` | Same verdict from CLI and Shuffle |

---

## 17. Customization later (seams built now, features deferred)

- Sources: entry-point plugins (`verdikt.sources`).
- Rules: user `rules.yaml` overrides the default.
- Notifiers: the same plugin pattern as sources (Slack, Telegram, Discord, Teams and email are built in; only the plugin mechanism is deferred).
- Themes: swap `tokens.css` values.
- Layout: UI panels as independent components, so a dashboard layout can be added without rewriting them.

---

## 18. Open decisions

- GeoLite2 needs a free MaxMind account and periodic database updates (`geoipupdate`).
- VirusTotal public API and Shodan InternetDB terms forbid commercial products. Check before using verdikt at work.
- Free-tier limits for urlscan, OTX, Pulsedive and abuse.ch are not published. Read them from response headers at runtime.
- abuse.ch added v2 URL paths in 2026. Check their changelog before writing those clients.

---

## 19. Additions after M9

Built in one pass at the user's request; each item is covered by tests and, for the UI, by Playwright.

| Area | What | Notes |
|---|---|---|
| Sources | `localfeeds` (Feodo, Spamhaus DROP, Tor exits, Tranco top 100k) and `hashlookup` (CIRCL) | Local data is downloaded by `verdikt feeds update`; lookups need no quota. Tranco matches exactly |
| Context | CISA KEV and EPSS for the CVEs InternetDB reports | `Report.cves`, informational only |
| Model | `Report.confidence`, `seen_before`, `cves`; `schema_version` 3 at the time (now 4, see 19b) | Confidence from `rules.yaml` weights; never changes the level |
| Data | Cache pruning and retention, source statistics, watchlist, analyst feedback, audit log | `VERDIKT_REPORT_RETENTION_DAYS`, `VERDIKT_AUDIT_LOG`, `VERDIKT_FEEDS_DIR` |
| CLI | `feeds update/status`, `watch add/list/remove/run`, `extract`, `bulk --text --csv --resume`, `check --stix` | Scheduling is left to cron or Task Scheduler |
| API | `/api/stats`, `/api/watchlist` (+ recheck), `/api/feeds` (+ update), `/api/extract`, `/api/reports/{id}/stix`, feedback | All token-gated, JSON-only POST (send `{}` for an empty body) |
| UI | Overview, Batch, Vulnerabilities, Seen before, feedback, Watch, STIX export | Plain Tailwind components; activity chart is inline SVG with a data table |
| Tests | Playwright end to end against `scripts/e2e_server.py` | Fake sources, in-memory database, no network; runs in CI |

Built later in 19b: MISP/STIX import, cases (saved investigations), the in-UI scheduler, passive DNS and RDAP domain age. Still not built: live MISP/OpenCTI push and per-result urlscan verdicts (needs a key).

### 19b. Second batch

| Area | What | Notes |
|---|---|---|
| Sources | `rdap` (domain age), `crtsh` (opt-in), `passivedns` (VirusTotal, opt-in), OpenPhish in `localfeeds` | New rule operator `metric__lt: N`. `Source` gained `timeout` and `quota_group` |
| Verdict | URLhaus host listing is suspicious, exact URL listing is malicious | Found on real data: `github.com` was malicious |
| Model | `SourceResult.fired/weight/role`; `schema_version` 4 | The UI "Why" panel |
| Data | Cases (notes, tags, linked reports; reports in a case survive retention), MISP/STIX import as a local list | |
| Output | Markdown and HTML report and case exports, MISP event JSON | Defanged, escaped, no script in HTML |
| Runtime | In-process scheduler in `verdikt ui` for watchlist and feeds (off by default, min 1 h) | `/api/scheduler`, run-now |

Not built: a urlscan per-result verdict source (result pages are 13 to 40 MB each and verdicts cannot be searched on the free plan), live MISP/OpenCTI push, a separate `verdikt daemon`.


### 19c. Review batch

| Area | What | Notes |
|---|---|---|
| Verdict | `virustotal: {malicious: 2}` is suspicious (was 1) | One engine alone is usually a false positive; one `suspicious` engine still counts |
| Watch | Re-checks run 4 at a time; a lookup that ended UNKNOWN because a source errored or was rate limited is not a verdict change | `POST /api/scheduler/{name}/start` runs a job in the background; `GET /api/scheduler` shows `running` and `progress` ("3/50") |
| Scheduler | One lock per job (no double runs); `last_run` persists in the new `kv` table, so a restart keeps the cadence | An overdue job waits a full interval: starting the UI never spends quota |
| Notify | Discord, Teams and email (stdlib `smtplib`); `VERDIKT_NOTIFY_COOLDOWN_HOURS`; `VERDIKT_WATCH_NOTIFY_ANY` | Discord sends `allowed_mentions: {parse: []}`; every dot of feed text is defanged; Slack markup characters in feed text are stripped |
| Detect | NAT64 wrapping a private IPv4 is refused; `.intranet .private .home .localdomain` are internal; `fullmatch` for every anchored pattern | |
| Imports | Parsing runs in a thread; the 100k cap applies before `detect()`; `RecursionError` is an import error | |
| Misc | `verdikt doctor`; audit log rotates at 10 MB to `.1`; locally matched sources (ttl 0) skip the cache write; unique temp names for feed writes; shared quota groups show the group's spend | |
