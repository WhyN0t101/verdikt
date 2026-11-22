# HTTP API

`verdikt ui` serves a JSON API under `/api/` and the built web app from one process. The web app is its only intended client; the same API is what the Shuffle app calls.

## Security model

The process holds your API keys, and any web page you visit can send requests to `localhost`, so every request is checked:

1. **Host header.** Only `127.0.0.1:<port>` and `localhost:<port>` are accepted; anything else gets `421`. This defeats DNS rebinding.
2. **Session token.** Every `/api/*` route and `/openapi.json` requires the `X-Verdikt-Token` header, compared in constant time. Missing or wrong gives `401`. A random token is generated per run and injected into the served page as `<meta name="verdikt-token">`. Set `VERDIKT_SESSION_TOKEN` to choose your own (for automation); `verdikt ui --dev` uses the fixed token `dev-token`.
3. **JSON-only POST.** A POST without `Content-Type: application/json` gets `415`, so a cross-site form cannot reach the API.
4. **No CORS.** No `Access-Control-*` headers are ever sent, so browsers refuse cross-origin reads.
5. **Binding.** The server listens on `127.0.0.1` only.

Responses also carry a strict `Content-Security-Policy` (scripts and connections from `self` only), `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`; `/api/*` responses are `Cache-Control: no-store`. API keys are never returned by any route.

## Routes

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/check` | Body `{"ioc": "...", "no_cache": false}`; returns a `Report` (vendor `raw` stripped) |
| GET | `/api/reports?limit=50&offset=0&q=&level=&type=` | History list, newest first (`limit` 1 to 200). `q` is a literal, case-insensitive substring of the indicator (up to 200 characters; `%` and `_` match themselves). `level` is `malicious`, `suspicious`, `safe` or `unknown`; `type` is `ip`, `domain`, `url`, `md5`, `sha1` or `sha256`. Anything else is `422`. Same row shape as before; there is no total count, so a full page means there may be more |
| GET | `/api/reports/{id}?raw=false` | One stored report; `raw=true` keeps vendor raw responses |
| GET | `/api/reports/{id}/diff?against=` | What changed since another report: verdict, counts, each source that moved (status, level, summary, changed metrics) and reasons added or removed. Without `against`, the newest earlier report of the same indicator; `previous_id` is `null` when there is none. `404` for an unknown id. Never includes `raw`; text is capped at 300 characters and stripped of control and bidi characters. `no_answer` is true when the new row is an error or rate limit, so it is never a clean result |
| GET | `/api/reports/{id}/history` | Everything stored about this report's indicator (exact match): `reports` (up to 50, newest first, `truncated`), `changes` (level changes over them), `cases` that hold them, `watched`, `watched_since` and the watch `events` (newest first). `404` for an unknown id. Case titles are returned as stored: render them as text |
| GET | `/api/reports/{id}/stix` | The report as a STIX 2.1 bundle (`Content-Type: application/stix+json`) |
| POST | `/api/reports/{id}/feedback` | Body `{"label": "false_positive" \| "false_negative" \| "correct", "note": ""}` (note up to 500 characters); returns the stored entry |
| GET | `/api/feedback` | Stored feedback, newest first |
| GET | `/api/reports/{id}/export?format=md\|html` | Shareable Markdown or self-contained HTML (defanged, escaped), as a download |
| GET | `/api/reports/{id}/misp` | The report as a MISP event JSON |
| GET, POST | `/api/cases` | List (optional `?tag=`) or create `{title, notes?, tags?}`. Title up to 120 characters, notes up to 20,000, up to 10 tags |
| GET, PATCH, DELETE | `/api/cases/{id}` | Read, update `{title?, notes?, tags?}`, delete |
| POST | `/api/cases/{id}/reports` | `{report_id}`: add a report. Reports in a case are exempt from retention |
| DELETE | `/api/cases/{id}/reports/{report_id}` | Remove a report from the case |
| GET | `/api/cases/{id}/export?format=md\|html` | The whole case as one document |
| GET | `/api/scheduler` | Jobs `watch` and `feeds`: interval, last run, last result, next run, `running` and `progress` (for example `3/50`) |
| POST | `/api/scheduler/{name}/start` | Start a job now and return at once; poll `GET /api/scheduler` for `running` and `progress` |
| POST | `/api/scheduler/{name}/run` | Run a job now and wait for it to finish |
| POST, DELETE | `/api/feeds/import` | POST `{name, content, all_attributes?}` imports a MISP event or STIX bundle as a local list; DELETE `?name=` removes it |
| GET | `/api/stats?days=30` | Dashboard data: checks per day by level, per-source health, recurring indicators, feedback counts (`days` 1 to 90) |
| GET | `/api/watchlist` | Watched entries, the latest verdict changes and `max_entries` (the cap, 50) |
| POST | `/api/watchlist` | Body `{"report_id": "..."}`: watch that report's indicator, using it as the baseline. `409` when the list (50) is full |
| DELETE | `/api/watchlist?ioc=...` | Stop watching an indicator |
| POST | `/api/watchlist/recheck` | Re-check every entry without the cache; returns the changes: `before` and `after` level, and `evidence_changed` (true when a source that answered both times changed its level, or too few sources still answer; `before == after` then means an evidence-only change) |
| GET | `/api/feeds` | Downloaded feeds: `name`, `count`, `fetched_at` |
| POST | `/api/feeds/update` | Download the feeds (about 14 MB); returns one result per feed |
| POST | `/api/extract` | Body `{"text": "..."}` (up to 200,000 characters): indicators found, and skipped ones with the reason. Nothing is looked up |
| GET | `/api/sources` | Per source: `name`, `enabled`, `requires_key`, `supports`, `used_today`, `daily_budget` |
| GET | `/api/health` | `{"status": "ok"}` |
| GET | `/` and `/assets/*` | The built single-page app |

Errors: `422` for input that is not a usable indicator (unknown format, internal target) with a `detail` message; `404` for an unknown report id; `401`, `415` and `421` as above.

## Example

```bash
VERDIKT_SESSION_TOKEN=change-me uv run verdikt ui --no-open

curl -s http://127.0.0.1:8765/api/check \
  -H "X-Verdikt-Token: change-me" \
  -H "Content-Type: application/json" \
  -d '{"ioc": "8.8.8.8"}'
```

Without the token header the same call returns `401`.

## The `Report` model

`Report` is the contract for the CLI, API, UI and SOAR glue. It carries `schema_version`, bumped on any breaking change.

| Field | Meaning |
|---|---|
| `schema_version` | Integer, currently 4 |
| `id` | UUID4 hex |
| `ioc`, `ioc_type` | Normalized indicator and its type (`ip`, `domain`, `url`, `md5`, `sha1`, `sha256`) |
| `level` | `malicious`, `suspicious`, `safe` or `unknown` (never `info`) |
| `confidence` | `low`, `medium` or `high`: weighted agreement with `level` (see `rules.yaml`). Never changes `level` |
| `cves` | CVEs InternetDB reported for the host, with `kev`, `kev_name`, `kev_added`, `ransomware`, `epss`, `percentile`. Context only: never changes `level` |
| `seen_before` | Earlier reports sharing this indicator or related infrastructure: `report_id`, `ioc`, `level`, `created_at`, `shared` |
| `agreeing`, `total` | Verdict-bearing sources that agree with `level`, out of those that answered successfully |
| `reasons` | Human-readable lines, one per rule that fired |
| `results` | One `SourceResult` per queried source (`fired`, `weight` and `role` explain how it counted): `source`, `status`, `metrics`, `level`, `summary`, `tags`, `link`, `related`, `cached`, `fetched_at`, `raw` |
| `geo` | Located IPs (the indicator and related IPs) with country, city, ASN |
| `graph` | `nodes` and `edges` for the relationship graph |
| `duration_ms`, `created_at` | Timing |

## TypeScript types

The frontend types in `web/src/types.ts` are generated from the OpenAPI schema; never edit them by hand. `/openapi.json` is token-gated at runtime, so the generator dumps the schema offline from the app object:

```bash
cd web && npm run gen:types      # runs scripts/dump_openapi.py, then openapi-typescript
```
