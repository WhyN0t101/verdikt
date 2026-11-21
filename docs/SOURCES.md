# Sources

Each source lives in one file under `src/verdikt/sources/`. It maps the vendor response to a `SourceResult` with plain `metrics`; `verdict.decide()` turns those metrics into row levels using `rules.yaml`. A source never sets a level.

## Overview

| Source | IP | Domain | URL | Hash | Key | Cache TTL | Daily budget | Role |
|---|---|---|---|---|---|---|---|---|
| `virustotal` | yes | yes | yes | yes | required | 24 h | 500 | high weight |
| `abuseipdb` | yes | | | | required | 6 h | 1000 | verdict |
| `urlscan` | yes | yes | yes | sha256 | optional | 12 h | 1000 | context only |
| `threatfox` | yes | yes | yes | yes | abuse.ch | 6 h | none | high weight |
| `urlhaus` | yes (host) | yes | yes | | abuse.ch | 6 h | none | high weight |
| `malwarebazaar` | | | | yes | abuse.ch | 7 d | none | high weight |
| `otx` | yes | yes | yes | yes | optional | 24 h | none | context only |
| `greynoise` | yes | | | | optional | 24 h | none | context, benign override |
| `internetdb` | yes | | | | none | 7 d | none | context only |
| `hashlookup` | | | | yes | none | 7 d | none | verdict (softens or flags) |
| `localfeeds` | yes | yes | yes | yes | none | local | none | blocklists, OpenPhish, Tor, top sites, imported lists |
| `rdap` | | yes | | | none | 7 d | none | verdict (weak): domain age |
| `crtsh` | | yes | | | none | 24 h | none | context only, opt-in |
| `passivedns` | yes | yes | | | VirusTotal | 24 h | shares VT's 500 | context only, opt-in |
| `hybrid` | | | | yes | required | 7 d | 200 | verdict |

"Context only" sources add data (ports, CVEs, hostnames) but never change the verdict. A source with a missing required key is disabled and is not queried.

## Metrics and default rules

Rule semantics: an integer means "metric is at least this value", a boolean means "metric is exactly this", and several keys in one source are OR'ed. A row that matches no rule is SAFE.

| Source | Metrics | Default rule |
|---|---|---|
| `virustotal` | `malicious`, `suspicious`, `harmless`, `undetected`, `total`, `last_analysis_age_days`, `reputation` (no default rule reads the last two) | MALICIOUS at `malicious >= 5`; SUSPICIOUS at `malicious >= 1` or `suspicious >= 1` |
| `abuseipdb` | `score`, `reports`, `tor` | MALICIOUS at `score >= 75`; SUSPICIOUS at `score >= 25` |
| `urlscan` | `scans` | INFO row |
| `threatfox` | `match`, `entries` | MALICIOUS when `match` is true |
| `urlhaus` | `match`, `online`, `url_online`, `urls` | MALICIOUS when `url_online` (the exact URL is listed and online); SUSPICIOUS when the host has an online listed URL. A listing with only offline URLs is not enough |
| `malwarebazaar` | `match` | MALICIOUS when `match` is true |
| `otx` | `pulses` | INFO row. The pulse count includes every pulse that merely mentions the indicator and is capped at 50 (it was 50 for `example.com`) |
| `greynoise` | `noise`, `riot` | INFO row; `riot` true downgrades SUSPICIOUS to SAFE |
| `internetdb` | `ports`, `vulns`, `hostnames` | INFO row |
| `rdap` | `age_days`, `expires_in_days` | SUSPICIOUS when `age_days__lt: 30` (a `__lt` key means less than) |
| `crtsh` | `certs`, `names`, `oldest_days`, `newest_days` | INFO row; subdomains seen on certificates become related domains |
| `passivedns` | `resolutions`, `flagged_neighbours` | INFO row; resolved IPs or pointing domains become related indicators |
| `hashlookup` | `known_good`, `known_malicious` | SUSPICIOUS when `known_malicious`; `known_good` softens SUSPICIOUS to SAFE |
| `localfeeds` | `blocklisted`, `tor_exit`, `top_site` | MALICIOUS when `blocklisted`; `top_site` (exact Tranco match) softens SUSPICIOUS to SAFE; `tor_exit` is a tag |
| `hybrid` | `malicious`, `threat_score`, `reports` | SUSPICIOUS when `malicious` is true |

## Outcomes every source handles

| Outcome | Status | Counts towards SAFE |
|---|---|---|
| Lookup succeeded, indicator present | `ok` | yes (if verdict-bearing) |
| Feed answered "no match" (ThreatFox, URLhaus, MalwareBazaar) | `ok` with `match: false` | yes |
| No record at the source (HTTP 404, GreyNoise not observed) | `not_found` | no; blocks SAFE if the source is high weight |
| HTTP 429, daily budget used up, `Retry-After` longer than the timeout | `rate_limited` | no; blocks SAFE if the source is high weight |
| Other 4xx or 5xx after retries, timeout, network error, malformed body | `error` | no; blocks SAFE if the source is high weight |

`query` never raises: the base class converts timeouts, network errors, odd JSON shapes and exhausted budgets into the statuses above.

## Notes per source

- **VirusTotal v3.** Key goes in the `x-apikey` header. URLs are looked up by their URL-safe base64 id. Domains also yield their resolved IPs as related indicators; files yield a suggested threat label as a malware-family node.
- **AbuseIPDB v2.** Key goes in the `Key` header. Looks back 90 days.
- **urlscan.io.** Search only (`/api/v1/search/`); verdikt never submits a scan, because submissions are public by default and make urlscan visit the target. Context only: on the free plan search rows carry no verdicts, `verdicts.*` fields cannot be searched (HTTP 403) and result pages need a login, so the row reports how many public scans exist and the IPs and domains seen on them. Per-result verdicts could be fetched with a urlscan key; that is not implemented or tested.
- **ThreatFox (v1 API, `Auth-Key` header).** The IOC search is a substring search, so only entries whose `ioc` equals the indicator (or an IP with a port, `1.2.3.4:80`) count as a match. Malware families become graph nodes.
- **URLhaus (v1 API).** Host lookups for IPs and domains, URL lookups for URLs. Hash lookups are not used.
- **MalwareBazaar.** Hash lookups; the signature becomes a malware-family node.
- **AlienVault OTX.** Counts pulses mentioning the indicator; pulse tags become tags.
- **GreyNoise Community.** `riot` means a known benign service. It acts only through `benign_override`.
- **Shodan InternetDB.** Open ports, CVEs and hostnames; hostnames become related domains.
- **Hybrid Analysis v2.** Hash search. `malicious` is true when any report's verdict is malicious.

The abuse.ch v1 endpoints with the `Auth-Key` header are the ones implemented. abuse.ch announced additional v2 paths with the key in the URL; verdikt does not use them because keys should stay out of URLs. Check the abuse.ch changelog before changing these clients. The vendor response shapes were taken from vendor documentation and verified only against hand-trimmed fixtures, not recorded live responses.

## Adding a source

1. Create `src/verdikt/sources/<name>.py` with a subclass of `BaseSource` that sets `name`, `supports`, `requires_key`, `rate`, `ttl` and optionally `daily_budget`, and implements `async lookup(ioc, http)`.
2. Map the response to a `SourceResult` and fill `metrics` with counts, scores or booleans. No thresholds and no `level` in the source. Set `link` to the source's web page for the indicator.
3. Register it in `sources/__init__.py`, add an empty key to `.env.example` and the field to `config.py`.
4. Add rules to `rules.yaml` (and `high_weight` or `context_only` if relevant) and a row to the tables above.
5. Test hit, miss, error and 429 with fixtures in `tests/fixtures/<name>/`. Record a real response once, then scrub keys, emails and account IDs and trim it to the fields used.

## Local feeds and hashlookup

- **localfeeds** reads files written by `verdikt feeds update`; it is disabled until they exist. Feodo Tracker (botnet C2 IPs) and Spamhaus DROP (hijacked or criminal networks, matched as CIDR) mean malicious. The Tor exit list only adds a tag. The Tranco list keeps the top 100,000 domains and matches exactly, so user-content hosts such as `evil.github.io` never inherit a popular parent. It is a list-only feed: "not listed" carries no weight.
- **hashlookup** (CIRCL, keyless) is checked per hash. The real EICAR response carries `hashlookup:trust` 100 **and** a `KnownMalicious` flag, so trust is ignored and only the flag decides. A hit means "known file", not "benign": it can only soften a suspicious verdict, never a malicious one.
- **CISA KEV and EPSS** are not sources: after the sources answer, the CVEs in InternetDB's `vulns` are looked up locally and attached to the report as `cves`, with a reason line when any is in KEV. They never change the verdict.
- Feed URLs are in `src/verdikt/sources/feeds.py`. Downloads are capped at 40 MB each, one failing feed never stops the others or removes its old copy, and files are written atomically. Licenses differ per feed (Spamhaus DROP and Tranco have their own terms); check them before using verdikt commercially.

## RDAP, crt.sh, passive DNS and OpenPhish

- **rdap** asks `rdap.org`, which redirects to the registry's own RDAP server (only this request follows redirects). For `sub.a.example.com` it strips labels, at most three, until a registry answers, so no public-suffix list is needed. A TLD with no RDAP service gives `not found`. A young domain is a weak signal: weight 1, suspicious only.
- **crtsh** queries unexpired certificates for the exact name. Responses for popular domains are large, so only a sample is kept as `raw`. It was 0.8 s for one domain, 13 s for `github.com` and a 20 s timeout for `example.com`, hence opt-in and a 20 s source timeout.
- **passivedns** uses VirusTotal's `/resolutions` endpoint with the same key, limiter and daily budget as the VirusTotal source (`quota_group`), so enabling it can use up the 4/min and 500/day sooner.
- **OpenPhish** (community feed, free for non-commercial use) is downloaded with the other feeds. A URL matches exactly (after normalization); a domain matches when it is the exact host of a listed URL, so `weeblysite.com` is not listed because `att-10page42.weeblysite.com` is.
- **urlscan** stays context only. With a key, search still carries no verdicts, verdict fields cannot be searched on the free plan, and the result pages that do hold verdicts are 13 to 40 MB each, so a per-result source was not built.

## Recorded fixtures

Fixtures marked real in `tests/fixtures/README.md` were recorded from live responses and trimmed to the fields the clients read. The first recording found three semantic problems that no hand-made fixture could: OTX's pulse count and URLhaus's offline host listings made `example.com` suspicious, and "no match" from list-only feeds (ThreatFox, URLhaus, MalwareBazaar) was counted as evidence against a malicious verdict, so a Tor exit node with VirusTotal 13/92 and AbuseIPDB 100 had low confidence. Not yet recorded: URLhaus URL lookups, Hybrid Analysis (no key), VirusTotal URL lookups, and a ThreatFox IP hit.
