# Fixtures

Every file here is JSON a source client parses. Never put keys, account data or reporter names in them (CLAUDE.md).

**Recorded** (real vendor responses captured 2026-11-21, trimmed to the fields the clients read and scrubbed):
`virustotal/ip_hit`, `virustotal/file_hit` (EICAR test file), `virustotal/domain_real`, `abuseipdb/hit`, `greynoise/noise`, `internetdb/hit`, `urlhaus/host_offline_real`, `threatfox/miss_real`, `threatfox/hit_domain_real` (a recent public feed entry), `malwarebazaar/hit_real` (a recent public sample), `malwarebazaar/miss_real`, `otx/domain_popular`, `urlscan/search_real`, `hashlookup/known_good`, `hashlookup/known_malicious` (EICAR), `hashlookup/miss` (the real 404 body), and everything in `feeds/` (real feed downloads cut down to a few rows: Feodo, Spamhaus DROP, Tor exits, Tranco zip, KEV, EPSS gzip).

**Hand-made** from vendor documentation, not yet verified against a live response: everything else, including all Hybrid Analysis files, `urlhaus/url_hit`, `urlhaus/host_hit`, `threatfox/hit` (IP with port) and `threatfox/near_miss`, `virustotal/domain_hit`, `virustotal/ip_clean`, `otx/hit` and `otx/clean`, `abuseipdb/clean`, `greynoise/riot`, `urlscan/miss`, `malwarebazaar/hit`.

To record a new one: run `verdikt check <ioc> --json --raw --no-cache`, take the `raw` of the source, trim it, scrub it, save it here, and list it above.

Also recorded on 2026-11-21: `rdap/example_com`, `crtsh/example_com`, `passivedns/domain` and `passivedns/ip` (VirusTotal resolutions, trimmed) and `feeds/openphish.txt`. MISP import files in the tests are hand-written from MISP's documented event format.

