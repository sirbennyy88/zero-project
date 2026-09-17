# Zero Project

**A public, open-data tracker of zero-day vulnerabilities exploited in the wild, AI-discovered security bugs, and vendor patch volumes — week by week since 2021.**

Live at **[zero.propulse.tech](https://zero.propulse.tech/)** (previously zero.peries.ca, which will redirect)

## What it shows

- **CISA KEV** — known exploited vulnerabilities added each week (part of the same KEV list CISA publishes; you can sort by ransomware use)
- **Claude Mythos findings** — vulnerabilities discovered by Anthropic's Claude models, tracked through our coordinated vulnerability disclosure program with severity and patch status
- **Vendor patch volume** — weekly CVE counts (HIGH and CRITICAL) by CNA (vendor/source) via Epoch AI's cve.org explorer
- **Microsoft Patch Tuesday** — KEV and total vulnerability counts each month
- **Oracle CPU** — security patch and CVE counts per critical patch update
- **.NET advisories** — monthly security advisory count from dotnet/announcements
- **GitHub Advisory Database** — monthly advisory counts by ecosystem (npm, PyPI, RubyGems, Go, Rust, Maven, NuGet, Composer) and per-framework/tool repos
- **Google TIG zero-days** — historical yearly counts of zero-days exploited before disclosure

Browse any week, search any CVE ID, jump to a specific date, download the data, or subscribe to the RSS feed.

## v2: new tabs

- **Products** — a watchlist of ~50 widely-run products/frameworks (Linux kernel, Chrome, OpenSSL, Kubernetes, LiteLLM, LangChain, etc.), matched against NVD via CPE, with per-product monthly CVE counts, severity breakdowns, and KEV hits
- **Governance** — a matrix mapping the site's ten core metrics to the security, AI, and regulatory frameworks each one evidences (NIST CSF 2.0, ISO/IEC 27001/42001, EU AI Act, MITRE ATLAS, and more)
- **CISO view** — an eight-number board-reporting summary computed from the same underlying data as the rest of the page
- **Time-to-exploit** — median days from a CVE's publication to its addition to the CISA KEV catalog, broken out by year
- **Exploited** tab now also includes a "what kind of thing is being exploited" category breakdown of KEV additions (edge/network appliance, browser & OS, on-prem collaboration, etc.)

### NVD_API_KEY (optional, speeds up the weekly run)

The Products watchlist is built by querying the NVD CPE API once per watched product. Without an API key, NVD rate-limits requests to about one every 6 seconds, so a full run can take 30+ minutes; with a key, that drops roughly 10x. It's optional — the pipeline works fine without one, just slower.

1. Request a free key at https://nvd.nist.gov/developers/request-an-api-key
2. Add it as a repository secret named `NVD_API_KEY` (Settings → Secrets and variables → Actions)

The workflow picks it up automatically if present, and runs unaffected (just slower) if it isn't set.

### Research notes

`data-src/research/` holds the source research behind the v2 additions — `frameworks.md` documents the framework-to-metric mapping used in the Governance tab, and `ciso-metrics.md` documents the CISO view's eight numbers and how each is derived.

## Data sources

- **CISA Known Exploited Vulnerabilities (KEV)** — https://www.cisa.gov/known-exploited-vulnerabilities (JSON feed)
- **Anthropic CVD Ledger** — https://red.anthropic.com/2026/cvd/data/ledger.json (Mythos findings)
- **Epoch AI CVE Explorer** — https://epoch.ai/ (CNA HIGH/CRITICAL counts via cve.org)
- **Microsoft MSRC CVRF API** — https://api.msrc.microsoft.com/cvrf/v3.0/updates (Patch Tuesday)
- **Oracle Security Alerts** — https://www.oracle.com/security-alerts/ (CPU patches and CVE counts)
- **GitHub Advisory Database REST API** — https://api.github.com/advisories (ecosystem and repo advisories)
- **.NET Announcements** — https://github.com/dotnet/announcements (security advisories)
- **Google Threat Intelligence** — historical zero-day exploit data (curated facts in manual.json)

## How the refresh works

Every Monday at **09:15 UTC**, a GitHub Actions workflow runs `python data-src/refresh.py`, which:
1. Fetches all primary feeds (CISA KEV, Anthropic ledger, Epoch AI, MSRC, Oracle, GitHub, .NET advisories)
2. Caches results locally; if a source is down, the previous cached result is used
3. Rebuilds `zeroweek-data.json`, `zeroweek-data.csv`, and `feed.xml` in the site root
4. Commits and pushes the updated data files
5. Deploys to GitHub Pages

**To refresh manually:**

```bash
python data-src/refresh.py
```

**Flags:**
- `--offline` — rebuild outputs from cache only, no network fetch
- `--skip a,b,c` — skip these fetchers (use their cache); names match the `@cached(...)` id: `kev,ledger,epoch,msrc,oracle,gh_eco,gh_repos,dotnet,cve_pub,nvd_watchlist,extra_feeds,euvd,epss,p0,exploit,ssvc,advisories,atlas,avid,csaf,ai_credit`
- `--only a,b,c` — run *only* these fetchers (inverse of `--skip`; every other fetcher uses its cache) — handy for iterating on one source without a full 10-20 minute run
- `--watchlist-limit N` — only pull the first N Products-tab watchlist entries (useful for a quick smoke test of `nvd_watchlist`)
- `--ai-credit-full` — force a full cvelistV5 zip rescan instead of the incremental delta scan
- `--since YYYY-MM-DD` — earliest date scoped into every fetcher (default `2016-01-01`)
- `GITHUB_TOKEN=...` — enables per-ecosystem monthly counts (requires many API calls; rate-limited without it) and raises GitHub's unauthenticated rate limits for `gh_repos`/`avid`/`ai_credit`
- `NVD_API_KEY=...` — required for a fast `nvd_watchlist` pull (0.7s/request vs 6.5s/request unkeyed); request one at https://nvd.nist.gov/developers/request-an-api-key

For example:
```bash
GITHUB_TOKEN=ghp_... NVD_API_KEY=... python data-src/refresh.py
python data-src/refresh.py --offline
python data-src/refresh.py --only advisories,extra_feeds   # quick check of just the RSS-based sources
```

Every fetcher is independent and wrapped so one bad source can't take down the run: on any exception
it logs `[name] FAILED (...) -> cache` and falls back to the last good cached copy, and `build()`
itself is wrapped so a bad merge doesn't overwrite yesterday's `zeroweek-data.*` with a half-built
file. Non-fatal issues (a feed returning 0 items, a degraded source) are collected into
`zeroweek-data.json`'s `meta.warnings`, and per-source freshness/row-counts are in `source_status`
(surfaced on the site's Data tab).

## File layout

```
.
├── index.html                 # Single-file web app (no build step required)
├── zeroweek-data.json        # All data: KEV weekly, Mythos findings, vendor volumes, etc.
├── zeroweek-data.csv         # Flat export of all records
├── feed.xml                   # RSS feed of new KEVs
├── og.png                     # Social preview image
├── data-src/
│   ├── refresh.py            # Main refresh pipeline (stdlib Python 3.10+)
│   ├── build_data.py         # Helper to compile JSON from feeds
│   ├── manual.json           # Curated facts: events, timeline, ecosystem list, repo list
│   ├── mythos_cves_raw.txt   # Raw list of Mythos CVE findings
│   ├── kev_2026_raw.txt      # Raw KEV data (for local testing)
│   ├── research/              # Source research behind the Governance/CISO tabs
│   ├── cache/                # Fetched data cached locally (refreshed each run)
│   └── *.log                  # Refresh run logs
├── .github/
│   ├── workflows/
│   │   └── refresh.yml       # GitHub Actions cron schedule (Monday 09:15 UTC)
│   └── ISSUE_TEMPLATE/       # GitHub issue templates for suggestions and data errors
├── run-refresh.ps1           # PowerShell helper to run refresh locally
├── install-scheduler.ps1     # Windows Task Scheduler setup (optional)
├── cloudflare/                 # D1 database, read API worker, weekly sync (see below)
└── CNAME                      # GitHub Pages custom domain (zero.propulse.tech, once DNS is live)
```

## Cloudflare: read API and database (optional, free-tier)

In addition to the static JSON/CSV files, the same data is mirrored into a Cloudflare D1 database
(`zero-project`) and exposed through a small read-only Worker API, so other tools can query a single
week, a single CVE, or search without downloading the full dataset.

- **API base URL:** `https://zero-project-api.benito-1d7.workers.dev`
- **Endpoints:**
  - `GET /api/weeks?from=&to=` — weekly KEV totals in a date range
  - `GET /api/week/{YYYY-MM-DD}` — KEV entries added that ISO week, joined with EPSS/exploit/SSVC signals
  - `GET /api/cve/{id}` — one CVE across KEV, EPSS, exploit signals, and SSVC
  - `GET /api/vendors?week=` — vendor (CNA) high/critical counts for a week
  - `GET /api/products/{id}` — monthly severity counts for a watchlist product
  - `GET /api/search?q=` — search CVE ID / vendor / product / name (limit 50)
  - `GET /api/stats` — row-count totals and last refresh timestamp

Example:

```bash
curl "https://zero-project-api.benito-1d7.workers.dev/api/stats"
curl "https://zero-project-api.benito-1d7.workers.dev/api/week/2026-08-31"
curl "https://zero-project-api.benito-1d7.workers.dev/api/search?q=chrome"
```

All responses are JSON with `Access-Control-Allow-Origin: *` and an hour of edge caching; rate limiting
relies on Cloudflare Workers' free-tier defaults. Source: `cloudflare/schema.sql` (schema),
`cloudflare/load_d1.py` (loader, run weekly by the refresh workflow), `cloudflare/worker/` (the Worker
itself).

### D1 free-tier budget

D1's free tier caps writes at **100,000 `rows_written`/day** (an index write counts too). The loader
is incremental: it diffs `zeroweek-data.json` against the committed `cloudflare/d1_manifest.json`
(a per-table map of primary key → row hash) and only writes rows that are new or changed, plus a
DELETE for rows that disappeared (skipped for a few append-only feeds). It also stops after a
configurable write budget (`--max-writes`, default 60,000) and defers the rest to the next weekly
run, so a full cold load — or a period of unusually heavy upstream churn — spreads safely over a
few days instead of blowing the daily cap in one run. `python cloudflare/load_d1.py --dry-run`
prints the planned per-table write counts without touching D1 or the manifest.

### Enabling the weekly D1 sync

The weekly workflow tries to sync the refreshed data into D1 automatically (`cloudflare: sync to D1`
step in `.github/workflows/refresh.yml`) but is set to `continue-on-error: true`, so a missing token
never breaks the site deploy. To enable it:

1. Create a Cloudflare API token: dashboard → **My Profile → API Tokens → Create Token** → start from the
   **"Edit Cloudflare Workers"** template, then add **D1: Edit** permission (Account level) to the same
   token. Copy the token value.
2. Add it as a repository secret:
   ```bash
   gh secret set CLOUDFLARE_API_TOKEN --repo sirbennyy88/zero-project
   ```
3. `CLOUDFLARE_ACCOUNT_ID` is already set as a repository secret.

**Status:** as of this writing `CLOUDFLARE_API_TOKEN` is *not* set (`gh secret list` shows only
`CLOUDFLARE_ACCOUNT_ID` and `NVD_API_KEY`), so every weekly run's `cloudflare: sync to D1` step fails
with `wrangler: CLOUDFLARE_API_TOKEN environment variable` and D1 has been stuck at the 2026-09-07
snapshot (`/api/stats` → `last_refresh: 2026-09-07T00:08:14Z`) while `zeroweek-data.json` keeps moving
forward weekly. The site itself is unaffected (it reads the static JSON, not D1) — this only stales
the optional read API. Add the secret above to resume the sync; `continue-on-error: true` on that step
means it will never fail the deploy either way.

**Custom domain:** `zero.propulse.tech` has no DNS record yet (`Resolve-DnsName` returns "DNS name does
not exist") — the CNAME in Cloudflare Pages hasn't been created. The Worker and site are both live at
their `*.workers.dev` / GitHub Pages URLs in the meantime; the CNAME file's domain will start resolving
once someone adds the CNAME record in the DNS zone (not something this pipeline can or should do).

### Troubleshooting fetchers

Advisory-feed sources are the most likely to break (vendors reshape their blogs/RSS without notice).
`[advisories:<id>] FAILED: ...` or `ok, 0 items` in `data-src/cache/last_run.log` points at the exact
feed; the URL list lives in `ADVISORY_FEEDS` in `refresh.py`. Recently fixed:
- **CISA alerts** — `cybersecurity-advisories/rss.xml` now 404s; switched to `cybersecurity-advisories/all.xml`,
  which is the correct current URL (confirmed 200 OK from a browser) but CISA's WAF still 403s Python's
  `urllib` specifically — every `www.cisa.gov` path we tried (the new URL, `/news.xml`, even the bare
  homepage) 403s to `urllib` while returning 200 to a real browser/`Invoke-WebRequest`, so this looks
  like a TLS/HTTP fingerprint block rather than a UA check, and isn't fixable from stdlib `urllib` alone.
  Only `cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (used by `fetch_kev`,
  served from a different path/CDN rule) is unaffected. The advisory feed correctly falls back to its
  cache and reports `ok: false` in `source_status` either way — nothing crashes, the KEV feed itself is
  unaffected, and the URL fix is still worth keeping since it's the right endpoint if CISA's WAF policy
  changes.
- **MSRC blog** — `msrc.microsoft.com/blog/rss.xml` now serves an HTML redirect, not XML, so it silently
  produced 0 items; switched to the Microsoft Security blog feed (`microsoft.com/en-us/security/blog/feed/`).
- **CCCS (Canadian Centre for Cyber Security) alerts** — `cyber.gc.ca`'s RSS API now 404s on every path
  we could find (their own error page comes back as a 200 Atom document, which used to be silently
  counted as "0 items"); the fetcher now detects that error document and marks the source `FAILED` so
  the last good cache is kept and `source_status` reflects reality instead of reporting a false "ok".
  No working replacement feed was found — if you find one, update `ADVISORY_FEEDS`.
- **Grafana advisories** (in `fetch_extra_feeds`) — HTML scraping of the advisories page stopped
  matching; switched to the site's own `security-advisories/index.xml` RSS feed.

## Suggest a tool or source

Have a vendor, ecosystem, or data feed you'd like Zero Project to track? **[Open an issue with the suggestion template.](https://github.com/sirbennyy88/zero-project/issues/new?template=suggestion.yml)**

We're looking for:
- A consistent, publicly available feed or API
- Weekly or monthly data we can fetch reliably
- Clear business value (who would look at it? what decision does it inform?)

## Report a data error

Found a wrong number, date, or attribution? **[Open an issue with the data-error template.](https://github.com/sirbennyy88/zero-project/issues/new?template=data-error.yml)**

Include the section name, what's wrong, and a URL to the primary source that shows the correct value.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## How to cite

> Zero Project — Zero-days per week, before and after Mythos. https://zero.propulse.tech/. Data refreshed every Monday. [Accessed DATE].

Or as BibTeX:

```bibtex
@misc{ZeroProject2026,
  title={Zero Project: Zero-days per week},
  author={Peries, Ben},
  url={https://zero.propulse.tech/},
  note={Refreshed weekly; last accessed [DATE]},
  year={2026}
}
```

## License

- **Code** — MIT License (copyright 2026 Ben Peries). See LICENSE file.
- **Data files** — CC BY 4.0 (the generated `zeroweek-data.*` and `feed.xml` files are open data)

See [LICENSE](LICENSE) for full text.

---

Built by [Ben Peries](https://peries.ca). Repository: [github.com/sirbennyy88/zero-project](https://github.com/sirbennyy88/zero-project)
