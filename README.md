# Zero Project

**A public, open-data tracker of zero-day vulnerabilities exploited in the wild, AI-discovered security bugs, and vendor patch volumes — week by week since 2021.**

Live at **[zero.peries.ca](https://zero.peries.ca/)**

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
- `GITHUB_TOKEN=...` — enables per-ecosystem monthly counts (requires many API calls; rate-limited without it)

For example:
```bash
GITHUB_TOKEN=ghp_... python data-src/refresh.py
python data-src/refresh.py --offline
```

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
└── CNAME                      # GitHub Pages domain (zero.peries.ca)
```

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

> Zero Project — Zero-days per week, before and after Mythos. https://zero.peries.ca/. Data refreshed every Monday. [Accessed DATE].

Or as BibTeX:

```bibtex
@misc{ZeroProject2026,
  title={Zero Project: Zero-days per week},
  author={Peries, Ben},
  url={https://zero.peries.ca/},
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
