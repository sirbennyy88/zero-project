# CISO/CIO Metrics Research — Zero Project

Prepared 2026-09-06 for zero.peries.ca (github.com/sirbennyy88/zero-project). Sources are primary where fetchable; secondary analyst sources are marked. All figures are dated — re-verify before hardcoding into copy that doesn't refresh weekly.

---

## Part A — What security leaders need from this tracker

### A1. CISA BOD 22-01 vs BOD 26-04

| | BOD 22-01 (superseded) | BOD 26-04 (current) |
|---|---|---|
| Title | Reducing the Significant Risk of Known Exploited Vulnerabilities | Prioritizing Security Updates Based on Risk |
| Effective date | 2021-11-03 | 2026-06-10 |
| Status | Revoked/superseded by BOD 26-04 (CISA keeps a "(Revoked)" copy of the 22-01 page) | Current; phased compliance |
| Remediation model | Two tiers, keyed only to CVE-assignment year | Four-variable risk matrix: asset exposure (internet-facing), KEV-catalog status, exploit-automation potential, technical impact (full vs. partial control) |
| Timelines | 6 months for CVEs assigned before 2021; **14 calendar days** for everything else added to KEV | Tiered: **3 / 14 / 60 calendar days**, or "fix at next scheduled upgrade" if none of the four risk criteria are met |
| Rationale given | Establish a standing catalog + remediation SLA for FCEB agencies | AI-accelerated exploitation has collapsed disclosure-to-weaponization from months to hours; CVSS-only prioritization no longer adequate |
| Compliance phase-in | Immediate on issuance for new KEV adds | 60 days (~Aug 2026) to update internal processes to the new tiered model; 180 days (~Dec 2026) to fully meet Table 1 timelines |

Sources: [BOD 26-04 (CISA)](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk), [BOD 26-04 Implementation Guidance (CISA)](https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk), [BOD 22-01 (CISA, revoked copy)](https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities-revoked), [BOD 22-01 (CISA, live copy)](https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities), [Tenable BOD 26-04 FAQ](https://www.tenable.com/blog/cisa-bod-26-04-FAQ-vulnerability-remediation-impact), [Axis Intelligence KEV Statistics](https://axis-intelligence.com/cisa-kev-statistics/).

Note: I could not pull the CISA directive pages themselves as readable text this session (both `cisa.gov/news-events/directives/...` fetches returned empty — likely client-rendered). The table above is triangulated from Tenable, Minimus, runZero, GuidePoint, Axis Intelligence and CIQ analyst writeups that quote the directive text; before publishing exact day-counts, do one direct fetch of the CISA page in a browser-rendering context (Chrome tool) to confirm the Table 1 wording verbatim.

**Derived metrics (computable from our data: CISA KEV JSON `dateAdded`, `cveID`, `dueDate`, `knownRansomwareCampaignUse`):**

1. **"KEV due this week"** — count of catalog entries where `dueDate` falls within the current Mon–Sun window. `dueDate` is already federal-remediation-adjusted per entry, so no extra logic needed beyond a date-range filter on the raw KEV JSON.
2. **"Median federal remediation window by month"** — for each calendar month, take `median(dueDate − dateAdded)` in days across entries added that month. As of Aug 2026 this median sits at **14 days**, down from **21 days** a year prior (Axis Intelligence); watch for it splitting into a visible 3/14/60-day trimodal distribution as BOD 26-04's Table 1 phases in through Dec 2026.
3. **"Share of KEV entries with ≤3-day windows"** — `count(dueDate − dateAdded <= 3) / count(all entries added since 2026-03)`. Axis Intelligence's July–Aug 2026 sample put this at **49.3%** of new adds since March 2026 (when the 3-day tier started appearing ahead of the directive's formal June signing — CISA phased the tightest tier in early via KEV catalog notes before BOD 26-04 was issued). Compute going forward directly from `dueDate` deltas rather than trusting a static percentage.

Why boards care: these three numbers are the plain-English answer to "are we going to make our federal SLA," and for private-sector boards they're the best available proxy for "how fast does the adversary community move now" — a number that used to be measured in weeks and is now measured in single-digit days for the worst class of bug.

---

### A2. Time-to-exploit (CVE publish → KEV add)

**Confirmed: yes, both sources expose what's needed.**

- **cvelistV5** (`github.com/CVEProject/cvelistV5`): raw JSON lives at
  `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{YYYY}/{bucket}xxx/CVE-{YYYY}-{N}.json`
  where `{bucket}` is the CVE number **integer-divided by 1000** (not the literal first 4 digits) — e.g. CVE-2025-32414 lives at `cves/2025/32xxx/CVE-2025-32414.json`, and CVE-2025-6537 lives at `cves/2025/6xxx/CVE-2025-6537.json`. The user's stated pattern (`NNNNxxx`) is close but should be corrected to `{cve_number // 1000}xxx` since bucket width varies (1–5 digits) with the CVE's own number, not a fixed 4-digit slice. `datePublished` sits under `cveMetadata.datePublished` (ISO-8601 UTC, e.g. `2025-06-26T02:22:21.320Z`); `cveMetadata.dateReserved` and `.dateUpdated` are also present. Verified via GitHub search hits on both example paths.
- **NVD API 2.0**: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-YYYY-NNNNN` returns a `vulnerabilities[0].cve.published` (ISO date) and `.cve.metrics.cvssMetricV31[0].cvssData` (or v30/v2) block with the CVSS vector/score. Confirmed live: I queried `services.nvd.nist.gov/rest/json/cpes/2.0` repeatedly this session and it responds with well-formed JSON including a `timestamp` field, so the sibling `cves/2.0` endpoint (same host/auth model) is the right one for per-CVE lookups.
- **Rate limits**: **5 requests per rolling 30 seconds without an API key; 50 per rolling 30 seconds with one.** Request a free key at `https://nvd.nist.gov/developers/request-an-api-key` — no paid tier, self-service, activation email arrives within minutes, key is revealed on clicking the activation link. Send it as the `apiKey` HTTP header (URL param also works but header is recommended).

**Formula:** `days_to_exploit = (KEV.dateAdded − CVE.datePublished_or_published).days`, computed per CVE by joining CISA KEV's `cveID` to either the cvelistV5 raw file or an NVD API lookup keyed on the same ID. For a weekly batch job against ~15–20 new KEV entries, a keyed NVD account (50 req/30s) clears the whole batch in one window; cvelistV5 raw fetches have no rate limit at all (plain GitHub raw content) and are the cheaper source if you don't need CVSS in the same call.

Sources: [NVD API key request](https://nvd.nist.gov/general/news/api-key-announcement), [NVD API key guide (ScanRook)](https://scanrook.io/blog/nvd-api-key-guide), [cvelistV5 repo](https://github.com/CVEProject/cvelistV5), example record [CVE-2025-32414.json](https://github.com/CVEProject/cvelistV5/blob/main/cves/2025/32xxx/CVE-2025-32414.json).

---

### A3. Edge-device / network-appliance exposure

Google Threat Intelligence Group's *2025 Zero-Day Review* (published ~March 2026, covering CY2025):
- **90 zero-days** exploited in the wild in 2025 (up from 78 in 2024).
- **48% of 2025's zero-days targeted enterprise-grade technology** — a record share, and for the first time enterprise targets edge out consumer platforms in aggregate share.
- Attacks concentrated on **edge devices, security appliances, and networking equipment** used for long-term persistent access; GTIG names UNC5221 and UNC3886 specifically as actors focused on security-appliance/edge-device access.
- Commercial surveillance vendors, not state-sponsored APTs, were the single most active category of zero-day users in 2025 (a first).

I did not find a distinct CISA-published percentage for edge-device share of exploited zero-days this session (CISA's own commentary tends to be qualitative — Secure-by-Design edge-device guidance, KEV catalog composition — rather than a headline stat like Google's 48%). Treat GTIG's 48% as the number to cite for "enterprise/edge share of zero-days," and use CISA KEV's own vendor distribution (computable from our existing `kev.json` cache) as the corroborating, always-fresh number.

Sources: [Google Cloud Blog — 2025 Zero-Day Review](https://cloud.google.com/blog/topics/threat-intelligence/2025-zero-day-review), [SecurityWeek summary](https://www.securityweek.com/google-half-of-2025s-90-exploited-zero-days-aimed-at-enterprises/), [Cybersecurity Dive summary](https://www.cybersecuritydive.com/news/half-exploited-zero-day-flaws-enterprise-grade-technology/814021/).

**Vendor/product → category mapping** (for tagging KEV entries by product class; match case-insensitively against KEV's `vendorProject` + `product` fields, first match wins, ≥60 entries):

```json
{
  "fortinet": "edge_appliance", "fortios": "edge_appliance", "fortiweb": "edge_appliance",
  "fortimanager": "edge_appliance", "fortiproxy": "edge_appliance", "fortimail": "edge_appliance",
  "ivanti": "edge_appliance", "pulse secure": "edge_appliance", "pulse connect secure": "edge_appliance",
  "connect secure": "edge_appliance", "policy secure": "edge_appliance", "endpoint manager mobile": "edge_appliance",
  "citrix": "edge_appliance", "netscaler": "edge_appliance",
  "palo alto": "edge_appliance", "pan-os": "edge_appliance", "globalprotect": "edge_appliance",
  "cisco asa": "edge_appliance", "adaptive security appliance": "edge_appliance",
  "cisco ios xe": "edge_appliance", "ios xe": "edge_appliance",
  "firepower": "edge_appliance", "fmc": "edge_appliance", "cisco ftd": "edge_appliance",
  "sonicwall": "edge_appliance", "check point": "edge_appliance", "checkpoint": "edge_appliance",
  "f5": "edge_appliance", "big-ip": "edge_appliance", "big-iq": "edge_appliance",
  "barracuda": "edge_appliance", "zyxel": "edge_appliance", "draytek": "edge_appliance",
  "d-link": "edge_appliance", "netgear": "edge_appliance", "tp-link": "edge_appliance",
  "ubiquiti": "edge_appliance", "mikrotik": "edge_appliance",
  "qnap": "edge_appliance", "synology": "edge_appliance",
  "sophos": "edge_appliance", "watchguard": "edge_appliance",

  "sharepoint": "on_prem_collaboration", "exchange server": "on_prem_collaboration",
  "exchange": "on_prem_collaboration", "outlook": "on_prem_collaboration",
  "confluence": "on_prem_collaboration", "jira": "on_prem_collaboration",
  "zimbra": "on_prem_collaboration", "roundcube": "on_prem_collaboration",

  "chrome": "browser_os", "v8": "browser_os", "chromium": "browser_os",
  "firefox": "browser_os", "mozilla": "browser_os", "webkit": "browser_os", "safari": "browser_os",
  "apple": "browser_os", "ios": "browser_os", "ipados": "browser_os", "macos": "browser_os",
  "android": "browser_os", "windows": "browser_os", "linux kernel": "browser_os", "edge": "browser_os",

  "litellm": "ai_ml_tooling", "langflow": "ai_ml_tooling", "langchain": "ai_ml_tooling",
  "mlflow": "ai_ml_tooling", "ray": "ai_ml_tooling", "n8n": "ai_ml_tooling",
  "ollama": "ai_ml_tooling", "vllm": "ai_ml_tooling", "huggingface": "ai_ml_tooling",
  "transformers": "ai_ml_tooling", "pytorch": "ai_ml_tooling", "tensorflow": "ai_ml_tooling",
  "anythingllm": "ai_ml_tooling", "open webui": "ai_ml_tooling", "comfyui": "ai_ml_tooling",

  "wordpress": "cms", "joomla": "cms", "drupal": "cms", "woocommerce": "cms", "elementor": "cms",

  "jetbrains": "developer_ci", "gitlab": "developer_ci", "gitea": "developer_ci",
  "jenkins": "developer_ci", "jfrog": "developer_ci", "github enterprise": "developer_ci",
  "teamcity": "developer_ci", "bamboo": "developer_ci",

  "docker": "virtualization_cloud", "kubernetes": "virtualization_cloud",
  "vmware": "virtualization_cloud", "vcenter": "virtualization_cloud", "esxi": "virtualization_cloud",
  "citrix hypervisor": "virtualization_cloud", "nutanix": "virtualization_cloud",
  "terraform": "virtualization_cloud",

  "postgresql": "database", "mysql": "database", "redis": "database", "valkey": "database",
  "elasticsearch": "database", "mongodb": "database", "kafka": "database",

  "okta": "identity", "keycloak": "identity", "onelogin": "identity", "ping identity": "identity",
  "active directory": "identity", "adfs": "identity",

  "moveit": "file_transfer_mft", "goanywhere": "file_transfer_mft", "accellion": "file_transfer_mft",
  "serv-u": "file_transfer_mft", "cleo": "file_transfer_mft", "webtransit": "file_transfer_mft",

  "veeam": "security_backup", "trend micro": "security_backup", "kaseya": "security_backup",
  "connectwise": "security_backup", "screenconnect": "security_backup", "n-able": "security_backup",

  "papercut": "enterprise_app", "sap": "enterprise_app", "oracle weblogic": "enterprise_app",
  "ibm websphere": "enterprise_app", "manageengine": "enterprise_app", "sap netweaver": "enterprise_app"
}
```

Suggested presentation: a stacked bar of weekly KEV adds colored by category, plus a single "edge-appliance share, trailing 12 weeks" KPI card.

---

### A4. Ransomware linkage (`knownRansomwareCampaignUse`)

- As of catalog version 2026.08.11 (1,665 entries), **~20.4% (339 entries)** carry `knownRansomwareCampaignUse: "Known"`.
- CISA does not always flip this flag publicly/promptly: independent tracking found **59 entries silently updated to "Known" in 2025 alone**, without a corresponding public catalog announcement — meaning the field is a lagging and sometimes-invisible-until-you-diff indicator, not a real-time one.
- Field was added to the schema in **October 2023**.

**How to present it:**
1. A simple **badge** on each KEV row/detail card: "Linked to ransomware" when the flag is `Known`.
2. A **weekly delta view** — diff this week's flag values against last week's cached KEV JSON (`data-src/cache/kev.json` already gives you this for free since the pipeline caches prior pulls) and surface "N entries silently reclassified as ransomware-linked this week" as its own timeline event. This is more informative than the raw share, since it catches CISA's undisclosed updates that most public dashboards miss.
3. A rolling **"% of catalog ransomware-linked"** trend line — flat-ish over time (~20%) so a jump is itself a signal worth flagging.

Sources: [Axis Intelligence KEV Statistics 2026](https://axis-intelligence.com/cisa-kev-statistics/), [The Register — CISA quietly updated ransomware flags on 59 flaws](https://www.theregister.com/security/2026/02/03/cisa-quietly-updated-ransomware-flags-on-59-flaws-last-year/4332634), [GreyNoise — Unmasking CISA's Hidden KEV Ransomware Updates](https://www.greynoise.io/blog/unmasking-cisas-hidden-kev-ransomware-updates), [CISA — Ransomware Vulnerability Warning Pilot](https://www.cisa.gov/news-events/news/ransomware-vulnerability-warning-pilot-updates-now-one-stop-resource-known-exploited-vulnerabilities).

---

### A5. Board-level "CISO view" KPI set (max 8)

| # | KPI | Definition | Formula (from our data) | Why the board cares |
|---|---|---|---|---|
| 1 | **KEV/week vs. 52-week baseline** | This week's new KEV adds vs. trailing-year weekly average | `count(this_week) / mean(count(week) for week in last 52 weeks)` | Single number for "is the threat tempo up or down" — a ratio >1.5 is a talking point on its own |
| 2 | **Fresh-vs-old ratio** | Share of new KEV adds whose CVE was published in the *same calendar year* vs. older CVEs | Already computed in `refresh.py`'s `kev_weekly()` (columns 2 vs 3) | Rising same-year share = adversaries weaponizing faster than patch cycles can absorb — the core justification for BOD 26-04 |
| 3 | **Edge-appliance share** | % of trailing-12-week KEV adds tagged `edge_appliance` via the mapping in A3 | `count(category==edge_appliance) / count(all, trailing 12wk)` | Directly maps to what to prioritize in the next patch cycle and vendor-risk conversations |
| 4 | **Median time-to-exploit** | Median days from CVE `datePublished`/`published` to KEV `dateAdded`, trailing 12 weeks | See A2 formula | Answers "how much runway do we actually have between disclosure and active exploitation" |
| 5 | **% KEV with ransomware use** | Share of trailing-12-week KEV adds with `knownRansomwareCampaignUse: Known`, plus a flag for silent reclassifications | See A4 | Ties vulnerability management directly to the risk category the board already tracks (ransomware) |
| 6 | **Patch-volume index** | Current month's Patch Tuesday CVE count ÷ mean monthly Patch Tuesday count, 2021–2025 baseline | Needs a stored 2021–2025 monthly-mean constant (compute once from MSRC historical data, store in `manual.json`, then divide live count against it each month) | Shows whether vendor patch load is structurally increasing (staffing/tooling case) vs. a one-off spike |
| 7 | **AI-discovery ratio** | Mythos/Glasswing disclosed findings (trailing period) ÷ same-period vendor-reported high/critical CVEs | `ledger.json` counts ÷ vendor CVE counts already in the pipeline | Quantifies how much of the "new vulnerability" flow is now AI-originated — a board-relevant vendor-risk and dual-use policy question |
| 8 | **Watchlist exposure count** | Number of distinct watchlist products (Part B) with ≥1 new relevant CVE this week | `count(distinct product where new_cve_this_week)` | Turns "what does this mean for *our* stack" into a single number instead of 50 separate feeds |

Definitions 1–2 and 6–7 reuse fields your `refresh.py` already computes or caches; 3–5 need the new category mapping and a ransomware-flag diff; 8 needs Part B's per-product feed wiring.

---

## Part B — Product watchlist data sources

CPE strings below were checked live against the NVD CPE Dictionary API (`https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=...`) on 2026-09-06; entries marked "not independently verified" follow standard NVD naming convention but weren't individually queried this session — spot-check before shipping. Use each `cpe` as the `virtualMatchString` param against `https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:...&pubStartDate=...&pubEndDate=...` for weekly CVE pulls (works with 0-day-old NVD publish lag issues acknowledged — NVD analysis backlogs can add days on top of CVE Program publish; cross-check against cvelistV5 raw files by CVE ID from the vendor's own advisory for zero lag).

Key per-product findings worth flagging:

- **Kubernetes**: `kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json` is live and returns real JSON — confirmed by direct fetch this session (records include `id` (CVE-YYYY-NNNNN), `url`, `summary`, and nested per-issue objects with their own `id`/`url`/`summary`). Good machine-readable weekly source, no auth.
- **PyTorch core**: NVD's CPE dictionary has **no dedicated `pytorch:pytorch` entry** — only `pytorchlightning`/`lightningai:pytorch_lightning` (a different project). PyTorch's own CVEs are tracked mainly via GitHub Security Advisories (GHSA) against `pytorch/pytorch`, not NVD CPE matching. Use the GHSA feed as primary; treat CPE matching as unreliable for this one.
- **Vue.js core**: similarly no dedicated `vuejs:vue` (or `vuejs:vuejs`) CPE — only `vuejs:vue_cli` exists in the dictionary. Use GHSA on `vuejs/core` as primary.
- **Angular**: NVD's dictionary has folded legacy AngularJS (1.x) and modern Angular (2+) under the same `angularjs:angularjs` vendor:product after a 2025 dictionary cleanup (`angular:angular` and the old `angularjs:angular` are both marked deprecated, pointing to `angularjs:angularjs`). This is confusing and worth a footnote if you ever surface raw CPE strings in the UI — filter by version range, not just vendor:product, to avoid conflating AngularJS 1.x bugs with Angular 17+ bugs.
- **Okta**: no NVD CPE entry at all (SaaS, not self-hosted software) — track via Okta's own security advisories page instead of CPE matching.
- **Cisco ASA**: the "obvious" CPE `cpe:2.3:o:cisco:adaptive_security_appliance` is deprecated; current is `cpe:2.3:a:cisco:adaptive_security_appliance_software`.
- **Ivanti Connect Secure**: current CPE deprecates the old Pulse Secure line (`cpe:2.3:a:pulsesecure:pulse_connect_secure` → `cpe:2.3:a:ivanti:connect_secure`) — if you're matching historical KEV entries pre-2023 rebrand, you need both strings.

```json
WATCHLIST = [
  {"name": "Kubernetes", "category": "virtualization_cloud", "cpe": ["cpe:2.3:a:kubernetes:kubernetes"], "extra_feed": "https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json"},
  {"name": "Node.js", "category": "developer_ci", "cpe": ["cpe:2.3:a:nodejs:node.js"], "extra_feed": "https://nodejs.org/en/feed/vulnerability.xml"},
  {"name": "Grafana", "category": "developer_ci", "cpe": ["cpe:2.3:a:grafana:grafana"], "extra_feed": "https://grafana.com/security/security-advisories/"},
  {"name": "ASP.NET Core / Blazor", "category": "developer_ci", "cpe": ["cpe:2.3:a:microsoft:asp.net_core"], "extra_feed": "https://github.com/dotnet/announcements/labels/Security"},
  {"name": "Django", "category": "developer_ci", "cpe": ["cpe:2.3:a:djangoproject:django"], "extra_feed": "https://www.djangoproject.com/rss/weblog/"},
  {"name": "Ruby on Rails", "category": "developer_ci", "cpe": ["cpe:2.3:a:rubyonrails:rails"], "extra_feed": "https://rubyonrails-security.googlegroups.com/"},
  {"name": "Laravel", "category": "developer_ci", "cpe": ["cpe:2.3:a:laravel:laravel"], "extra_feed": "https://github.com/laravel/framework/security/advisories"},
  {"name": "Spring Framework / Boot / Security", "category": "developer_ci", "cpe": ["cpe:2.3:a:vmware:spring_framework", "cpe:2.3:a:vmware:spring_boot", "cpe:2.3:a:vmware:spring_security"], "extra_feed": "https://spring.io/security"},
  {"name": "Next.js", "category": "developer_ci", "cpe": ["cpe:2.3:a:vercel:next.js"], "extra_feed": "https://github.com/vercel/next.js/security/advisories"},
  {"name": "React", "category": "developer_ci", "cpe": ["cpe:2.3:a:facebook:react"], "extra_feed": "https://github.com/facebook/react/security/advisories"},
  {"name": "Angular", "category": "developer_ci", "cpe": ["cpe:2.3:a:angularjs:angularjs"], "extra_feed": "https://github.com/angular/angular/security/advisories"},
  {"name": "Vue", "category": "developer_ci", "cpe": ["cpe:2.3:a:vuejs:vue_cli"], "extra_feed": "https://github.com/vuejs/core/security/advisories"},
  {"name": "Electron", "category": "developer_ci", "cpe": ["cpe:2.3:a:electronjs:electron"], "extra_feed": "https://github.com/electron/electron/security/advisories"},
  {"name": "Jenkins", "category": "developer_ci", "cpe": ["cpe:2.3:a:jenkins:jenkins"], "extra_feed": "https://www.jenkins.io/security/advisories/"},
  {"name": "GitLab", "category": "developer_ci", "cpe": ["cpe:2.3:a:gitlab:gitlab"], "extra_feed": "https://about.gitlab.com/releases/categories/releases/"},
  {"name": "Atlassian Jira / Confluence", "category": "on_prem_collaboration", "cpe": ["cpe:2.3:a:atlassian:jira", "cpe:2.3:a:atlassian:confluence_server"], "extra_feed": "https://confluence.atlassian.com/security/atlassian-security-advisories-33528133.html"},
  {"name": "WordPress core", "category": "cms", "cpe": ["cpe:2.3:a:wordpress:wordpress"], "extra_feed": "https://wordpress.org/news/category/security/feed/"},
  {"name": "OpenSSL", "category": "developer_ci", "cpe": ["cpe:2.3:a:openssl:openssl"], "extra_feed": "https://openssl-library.org/news/vulnerabilities/index.html"},
  {"name": "Linux kernel", "category": "browser_os", "cpe": ["cpe:2.3:o:linux:linux_kernel"], "extra_feed": "https://cve.org/CVERecord/SearchResults?query=assigner%3ALinux%20Kernel%20CVEs"},
  {"name": "Chrome", "category": "browser_os", "cpe": ["cpe:2.3:a:google:chrome"], "extra_feed": "https://chromereleases.googleblog.com/search/label/Stable%20updates"},
  {"name": "Firefox", "category": "browser_os", "cpe": ["cpe:2.3:a:mozilla:firefox"], "extra_feed": "https://www.mozilla.org/en-US/security/advisories/"},
  {"name": "iOS / macOS", "category": "browser_os", "cpe": ["cpe:2.3:o:apple:iphone_os", "cpe:2.3:o:apple:macos"], "extra_feed": "https://support.apple.com/en-us/100100"},
  {"name": "Android", "category": "browser_os", "cpe": ["cpe:2.3:o:google:android"], "extra_feed": "https://source.android.com/docs/security/bulletin"},
  {"name": "Windows", "category": "browser_os", "cpe": ["cpe:2.3:o:microsoft:windows_server_2022", "cpe:2.3:o:microsoft:windows_11"], "extra_feed": "https://msrc.microsoft.com/update-guide/rss"},
  {"name": "Exchange", "category": "on_prem_collaboration", "cpe": ["cpe:2.3:a:microsoft:exchange_server"], "extra_feed": "https://msrc.microsoft.com/update-guide/rss"},
  {"name": "SharePoint", "category": "on_prem_collaboration", "cpe": ["cpe:2.3:a:microsoft:sharepoint_server"], "extra_feed": "https://msrc.microsoft.com/update-guide/rss"},
  {"name": "Fortinet FortiOS", "category": "edge_appliance", "cpe": ["cpe:2.3:o:fortinet:fortios"], "extra_feed": "https://www.fortiguard.com/psirt"},
  {"name": "Palo Alto PAN-OS", "category": "edge_appliance", "cpe": ["cpe:2.3:o:paloaltonetworks:pan-os"], "extra_feed": "https://security.paloaltonetworks.com/rss.xml"},
  {"name": "Cisco ASA / IOS XE", "category": "edge_appliance", "cpe": ["cpe:2.3:a:cisco:adaptive_security_appliance_software", "cpe:2.3:o:cisco:ios_xe"], "extra_feed": "https://sec.cloudapps.cisco.com/security/center/publicationListing.x"},
  {"name": "Ivanti EPMM / Connect Secure", "category": "edge_appliance", "cpe": ["cpe:2.3:a:ivanti:endpoint_manager_mobile", "cpe:2.3:a:ivanti:connect_secure"], "extra_feed": "https://forums.ivanti.com/s/securityadvisories"},
  {"name": "Citrix NetScaler", "category": "edge_appliance", "cpe": ["cpe:2.3:a:citrix:netscaler_application_delivery_controller", "cpe:2.3:a:citrix:netscaler_gateway"], "extra_feed": "https://support.citrix.com/csa/all"},
  {"name": "VMware vCenter / ESXi", "category": "virtualization_cloud", "cpe": ["cpe:2.3:a:vmware:vcenter_server", "cpe:2.3:o:vmware:esxi"], "extra_feed": "https://support.broadcom.com/web/ecx/security-advisory"},
  {"name": "Docker", "category": "virtualization_cloud", "cpe": ["cpe:2.3:a:docker:docker"], "extra_feed": "https://github.com/moby/moby/security/advisories"},
  {"name": "Terraform", "category": "virtualization_cloud", "cpe": ["cpe:2.3:a:hashicorp:terraform"], "extra_feed": "https://discuss.hashicorp.com/c/security/33"},
  {"name": "Kafka", "category": "database", "cpe": ["cpe:2.3:a:apache:kafka"], "extra_feed": "https://kafka.apache.org/cve-list"},
  {"name": "PostgreSQL", "category": "database", "cpe": ["cpe:2.3:a:postgresql:postgresql"], "extra_feed": "https://www.postgresql.org/support/security/"},
  {"name": "MySQL", "category": "database", "cpe": ["cpe:2.3:a:oracle:mysql"], "extra_feed": "https://www.oracle.com/security-alerts/"},
  {"name": "Redis / Valkey", "category": "database", "cpe": ["cpe:2.3:a:redis:redis", "cpe:2.3:a:valkey:valkey"], "extra_feed": "https://github.com/redis/redis/security/advisories"},
  {"name": "Elasticsearch", "category": "database", "cpe": ["cpe:2.3:a:elastic:elasticsearch"], "extra_feed": "https://www.elastic.co/community/security"},
  {"name": "Splunk", "category": "database", "cpe": ["cpe:2.3:a:splunk:splunk"], "extra_feed": "https://advisory.splunk.com/"},
  {"name": "Okta", "category": "identity", "cpe": [], "extra_feed": "https://sec.okta.com/"},
  {"name": "Keycloak", "category": "identity", "cpe": ["cpe:2.3:a:redhat:keycloak"], "extra_feed": "https://github.com/keycloak/keycloak/security/advisories"},
  {"name": "LiteLLM", "category": "ai_ml_tooling", "cpe": ["cpe:2.3:a:litellm:litellm"], "extra_feed": "https://github.com/BerriAI/litellm/security/advisories"},
  {"name": "Langflow", "category": "ai_ml_tooling", "cpe": ["cpe:2.3:a:langflow:langflow"], "extra_feed": "https://github.com/langflow-ai/langflow/security/advisories"},
  {"name": "LangChain", "category": "ai_ml_tooling", "cpe": ["cpe:2.3:a:langchain:langchain"], "extra_feed": "https://github.com/langchain-ai/langchain/security/advisories"},
  {"name": "MLflow", "category": "ai_ml_tooling", "cpe": ["cpe:2.3:a:lfprojects:mlflow"], "extra_feed": "https://github.com/mlflow/mlflow/security/advisories"},
  {"name": "Ollama", "category": "ai_ml_tooling", "cpe": ["cpe:2.3:a:ollama:ollama"], "extra_feed": "https://github.com/ollama/ollama/security/advisories"},
  {"name": "vLLM", "category": "ai_ml_tooling", "cpe": ["cpe:2.3:a:vllm:vllm"], "extra_feed": "https://github.com/vllm-project/vllm/security/advisories"},
  {"name": "Hugging Face transformers", "category": "ai_ml_tooling", "cpe": ["cpe:2.3:a:huggingface:transformers"], "extra_feed": "https://github.com/huggingface/transformers/security/advisories"},
  {"name": "PyTorch", "category": "ai_ml_tooling", "cpe": [], "extra_feed": "https://github.com/pytorch/pytorch/security/advisories"},
  {"name": "TensorFlow", "category": "ai_ml_tooling", "cpe": ["cpe:2.3:a:google:tensorflow"], "extra_feed": "https://github.com/tensorflow/tensorflow/security/advisories"}
]
```

Notes on `extra_feed` reliability: MSRC's `update-guide/rss` and vendor GitHub `/security/advisories` feeds are Atom/RSS and machine-parseable with stdlib `xml`/`re` (matches `refresh.py`'s no-dependency style). `chromereleases.googleblog.com` and Mozilla's advisories page are HTML, not JSON — need light scraping, same as the existing `epoch`/`dotnet` fetchers already do per `refresh.py`. Kubernetes' official feed is the only one in this list confirmed as clean structured JSON with no scraping needed.

---

## Executive summary — what the page must add

1. Add a **"CISO view"** KPI strip (Part A5, 8 cards) above or beside the existing timeline — boards want one screen, not the full feed.
2. Wire **BOD 26-04's 3/14/60-day tiers** into KEV rendering; the old "14-day blanket" framing is now wrong and should be retired.
3. Compute and surface **time-to-exploit** (CVE publish → KEV add) per entry using cvelistV5 raw JSON (no rate limit) with NVD API 2.0 as CVSS enrichment (get a free key now — 50 req/30s vs. 5).
4. Add the **vendor→category mapping** (Part A3 JSON) to tag every KEV row; ship an **edge-appliance share** trend line — it's the single stat GTIG's 2025 report makes most defensible (48% enterprise, edge-concentrated).
5. Surface **ransomware linkage** as a badge plus a **silent-reclassification diff** each week — this catches what CISA doesn't announce.
6. Register a free **NVD API key** immediately; current unauthenticated 5/30s limit will bottleneck the growing watchlist.
7. Expand `manual.json`'s product watchlist with the 51-entry `WATCHLIST` block above; wire Kubernetes' official JSON feed first — it's the cleanest new source.
8. Flag PyTorch, Vue, Okta, and Angular as **CPE-matching-unreliable**; route them to GHSA/vendor advisories instead of `virtualMatchString` queries.
9. Store a **2021–2025 monthly Patch Tuesday mean** as a constant in `manual.json` to power the patch-volume index (KPI 6) — this doesn't exist in the pipeline yet and needs one manual backfill.
10. Re-verify the BOD 26-04 exact day-tier language directly against `cisa.gov` (this session's fetch came back empty, likely JS-rendered) before publishing any specific day-count as a direct quote rather than a paraphrase.
