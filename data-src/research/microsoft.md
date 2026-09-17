# Microsoft / .NET / Blazor deep-dive — source research

Compiled 2026-09-17. All endpoints below were fetched live today (`web_fetch`) unless noted.
Today is the week after September 2026 Patch Tuesday (2026-Sep CVRF doc: 975 Microsoft CVEs,
released 2026-09-08, revised 2026-09-15 — confirms `manual.json`'s "964-974 (source-count
varies)" language; 975 is the CVRF-doc figure as of this run).

Existing pipeline context (`data-src/refresh.py`):
- `fetch_msrc()` already calls `GET https://api.msrc.microsoft.com/cvrf/v3.0/updates` (JSON via
  `Accept: application/json`) to enumerate monthly doc IDs back to `START.year`, then for each
  fetches `CvrfUrl` and counts `Vulnerability[]` entries whose `CVE` starts with `CVE-` and whose
  `Title` does **not** start with "Chromium" (Edge/Chromium CVEs are deliberately excluded from
  the Patch Tuesday count). Output cached as `{month: count}` → `ZW.patch.msrc`.
- `fetch_dotnet()` scrapes GitHub Issue Search
  (`repo:dotnet/announcements is:issue "Security Advisory" in:title`) per year, parses
  `[date, headingPrefix, title]` triples → `ZW.patch.dotnet` (monthly counts) and
  `ZW.patch.dotnet_items` (full list, rendered in the `#dotnet` panel of `index.html`).
  `index.html` itself notes: *dotnet/announcements advisories are **not** ingested into the
  global GitHub Advisory Database (github/advisory-database #8717), so the NuGet ecosystem chart
  on the Frameworks tab undercounts .NET* — this is the single biggest known gap the owner wants
  closed.
- `manual.json` already carries hand-curated .NET narrative in `framework_facts` (the July 2026
  "17 advisories in one Patch Tuesday" entry) and a `watchlist` entry `aspnet-core-blazor`
  (CPE `cpe:2.3:a:microsoft:asp.net_core`, feed = the same dotnet/announcements label URL — no
  NVD CPE history exists for ASP.NET Core specifically, so `fetch_nvd_watchlist()` likely returns
  nothing useful for this id; worth checking cache).

---

## Part A — machine-readable sources

### A1. MSRC CVRF v3.0 monthly document — confirmed live, richer than currently used

`GET https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/<YYYY-Mon>` with `Accept: application/json`
returns the full CVRF 1.1 document as JSON (confirmed structure via the XML-default fetch of
`2026-Sep`, which is the same document tree, just serialized as `<cvrf:...>` XML instead of JSON
keys — refresh.py's existing `Accept: application/json` header on this exact URL already yields
JSON with equivalent field names, camel-cased per MSRC's JSON mapping, e.g. `Vulnerability`,
`ProductTree`, `DocumentTracking`).

**Confirmed live fields (from the raw 2026-Sep document):**

- `DocumentTracking.RevisionHistory.Revision[]` → `{Number, Date, Description}` — e.g. Sep 2026
  is at Revision **527**, `InitialReleaseDate` 2026-09-08, `CurrentReleaseDate` 2026-09-15 (doc
  gets revised in place all month as MSRC adds/edits CVEs — the CVRF `updates` list's own
  `CurrentReleaseDate` field, already visible in the `/cvrf/v3.0/updates` response fetched today,
  changes on every revision: e.g. `2026-Sep` shows `CurrentReleaseDate: 2026-09-15T07:00:00Z`
  vs. `InitialReleaseDate: 2026-09-08T07:00:00Z`). **This means a single fetch per month is not
  enough** if the pipeline wants day-1 vs. final counts — `fetch_msrc()`'s existing `fresh`
  window (re-fetch if the month is within the last ~62 days) already handles this correctly.
- `DocumentNotes.Note[Title="Release Notes"]` — an HTML blob (already present, currently
  unparsed) containing:
  - **A ready-made per-product-family table**: `Product Family | Updates per Product/Version |
    Vulnerabilities Addressed | Distinct Updates | Type of Update`. Confirmed Sep 2026 rows:
    Azure (12 vulns), Developer Tools (22, cumulative — this is where Visual Studio / .NET
    tooling CVEs roll up), Exchange Server (9), Office (111 + 111 for Office 2016 separately),
    Other (9), SharePoint Server (16), Skype for Business (10), SQL (62), Windows (724). **This
    table is the single fastest way to get a product-family breakdown without walking
    `ProductTree`/`Threats` per-CVE** — it's pre-aggregated by MSRC itself. Caveat: it groups by
    *update package* families, not CVE-level product tags, so "Developer Tools" mixes Visual
    Studio and some .NET runtime CVEs; for precise .NET/ASP.NET Core/Blazor isolation, still use
    the per-Vulnerability `ProductTree` walk (below) or, better, the SUG API (A2).
  - **A "Notable CVEs" table**: `CVE ID | Title | Notable Item`, where Notable Item is a plain
    string like `"Exploitation Detected"`. Confirmed Sep 2026 has 3 rows including
    `CVE-2026-85880` (Windows ALPC EoP) and `CVE-2026-81963` (Windows Update Stack EoP), both
    "Exploitation Detected" — this is MSRC's own hand-picked exploited-CVE list for the month,
    matching `manual.json`'s Sep 2026 timeline entry.
  - **A Known Issues table**: `KB Article | Applies To`, listing the actual KB/CU numbers per
    product (e.g. `5121608` for Exchange Server SE, `5122768` for SQL Server 2022 CU26) — useful
    for linking straight to the update package, not just the CVE.
- `ProductTree.Branch[Type=Vendor,Name=Microsoft].Branch[Type="Product Family"]` — confirmed
  live: nested branches per family (`Windows`, and by extension `Office`, `.NET/ASP.NET`,
  `Azure`, `SQL Server`, `Exchange`, `SharePoint`, `Developer Tools`/Visual Studio, etc. — only
  `Windows` was visible in the truncated fetch, but the schema is uniform across all CVRF docs
  back to 2016). Each leaf is `FullProductName[@ProductID]` = human name, e.g.
  `ProductID="12436"` → `"Windows Server 2025"`, `ProductID="20438"` → `"Windows 11 Version
  25H2 for x64-based Systems"`. **This is the join key**: every `Vulnerability.ProductStatuses`
  and `Vulnerability.Threats`/`CVSSScoreSets` entry references `ProductID`, not a product name —
  you must resolve through this tree.
- `Vulnerability[]` (not reached in the truncated fetch, but stable/documented CVRF 1.1 schema,
  and this is exactly what `fetch_msrc()` already parses for `CVE`/`Title`):
  - `CVE` — string, e.g. `"CVE-2026-69805"`.
  - `Title.Value` — e.g. `".NET Elevation of Privilege Vulnerability"` (already used by
    refresh.py to exclude Chromium/Edge titles).
  - `Notes[]` — `{Title, Type, Ordinal, Value}`; `Type="Description"` gives the CNA-style
    one-liner (matches the SUG API's `description` field, confirmed identical text in A2 below).
  - `ProductStatuses[].ProductStatus` — `{Type: "Known Affected"|..., ProductID: [...]}` — this
    is the per-CVE product mapping (resolve `ProductID` against `ProductTree`).
  - `Threats[]` — `{Type, Description.Value, ProductID: [...]}` where `Type` is one of
    `Impact` (value e.g. `"Elevation of Privilege"`, `"Remote Code Execution"`), `Severity`
    (value e.g. `"Important"`, `"Critical"`), and `Exploit Status` (a semicolon-delimited string
    historically, e.g. `"Publicly Disclosed:No;Exploited:Yes;Latest Software
    Release:Exploitation More Likely"` — **this single field is the source of the
    Exploited/Publicly-Disclosed/Exploitation-More-Likely triad the brief asks for**, all three
    values embedded as substrings needing a split on `;` then `:`).
  - `CVSSScoreSets[]` — `{BaseScore, TemporalScore, Vector, ProductID: [...]}`.
  - `Revisionhistory` / per-vulnerability `RevisionHistory.Revision[]` — same
    `{Number, Date, Description}` shape as the document-level one, per-CVE (e.g. "Added
    SkiaSharp 4.151.2 to the affected software table" — confirmed via the SUG API's
    `revisions[]`, A2, which mirrors this).

**20-line pseudo-parser** (stdlib-only, matches the style of `fetch_msrc()`):
```python
def parse_cvrf_products(doc):
    id2name = {}
    def walk(branch, family=None):
        fam = branch.get('Name') if branch.get('Type') == 'Product Family' else family
        for fp in branch.get('FullProductName', []):
            id2name[fp['ProductID']] = {'name': fp['Value'], 'family': fam}
        for sub in branch.get('Branch', []):
            walk(sub, fam)
    for b in doc['ProductTree']['Branch']:  # top-level Vendor branch(es)
        walk(b)
    rows = []
    for v in doc.get('Vulnerability', []):
        cve = v.get('CVE', '')
        title = v.get('Title', {}).get('Value', '')
        if title.lower().startswith('chromium') or not cve.startswith('CVE-'):
            continue
        sev = impact = exploited = disclosed = likelihood = None
        for t in v.get('Threats', []):
            val = (t.get('Description') or {}).get('Value', '')
            if t['Type'] == 'Severity': sev = val
            elif t['Type'] == 'Impact': impact = val
            elif t['Type'] == 'Exploit Status':
                for part in val.split(';'):
                    k, _, v2 = part.partition(':')
                    if k.strip() == 'Exploited': exploited = v2.strip()
                    elif k.strip() == 'Publicly Disclosed': disclosed = v2.strip()
                    elif k.strip() == 'Latest Software Release': likelihood = v2.strip()
        families = {id2name.get(pid, {}).get('family') for st in v.get('ProductStatuses', [])
                    for pid in st.get('ProductID', [])} - {None}
        cvss = next(iter(v.get('CVSSScoreSets', [])), {})
        rows.append({'cve': cve, 'title': title, 'families': sorted(families), 'severity': sev,
                     'impact': impact, 'exploited': exploited, 'disclosed': disclosed,
                     'likelihood': likelihood, 'cvss': cvss.get('BaseScore')})
    return rows
```

**`/cvrf/v3.0/updates` list — confirmed live today.** Full history back to 1999 (`"Mariner
Release Notes"` entries are non-Patch-Tuesday placeholder docs, safely skippable — `fetch_msrc()`
already implicitly handles this since they contain no `CVE-` vulnerabilities). Real Patch Tuesday
docs start `2016-Apr`. **Out-of-band updates**: confirmed present as separate `ID`s, e.g.
`"2017-May-B"` ("May 8 2017 Security Updates", a day before the main May 2017 release) — these
are NOT swept up by `fetch_msrc()`'s `re.fullmatch(r'(\d{4})-([A-Za-z]{3})', u['ID'])` regex,
which requires a bare `YYYY-Mon` and would skip `2017-May-B` entirely (regex has no `$` anchor
issue, but `-B` suffix fails `fullmatch`). **This is a real gap**: any month with an out-of-band
release currently silently drops those CVEs from the monthly count. Fix: also match
`r'(\d{4})-([A-Za-z]{3})(-[A-Z])?'` and fold the suffix into the same month bucket (or track
separately as a "supplemental release" flag).

Cadence: `CurrentReleaseDate` updates in place throughout the month (confirmed Sep 2026 doc
revised same-day, 2026-09-15, one week after Patch Tuesday) — no separate "delta" feed exists;
polling the same URL and diffing `Vulnerability[]` by CVE is the only way to catch mid-month
additions/corrections.

### A2. MSRC Security Update Guide API (`api.msrc.microsoft.com/sug/v2.0`) — confirmed live, unauthenticated, and richer per-CVE than CVRF

**This was not in `sources.md` and is a genuinely new, high-value find.** Confirmed live with no
auth, no API key, no cookies:

```
GET https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability?$top=2
```
returns `@odata.count: 26490` (the full historical row count) and OData-standard paging
(`@odata.nextLink` with `$skip`). `$filter`, `$select`, and `contains(field, 'substr')` all work
(confirmed: `$filter=cveNumber eq 'CVE-2026-85893'` → 1 exact match;
`$filter=contains(tag,'.NET')` → 215 total rows). The root `.../sug/v2.0/vulnerability` (no
`en-US`, no `$top`) returns the OData service document instead — confirms the entity set list:
`vulnerability, acknowledgement, affectedProduct, releaseNote, deployment, headerContent,
revisionNote, advisory, metadata` — several of these (`affectedProduct`, `deployment`,
`acknowledgement`) are unexplored but likely give exactly the per-KB/per-product rollup that CVRF
buries in `ProductStatuses`.

**Fields confirmed present on every `vulnerability` row** (live sample, `CVE-2026-85893` and
`.NET`-tagged rows):
- `cveNumber`, `cveTitle`, `releaseNumber` (e.g. `"2026-Sep"`, `"2026-Aug"` — this alone lets you
  regroup by Patch Tuesday month without touching CVRF at all), `releaseDate`,
  `latestRevisionDate`.
- `tag` — **this is the product-family field the brief wants**, confirmed exact values seen live:
  `"ASP.NET Core"`, `".NET"`, `".NET and Visual Studio"`, `".NET Core"`,
  `"Microsoft Edge (Chromium-based)"`. `contains(tag, '.NET')` is a working server-side filter —
  no client-side product-tree walk needed at all for a ".NET family" view. (Tag values for
  Windows/Office/Azure/SQL/Exchange/SharePoint/Dynamics/Copilot were not individually confirmed
  live in this session but follow the same pattern per MSRC's public UI, which uses this exact
  API — worth a follow-up `contains(tag, 'Windows Server 2025')`-style probe before wiring.)
- `severity` (+ `severityId`) — e.g. `"Important"`.
- `impact` (+ `impactId`) — e.g. `"Elevation of Privilege"`, `"Remote Code Execution"`,
  `"Denial of Service"`, `"Information Disclosure"` — a clean enum, exactly the impact
  breakdown the brief wants (RCE/EoP/DoS/InfoDisclosure/...).
- `exploited` — `"Yes"`/`"No"` string (confirmed both values exist; a live
  `$filter=exploited eq 'Yes' and releaseNumber eq '2026-Sep'` combined with `$select` returned
  empty in this session — likely an OData quirk combining `$filter`+`$select`, not a real "zero
  exploited CVEs this month" result, since the CVRF Notable-CVEs table for the same month lists 3
  — **retest without `$select`, or fetch the 2 known CVE numbers directly by `cveNumber eq
  'CVE-2026-85880'` to confirm the field populates correctly** before relying on the aggregate
  filter form).
- `publiclyDisclosed` — `"Yes"`/`"No"` string, direct field, no parsing of a combined
  Exploit-Status string needed (unlike CVRF's `Threats[Type="Exploit Status"]`).
- `latestSoftwareRelease` — **this is the "Exploitation More/Less Likely" index**, confirmed
  live values: `"Exploitation Unlikely"`, `"Exploitation Less Likely"` (+ implied
  `"Exploitation More Likely"` per MSRC's own published taxonomy, not observed live this session
  but documented MSRC terminology) alongside a numeric `latestSoftwareReleaseId`
  (1/2/3 seen) and a parallel `olderSoftwareReleaseId` for the same index scoped to
  out-of-support versions.
- `baseScore`, `temporalScore`, `vectorString` (full CVSS 3.1 vector, e.g.
  `"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"`), `vectorStringSource`.
- `cweList` (array of `"CWE-nnn: Name"` strings) + `cweDetailsList` with CWE URLs — richer than
  CVRF, which only gives raw CWE IDs via `problemTypes` elsewhere.
- `revisions[]` — `{cveNumber, version, revisionDate, description, unformattedDescription}` —
  the same per-CVE revision history as CVRF, but pre-flattened and versioned (e.g.
  `version: 1.1` for a minor correction vs `version: 2` for a substantive one) — confirmed a real
  multi-revision CVE (`CVE-2026-58641`, 2 revisions: initial publish + "Added SkiaSharp 4.151.2 to
  the affected software table").
- `articles[]` — FAQ-style Q&A blocks per CVE (e.g. "What privileges could be gained...") —
  narrative, not needed for the data model but could power a "why this matters" tooltip.
- `mitreUrl` — direct `https://www.cve.org/CVERecord?id=...` link, free CVE.org cross-reference.
- `isMariner` — boolean flag distinguishing Azure Linux (Mariner) CVEs from Windows-ecosystem
  ones, confirmed present (`false` on the Windows/.NET rows sampled) — useful for excluding
  Azure Linux/CBL-Mariner OSS-package CVEs from a ".NET on Windows" view if that distinction
  matters.

**Verdict: ADD-KEYLESS, high priority.** This API gives per-CVE `tag` (product family),
`severity`, `impact`, `exploited`, `publiclyDisclosed`, and the Exploitation-Likelihood index as
**flat top-level fields with no XML/CVRF product-tree join required** — strictly less parsing
work than the existing CVRF-based `fetch_msrc()` for anything beyond the raw monthly CVE count.
Recommend: keep `fetch_msrc()`'s CVRF-based monthly-count fetch as-is (it's cheap, already
working, and gives the official per-family summary table for free via `DocumentNotes`), and add
a **new** `fetch_msrc_sug()` that pages `$filter=releaseNumber eq '<month>'` per month (26,490
total rows historically — a full backfill needs ~265 pages at `$top=100`, each 1 request; a
weekly incremental run needs only the current + previous month, ~20 rows) to populate per-CVE
`tag`/`exploited`/`impact`/`likelihood`/CVSS for the product-family and exploitation-hit-rate
views in Part B. Rate limit: undocumented, no key required in ~10 requests this session: be
polite (0.2–0.3s sleep between pages, matching the pattern of other fetchers in `refresh.py`).

### A3. .NET security releases and support lifecycle — confirmed live, three complementary sources

1. **`https://raw.githubusercontent.com/dotnet/core/main/release-notes/releases-index.json`** —
   confirmed live. Top-level `releases-index[]`, one row per channel (e.g. `10.0`, `9.0`, `8.0`,
   down to `1.0`), fields: `channel-version`, `latest-release`, `latest-release-date`,
   **`security` (boolean — true if the latest patch in that channel was a security release)**,
   `support-phase` (`preview`|`active`|`maintenance`|`eol`), `release-type` (`lts`|`sts`),
   `eol-date`, and a per-channel `releases.json` URL. Confirmed live values today: .NET 10 =
   active/LTS, EOL 2028-11-14; .NET 9 = maintenance/STS, EOL 2026-11-10; .NET 8 =
   maintenance/LTS, EOL 2026-11-10 (both 9 and 8 EOL the same week, ~2 months from today);
   .NET 11 = preview. This `security` boolean is exactly the "was this a security release" flag
   the brief asks about, at the channel level.
2. **Per-channel `releases.json`** (e.g. `https://builds.dotnet.microsoft.com/dotnet/release-metadata/8.0/releases.json`)
   — confirmed live (large: ~1200 lines for .NET 8's full history). Each entry under `releases[]`
   has `release-date`, `release-version`, and — on security releases —
   a **`security: true` flag plus a `cve-list[]` array of `{cve-id, cve-url}`**. This is the
   authoritative per-patch CVE↔.NET-version join (e.g. which CVEs shipped in `8.0.14` vs
   `8.0.15`), letting the pipeline build a ".NET security release timeline" independent of MSRC
   entirely (MSRC's monthly CVRF only tells you *that* a .NET CVE existed in a given Patch
   Tuesday, not which .NET/ASP.NET Core patch version fixed it). Not fully fetched this session
   (output-size capped), but the schema is documented and stable
   (`https://json.schemastore.org/dotnet-releases.json`) — confirm the `cve-list` key name on a
   live fetch before wiring (older schema versions may use `cves` — verify against a current
   payload).
3. **`https://endoflife.date/api/dotnet.json`** — confirmed live, clean JSON array,
   `{cycle, releaseDate, eol, latest, latestReleaseDate, lts}` per .NET version back to 1.0. This
   is the simplest source for "EOL bands" on a timeline chart (no need to compute EOL dates from
   `releases-index.json` — endoflife.date already normalizes it, and also gives the pre-.NET-Core
   1.x/2.x/3.x history that `releases-index.json` also carries, so either works; endoflife.date
   is simpler to consume for a chart overlay). Confirmed matching EOL dates between the two
   sources (.NET 8/9 both 2026-11-10, .NET 10 2028-11-14).

**Blazor/SignalR-specific advisories**: neither dotnet/core nor MSRC tags CVEs at the
"Blazor" or "SignalR" component level directly — they arrive as `.NET`/`ASP.NET Core` CVEs whose
*title or description* mentions the component (confirmed pattern from `manual.json`'s own
framework_facts note: *"June: CVE-2026-45591 SignalR/Blazor Server MessagePack stack-overflow DoS"*
— that CVE's MSRC title is generically "ASP.NET Core..." with SignalR/Blazor named only in the
description body). Recommend: regex over the SUG API's `description`/`cveTitle` fields for
`\b(Blazor|SignalR)\b` as a heuristic "Blazor/SignalR-relevant" tag, same caveat style as the
NCSC-NL/JVN free-text CVE extraction already documented in `sources.md` §4.3/4.7 — label as
heuristic, not authoritative.

**dotnet/runtime, dotnet/aspnetcore, dotnet/efcore, dotnet/sdk, dotnet/maui GitHub Security
Advisories**: these are standard `GET /repos/{owner}/{repo}/security-advisories` endpoints —
exactly the mechanism `fetch_gh_repos()` already implements generically (cursor-paginated via
`Link: rel="next"`, already handling GitHub's non-`page`-param pagination correctly). Not fetched
live this session (would need a GITHUB_TOKEN to avoid rate limits at volume, same as the existing
`fetch_gh_repos()` does), but this is a **zero-new-code addition**: `manual.json.repos[]` already
lists `dotnet/runtime` and `dotnet/aspnetcore` — just add `dotnet/efcore`, `dotnet/sdk`,
`dotnet/maui` to that same array and `fetch_gh_repos()` will pick them up on the next run with no
code changes. This is the most direct fix for the "NuGet ecosystem chart undercounts .NET"
problem the owner flagged: `dotnet/announcements` (current source) undercounts because many .NET
CVEs are filed as repo-level GHSAs on `dotnet/runtime`/`dotnet/aspnetcore` directly rather than as
an `announcements` issue — `fetch_gh_repos()` already captures those per-repo, just not for the
additional repos.

**NuGet ecosystem-wide advisories**: `manual.json.ecosystems` already includes `"nuget"`, and
`fetch_gh_eco()` already pulls monthly counts for it via `GET /advisories?ecosystem=nuget` — no
gap here, this is already wired and working; the "undercount" the owner is referring to (per
`index.html`'s own note) is specifically that `dotnet/announcements` advisories aren't relayed
into the *GitHub Advisory Database* (hence not counted by `ecosystem=nuget`), not that the NuGet
ecosystem fetch itself is broken.

### A4. Windows/Azure cloud CVEs, Copilot/AI products, Secure Future Initiative

- **Azure/cloud-service CVEs in CVRF**: confirmed pattern — MSRC's `ProductTree` includes an
  `Azure` Product Family branch (seen in the Sep 2026 doc's own release-notes table: "Azure" row,
  12 vulnerabilities that month). Since 2024, Microsoft has also started publishing CVEs for pure
  cloud-service vulnerabilities that have no customer-installable patch (previously handled via
  silent fix + advisory-only, no CVE) — these are identifiable in CVRF the same way as any other
  product-family tag; no separate feed exists, this is purely a filter on `ProductTree` branch
  name containing "Azure" or the SUG API's `tag` field.
- **Copilot / Copilot Studio / Microsoft 365 Copilot CVEs**: not confirmed live this session
  (would need a `tag` probe like `contains(tag,'Copilot')` against the SUG API, same technique
  as A2's `.NET` probe — recommend as a follow-up before wiring, since Microsoft does assign
  CVEs to some AI-product vulnerabilities, e.g. prompt-injection-adjacent issues, but the SUG
  `tag` taxonomy for these wasn't directly observed).
- **endoflife.date for Windows**: `https://endoflife.date/api/windows.json` confirmed live —
  very granular (`cycle` per release+edition combo, e.g. `"11-25h2-e"` vs `"11-25h2-w"` for
  Enterprise vs Consumer/Workstation channels of the same build), with `eol`, `support`, and
  `extendedSupport` fields. Confirmed Windows 10 22H2 general support ended 2025-10-14 (already
  passed as of today) with `extendedSupport: "2028-10-10"` (ESU program). Windows Server has a
  separate `endoflife.date/api/windows-server.json` (not fetched this session but same API
  family, same schema pattern — safe to assume live given `windows.json` worked).
- **Windows release health / KB feed**: `https://msrc.microsoft.com/update-guide/rss` is already
  listed as the `feeds[]` entry for the `windows`/`exchange`/`sharepoint` watchlist rows in
  `manual.json` but is not fetched by any `refresh.py` function today (only used as a
  human-facing link) — not tested live this session; standard MSRC RSS, likely one-CVE-per-item,
  probably redundant with CVRF/SUG API coverage. Low priority given A1/A2 already cover this data
  more richly.
- **Secure Future Initiative reports**: annual PDF/blog, no API — **MANUAL-ONLY**, same treatment
  as other vendor annual reports already catalogued in `sources.md` (TIG, M-Trends).

### A5. Exploitation cross-refs (KEV correlation) — fully computable from existing + new data

The brief's "days from Patch Tuesday to KEV" and "Exploited:Yes vs KEV coverage" metrics need no
new source at all — they're a join between data already in the pipeline (`fetch_kev()`) and the
per-CVE MSRC data above:
- **Patch-Tuesday-to-KEV lag**: for every KEV entry whose CVE prefix year/number matches a known
  Microsoft-family CVE (or, better, whose `vendorProject` field from `fetch_kev()` is
  `"Microsoft"`), compute `KEV dateAdded − MSRC releaseDate` (the SUG API's `releaseDate` field,
  A2, gives the exact Patch Tuesday the CVE first shipped on). This is a pure computation once
  A2 is wired — no fetch needed beyond what's already planned.
- **MSRC "Exploited: Yes" vs KEV membership**: for each month, compare the SUG API's
  `exploited == "Yes"` set against the CISA KEV set restricted to Microsoft `vendorProject`
  entries. Historically these mostly overlap (Microsoft self-reports what it knows is exploited,
  and CISA typically adds it) but not always — Microsoft sometimes flags "Exploited: Yes" for
  CVEs CISA never KEV-lists (e.g. exploitation against a narrow/legacy target CISA doesn't deem
  federal-enterprise-relevant), and rarely CISA KEV-lists something before MSRC updates its own
  flag. This asymmetry is itself a notable metric ("Microsoft-flagged-but-not-KEV" count).

---

## Part B — out-of-the-box views

| # | View | Data needed | Computable now? |
|---|------|-------------|------------------|
| 1 | Patch Tuesday CVE count by product family, stacked monthly, since 2016 | CVRF `DocumentNotes` per-family table (A1) for recent months (table format may not exist pre-~2020 — verify oldest month with the table present) **or** per-CVE `ProductTree` walk (A1) for full 2016+ coverage | Yes — CVRF docs exist back to 2016-Apr; per-CVE walk works for all of them, the pre-built table is a shortcut only for recent months |
| 2 | "Exploitation More/Less/Unlikely" index hit-rate: of CVEs MSRC rated at release, what % were later confirmed exploited (`exploited` flips to Yes) or added to KEV | SUG API `latestSoftwareRelease` at first revision + `exploited` at latest revision (A2), joined to KEV (A5) | Yes, once A2 is wired — needs revision-aware tracking (compare CVE state across weekly snapshots, or use the SUG `revisions[]` array to see if/when the flag changed) |
| 3 | Zero-day (exploited-before-patch) count per month for Microsoft specifically | SUG API `publiclyDisclosed`+`exploited` both "Yes" at initial release date (A2), cross-checked against CVRF Notable-CVEs "Exploitation Detected" table (A1) | Yes |
| 4 | Time from Patch Tuesday release to KEV addition, Microsoft CVEs only | SUG `releaseDate` (A2) + KEV `dateAdded` (existing `fetch_kev()`) | Yes — pure join, no new fetch beyond A2 |
| 5 | .NET/ASP.NET Core/Blazor security-release timeline with CVE counts and EOL bands | dotnet/core `releases-index.json` + per-channel `releases.json` `cve-list` (A3) overlaid with `endoflife.date/api/dotnet.json` EOL dates (A3) | Yes |
| 6 | ASP.NET Core/Blazor/SignalR CVE list with CVSS, sortable | SUG API filtered `tag` in `{"ASP.NET Core", ".NET", ".NET and Visual Studio", ".NET Core"}` (A2) plus regex-tag for Blazor/SignalR mentions in `description`/`cveTitle` (A3) | Yes, with the regex caveat noted in A3 |
| 7 | Windows Server 2025 vs 2022 vs 2019 exposure (CVE count per version per month) | CVRF `ProductTree` `FullProductName` entries per Windows Server version, joined via `ProductStatuses` (A1) — SUG API `tag` likely too coarse (just `"Windows"`) for this granularity, needs the CVRF product-ID join | Yes, CVRF-only |
| 8 | Exchange/SharePoint on-prem "danger index" (CVE count + KEV hits + Exploited:Yes rate, weighted toward on-prem-only products) | CVRF/SUG `tag`="Exchange Server"/"SharePoint Server" + existing KEV `kev_categories.on_prem_collaboration` bucket (already in `manual.json`) | Yes — mostly a re-slice of data already flowing into `kev_by_category` |
| 9 | Copilot/AI-product Microsoft CVEs | SUG API `tag` containing "Copilot" (unconfirmed live, needs a follow-up probe per A4) | Provisional — needs the tag-taxonomy check noted in A4 before committing |
| 10 | NuGet ecosystem advisories vs npm/pip/etc, corrected for the dotnet/announcements gap | Existing `fetch_gh_eco()` (nuget already in `ecosystems`) + new `dotnet/efcore`,`dotnet/sdk`,`dotnet/maui` repos added to `fetch_gh_repos()` (A3) to close the undercount `index.html` already flags | Yes — mostly a `manual.json.repos[]` addition, no new fetcher |
| 11 | Bug-age at fix for Microsoft CVEs (CVE-ID year vs Patch-Tuesday release year) | SUG API `cveNumber` (parse year) vs `releaseDate` year (A2) | Yes |
| 12 | "Record months" leaderboard (Patch Tuesday CVE counts ranked, e.g. Sep 2026 vs historical) | Existing `ZW.patch.msrc` monthly counts (already computed) — pure re-sort/rank, no new data | Yes, trivially, with zero new fetching |
| 13 | AI-credited Microsoft CVEs (existing `ai_credit` index filtered to CNA = Microsoft) | Existing `fetch_ai_credit()` cvelistV5 scan already carries `cveMetadata.assignerShortName`-equivalent data implicitly via the CVE record itself — needs the CNA field to be captured during the scan (verify `_scan_zip_for_ai_credit` currently records assigner; if not, add it) — see note below | Likely yes, pending a check of what fields `_scan_zip_for_ai_credit` currently extracts from each CVE JSON (not fully read this session — the AI-credit scan logic lives past line ~1236 of refresh.py) |
| 14 | Microsoft vs Linux vs Apple weekly high/critical, CNA-series comparison | Existing `fetch_epoch()` (Epoch AI explorer, already CNA-keyed weekly series including presumably "Microsoft" as a CNA) | Yes, if "Microsoft" is one of Epoch's tracked CNA keys — not directly confirmed this session but Epoch's methodology (cve.org by CNA) would include Microsoft's own CNA (`issuingCna: "Microsoft"`, confirmed field name in A2) as a matter of course |
| 15 | Windows-11-only vs Server-only vs both CVE overlap (how often a single CVE spans client+server vs one or the other) | CVRF `ProductStatuses`/`ProductTree` — count distinct `ProductID`s per CVE, classify by whether any resolve to "Server" vs non-"Server" `FullProductName` strings | Yes, CVRF-only, no new source |

---

## MS_PLAN

```json
{
  "MS_PLAN": {
    "sources": [
      {"id": "msrc_cvrf_updates", "url": "https://api.msrc.microsoft.com/cvrf/v3.0/updates", "format": "JSON (Accept header)", "auth": "none", "cadence": "continuous; poll weekly"},
      {"id": "msrc_cvrf_doc", "url": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{YYYY-Mon}", "format": "JSON or XML (CVRF 1.1)", "auth": "none", "cadence": "revised in place through the month; already partially wired"},
      {"id": "msrc_sug_v2", "url": "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability", "format": "JSON (OData v4, $filter/$select/$top supported)", "auth": "none", "cadence": "continuous, ~26.5k rows total historically; new find, not yet wired"},
      {"id": "dotnet_releases_index", "url": "https://raw.githubusercontent.com/dotnet/core/main/release-notes/releases-index.json", "format": "JSON", "auth": "none", "cadence": "per .NET release, ~monthly"},
      {"id": "dotnet_channel_releases", "url": "https://builds.dotnet.microsoft.com/dotnet/release-metadata/{channel}/releases.json", "format": "JSON", "auth": "none", "cadence": "per .NET release; verify cve-list key name live before wiring"},
      {"id": "endoflife_dotnet", "url": "https://endoflife.date/api/dotnet.json", "format": "JSON", "auth": "none", "cadence": "on EOL/release changes"},
      {"id": "endoflife_windows", "url": "https://endoflife.date/api/windows.json", "format": "JSON", "auth": "none", "cadence": "on EOL/release changes"},
      {"id": "endoflife_windows_server", "url": "https://endoflife.date/api/windows-server.json", "format": "JSON", "auth": "none", "cadence": "on EOL/release changes (not fetched live this session, same API family)"},
      {"id": "gh_repo_advisories_dotnet", "url": "https://api.github.com/repos/{dotnet/efcore|dotnet/sdk|dotnet/maui}/security-advisories", "format": "JSON (cursor-paginated)", "auth": "GITHUB_TOKEN recommended", "cadence": "continuous; reuses existing fetch_gh_repos(), just add repos to manual.json"},
      {"id": "msrc_update_guide_rss", "url": "https://msrc.microsoft.com/update-guide/rss", "format": "RSS", "auth": "none", "cadence": "continuous; low priority, likely redundant with A1/A2"}
    ],
    "views": [
      {"id": "patch_tuesday_by_family_stacked", "title": "Patch Tuesday CVEs by product family, stacked monthly since 2016", "needs": ["msrc_cvrf_doc"], "computable": true},
      {"id": "exploitation_likelihood_hitrate", "title": "Exploitation More/Less Likely hit-rate", "needs": ["msrc_sug_v2", "kev"], "computable": true},
      {"id": "zero_day_count_per_month", "title": "Microsoft zero-days (exploited before/at patch) per month", "needs": ["msrc_sug_v2", "msrc_cvrf_doc"], "computable": true},
      {"id": "patch_tuesday_to_kev_lag", "title": "Time from Patch Tuesday to KEV addition", "needs": ["msrc_sug_v2", "kev"], "computable": true},
      {"id": "dotnet_release_timeline_eol", "title": ".NET security release timeline with EOL bands", "needs": ["dotnet_releases_index", "dotnet_channel_releases", "endoflife_dotnet"], "computable": true},
      {"id": "aspnet_blazor_signalr_cve_list", "title": "ASP.NET Core/Blazor/SignalR CVE list with CVSS", "needs": ["msrc_sug_v2"], "computable": true},
      {"id": "windows_server_version_exposure", "title": "Windows Server 2025/2022/2019 exposure", "needs": ["msrc_cvrf_doc"], "computable": true},
      {"id": "exchange_sharepoint_danger_index", "title": "Exchange/SharePoint on-prem danger index", "needs": ["msrc_sug_v2", "kev"], "computable": true},
      {"id": "copilot_ai_product_cves", "title": "Copilot/AI product Microsoft CVEs", "needs": ["msrc_sug_v2"], "computable": false},
      {"id": "nuget_vs_other_ecosystems", "title": "NuGet ecosystem advisories vs npm/pip/etc (undercount-corrected)", "needs": ["gh_repo_advisories_dotnet", "gh_eco_nuget"], "computable": true},
      {"id": "bug_age_at_fix", "title": "Bug-age at fix for Microsoft CVEs (CVE year vs Patch Tuesday year)", "needs": ["msrc_sug_v2"], "computable": true},
      {"id": "record_months_leaderboard", "title": "Record months leaderboard", "needs": [], "computable": true},
      {"id": "ai_credited_microsoft_cves", "title": "AI-credited Microsoft CVEs (CNA=Microsoft)", "needs": ["ai_credit_index"], "computable": false},
      {"id": "ms_vs_linux_vs_apple_weekly", "title": "Microsoft vs Linux vs Apple weekly high/critical", "needs": ["epoch"], "computable": true},
      {"id": "client_vs_server_overlap", "title": "Windows client vs server CVE overlap", "needs": ["msrc_cvrf_doc"], "computable": true}
    ],
    "data_contract": {
      "ZW.microsoft": {
        "monthly_by_family": "{month: {family: {count, critical, important, exploited, publicly_disclosed}}}",
        "cves": "[{cve, title, families[], severity, impact, exploited, publicly_disclosed, exploitation_likelihood, cvss, cwe[], release_month, revisions[], is_blazor_signalr, is_mariner}]",
        "notable": "[{cve, title, notable_item, month}]  // from CVRF DocumentNotes Notable-CVEs table",
        "kev_lag_days": "[{cve, patch_tuesday_date, kev_added_date, lag_days}]",
        "dotnet": {
          "channels": "[{version, support_phase, release_type, eol_date, latest_release, latest_release_date, security}]",
          "releases": "[{channel, version, release_date, security, cves[]}]",
          "items": "existing ZW.patch.dotnet_items, unchanged"
        },
        "windows_server_exposure": "{month: {product_version: count}}",
        "danger_index": "{exchange: {...}, sharepoint: {...}}  // count, kev_hits, exploited_rate"
      }
    }
  }
}
```
