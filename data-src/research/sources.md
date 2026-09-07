# Zero Project — source registry research

Compiled 2026-09-06. Every candidate was checked against the live endpoint with `web_fetch`
where the endpoint is a plain GET; results are quoted where useful. A few endpoints returned
an empty body to the fetcher despite being documented, working feeds elsewhere (see "fetch
notes" under each — these are flagged NEEDS-RETEST rather than SKIP, since `refresh.py`'s own
`http()` helper with a browser UA may succeed where the sandboxed fetcher did not). Nothing
here should be wired into `refresh.py` without a final manual curl from the CI runner, since
GitHub Actions egress IPs occasionally get treated differently than this sandbox.

Legend: **ADD-KEYLESS** wire in now, no auth. **ADD-WITH-KEY** wire in, needs a free/paid key
(store as a GH Actions secret, `cached()`-wrap so a missing key doesn't break the run).
**MANUAL-ONLY** no API/feed exists in machine-readable form worth scripting — link it, don't
ingest it. **SKIP** not worth the engineering cost or redundant with something already wired.

---

## 1. MITRE

### 1.1 CVE Program cvelistV5 (raw JSON) — already wired
`https://raw.githubusercontent.com/CVEProject/cvelistV5/main/<year>/<Nxx>/CVE-<year>-<N>.json`
Verdict: **ADD-KEYLESS** (confirmed already in use). Confirmed live: repo README fetched
today — updated **every ~7 minutes** from the CVE Services API, git-clone or Release-zip
distribution, CVE Record Format v5.2.0 (adds PURL support, Oct 2025). CISA-ADP container
(since June 2024, backdated to Feb 2024) embeds **SSVC** and **KEV** metadata directly in the
CVE record — see 1.1a below, this may let us drop a separate scrape for SSVC.
Licence: CVE Program Terms of Use (free reuse, attribution). No rate limit for git clone;
raw.githubusercontent.com is CDN-fronted and fine for per-CVE fetches.
Incremental fetch: **`cvelistV5/deltaLog.json`** — confirmed referenced in the live README
("normally retains a rolling 30 days... modification history"); fetch this instead of
re-cloning, then pull only the changed per-CVE JSON files it lists. This is a real
improvement over whatever cadence `refresh.py` uses today for cvelistV5 — check if it already
does delta fetching, and switch to `deltaLog.json` if not.
Mapping: existing CVE enrichment (CWE, CVSS, dates) feed for all tabs.

### 1.1a CISA-ADP container inside cvelistV5 (SSVC + KEV, embedded)
Verified live via `https://cveawg.mitre.org/api/cve/CVE-2024-3400` (see 1.2) — the `adp`
array contains an object with `providerMetadata.shortName: "CISA-ADP"` holding
`metrics[].other.content` = SSVC decision (`Exploitation`, `Automatable`, `Technical Impact`)
**and** a `kev` object (`dateAdded`, `reference`). This is CISA's own SSVC scoring, already
inside every enriched CVE record — no separate SSVC scrape needed if the CVE-record fetcher
parses the `adp` array.
Verdict: **ADD-KEYLESS** (free, part of 1.1's payload — this replaces "CISA SSVC" in
category 2 as a candidate; SSVC and KEV membership arrive for free with cvelistV5/CVE.org API
records, whichever is already being fetched).
Mapping: exploitation-evidence corroboration column, KEV cross-check.

### 1.2 CVE.org API (cveawg.mitre.org)
`https://cveawg.mitre.org/api/cve/CVE-2024-3400` — confirmed live today, returns the full
JSON CVE record shown in 1.1a (`dataType`, `cveMetadata`, `containers.cna`, `containers.adp`).
Verdict: **ADD-KEYLESS** for spot single-CVE lookups (e.g. resolving a CVE seen in a partner
feed that isn't yet in the local cvelistV5 clone); **not** a bulk-fetch replacement for
cvelistV5 (no bulk/list endpoint without auth — `cve.org` bulk download requires an account).
Rate limit: undocumented, be polite (few req/s). Format: JSON, CVE Record Format 5.x.
Licence: CVE Program Terms of Use.
Mapping: on-demand CVE detail lookups, not a scheduled fetcher.

### 1.3 MITRE ATT&CK STIX (attack-stix-data)
`https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`
(always-current bundle) + `index.json` (collection index). Confirmed live via README fetch
today. Format: STIX 2.1 JSON bundles, one per domain (enterprise/mobile/ics).
Verdict: **ADD-KEYLESS**, but only if we actually want technique tagging on KEV entries —
this is a large STIX bundle (tens of MB) to parse for what would be a "related ATT&CK
technique" chip. Given the pipeline is stdlib-only and weekly, recommend **MANUAL-ONLY /
SKIP for now**: fetching + parsing STIX with pure stdlib json is doable but mapping a CVE to
an ATT&CK technique isn't a data-join MITRE provides (ATT&CK doesn't reference CVEs) — you'd
need a third-party crosswalk (e.g. from vendor advisories) which doesn't exist as a feed.
Not worth the weekly bandwidth for a feature we can't actually populate.
Cadence: STIX releases ~3x/year. Licence: ATT&CK Terms of Use (attribution required).

### 1.4 MITRE ATLAS (atlas-data)
`https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS-latest.yaml`.
Confirmed live via README fetch today: monthly content releases (`YYYY.MM.N` versioning),
YAML top-level keys `tactics`, `techniques`, `mitigations`, `case-studies`, `relationships`.
This is AI/ML attack technique taxonomy, not vulnerability data — **case-studies** are the
interesting bit (real incidents against AI systems, some tied to specific product CVEs, e.g.
prompt-injection or model-extraction incidents).
Verdict: **MANUAL-ONLY**. Same problem as ATT&CK STIX — no CVE crosswalk field exists in the
schema (`case-studies` link to `techniques`, not CVE IDs). Given the site already tracks
Anthropic's ledger.json as its AI-specific source, ATLAS case studies are worth a human
skimming quarterly for anything CVE-bearing to hand-add to `manual.json`, not a scripted
fetch. Cadence: monthly. Licence: MITRE Corp, public release, non-commercial-friendly (check
before commercial reuse — the tracker is non-commercial so fine).

**Correction, 2026-09-06:** Follow-up research in `research/ai-frameworks-data.md` §1.1
revisits this. The narrow factual claim above (no CVE crosswalk field in the schema) still
holds and was re-confirmed live against the current `format-version: 6.0.0` schema — but the
MANUAL-ONLY verdict was too narrow. ATLAS's `case-studies` (each with `date`, `date-granularity`,
`type` Incident/Exercise, `actor`, `target`, `description`) plus the separate `relationships`
block (linking each case-study to `techniques`/`tactics` via `employs[]`) form a complete,
self-contained, dated dataset in their own right — no CVE join needed or expected, because
ATLAS was never modeling CVEs in the first place. Updated verdict: **ADD-KEYLESS** for a new,
standalone "AI attacks/incidents" series (case studies by year, top techniques/tactics, latest
incidents list), fetched monthly from `dist/v6/ATLAS-latest.yaml` (raw YAML at
`github.com/mitre-atlas/atlas-data`) — separate from, and explicitly not a source for, CVE/KEV
tagging. See the registry entry below, updated to match.

### 1.5 CWE (Common Weakness Enumeration)
`https://cwe.mitre.org/data/xml/cwec_latest.xml.zip` (canonical XML, versioned ~3-4x/year) —
not fetched live today (page too large/slow for a quick check; this is well-documented and
stable). CWE IDs already arrive embedded in every CVE record's `problemTypes` (see 1.2's
`CWE-77`/`CWE-20` in the CVE-2024-3400 example) — **no separate CWE fetch is needed** for
tagging; the raw CWE ID + description text is already sufficient for display. Only fetch the
full CWE catalog if the page wants a CWE *name* lookup table (`CWE-77` → "Command Injection")
rather than showing the raw ID — that's a static ~1000-row lookup, fine to vendor once as a
JSON in the repo rather than re-fetch weekly.
Verdict: **SKIP** (weekly fetch) / one-time **MANUAL-ONLY** vendoring of the ID→name table if
the page wants human-readable CWE names instead of bare `CWE-nnn`.

---

## 2. Exploitation evidence

### 2.1 FIRST EPSS
`https://api.first.org/data/v1/epss?cve=CVE-2024-3400` — confirmed live today:
```json
{"status":"OK","total":1,"data":[{"cve":"CVE-2024-3400","epss":"0.999990000","percentile":"1.000000000","date":"2026-09-05"}]}
```
Verdict: **ADD-KEYLESS**. Response shape: `data[]` of `{cve, epss, percentile, date}`.
Cadence: daily (EPSS model retrained daily; date field confirms same-day data). Rate limit:
undocumented but generous for reasonable batch sizes — batch CVEs with `cve=CVE-1,CVE-2,...`
(comma-separated, confirmed supported by the API) rather than one request per CVE; for the
full KEV list (~1400 CVEs) that's ~a dozen requests of ~100 CVEs each, well within budget.
Daily bulk CSV alternative: `https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz` — better
for a full-catalog EPSS join if we ever score more than the KEV set.
Licence: free, CC-style (FIRST.org data reuse policy, attribution requested).
Mapping: add an EPSS score/percentile column next to each KEV entry — directly answers "how
likely is this to be exploited" independent of "is it already known-exploited." High-value,
low-cost addition.
Incremental fetch: query only CVEs already in the local KEV/CVE cache each run; EPSS scores
drift daily so re-fetch all tracked CVEs every run rather than caching indefinitely.

### 2.2 VulnCheck KEV
`https://api.vulncheck.com/v3/index/vulncheck-kev` — requires a free VulnCheck API key
(community tier). Not fetched live (key-gated, can't test without credentials in this
session). Known from documentation: JSON response mirrors CISA KEV shape but with a larger
and earlier-dated catalog (VulnCheck backdates entries CISA hasn't added yet, and adds
non-US-government sourced exploitation evidence). Cadence: near-real-time. Rate limit: free
tier is modest (check current VulnCheck docs for the exact number before committing).
Verdict: **ADD-WITH-KEY** — worth it specifically *because* it's broader than CISA KEV
(different criteria, catches vendor-disclosed-but-not-CISA-catalogued exploitation) — but
only do this if there's appetite to hold a `VULNCHECK_API_KEY` GitHub secret; otherwise
**MANUAL-ONLY** (spot-check via their public web UI when a KEV entry looks incomplete).
Mapping: a "corroborating exploitation source" badge distinct from CISA KEV, useful for the
10-year backfill (see below) since VulnCheck's KEV coverage reaches further back than CISA's
Nov-2021 catalog start.

### 2.3 GreyNoise
Community API (`api.greynoise.io`) needs a free key; GreyNoise's product is *scanning/attack
traffic telemetry* per IP/tag, not a CVE-indexed "is this exploited" feed in the free tier —
their CVE-level exploitation intel (GreyNoise's "Exploit Detection" / trends) is a paid
product. Not fetched live (key-gated).
Verdict: **SKIP** for this pipeline — the free tier doesn't give a scriptable CVE→exploited
mapping, and the paid tier is out of scope for a public no-budget project. Worth a "trends"
link, not an ingest.

### 2.4 Shadowserver exploited-vulns dashboard/API
Shadowserver publishes a dashboard (`https://dashboard.shadowserver.org/statistics/vulnerability/`)
and offers free API access but it's report-subscription-based (daily CSV/JSON reports mailed
or pulled per registered organization), not an open unauthenticated catalog endpoint. Not
fetched live (requires org registration).
Verdict: **MANUAL-ONLY** — Shadowserver's model doesn't fit a public unauthenticated weekly
GitHub Actions job; registering as an org for report access is out of scope for a hobby
tracker. Link the dashboard as a reference in a "further reading" section.

### 2.5 CISA SSVC
Superseded by 1.1a — SSVC decision points arrive embedded in the CISA-ADP container of every
enriched cvelistV5/CVE.org record. No standalone SSVC feed exists outside that.
Verdict: **SKIP** as a separate source (covered by 1.1a).

### 2.6 Google Project Zero "0day In the Wild" spreadsheet
`https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY/gviz/tq?tqx=out:csv`
— confirmed live today, returns real CSV content (intro/scope text in the first ~15 rows,
confirmed the sheet is the genuine Project Zero 0day tracker: "data collection starts from
the day we announced Project Zero -- July 15, 2014", contact `0day-in-the-wild@google.com`).
Note the intro block itself says "Last updated: 2023-04-20" — that's stale front-matter text
in the sheet's own header rows, not proof the *data* is frozen; Project Zero does still
publish to this sheet (cross-check against their blog before treating it as abandoned — treat
with caution and note the possible staleness in the UI).
Format: CSV via Google Visualization API `gviz/tq` export — this is the correct/stable public
export mechanism (no auth, works for any publicly-shared Sheet). Real data rows start after
the intro block: expect columns like CVE, vendor, product, type, date-discovered,
discovery-method, advisory, root-cause-analysis links. Grab a real export and inspect the
header row before writing a parser — the schema/column order isn't guaranteed to be fixed.
Cadence: irregular, event-driven (P0 adds a row when they confirm an in-the-wild 0day).
Licence: Google, public sheet — reuse for a threat-intel tracker with attribution is
standard practice (many trackers already mirror this sheet).
Verdict: **ADD-KEYLESS**. This is the single best source for the 10-year backfill (2014+,
predates CISA KEV entirely) — see backfill section.
Incremental fetch: re-fetch the whole CSV weekly (it's small, a few hundred rows) and diff
against the cached copy; no row-level pagination exists or is needed at this size.

### 2.7 Google TIG (Threat Intelligence Group) annual reports — already manual
Verdict: **MANUAL-ONLY** (unchanged — TIG publishes an annual "0-days exploited in the wild"
PDF/blog post with a yearly count and named-CVE list, no API. Already handled as manual entry
per the brief). Worth continuing to hand-transcribe once a year.

### 2.8 Mandiant M-Trends
Annual PDF report, no API/feed. Verdict: **MANUAL-ONLY** — same treatment as TIG, useful for
cross-checking the yearly zero-day count and for the pre-2021 backfill narrative, not a
scriptable source.

---

## 3. Exploit availability

### 3.1 Exploit-DB (`files_exploits.csv`)
Canonical source: `https://gitlab.com/exploit-database/exploitdb` — the raw-file fetch
returned an empty body to this session's fetcher (`https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv`
and the `offensive-security/exploitdb` GitHub mirror equivalent both came back empty rather
than erroring, which usually means the sandboxed fetcher choked on GitLab's raw-file redirect
or a large-file LFS pointer rather than that the file doesn't exist — this repo and file are
well-documented and stable). **NEEDS-RETEST from the actual GitHub Actions runner** with
Python's `urllib` (matching `refresh.py`'s own `http()` helper) before final go/no-go — do
not trust this session's null result as a real SKIP signal.
Format (per public documentation): CSV with columns `id, file, description, date_published,
author, type, platform, port, date_added, date_updated, verified, codes, tags, aliases,
screenshot_url, application_url, source_url` — `codes` often contains the associated CVE
ID(s), which is the join key we need.
Cadence: continuous (new PoCs added daily), the CSV is regenerated on every commit.
Licence: Exploit-DB / OffSec — CSV redistribution is standard practice, many tools consume it
raw; no auth needed.
Verdict: **ADD-KEYLESS** (pending the runner retest above). Mapping: "public PoC exists"
boolean/count per CVE, and exploit-publication-date for time-to-exploit metrics predating KEV.
Incremental fetch: full CSV re-download weekly (file is a few MB, not worth diffing).

### 3.2 Metasploit modules_metadata_base.json
`https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json`
— confirmed live and fetchable today (only failed here because of this session's output-size
cap, not because the endpoint is broken — 85KB+ of valid JSON came back before truncation).
Format: JSON object keyed by module path, each value containing `name`, `fullname`,
`references` (array including `["CVE", "2024-3400"]`-style tuples), `disclosure_date`, `rank`,
`type`. This is exactly the CVE↔exploit-module join needed, plus a disclosure date useful for
time-to-weaponization metrics.
Cadence: continuous (rebuilt on every framework commit, effectively daily).
Licence: BSD-3-Clause (Metasploit Framework), redistribution fine.
Verdict: **ADD-KEYLESS**. Mapping: "Metasploit module available" boolean + link, a stronger
exploit-availability signal than Exploit-DB alone since a Metasploit module implies a
weaponized, maintained exploit rather than a one-off PoC.
Incremental fetch: full JSON re-download weekly (parse client-side with stdlib `json`, filter
to `references` containing `"CVE"` entries — cheap even at full-file size).

### 3.3 Nuclei templates (`cves.json` / `cves/` directory)
`https://github.com/projectdiscovery/nuclei-templates` — CVE-tagged templates live under
`http/cves/<year>/CVE-<year>-<n>.yaml`; there is also a generated
`https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json` index in
some releases (verify the exact current path before wiring — ProjectDiscovery has reorganized
this repo's layout more than once). Not fetched live this session (lower priority, redundant
signal with 3.1/3.2).
Verdict: **ADD-KEYLESS** but lower priority — a Nuclei template existing is a similar signal
to a Metasploit module (weaponized, automatable scanning/exploitation), marginal value once
3.1 and 3.2 are wired. Add only if there's appetite for a third "exploit tooling" badge.
Cadence: continuous. Licence: MIT (nuclei-templates repo).

### 3.4 PoC-in-GitHub (nomi-sec)
`https://github.com/nomi-sec/PoC-in-GitHub` — per-CVE JSON files
(`YYYY/CVE-YYYY-NNNNN.json`) listing GitHub repos referencing that CVE, auto-scraped from
GitHub search. Not fetched live this session.
Verdict: **ADD-KEYLESS**, but treat as a noisy signal — GitHub repos "referencing" a CVE
include write-ups, scanners, and unrelated forks, not just working exploits; if wired in,
present as "N GitHub repos reference this CVE" rather than implying each is a verified PoC.
Cadence: near-daily (scraper-driven). Licence: repo is MIT, underlying data is scraped GitHub
metadata — fine for a link-out/count column, not for reproducing repo contents.

### 3.5 Rapid7 AttackerKB / vulnerability DB / blog RSS
AttackerKB requires a Rapid7 account/API key and is aimed at analyst commentary/scoring
rather than a machine feed suited to weekly automation. The Rapid7 blog has a standard RSS
feed. Verdict: AttackerKB **SKIP** (key friction, low incremental value over EPSS+KEV+
Metasploit already covering the "how exploitable/exploited" question); blog RSS
**MANUAL-ONLY** (digest link, category 7 treatment).

### 3.6 Packet Storm
`https://packetstormsecurity.com/files/tags/exploit/` has an RSS feed
(`https://packetstormsecurity.com/rss/exploit.xml` or similar — verify exact path) covering
new exploit publications; no structured CVE-indexed JSON API. Verdict: **MANUAL-ONLY** /
low-priority **ADD-KEYLESS** RSS parse if a "recent exploit publications" ticker is wanted —
CVE extraction would need regex over titles/descriptions (unstructured), which is weaker than
3.1/3.2's structured CVE fields. Skip unless the page specifically wants a chronological
exploit-publication ticker.

---

## 4. Vendor/national feeds

### 4.1 ENISA EUVD
Two endpoints confirmed **live today**, both unauthenticated JSON:
- `https://euvdservices.enisa.europa.eu/api/lastvulnerabilities` — recent vulnerabilities,
  fields: `id` (EUVD-YYYY-NNNNN), `enisaUuid`, `description`, `datePublished`, `dateUpdated`,
  `baseScore`, `baseScoreVersion`, `baseScoreVector`, `references`, `aliases` (CVE/GHSA
  cross-refs), `assigner`, `epss`, `enisaIdVendor[]`.
- `https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities` — **has the
  `exploited_flag` we need built in**: confirmed response includes `"exploitedSince":"Jul 10,
  2026, 12:00:00 AM"` on each entry, plus CVSS 4.0 vectors carrying `E:A` (Exploited: Active)
  in the vector string itself, and an `epss` field already computed per-record. This is a
  genuinely strong, EU-perspective complement to CISA KEV — catches EU-notified exploitation
  (e.g. the Joomla extension RCEs in the sample response) that may lag or never appear in
  CISA's US-government-focused catalog.
There's also `/api/vulnerabilities?...` (paginated full catalog with filters, per the brief) —
not fetched live but documented in ENISA's own API reference; follow the same auth-free
pattern.
Verdict: **ADD-KEYLESS**. Cadence: appears to update multiple times daily (timestamps to the
minute in the sample). Rate limit: undocumented, no key required, be a good citizen (a few
req/week is trivial). Licence: ENISA, EU public-sector open data — free reuse.
Mapping: a second "exploited in the wild" column/badge alongside CISA KEV, explicitly labeled
by source so readers can see EU vs US coverage differ; also feeds the `aliases` CVE join to
enrich records already tracked from KEV/cvelistV5.
Incremental fetch: poll `/api/exploitedvulnerabilities` each run and diff against cached IDs
by `id` (EUVD number) — cheap since the endpoint already returns only a rolling recent window.

### 4.2 Canadian Centre for Cyber Security
The `www.cyber.gc.ca/en/alerts-advisories/rss.xml` and `/webservice/en/rss.xml` guesses both
came back empty to this session's fetcher — the Cyber Centre's site has been restructured
multiple times and the exact current RSS path needs a manual browser check (their alerts
page is at `cyber.gc.ca/en/alerts-advisories`, but the feed URL pattern wasn't confirmed live).
Verdict: **NEEDS-RETEST** (do a browser fetch of the alerts-advisories page and read the
`<link rel="alternate" type="application/rss+xml">` tag to get the true current URL) — treat
provisionally as **MANUAL-ONLY** until a working feed URL is confirmed, rather than wiring in
a guessed URL that could silently 404 forever in CI.

### 4.3 NCSC-NL advisories
`https://advisories.ncsc.nl/rss/advisories` — confirmed **live today**, real RSS 2.0 feed,
`<lastBuildDate>` current to today, ~20 most-recent advisories per pull. Each item has a
severity code baked into the title (e.g. `[H/H]`, `[M/H]` = impact/likelihood), and body text
often explicitly states when a CVE has public PoC or is a "Zero-Day" being actively exploited
(confirmed in the sample: "NCSC-2026-0337 ... Zero-Day kwetsbaarheden verholpen in SMA1000
... Beide kwetsbaarheden zijn als zero-days misbruikt" — SonicWall SMA1000 zero-days).
Format: standard RSS, Dutch-language free text (no structured CVE/exploited field — CVE IDs
appear inline in the description text and would need regex extraction, e.g.
`CVE-\d{4}-\d{4,7}`).
Cadence: near-daily. Licence: NCSC-NL, Dutch government, free reuse expected for security
tracking (no explicit terms hit in the feed itself — check the advisories.ncsc.nl site
footer before commercial reuse; fine for a non-commercial tracker).
Verdict: **ADD-KEYLESS**. Mapping: national-CERT corroboration column; regex-extract CVE IDs
and a naive keyword match (`zero-day`, `zero day`, `actief misbruikt`, `publieke PoC`) as a
weak-signal "flagged by NCSC-NL as exploited/PoC-available" boolean — clearly label as
heuristic, not authoritative, since it's free-text parsing.
Incremental fetch: RSS only carries ~20-30 most recent items — poll weekly and dedupe by
`guid` (the `NCSC-2026-NNNN [version]` string) against a cached ID set.

### 4.4 NCSC-NL CSAF (structured alternative)
NCSC-NL also publishes CSAF (Common Security Advisory Framework) machine-readable versions of
these same advisories (`https://advisories.ncsc.nl/csaf/...` pattern per CSAF-standard
publishers) — not fetched live, but if the RSS free-text CVE/severity extraction proves
unreliable, CSAF JSON would give structured `vulnerabilities[].cve` and
`threats[].category == "exploit_status"` fields instead of regex. Worth a follow-up check;
noted here as the "if 4.3's regex is too noisy" upgrade path.
Verdict: **ADD-WITH-KEY**-equivalent effort (no key, but needs the exact CSAF index URL
confirmed) — treat as **NEEDS-RETEST**, prefer over 4.3 if confirmed working with less parsing.

### 4.5 BSI CSW (Germany, CSAF)
Germany's BSI publishes CSAF advisories via a CSAF trusted provider structure
(`https://wid.cert-bund.de/.well-known/csaf/...` or similar — BSI's public feed is commonly
consumed via the CERT-Bund WID portal). Not fetched live this session.
Verdict: **NEEDS-RETEST** to find the exact current CSAF index/ROLIE feed URL; provisionally
**MANUAL-ONLY** until confirmed. CSAF gives structured exploit-status fields when it works,
making this worth the follow-up effort.

### 4.6 CERT-FR (ANSSI)
Confirmed the site is alive and its RSS infrastructure exists — a 404 page fetched today
listed the *correct* feed URLs directly in its own navigation:
`https://cert.ssi.gouv.fr/avis/feed/`, `https://cert.ssi.gouv.fr/alerte/feed/`,
`https://cert.ssi.gouv.fr/cti/feed/`, `https://cert.ssi.gouv.fr/feed/` (all sécurité
advisories combined). This session's own fetch of `avis/feed/` still 404'd even with the
trailing slash the nav bar itself links to — possibly a transient issue or a fetcher
normalization quirk stripping the trailing slash before the request goes out.
Verdict: **NEEDS-RETEST** with a plain `urllib.request` call from the CI runner (the URLs are
now known-correct per the site's own navigation, this session's tool just didn't successfully
hit them) — high confidence this becomes **ADD-KEYLESS** once retested; standard RSS,
`Alertes` feed specifically = ANSSI's highest-severity/actively-exploited advisories, closest
French-government analogue to CISA KEV.

### 4.7 JPCERT/JVN (JVNRSS)
`https://jvn.jp/rss/jvn.rdf` — confirmed **live today**, real RDF/RSS 1.0 feed, ~20 recent
items, Japanese-language, mixes JVN# (Japan-specific coordinated disclosures) and JVNVU# (US-
CERT/CISA ICS advisories relayed into Japanese) identifiers. Sample confirmed CVE-bearing
items (e.g. "OpenSSLのOCSPレスポンス検証における...の脆弱性（CVE-2026-54876）" — CVE inline in
title) and cross-posts of CISA ICS advisories.
Format: RDF/XML (RSS 1.0), `dc:date`, `dc:identifier`, `title`/`description` free text with
inline CVE IDs sometimes in the title, sometimes not.
Cadence: multiple times per day. Licence: JPCERT/CC, Japanese government-adjacent CERT, free
reuse for security awareness is standard.
Verdict: **ADD-KEYLESS**, same regex-CVE-extraction caveat as NCSC-NL — useful mainly for
Japan-specific vendor coverage (JVN# entries) not seen elsewhere, and as one more
corroboration point, not a primary exploited-flag source.
Incremental fetch: dedupe by `dc:identifier` against cached set, poll weekly (feed only shows
~20 most recent so more frequent polling would be needed to not miss items if it ever gets
wired for daily use — for a weekly pipeline, note that a very active week could push items off
the 20-item window; consider JVN's iCalendar/other export or paginated API if completeness
matters more than "recent highlights").

### 4.8 ACSC (Australia) alerts RSS
`https://www.cyber.gov.au/rss` or an alerts-specific path — not fetched live this session.
Verdict: **NEEDS-RETEST**; ACSC (part of the Australian Signals Directorate) does publish RSS
for alerts/advisories, treat as **MANUAL-ONLY** provisionally.

### 4.9 UK NCSC
`https://www.ncsc.gov.uk/api/1/services/v1/report-a-cyber-incident/...` isn't relevant; the
UK NCSC's news/advisories has an RSS feed at `https://www.ncsc.gov.uk/api/1/services/v1/notification-feed`
or similar — not confirmed live. Verdict: **NEEDS-RETEST** / **MANUAL-ONLY** provisionally,
same treatment as ACSC.

### 4.10 CERT-EU advisories RSS
CERT-EU publishes a security advisories RSS but access has historically been partly
restricted to EU institution constituents for some content; public-facing advisories do have
a feed at `https://cert.europa.eu/publications/security-advisories`. Not fetched live.
Verdict: **NEEDS-RETEST**; likely **MANUAL-ONLY** given CERT-EU's constituency-first
publication model — lower priority than ENISA EUVD (4.1), which already gives EU-wide
structured coverage with a genuine exploited flag.

---

## 5. Vendor threat intel

None of these were fetched live this session — they're all either blog RSS feeds (well-
understood, standard WordPress/Ghost/custom RSS, no surprises expected) or require paid/
gated APIs. Grouping the verdicts:

- **CrowdStrike**: Global Threat Report is an annual PDF (**MANUAL-ONLY**); blog has RSS
  (**MANUAL-ONLY**, digest link per category 7 treatment — no exploitation-flag field in RSS).
- **Rapid7 blog**: RSS exists, **MANUAL-ONLY** digest link.
- **Cisco Talos**: blog RSS (`https://blog.talosintelligence.com/rss/`) — **MANUAL-ONLY**
  digest link. Talos vulnerability reports have their own advisory RSS
  (`https://www.talosintelligence.com/vulnerability_reports` feed) — worth a **NEEDS-RETEST**
  since Talos advisories often include a CVE + exploitation status per advisory, more
  structured than a general blog.
- **Unit 42 (Palo Alto)**: blog RSS, **MANUAL-ONLY**.
- **Microsoft MSTIC/MSRC blog**: RSS exists; note MSRC's *CVRF API* (already wired per the
  brief) is the structured source — the blog is narrative-only, **MANUAL-ONLY**.
- **Google Threat Intelligence (formerly Mandiant) blog**: RSS, **MANUAL-ONLY**.
- **Tenable/Qualys/Wiz/Horizon3**: all have blog RSS, all **MANUAL-ONLY** — these are
  vendor marketing/research blogs, not structured feeds, and there are already enough
  structured sources (KEV, EPSS, EUVD, VulnCheck) to cover the "is it exploited" question
  without leaning on vendor blog scraping.
- **ZDI (Zero Day Initiative) advisories RSS**: `https://www.zerodayinitiative.com/rss/published/`
  — confirmed **live and fetchable today** (large valid RSS response, truncated only by this
  session's output cap, not by the endpoint). This is genuinely structured — ZDI advisories
  are one-CVE-per-advisory with CVSS and a disclosure/patch timeline. Verdict:
  **ADD-KEYLESS**. Mapping: ZDI-purchased-vulnerability disclosure column — useful because
  ZDI's coordinated-disclosure deadline structure gives a clean "time from ZDI acquisition to
  vendor patch" metric distinct from KEV's time-to-exploitation metric.
- **Wordfence vulnerability API**: the guessed endpoint
  (`wordfence.com/api/intelligence/v2/vulnerabilities/production`) came back empty to this
  session's fetcher — Wordfence does publish a free vulnerability feed but the exact current
  path/format needs confirming (their intelligence API has changed shape before). Verdict:
  **NEEDS-RETEST**; if confirmed, **ADD-KEYLESS** (WordPress plugin/theme CVEs, useful given
  how much of the KEV/EUVD catalog skews toward CMS plugins already).
- **Patchstack (WordPress)**: similar space to Wordfence, has a public API
  (`https://patchstack.com/database/api`) with a free tier requiring a key. Verdict:
  **ADD-WITH-KEY** if WordPress-ecosystem coverage becomes a priority; otherwise redundant
  with Wordfence + GitHub Advisory DB (already wired) + EUVD, which already surface most
  high-severity WordPress plugin RCEs. **SKIP** for now, revisit if a "WordPress zero-days"
  section is wanted.
- **HackerOne hacktivity**: no public API without auth for structured pulls, and hacktivity
  disclosures are bug-bounty writeups, not necessarily in-the-wild exploitation. **SKIP** per
  the brief's own note.

---

## 6. AI-vulnerability sources beyond Anthropic

### 6.1 OSV.dev API
`https://api.osv.dev/v1/query` (POST, body `{"commit":...}` or `{"version":..., "package":...}`)
and `https://api.osv.dev/v1/vulns/{id}` (GET, per-ID lookup) — the GET-by-ID calls in this
session came back empty for both a plausible GHSA ID and a fabricated OSV ID, which for a
fabricated ID is *expected* (404-equivalent) but for the real GHSA ID suggests either a fetch-
tool quirk (OSV returns `Content-Type: application/json` which some fetchers mis-handle on
empty-vs-error) or that ID no longer resolves. **NEEDS-RETEST** with a plain HTTP client and a
freshly-looked-up valid GHSA/CVE ID before final verdict — OSV.dev is a well-established,
heavily-used, free, unauthenticated Google-run service and is very likely fine; treat this
session's null result as inconclusive, not a real signal.
Format (per public OSV schema docs): `{id, summary, details, aliases[], affected[], severity[],
references[], database_specific, credits[]}` — `credits[]` is exactly the field needed to find
entries credited to Big Sleep / other AI-discovery-agent bylines (6.2 below), and `aliases[]`
gives the CVE cross-reference.
Verdict: **ADD-KEYLESS** (pending retest) — this is genuinely useful beyond just "AI
vulnerabilities": OSV covers open-source package ecosystems broadly (PyPI, npm, Go, crates.io,
Maven, RubyGems, etc.) with a consistent schema, and GitHub Advisory DB (already wired) is
itself one of OSV's data sources, so there may be overlap to de-duplicate against rather than
pure incremental value — worth checking against the existing GHSA fetcher for overlap before
wiring a second full ingest.
Cadence: continuous. Rate limit: generous, documented as fine for "reasonable" automated use;
batch queries via `querybatch` endpoint for efficiency if pulling many packages/CVEs at once.
Licence: CC-BY-4.0 (OSV schema/data), Google-run infrastructure, free.
Incremental fetch: OSV also publishes bulk GCS exports (`gs://osv-vulnerabilities/`, mirrored
over HTTPS at `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip`) —
better than looping per-package API calls for a full-catalog scan; use the API only for
targeted lookups (e.g. resolving one alias found in another feed).

### 6.2 Google Big Sleep disclosures
No dedicated Big Sleep feed exists — Big Sleep (Google DeepMind + Project Zero's AI-agent
vulnerability-finding project) discloses through the **normal Project Zero pipeline**: the
Project Zero blog (RSS: `https://googleprojectzero.blogspot.com/feeds/posts/default`) and
individual CVE/OSV entries where the `credits`/finder field names "Big Sleep" or "Google Big
Sleep." The cleanest machine-readable path is **querying OSV.dev (6.1) and filtering
`credits[].name` for "Big Sleep"** rather than trying to scrape the P0 blog for AI-specific
posts.
Verdict: **ADD-KEYLESS** as a *filter* on 6.1's OSV ingest (add a "found by Big Sleep / AI
agent" derived flag by string-matching the credits field), not a separate fetcher. Project
Zero blog RSS itself: **MANUAL-ONLY** digest link (no structured CVE/credit field in RSS).

### 6.3 OpenAI Daybreak / "Patch the Planet"
No public API or feed found for this — OpenAI's AI-security-research disclosures (if
published) appear as ad-hoc blog posts, not a structured feed. Verdict: **MANUAL-ONLY** — a
human should periodically check OpenAI's safety/security blog and hand-add any CVE-bearing
disclosures to `manual.json`, same treatment as the existing Anthropic ledger but without an
equivalent structured `ledger.json`-style export (confirm OpenAI hasn't since published one;
none was found at the well-known paths).

### 6.4 Hugging Face / MLflow advisories via OSV
Both HF and MLflow ecosystem advisories flow into GitHub Advisory DB and, from there, into
OSV.dev (OSV has a `PyPI` ecosystem covering `transformers`, `mlflow`, etc., and HF's own
advisories are typically GHSA-numbered). No separate feed needed.
Verdict: **SKIP as a separate source** — fully covered by 6.1 (OSV) and the already-wired
GitHub Advisory DB fetcher; just make sure the existing GHSA ecosystem filter list includes
`PyPI`/ML-relevant ecosystems (`transformers`, `mlflow`, `torch`, `tensorflow`, etc.) if it's
currently scoped narrower.

### 6.5 Protect AI huntr
`https://huntr.com` runs AI/ML-specific bug bounties; a guessed RSS path
(`huntr.com/bounties.rss`) came back empty this session. Verdict: **NEEDS-RETEST** — huntr
disclosures (many ML-framework RCEs) are a genuinely good fit for this tracker's AI angle if a
real feed exists; check their disclosed-bounties page for a documented API/RSS before writing
this off. Provisionally **MANUAL-ONLY**.

### 6.6 Snyk / Sonatype OSS reports
Both are commercial vulnerability databases with API access gated behind paid/enterprise
tiers for bulk use; Snyk's vulnerability DB has some public web pages but no confirmed free
bulk API. Verdict: **SKIP** — redundant with OSV.dev + GitHub Advisory DB for open-source
package vulnerabilities, and the annual "State of Open Source Security" reports from both are
**MANUAL-ONLY** reading material at most, not ingestible.

---

## 7. Weekly digests (link only, do not ingest)

All of these are **MANUAL-ONLY** by design per the brief — they're editorial digests meant for
a "further reading" section, not structured data:
- SANS @RISK newsletter (email/web, no API)
- CISA weekly bulletin (`https://www.cisa.gov/news-events/bulletins` — has an RSS feed worth
  linking, e.g. as a "this week's full CISA bulletin" link, but the KEV JSON already covers
  the exploited-vuln subset we actually score)
- The Record (Recorded Future News) — has RSS, link as a curated-reading feed
- BleepingComputer RSS, zero-day tag (`https://www.bleepingcomputer.com/tag/zero-day/feed/` —
  a plausible path, worth a **NEEDS-RETEST** if a "in the news this week" linked-headlines
  widget is wanted; still MANUAL/link-only, not data to parse for CVE facts)

---

## 10-year backfill plan (2016–2020)

CISA KEV only goes back to when it was created (catalog effectively starts Nov 2021, though
some entries carry earlier `dateAdded` backfills done by CISA itself). To honestly show
"zero-days exploited in the wild" history for 2016–2020, before KEV existed, combine:

1. **Google Project Zero "0day In the Wild" sheet (2.6)** — the only source here with
   continuous coverage back to **July 2014**, confirmed live today. This is the backbone of
   the backfill: pull the full CSV, filter rows to 2016–2020, and use its `date discovered`
   column as the timeline anchor.
2. **Google TIG / Mandiant annual reports (2.7/2.8, MANUAL-ONLY)** — cross-check the P0
   sheet's yearly counts against TIG's/Mandiant's own published yearly zero-day tallies for
   2016–2020 (TIG's earliest reports cover this range) — use these as a sanity-check total,
   not a row-level data source, since they don't publish machine-readable CVE lists, just
   annual summaries and named highlights.
3. **VulnCheck KEV (2.2, if keyed)** — VulnCheck backdates some historical exploitation
   evidence further than CISA KEV's Nov-2021 start; if a key is obtained, pull their full
   history and see how far back their `date_added` values actually go — likely helps fill
   2020-2021 gaps more than reaching cleanly to 2016.
4. **Exploit-DB (3.1) publication dates + Metasploit (3.2) `disclosure_date`** — these give
   "a public exploit existed by date X" which is a *different, weaker* claim than "confirmed
   exploited in the wild" — useful only as corroborating context (e.g. "PoC published within N
   days of disclosure"), not as a source of in-the-wild confirmation. Do not conflate exploit-
   publication with in-the-wild-exploitation in the UI.
5. **NVD published dates** (already wired via the NVD API 2.0 fetcher) — gives the CVE
   disclosure timeline backbone to anchor the P0 sheet's rows against, and to compute
   "time from disclosure to confirmed in-the-wild use" for the backfilled period.

**How to present this honestly**: label the pre-2021 section something explicit like
"Zero-days exploited in the wild, 2016–2020 (pre-CISA KEV, sourced from Google Project Zero's
tracker)" with a visible methodology note that this uses a **different definition and a
different, narrower set of investigators** than the post-2021 CISA KEV series — Project Zero's
sheet is scoped to targets P0 actively investigates (their own README says so explicitly:
"this list includes targets that Project Zero has previously investigated... or will
investigate in the near future"), so it is not a complete census the way KEV aims to be for
US federal risk. Show the two series on visually distinct chart segments (e.g. a dashed line
or a clear color/legend break at the KEV start date) rather than one continuous line that
implies equivalent completeness across the boundary.

---

```json
SOURCES_REGISTRY = [
  {"id":"cvelistv5","name":"CVE List V5 (raw JSON)","org":"MITRE/CVE Program","url":"https://github.com/CVEProject/cvelistV5","endpoint":"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/<year>/<Nxx>/CVE-<year>-<n>.json","auth":"none","format":"json","cadence":"~7 min","licence":"CVE Program Terms of Use","exploited_flag":false,"coverage_start":"1999","verdict":"ADD-KEYLESS","page_use":"core CVE enrichment, all tabs"},
  {"id":"cvelistv5-delta","name":"cvelistV5 deltaLog","org":"MITRE/CVE Program","url":"https://github.com/CVEProject/cvelistV5","endpoint":"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/deltaLog.json","auth":"none","format":"json","cadence":"~7 min, 30-day rolling window","licence":"CVE Program Terms of Use","exploited_flag":false,"coverage_start":"n/a","verdict":"ADD-KEYLESS","page_use":"incremental-fetch driver for cvelistv5"},
  {"id":"cisa-adp-ssvc-kev","name":"CISA-ADP container (SSVC + KEV, embedded)","org":"CISA (via CVE Program)","url":"https://github.com/cisagov/vulnrichment","endpoint":"embedded in cvelistv5/cve.org records, containers.adp[]","auth":"none","format":"json","cadence":"~7 min","licence":"CVE Program Terms of Use","exploited_flag":true,"coverage_start":"2024-02","verdict":"ADD-KEYLESS","page_use":"SSVC + KEV corroboration, replaces standalone SSVC source"},
  {"id":"cve-org-api","name":"CVE.org API (CVE Services)","org":"MITRE/CVE Program","url":"https://www.cve.org","endpoint":"https://cveawg.mitre.org/api/cve/{CVE-ID}","auth":"none","format":"json","cadence":"real-time","licence":"CVE Program Terms of Use","exploited_flag":false,"coverage_start":"1999","verdict":"ADD-KEYLESS","page_use":"on-demand single-CVE lookups"},
  {"id":"attack-stix","name":"ATT&CK STIX data","org":"MITRE","url":"https://github.com/mitre-attack/attack-stix-data","endpoint":"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json","auth":"none","format":"stix2.1-json","cadence":"~3x/year","licence":"ATT&CK Terms of Use","exploited_flag":false,"coverage_start":"n/a","verdict":"SKIP","page_use":"no CVE crosswalk exists; not worth weekly fetch"},
  {"id":"atlas-data","name":"MITRE ATLAS","org":"MITRE","url":"https://github.com/mitre-atlas/atlas-data","endpoint":"https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/ATLAS-latest.yaml","auth":"none","format":"yaml","cadence":"monthly","licence":"MITRE public release","exploited_flag":false,"coverage_start":"2020-12","verdict":"ADD-KEYLESS","page_use":"AI-found tab: standalone AI attack case-studies series (by year, top techniques/tactics, latest incidents list) via case-studies[]/relationships[].employs[]; no CVE crosswalk, kept separate from KEV/CVE tables"},
  {"id":"cwe","name":"CWE catalog","org":"MITRE","url":"https://cwe.mitre.org","endpoint":"https://cwe.mitre.org/data/xml/cwec_latest.xml.zip","auth":"none","format":"xml","cadence":"~3-4x/year","licence":"MITRE public release","exploited_flag":false,"coverage_start":"n/a","verdict":"SKIP","page_use":"CWE IDs already arrive via CVE record problemTypes; only fetch for a one-time ID-to-name lookup table"},
  {"id":"epss","name":"FIRST EPSS","org":"FIRST.org","url":"https://www.first.org/epss/","endpoint":"https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2,...","auth":"none","format":"json","cadence":"daily","licence":"FIRST.org data reuse policy","exploited_flag":false,"coverage_start":"2021","verdict":"ADD-KEYLESS","page_use":"EPSS score/percentile column next to KEV entries"},
  {"id":"vulncheck-kev","name":"VulnCheck KEV","org":"VulnCheck","url":"https://vulncheck.com","endpoint":"https://api.vulncheck.com/v3/index/vulncheck-kev","auth":"key","format":"json","cadence":"near-real-time","licence":"VulnCheck community terms","exploited_flag":true,"coverage_start":"~2020","verdict":"ADD-WITH-KEY","page_use":"broader exploited-vuln corroboration + backfill aid"},
  {"id":"greynoise","name":"GreyNoise","org":"GreyNoise","url":"https://greynoise.io","endpoint":"https://api.greynoise.io","auth":"key","format":"json","cadence":"real-time","licence":"GreyNoise community terms","exploited_flag":false,"coverage_start":"n/a","verdict":"SKIP","page_use":"free tier lacks CVE-indexed exploited feed"},
  {"id":"shadowserver","name":"Shadowserver exploited-vulns","org":"Shadowserver Foundation","url":"https://dashboard.shadowserver.org","endpoint":"org-registration based reports, no open API","auth":"key","format":"csv/json (subscription)","cadence":"daily","licence":"Shadowserver terms","exploited_flag":true,"coverage_start":"n/a","verdict":"MANUAL-ONLY","page_use":"dashboard link only"},
  {"id":"p0-0day-sheet","name":"Google Project Zero 0day In the Wild","org":"Google Project Zero","url":"https://googleprojectzero.blogspot.com/p/0day.html","endpoint":"https://docs.google.com/spreadsheets/d/1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY/gviz/tq?tqx=out:csv","auth":"none","format":"csv","cadence":"irregular, event-driven","licence":"Google public sheet, attribution expected","exploited_flag":true,"coverage_start":"2014","verdict":"ADD-KEYLESS","page_use":"10-year backfill backbone, pre-KEV zero-day history"},
  {"id":"google-tig","name":"Google TIG annual report","org":"Google Threat Intelligence Group","url":"https://cloud.google.com/blog/topics/threat-intelligence","endpoint":"annual blog/PDF, no API","auth":"none","format":"pdf/html","cadence":"annual","licence":"Google, editorial reuse only","exploited_flag":true,"coverage_start":"~2015","verdict":"MANUAL-ONLY","page_use":"yearly zero-day count cross-check"},
  {"id":"mandiant-mtrends","name":"Mandiant M-Trends","org":"Google/Mandiant","url":"https://www.mandiant.com/m-trends","endpoint":"annual PDF, no API","auth":"none","format":"pdf","cadence":"annual","licence":"Mandiant, editorial reuse only","exploited_flag":true,"coverage_start":"~2010","verdict":"MANUAL-ONLY","page_use":"pre-2021 backfill narrative cross-check"},
  {"id":"exploitdb-csv","name":"Exploit-DB files_exploits.csv","org":"Offensive Security","url":"https://gitlab.com/exploit-database/exploitdb","endpoint":"https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv","auth":"none","format":"csv","cadence":"continuous","licence":"Exploit-DB/OffSec, standard redistribution","exploited_flag":false,"coverage_start":"~1999","verdict":"ADD-KEYLESS","page_use":"public-PoC-exists flag + historic exploit-publication dates"},
  {"id":"metasploit-modules","name":"Metasploit modules_metadata_base.json","org":"Rapid7","url":"https://github.com/rapid7/metasploit-framework","endpoint":"https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json","auth":"none","format":"json","cadence":"continuous","licence":"BSD-3-Clause","exploited_flag":false,"coverage_start":"~2003","verdict":"ADD-KEYLESS","page_use":"weaponized-exploit-available flag, disclosure_date for TTW metrics"},
  {"id":"nuclei-templates","name":"Nuclei CVE templates","org":"ProjectDiscovery","url":"https://github.com/projectdiscovery/nuclei-templates","endpoint":"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/cves/","auth":"none","format":"yaml","cadence":"continuous","licence":"MIT","exploited_flag":false,"coverage_start":"~2020","verdict":"ADD-KEYLESS","page_use":"optional third exploit-tooling badge, lower priority than exploitdb/metasploit"},
  {"id":"poc-in-github","name":"PoC-in-GitHub","org":"nomi-sec (community)","url":"https://github.com/nomi-sec/PoC-in-GitHub","endpoint":"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/<year>/CVE-<year>-<n>.json","auth":"none","format":"json","cadence":"~daily","licence":"MIT (repo), scraped GitHub metadata","exploited_flag":false,"coverage_start":"~2017","verdict":"ADD-KEYLESS","page_use":"GitHub-repo-reference count per CVE, labeled as noisy signal"},
  {"id":"attackerkb","name":"Rapid7 AttackerKB","org":"Rapid7","url":"https://attackerkb.com","endpoint":"key-gated API","auth":"key","format":"json","cadence":"continuous","licence":"Rapid7 terms","exploited_flag":false,"coverage_start":"n/a","verdict":"SKIP","page_use":"redundant with EPSS/KEV/Metasploit"},
  {"id":"packetstorm","name":"Packet Storm exploit feed","org":"Packet Storm Security","url":"https://packetstormsecurity.com","endpoint":"RSS, exact path unverified","auth":"none","format":"rss","cadence":"continuous","licence":"Packet Storm terms","exploited_flag":false,"coverage_start":"n/a","verdict":"MANUAL-ONLY","page_use":"optional exploit-publication ticker, unstructured CVE extraction"},
  {"id":"enisa-euvd-last","name":"ENISA EUVD last vulnerabilities","org":"ENISA","url":"https://euvd.enisa.europa.eu","endpoint":"https://euvdservices.enisa.europa.eu/api/lastvulnerabilities","auth":"none","format":"json","cadence":"multiple times daily","licence":"ENISA/EU open data","exploited_flag":false,"coverage_start":"2024","verdict":"ADD-KEYLESS","page_use":"EU vulnerability catalog, CVE/GHSA alias enrichment"},
  {"id":"enisa-euvd-exploited","name":"ENISA EUVD exploited vulnerabilities","org":"ENISA","url":"https://euvd.enisa.europa.eu","endpoint":"https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities","auth":"none","format":"json","cadence":"multiple times daily","licence":"ENISA/EU open data","exploited_flag":true,"coverage_start":"2024","verdict":"ADD-KEYLESS","page_use":"second exploited-in-the-wild column, EU perspective distinct from CISA KEV"},
  {"id":"enisa-euvd-full","name":"ENISA EUVD full vulnerabilities (paginated)","org":"ENISA","url":"https://euvd.enisa.europa.eu","endpoint":"https://euvdservices.enisa.europa.eu/api/vulnerabilities","auth":"none","format":"json","cadence":"multiple times daily","licence":"ENISA/EU open data","exploited_flag":false,"coverage_start":"2024","verdict":"ADD-KEYLESS","page_use":"full-catalog backstop query, filtered/paginated as needed"},
  {"id":"cert-eu","name":"CERT-EU advisories","org":"CERT-EU","url":"https://cert.europa.eu/publications/security-advisories","endpoint":"unconfirmed RSS path","auth":"none","format":"rss","cadence":"unknown","licence":"CERT-EU terms","exploited_flag":false,"coverage_start":"n/a","verdict":"MANUAL-ONLY","page_use":"redundant with ENISA EUVD; low priority"},
  {"id":"cyber-gc-ca","name":"Canadian Centre for Cyber Security alerts","org":"Canadian Centre for Cyber Security","url":"https://www.cyber.gc.ca/en/alerts-advisories","endpoint":"RSS path unconfirmed, needs browser check","auth":"none","format":"rss","cadence":"unknown","licence":"Government of Canada open data","exploited_flag":false,"coverage_start":"n/a","verdict":"MANUAL-ONLY","page_use":"pending URL confirmation"},
  {"id":"ncsc-nl","name":"NCSC-NL advisories","org":"NCSC-NL","url":"https://advisories.ncsc.nl","endpoint":"https://advisories.ncsc.nl/rss/advisories","auth":"none","format":"rss","cadence":"near-daily","licence":"NCSC-NL, free reuse expected","exploited_flag":false,"coverage_start":"~2018","verdict":"ADD-KEYLESS","page_use":"national-CERT corroboration, heuristic CVE/exploited regex extraction from free text"},
  {"id":"ncsc-nl-csaf","name":"NCSC-NL CSAF advisories","org":"NCSC-NL","url":"https://advisories.ncsc.nl","endpoint":"CSAF index path unconfirmed","auth":"none","format":"csaf-json","cadence":"near-daily","licence":"NCSC-NL, free reuse expected","exploited_flag":true,"coverage_start":"~2018","verdict":"MANUAL-ONLY","page_use":"structured upgrade path over 4.3's RSS if confirmed"},
  {"id":"bsi-csaf","name":"BSI CSW (CERT-Bund) CSAF","org":"BSI (Germany)","url":"https://wid.cert-bund.de","endpoint":"CSAF/ROLIE feed path unconfirmed","auth":"none","format":"csaf-json","cadence":"unknown","licence":"BSI, German government open data","exploited_flag":true,"coverage_start":"n/a","verdict":"MANUAL-ONLY","page_use":"pending URL confirmation"},
  {"id":"cert-fr","name":"CERT-FR (ANSSI) alertes","org":"ANSSI","url":"https://cert.ssi.gouv.fr","endpoint":"https://cert.ssi.gouv.fr/alerte/feed/","auth":"none","format":"rss","cadence":"unknown, likely near-daily","licence":"ANSSI, French government open data","exploited_flag":false,"coverage_start":"n/a","verdict":"MANUAL-ONLY","page_use":"retest with plain HTTP client, high confidence upgrade to ADD-KEYLESS"},
  {"id":"jvn-rss","name":"JVNRSS","org":"JPCERT/CC + IPA","url":"https://jvn.jp","endpoint":"https://jvn.jp/rss/jvn.rdf","auth":"none","format":"rdf","cadence":"multiple times daily","licence":"JPCERT/CC, free reuse expected","exploited_flag":false,"coverage_start":"~2004","verdict":"ADD-KEYLESS","page_use":"Japan-specific vendor coverage, corroboration"},
  {"id":"acsc-rss","name":"ACSC alerts","org":"Australian Cyber Security Centre","url":"https://www.cyber.gov.au","endpoint":"RSS path unconfirmed","auth":"none","format":"rss","cadence":"unknown","licence":"Australian government open data","exploited_flag":false,"coverage_start":"n/a","verdict":"MANUAL-ONLY","page_use":"pending URL confirmation"},
  {"id":"uk-ncsc","name":"UK NCSC news/advisories","org":"UK NCSC","url":"https://www.ncsc.gov.uk","endpoint":"feed path unconfirmed","auth":"none","format":"rss","cadence":"unknown","licence":"UK government open data","exploited_flag":false,"coverage_start":"n/a","verdict":"MANUAL-ONLY","page_use":"pending URL confirmation"},
  {"id":"zdi-rss","name":"ZDI published advisories","org":"Trend Micro Zero Day Initiative","url":"https://www.zerodayinitiative.com","endpoint":"https://www.zerodayinitiative.com/rss/published/","auth":"none","format":"rss","cadence":"continuous","licence":"ZDI, standard RSS reuse","exploited_flag":false,"coverage_start":"~2005","verdict":"ADD-KEYLESS","page_use":"one-CVE-per-advisory disclosure timeline, ZDI-acquisition-to-patch metric"},
  {"id":"talos-vuln-reports","name":"Talos vulnerability reports","org":"Cisco Talos","url":"https://www.talosintelligence.com/vulnerability_reports","endpoint":"RSS/feed path unconfirmed","auth":"none","format":"rss","cadence":"unknown","licence":"Cisco Talos terms","exploited_flag":false,"coverage_start":"n/a","verdict":"MANUAL-ONLY","page_use":"pending URL confirmation, more structured than general blog"},
  {"id":"wordfence-api","name":"Wordfence Intelligence vulnerability API","org":"Wordfence (Defiant)","url":"https://www.wordfence.com/threat-intel/","endpoint":"path unconfirmed, prior guess returned empty","auth":"none","format":"json","cadence":"daily","licence":"Wordfence Intelligence terms","exploited_flag":false,"coverage_start":"n/a","verdict":"MANUAL-ONLY","page_use":"pending URL confirmation, WordPress plugin/theme CVEs"},
  {"id":"patchstack-api","name":"Patchstack vulnerability database API","org":"Patchstack","url":"https://patchstack.com/database/api","endpoint":"https://patchstack.com/database/api","auth":"key","format":"json","cadence":"daily","licence":"Patchstack API terms","exploited_flag":false,"coverage_start":"n/a","verdict":"SKIP","page_use":"redundant with Wordfence/GHSA/EUVD for now"},
  {"id":"osv-dev","name":"OSV.dev API","org":"Google/OSV","url":"https://osv.dev","endpoint":"https://api.osv.dev/v1/query (POST) and /v1/vulns/{id} (GET)","auth":"none","format":"json","cadence":"continuous","licence":"CC-BY-4.0","exploited_flag":false,"coverage_start":"varies by ecosystem","verdict":"ADD-KEYLESS","page_use":"open-source package vuln join, Big Sleep credit filter, check overlap with existing GHSA fetcher first"},
  {"id":"osv-big-sleep-filter","name":"Big Sleep disclosures (via OSV credits filter)","org":"Google DeepMind/Project Zero","url":"https://googleprojectzero.blogspot.com","endpoint":"derived: OSV.dev entries where credits[].name matches Big Sleep","auth":"none","format":"json","cadence":"continuous","licence":"CC-BY-4.0 (via OSV)","exploited_flag":false,"coverage_start":"2024","verdict":"ADD-KEYLESS","page_use":"AI-vulnerability-discovery tab, alongside Anthropic ledger"},
  {"id":"openai-daybreak","name":"OpenAI security disclosures","org":"OpenAI","url":"https://openai.com","endpoint":"none confirmed, ad-hoc blog posts","auth":"none","format":"html","cadence":"irregular","licence":"editorial reuse only","exploited_flag":false,"coverage_start":"n/a","verdict":"MANUAL-ONLY","page_use":"hand-add CVE-bearing disclosures to manual.json"},
  {"id":"huntr","name":"Protect AI huntr","org":"Protect AI","url":"https://huntr.com","endpoint":"RSS path unconfirmed, prior guess returned empty","auth":"none","format":"rss","cadence":"continuous","licence":"huntr terms","exploited_flag":false,"coverage_start":"n/a","verdict":"MANUAL-ONLY","page_use":"pending URL confirmation, ML-framework CVE disclosures"},
  {"id":"sans-atrisk","name":"SANS @RISK newsletter","org":"SANS","url":"https://www.sans.org/newsletters/at-risk/","endpoint":"none, email/web only","auth":"none","format":"html","cadence":"weekly","licence":"SANS terms","exploited_flag":false,"coverage_start":"n/a","verdict":"MANUAL-ONLY","page_use":"further-reading link"},
  {"id":"cisa-bulletin","name":"CISA weekly vulnerability bulletin","org":"CISA","url":"https://www.cisa.gov/news-events/bulletins","endpoint":"RSS available on bulletins page","auth":"none","format":"rss","cadence":"weekly","licence":"US government public domain","exploited_flag":false,"coverage_start":"n/a","verdict":"MANUAL-ONLY","page_use":"further-reading link"},
  {"id":"the-record","name":"The Record (Recorded Future News)","org":"Recorded Future","url":"https://therecord.media","endpoint":"RSS available","auth":"none","format":"rss","cadence":"daily","licence":"editorial reuse only","exploited_flag":false,"coverage_start":"n/a","verdict":"MANUAL-ONLY","page_use":"further-reading link"},
  {"id":"bleepingcomputer-0day","name":"BleepingComputer zero-day tag RSS","org":"BleepingComputer","url":"https://www.bleepingcomputer.com/tag/zero-day/","endpoint":"https://www.bleepingcomputer.com/tag/zero-day/feed/ (unconfirmed)","auth":"none","format":"rss","cadence":"as-published","licence":"editorial reuse only","exploited_flag":false,"coverage_start":"n/a","verdict":"MANUAL-ONLY","page_use":"optional in-the-news headline widget, link only"},
  {"id":"cisa-alerts","name":"CISA alerts","org":"CISA","url":"https://www.cisa.gov/news-events/cybersecurity-advisories","endpoint":"https://www.cisa.gov/cybersecurity-advisories/rss.xml","auth":"none","format":"rss","cadence":"as-published","licence":"US government public domain","exploited_flag":false,"coverage_start":"n/a","verdict":"ADD-KEYLESS","page_use":"advisories feed panel; retested 2026-09-06 from the CI runner and consistently 403s (likely bot-blocked), tracked as failed rather than dropped"},
  {"id":"talos-blog","name":"Cisco Talos blog","org":"Cisco Talos","url":"https://blog.talosintelligence.com","endpoint":"https://blog.talosintelligence.com/rss/","auth":"none","format":"rss","cadence":"as-published","licence":"Cisco Talos terms","exploited_flag":false,"coverage_start":"n/a","verdict":"ADD-KEYLESS","page_use":"advisories feed panel, keyword-filtered for vulnerability/exploit posts (mixed general-security blog)"},
  {"id":"msrc-blog","name":"Microsoft MSRC blog","org":"Microsoft MSRC","url":"https://msrc.microsoft.com/blog/","endpoint":"https://msrc.microsoft.com/blog/rss.xml","auth":"none","format":"rss","cadence":"as-published","licence":"Microsoft terms","exploited_flag":false,"coverage_start":"n/a","verdict":"ADD-KEYLESS","page_use":"advisories feed panel; retested 2026-09-06, the RSS path currently serves the SPA shell rather than a feed (0 parseable items) — tracked live rather than hardcoded as failed"},
  {"id":"gtig-blog","name":"Google Threat Intelligence blog","org":"Google Threat Intelligence Group","url":"https://cloud.google.com/blog/topics/threat-intelligence","endpoint":"https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v","auth":"none","format":"rss","cadence":"as-published","licence":"Google terms","exploited_flag":false,"coverage_start":"n/a","verdict":"ADD-KEYLESS","page_use":"advisories feed panel, keyword-filtered"},
  {"id":"rapid7-blog","name":"Rapid7 blog","org":"Rapid7","url":"https://blog.rapid7.com","endpoint":"https://blog.rapid7.com/rss/","auth":"none","format":"rss","cadence":"as-published","licence":"Rapid7 terms","exploited_flag":false,"coverage_start":"n/a","verdict":"ADD-KEYLESS","page_use":"advisories feed panel, keyword-filtered"},
  {"id":"crowdstrike-blog","name":"CrowdStrike blog","org":"CrowdStrike","url":"https://www.crowdstrike.com/blog/","endpoint":"https://www.crowdstrike.com/blog/feed/","auth":"none","format":"rss","cadence":"as-published","licence":"CrowdStrike terms","exploited_flag":false,"coverage_start":"n/a","verdict":"ADD-KEYLESS","page_use":"advisories feed panel, keyword-filtered"},
  {"id":"unit42-blog","name":"Unit 42 blog","org":"Palo Alto Networks Unit 42","url":"https://unit42.paloaltonetworks.com","endpoint":"https://unit42.paloaltonetworks.com/feed/","auth":"none","format":"rss","cadence":"as-published","licence":"Palo Alto Networks terms","exploited_flag":false,"coverage_start":"n/a","verdict":"ADD-KEYLESS","page_use":"advisories feed panel, keyword-filtered"},
  {"id":"avid-db","name":"AVID (AI Vulnerability Database)","org":"AVID (avidml)","url":"https://github.com/avidml/avid-db","endpoint":"https://raw.githubusercontent.com/avidml/avid-db/main/reports/<year>/AVID-<year>-R<n>.json and /vulnerabilities/<year>/AVID-<year>-V<n>.json","auth":"none","format":"json","cadence":"irregular, event-driven","licence":"MIT","exploited_flag":false,"coverage_start":"2022","verdict":"ADD-KEYLESS","page_use":"AI-found tab: standalone AI-vulnerability series keyed by AVID report/vuln IDs (risk domain, CVSS when present, lifecycle stage); embedded CVE refs (e.g. CVE-2024-10950) treated as bonus enrichment, not the primary join"},
  {"id":"bsi-csaf-aggregator","name":"BSI CERT-Bund CSAF aggregator","org":"BSI (Germany)","url":"https://wid.cert-bund.de","endpoint":"https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json","auth":"none","format":"csaf-json","cadence":"continuous","licence":"BSI, German government open data","exploited_flag":false,"coverage_start":"n/a","verdict":"ADD-KEYLESS","page_use":"meta-index of CSAF-compliant vendor PSIRT feeds (Red Hat, CISA, Siemens, Nozomi, ABB, Huawei, Schneider Electric, etc.); discovery mechanism for further CSAF provider-metadata.json feeds to walk"},
  {"id":"redhat-csaf","name":"Red Hat CSAF/VEX","org":"Red Hat Product Security","url":"https://security.access.redhat.com","endpoint":"https://security.access.redhat.com/data/csaf/v2/provider-metadata.json","auth":"none","format":"csaf-json","cadence":"continuous","licence":"Red Hat, standard reuse-friendly terms for defensive tooling","exploited_flag":true,"coverage_start":"~2000","verdict":"ADD-KEYLESS","page_use":"structured, spec-guaranteed exploit-status flag per advisory (threats[].category == exploit_status) via the VEX distribution; stronger signal than free-text regex sources"},
  {"id":"oasis-cosai-riskmap","name":"OASIS CoSAI Risk Map","org":"Coalition for Secure AI (OASIS)","url":"https://github.com/cosai-oasis/secure-ai-tooling","endpoint":"https://raw.githubusercontent.com/cosai-oasis/secure-ai-tooling/main/risk-map/yaml/risks.yaml","auth":"none","format":"yaml","cadence":"periodic, GitHub releases/PRs","licence":"Apache License 2.0","exploited_flag":false,"coverage_start":"n/a","verdict":"STANDARD-ONLY","page_use":"one-time vendored risk/control taxonomy table; tagging vocabulary applied to AVID/AIID/ATLAS records, not a source of dated records itself"},
  {"id":"owasp-llm-top10-2025","name":"OWASP Top 10 for LLM Applications (2025)","org":"OWASP GenAI Security Project","url":"https://genai.owasp.org","endpoint":"https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf","auth":"none","format":"pdf","cadence":"annual revision","licence":"OWASP, CC-BY-SA","exploited_flag":false,"coverage_start":"n/a","verdict":"STANDARD-ONLY","page_use":"one-time vendored 10-row lookup (LLM01-LLM10 id/name/description) for tagging AVID/AIID records, e.g. relates-to-LLM01-Prompt-Injection"},
  {"id":"owasp-ml-top10","name":"OWASP Machine Learning Security Top 10","org":"OWASP","url":"https://github.com/OWASP/www-project-machine-learning-security-top-10","endpoint":"https://github.com/OWASP/www-project-machine-learning-security-top-10/tree/main/docs","auth":"none","format":"markdown","cadence":"revised periodically","licence":"OWASP, CC-BY-SA","exploited_flag":false,"coverage_start":"n/a","verdict":"STANDARD-ONLY","page_use":"one-time vendored 10-row lookup (ML01:2023-ML10:2023 id/name/description) for tagging AI-vulnerability records"}
]
```
