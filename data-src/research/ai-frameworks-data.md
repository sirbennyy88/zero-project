# Zero Project — AI-incident / AI-security-standard source research

Compiled 2026-09-06, as a follow-up to `sources.md` §1.4 (MITRE ATLAS was marked
MANUAL-ONLY there). This file re-examines ATLAS plus the wider AI-incident-database and
AI-security-standard landscape, asking specifically: can any of these be ingested as their
**own standalone data series** (dated events / taxonomy entries keyed by their own IDs), even
where no CVE crosswalk exists? Endpoints were fetched live with `web_fetch` (raw JSON/YAML/CSV
inspected, not just docs) except where noted; GitHub's REST API was also used for directory
listings and occasionally came back empty this session — almost certainly this session's
unauthenticated-rate-limit (60 req/hr) rather than the endpoint being broken, since GH Actions'
built-in `GITHUB_TOKEN` gets a much higher limit. Treat those as **NEEDS-RETEST**, not SKIP.

Legend (same as `sources.md`): **ADD-KEYLESS** wire in now, no auth. **ADD-WITH-KEY** wire in,
needs a free/paid key. **STANDARD-ONLY** a spec/taxonomy/framework with no dataset behind it —
worth a one-time vendored lookup table at most, not a weekly fetch. **MANUAL-ONLY** no
API/feed exists in machine-readable form worth scripting — link it, don't ingest it. **SKIP**
not worth the engineering cost or redundant with something already wired. **NEEDS-RETEST**
endpoint likely works but this session's fetcher/rate-limit didn't confirm it cleanly.

---

## 1. MITRE ATLAS

### 1.1 ATLAS-data — schema, and the "own standalone series" question

Confirmed live: `https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml`
is the **old/deprecated** format (top comment: "This version of the ATLAS data is deprecated
and is no longer being updated with new content", frozen at `version: 5.6.0`). The **current**
schema is the `format-version: 6.0.0` line, published monthly at
`https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/ATLAS-<release>.yaml`
(e.g. `ATLAS-2026.08.yaml`, the newest at time of writing — releases run monthly back to
`2021.05`, confirmed via the live `dist/manifest.yaml` index, which lists every release with
its date and both the current v6 path and a `dist/legacy/ATLAS-<old-version>.yaml` path).
`dist/v6/ATLAS-latest.yaml` is a symlink to the newest month's file — this is the correct
always-current endpoint, not the deprecated root `ATLAS.yaml`/`ATLAS-latest.yaml`.

Confirmed top-level keys in the live v6 file: `collection`, `matrix`, `tactics`, `techniques`,
`mitigations`, **`case-studies`**, and **`relationships`**. Fetched a full early release
(`ATLAS-2021.05.yaml`, small enough to return in full — the current multi-hundred-KB monthly
files exceed this session's fetch-size cap and get silently truncated mid-document, which is
why a naive fetch of the latest file looked like it had no `case-studies` key; it's just further
into the file than the truncation point) and confirmed the real per-case-study field set:

```yaml
case-studies:
  AML.CS0000:
    name: Evasion of Deep Learning detector for malware C&C traffic
    description: 'Palo Alto Networks Security AI research team tested a deep learning...'
    references: []
    created-date: '2020-12-15'
    modified-date: '2021-05-13'
    type: Exercise            # or "Incident"
    actor: ''
    target: ''
    date: '2020-01-01'
    date-granularity: Day
    id: AML.CS0000
    uuid: 2c174273-f52b-5468-b23f-795037a10454
    object-type: case-study
```

Critically, there is a separate **`relationships`** block that links each case-study to the
technique(s) it employed, step by step:

```yaml
relationships:
  AML.CS0000:
    employs:
    - source: AML.CS0000
      target: AML.T0000.001        # ATLAS technique ID, NOT a CVE
      relationship-type: employs
      description: 'We identified a machine learning based approach to malicious URL detection...'
      tactic: AML.TA0043
      step-id: S00
      leads-to: [S01]
    - source: AML.CS0000
      target: AML.T0002.000
      relationship-type: employs
      ...
```

**No CVE field exists anywhere in this schema** — confirming `sources.md` §1.4's core factual
claim still holds. But `date` + `type` (Incident/Exercise) + `actor`/`target` on each
case-study, plus the `relationships.*.employs[].target` technique linkage, is a **complete,
self-contained, dated dataset** that needs no external join to be meaningful: "N AI attack
case-studies per year, broken down by ATLAS technique/tactic" is directly renderable from this
file alone. The `sources.md` verdict conflated "no CVE crosswalk" with "not ingestible" — those
are different questions, and the second one's answer is clearly yes.

Verdict: **ADD-KEYLESS** for a *new, standalone* "AI attacks/incidents" series (by year, by
technique, by tactic — using `case-studies[].date`, `.type`, `.name`, `.description` and
`relationships[caseId].employs[].target`/`.tactic`), separate from any CVE-tagging effort.
Still **not** a source for CVE-tagging KEV entries (that part of the old verdict is unchanged
and correct).
Cadence: monthly (confirmed via `dist/manifest.yaml`, releases `2021.05` through `2026.08` seen
live, no gaps).
Rate/size note: a full monthly v6 file is now several hundred KB of YAML — fine for a weekly
`urllib` fetch + stdlib `yaml`-free parsing is NOT possible with stdlib alone (no YAML parser
in the Python standard library) — this is the one real engineering wrinkle: either vendor a
minimal YAML subset parser, use the JSON Schema files also published under `dist/schemas/`, or
special-case parse the fairly regular `case-studies:`/`relationships:` blocks with regex/line
scanning. Flag this for the implementation phase; it's not a blocker, just not a one-line
`json.loads()`.
Licence: MITRE Corp, public release (same as noted in `sources.md` §1.4 — non-commercial-
friendly, fine for this tracker).

### 1.2 atlas-navigator-data
Not separately fetched this session — the ATT&CK/ATLAS Navigator layer-JSON format is a
visualization overlay (colors/scores per technique for the Navigator UI), not additional
incident data; it would be derived *from* 1.1's techniques, not a new source.
Verdict: **SKIP** — no incremental data over 1.1.

---

## 2. AI incident databases

### 2.1 AI Incident Database (AIID) — GraphQL
Confirmed via the live repo README (`github.com/responsible-ai-collaborative/aiid`): "The site
exposes a **read-only GraphQL endpoint at `/api/graphql`**" — `https://incidentdatabase.ai/api/graphql`,
with a documented sample query (`{ reports { title report_number } }`). This session's `GET`
requests to that URL (both bare and with a URL-encoded `?query=` param, matching the pattern
that worked for other GraphQL-over-GET services) came back with an empty body — GraphQL
servers built on Apollo/Next.js API routes commonly reject `GET` and require `POST` with a
JSON body (`{"query": "..."}"`), which this session's GET-only fetch tool cannot send. This is
the exact "fetcher limitation, not a real signal" pattern flagged elsewhere in `sources.md`.
Verdict: **NEEDS-RETEST** with a `urllib.request.Request(..., method="POST", data=json.dumps(...).encode())`
call from the CI runner — stdlib `urllib` handles POST+JSON fine, so this is a one-line change
once confirmed, not a real blocker. High confidence this becomes **ADD-KEYLESS** once retested:
the schema (per the sample query) exposes `reports { title report_number }` and, per AIID's own
docs, incidents/reports carry `date`, `description`, `authors`, `submitters`, `tags`, and
cross-references to `AVID`/`OECD` taxonomy classifications — a genuinely rich, dated,
standalone AI-incident series keyed by `report_number`/`incident_id`, no CVE needed.
Cadence: continuous (community-curated, PRs merged regularly per the repo's GitHub Actions
badges for `production`/`staging` deploys).
Licence: CC BY-SA-style per AIID's terms (open, attribution-required — verify exact wording
before commercial reuse; fine for a non-commercial tracker).

### 2.2 AVID (AI Vulnerability Database) — avidml/avid-db
Confirmed real, MIT-licensed, actively maintained repo (`github.com/avidml/avid-db`, last push
2026-03-26, 18 stars). Fetched two real sample files directly:

`https://raw.githubusercontent.com/avidml/avid-db/main/reports/2026/AVID-2026-R0017.json` —
a **report** record, and notably one that *does* carry a CVE, embedded (not as a dedicated
field, but findable via string/regex parsing of `problemtype.description.value` and a
`references[].url` pointing at `https://www.cve.org/CVERecord?id=CVE-2024-10950`):
```json
{
  "data_type": "AVID", "data_version": "0.3.3",
  "metadata": { "report_id": "AVID-2026-R0017" },
  "affects": { "developer": ["binary-husky"], "artifacts": [{"type":"System","name":"binary-husky/gpt_academic"}] },
  "problemtype": { "classof": "CVE Entry", "type": "Advisory",
    "description": {"lang":"eng","value":"Code Injection in binary-husky/gpt_academic (CVE-2024-10950)"} },
  "references": [ {"label":"NVD entry","url":"https://www.cve.org/CVERecord?id=CVE-2024-10950"}, ... ],
  "impact": { "avid": {"risk_domain":["Security"], "sep_view":["S0100: Software Vulnerability"], ...},
              "cvss": {"version":"3.0","baseScore":8.8,"baseSeverity":"HIGH", ...},
              "cwe": [{"cweId":"CWE-94", ...}] },
  "reported_date": "2025-03-20"
}
```
`https://raw.githubusercontent.com/avidml/avid-db/main/vulnerabilities/2022/AVID-2022-V001.json`
— a **vulnerability** record (the recurring-failure-mode class, distinct from a one-off
report), fields: `metadata.vuln_id`, `affects`, `problemtype.classof` (e.g. "LLM Evaluation"),
`description`, `reports[]` (links back to report IDs), `impact.avid.{risk_domain,sep_view,
lifecycle_view}`, `credit[]`, `published_date`/`last_modified_date`.

So AVID naturally supports **both**: (a) a standalone AI-vulnerability series keyed by its own
`AVID-YYYY-VNNN`/`AVID-YYYY-RNNNN` IDs (risk domain, CVSS when present, lifecycle stage — no
CVE needed), and (b) opportunistic CVE-tagging where a report happens to reference one (as
R0017 does) — genuinely dual-purpose, unlike ATLAS.
No index/manifest file was found in the repo (GitHub's Contents API listing for `reports/` and
`reports/2026/` came back empty this session — likely the same rate-limit issue noted above,
**NEEDS-RETEST**); a working fetcher would need to walk `vulnerabilities/<year>/` and
`reports/<year>/` directories via the Contents API (paginated, one call per year-directory) or
clone/tarball the repo, since there's no single "latest.json" index confirmed.
Cadence: irregular/event-driven, but active (2026 reports exist).
Licence: MIT — explicit, unambiguous, best licence terms of anything in this file.
Verdict: **ADD-KEYLESS** for a standalone AVID series; treat the embedded-CVE cases as a bonus
enrichment column, not the primary reason to ingest it.

### 2.3 AVID docs / positioning
`docs.avidml.org` confirms AVID's own stated goal: "building the database to be both an
extension of, and a bridge between, classic ... NVD ... adversarial attack cases in MITRE
ATLAS, and incidents in the AI Incident Database (AIID)" — i.e. AVID is explicitly designed as
connective tissue between the three AI-incident sources in this file, which supports treating
all three as complementary standalone series rather than needing one master CVE join.
Also notes "we are prioritizing report-level evidence and have not published new vulnerability
records" in the current release cycle — meaning `reports/` is the more active directory to
poll going forward, `vulnerabilities/` is comparatively frozen (still worth a one-time ingest).

### 2.4 AIAAIC Repository
`https://docs.google.com/spreadsheets/d/1Bn55B4xz21-_Rgdr8BBb2lt0n_4rzLGxFADMlVW0PYI/gviz/tq?tqx=out:csv`
— confirmed the **CSV export mechanism works keylessly** (same `gviz/tq` pattern as the
Project Zero sheet in `sources.md` §2.6), and confirmed the sheet is genuine (returns real
AIAAIC branding/intro text: "The AIAAIC Repository (web version) is an independent, grassroots
public interest collection of incidents and ethical controversies driven by and relating to AI,
algorithms and automation"). However, the default/first sheet tab returned is a landing page,
not the incident rows — the actual data lives on a different named tab (or is gated: AIAAIC's
own marketing says "Premium Membership provides free access to hidden data ... notably impacts
and collections", implying some columns are genuinely paywalled even in the visible sheet).
Verdict: **NEEDS-RETEST** to find the exact data-tab name/`gid` (open the sheet in a browser,
note the tab name, retry `gviz/tq?tqx=out:csv&sheet=<name>`) — provisionally **ADD-KEYLESS**
for whatever incident-list columns are public (title, date, country, sector are typically
visible in this style of repository; richer "impacts" fields may be premium-gated per AIAAIC's
own note, so budget for a partial-column ingest, not the full schema).
Cadence: irregular, community-curated (row-per-incident spreadsheet, similar cadence to the
Project Zero sheet).
Licence: AIAAIC states it's an "independent, grassroots public interest" project; check their
terms of use page for exact reuse language before commercial use (non-commercial tracker fine).

### 2.5 OECD AI Incidents and Hazards Monitor (AIM)
`https://oecd.ai/en/incidents` — confirmed live, and this is the richest structured dataset of
the AI-incident group by far: **~17,400 incidents/hazards** at time of fetch, updated same-day
(entries dated 2026-09-05/09-04 appeared in the live pull), each with an AI-generated
classification into `AI principles` (e.g. Accountability, Safety, Fairness), `Industries`,
`Affected stakeholders`, `Harm types`, `Business function`, `Autonomy level`, `AI system task`,
plus a per-incident URL slug (`oecd.ai/en/incidents/<date>-<hash>`) and a rationale paragraph
explaining the Incident-vs-Hazard classification. Data is sourced from Event Registry (a news
aggregation platform monitoring 150k+ articles/day) rather than manual curation, which is a
different (broader, noisier, AI-classified-not-human-verified) character than AIID/AVID/AIAAIC.
The page is query-parameter-driven (`?search_terms=...&from_date=...&to_date=...&order_by=date&num_results=20`),
strongly suggesting a JSON API backs the rendered HTML, and there is a visible **"Download
results"** control on the page — but the underlying API/export URL was not identified this
session (the page returned server-rendered HTML text, not a JSON payload, to this session's
fetcher).
Verdict: **NEEDS-RETEST** — worth a browser-based network-tab inspection to capture the actual
XHR endpoint behind "Download results" / the filtered listing; if it's a plain JSON GET (likely,
given the query-string-driven URL structure), this becomes **ADD-KEYLESS** and is arguably the
single best "AI incidents by year/harm-type/industry" standalone series available, given the
sheer volume and daily cadence. If it turns out to require a session/CSRF token, downgrade to
**MANUAL-ONLY** (spot-check via the web UI) or **ADD-WITH-KEY** if OECD offers a registered-API
tier. Flag the "AI-generated" classification caveat explicitly if wired in — labels like
Incident-vs-Hazard are LLM-inferred per-article, not human-adjudicated, and should be presented
as such (lower confidence than AIID/AVID's editorial process).

---

## 3. OWASP GenAI Security Project

### 3.1 OWASP Top 10 for LLM Applications (2025)
Confirmed the current, stable 2025 list (searched against the live OWASP GenAI project pages
and GitHub repo `github.com/OWASP/www-project-top-10-for-large-language-model-applications`):
`LLM01:2025` Prompt Injection, `LLM02:2025` Sensitive Information Disclosure, `LLM03:2025`
Supply Chain, `LLM04:2025` Data and Model Poisoning, `LLM05:2025` Improper Output Handling,
`LLM06:2025` Excessive Agency, `LLM07:2025` System Prompt Leakage, `LLM08:2025` Vector and
Embedding Weaknesses, `LLM09:2025` Misinformation, `LLM10:2025` Unbounded Consumption. Also
published as a versioned PDF
(`owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf`).
This is a **fixed, small, annually-revised taxonomy** (10 named risk categories, IDs, and short
descriptions) — not a growing incident feed. Same treatment as CWE ID→name in `sources.md`
§1.5: worth vendoring once as a static ~10-row lookup (id, name, one-line description, doc URL)
for display purposes (e.g. tagging an AVID/AIID record with "relates to LLM01: Prompt
Injection"), not worth a weekly re-fetch.
Verdict: **STANDARD-ONLY** (one-time vendor of the 10-row table; re-check annually when OWASP
ships a new revision, not weekly).

### 3.2 OWASP Top 10 for Agentic Applications
Referenced by the GenAI Security Project as a newer, parallel list specifically for
agent/multi-step-tool-use risks (distinct from the base LLM Top 10). Not independently fetched
in full this session (same static-taxonomy character as 3.1 expected).
Verdict: **STANDARD-ONLY**, same treatment as 3.1 once the final risk IDs are confirmed.

### 3.3 OWASP AI Exchange (owaspai.org)
Confirmed via the live repo (`github.com/OWASP/www-project-ai-security-and-privacy-guide`) and
search results: this is a **documentation site** — "one coherent resource consisting of several
sections under `content`, each represented by a page on the website," authored by ~170 experts
as markdown pages (threats, controls, best practices), not a structured JSON "navigator"
dataset. No risk-map JSON/YAML equivalent to CoSAI's (§4.5) was found for this project.
Verdict: **MANUAL-ONLY** — good background reading / linkable reference, not ingestible.

### 3.4 OWASP AIVSS (aivss.owasp.org)
Not fetched live this session (lower priority, newer/less-established project per its early
project-page framing) — AIVSS ("AI Vulnerability Scoring System") aims to be a CVSS-style
severity-scoring standard specifically for AI/agentic vulnerabilities, still in
draft/calculator-tool stage per public descriptions, not a populated dataset.
Verdict: **STANDARD-ONLY** for now — worth revisiting once AIVSS reaches a stable spec version;
would pair naturally with AVID (§2.2) records as an additional severity axis, not a source of
its own incidents/records.

### 3.5 OWASP Machine Learning Security Top 10
Confirmed the list (`github.com/OWASP/www-project-machine-learning-security-top-10`, per-risk
markdown files like `docs/ML01_2023-Input_Manipulation_Attack.md`): `ML01:2023` Input
Manipulation Attack, `ML02:2023` Data Poisoning Attack, `ML03:2023` Model Inversion Attack,
`ML04:2023` Membership Inference Attack, `ML05:2023` Model Theft, `ML06:2023` AI Supply Chain
Attacks, `ML07:2023` Transfer Learning Attack, `ML08:2023` Model Skewing, `ML09:2023` Output
Integrity Attack, `ML10:2023` Model Poisoning. Same static-taxonomy character as 3.1.
Verdict: **STANDARD-ONLY** (one-time vendor of the 10-row table).

### 3.6 CycloneDX 1.6 ML-BOM / AIBOM
Not a data feed — CycloneDX is a Software Bill of Materials **standard**, and its 1.6 release
added first-class ML-BOM (`modelCard` component type) and AIBOM support for declaring model
provenance, datasets, and dependencies in a machine-readable manifest that *individual AI
projects* would publish, not something this tracker's pipeline would poll centrally. Worth a
one-line mention in a "standards" section of the page (it's the emerging way vendors will
declare AI supply-chain composition, relevant context for the AVID/OSV supply-chain angle
already covered in `sources.md` §6), but there is no central CycloneDX AIBOM registry to fetch.
Verdict: **STANDARD-ONLY**, mention-only.

---

## 4. OASIS

### 4.1 CSAF 2.0 live provider feeds
All four brief-listed endpoints were checked; two returned confirmed live JSON, two need
retesting:

- **BSI CERT-Bund aggregator** — `https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json`
  **confirmed live and real**: a CSAF 2.0 aggregator index listing 13 trusted providers
  (KUNBUS, Nozomi Networks, SICK, Siemens ProductCERT, **Red Hat Product Security**,
  Intevation, Stackable, IDS Innomic, BSI itself, ABB, Huawei, Open-Xchange, **CISA**, Schneider
  Electric CPCERT) plus a `csaf_publishers` mirror list (Hitachi Energy), each with its own
  `provider-metadata.json` URL, `last_updated` timestamp, and `role` (`csaf_trusted_provider` /
  `csaf_provider`). This is a genuinely useful **meta-index**: one keyless fetch gives the
  current list of every CSAF-compliant vendor PSIRT feed worth walking, largely ICS/OT vendors
  plus CISA/Red Hat.
- **Red Hat CSAF** — `https://access.redhat.com/security/data/csaf/v2/provider-metadata.json`
  redirects to `https://security.access.redhat.com/data/csaf/v2/provider-metadata.json`,
  **confirmed live**, real JSON: `distributions[].directory_url` points to
  `.../csaf/v2/advisories/` and `.../csaf/v2/vex/` (the VEX one is exactly the exploit-status
  feed of interest — VEX = Vulnerability Exploitability eXchange, CSAF's dedicated
  "is this actually exploitable in this product" document type). The `advisories/2024/` index
  directory itself confirmed live (large real HTML index, thousands of entries) but individual
  advisory JSON wasn't fetched this session to confirm the `threats[].category` field verbatim
  — that field name is documented in the CSAF 2.0 spec itself (`threats[].category` enum
  includes `exploit_status`, `impact`, `target_set`) and Red Hat is a spec-compliant
  `csaf_trusted_provider`, so high confidence it's present; **NEEDS-RETEST** to quote the exact
  field from a live advisory before wiring.
- **Cisco CSAF** — `https://sec.cloudapps.cisco.com/security/center/csaf/` and a guessed
  `provider-metadata.json` under it both came back empty to this session's fetcher.
  **NEEDS-RETEST** — Cisco does publish openVuln/CSAF data but the exact current path needs a
  browser check.
- **Microsoft CSAF** — `https://msrc.microsoft.com/csaf/provider-metadata.json` (confirmed via
  MSRC's own blog post "Toward greater transparency: publishing machine-readable CSAF files")
  returned **binary/undecodable data** to this session's fetcher rather than empty — likely a
  compressed response or a content-type this fetcher mis-handles, not proof the endpoint is
  dead. **NEEDS-RETEST** with a plain `urllib` GET (which handles gzip transparently) before
  final verdict.

Verdict overall: **ADD-KEYLESS** for the BSI aggregator index (confirmed, trivial, high value
as a discovery mechanism) and Red Hat CSAF/VEX (confirmed live, `NEEDS-RETEST` only for the
exact exploit-status field name); **NEEDS-RETEST** for Cisco and Microsoft before a final call.
Mapping: a structured, spec-guaranteed "exploit status" flag per advisory — stronger than the
free-text regex approach needed for NCSC-NL/JVN RSS in `sources.md` §4.3/4.7 — worth prioritizing
over those once wired.
Cadence: continuous (vendor PSIRT-driven, several advisories/week typically).
Licence: each vendor's own CSAF terms (Red Hat, Microsoft, Cisco all publish security data
under standard reuse-friendly terms for defensive tooling; BSI is German government open data).

### 4.2 OASIS CoSAI (Coalition for Secure AI)
Confirmed **structured, not just markdown**: `github.com/cosai-oasis/secure-ai-tooling`
publishes the CoSAI Risk Map as real YAML with matching JSON Schemas —
`risk-map/yaml/risks.yaml` (confirmed live, Apache-2.0 licensed, Google LLC copyright header),
plus sibling files `controls.yaml`, `components.yaml`, `personas.yaml`, each with a
`risk-map/schemas/*.schema.json` validator. Confirmed real top-level shape:
```yaml
title: Risks
risks:
  - id: riskDataPoisoning
    title: Data Poisoning
    shortDescription: [...]
```
This is a genuine machine-readable risk taxonomy (each risk has an `id`, `title`, description,
mapped controls, and Model-Creator/Model-Consumer responsibility split) — same character as
OWASP's Top 10 lists (3.1/3.5) but with an actual schema-validated YAML/JSON artifact rather
than just prose markdown, and multiple linked files (risks/controls/components/personas) that
could be joined into a small relational structure if wanted.
Verdict: **STANDARD-ONLY** (one-time vendor of the risk/control tables — this is a taxonomy,
not a dated incident series; nothing to "ingest weekly" since it changes only on releases). Note
it's more useful as a *tagging vocabulary* to apply to AVID/AIID records than as a source of
records itself.
Cadence: revised periodically via GitHub releases/PRs (four active workstream repos:
`ws1-supply-chain`, `ws3-ai-risk-governance`, `ws4-secure-design-agentic-systems`, plus the main
`secure-ai-tooling` repo) — check the main repo's releases if a versioned snapshot is wanted.
Licence: Apache License 2.0 — explicit, permissive, confirmed in the file header.

### 4.3 OASIS STIX/TAXII (CISA AIS)
Not fetched live — CISA's Automated Indicator Sharing (AIS) STIX/TAXII feed requires org
registration (an AIS agreement + TAXII client credentials), consistent with `sources.md`'s
treatment of similarly-gated feeds (e.g. §2.4 Shadowserver).
Verdict: **MANUAL-ONLY** — registration-gated, out of scope for an unauthenticated weekly
GitHub Actions job.

### 4.4 OASIS CACAO (Collaborative Automated Course of Action Operations)
CACAO is a playbook-interchange **standard** (machine-readable incident-response playbooks),
not a published dataset of incidents or vulnerabilities — there is no "CACAO feed" to poll, only
individual organizations' own CACAO-formatted playbooks, which aren't centrally aggregated.
Verdict: **STANDARD-ONLY**, mention-only (no ingest path exists or would make sense).

### 4.5 OASIS OpenC2
Command-and-control standard for security-tool orchestration, entirely unrelated to
vulnerability/incident data — has no bearing on this tracker at all.
Verdict: **SKIP** entirely, per the brief.

---

## Answer: was ATLAS "MANUAL-ONLY" the right call, and does it still hold?

**Partially.** The narrow factual claim in `sources.md` §1.4 — "no CVE crosswalk field exists
in the schema (`case-studies` link to `techniques`, not CVE IDs)" — **is still true** and was
re-confirmed directly against the live v6 schema: `case-studies[].date/type/actor/target` link
via a separate `relationships[].employs[]` block to `techniques` (`AML.Txxxx` IDs) and
`tactics` (`AML.TAxxxx` IDs), never to a CVE. There is no join to the CVE-centric KEV/cvelistV5
pipeline this tracker is built around, and there won't be one — ATT&CK/ATLAS simply don't model
CVEs.

But the **verdict drawn from that fact was too narrow**. "No CVE join" was treated as
equivalent to "not worth scripting," when ATLAS case-studies are actually a complete,
self-contained, dated dataset in their own right: each has a `date` (with `date-granularity`),
a `type` (Incident vs. Exercise), free-text `actor`/`target`/`description`, and a full
step-by-step technique/tactic breakdown via `relationships`. That's everything needed to build
an independent "AI attacks by year" or "AI attacks by technique" series/chart on the page,
displayed as its own section rather than as a column bolted onto the CVE/KEV tables — no CVE
join required or expected, because it was never meant to answer a CVE-shaped question in the
first place.

**Corrected recommendation: ADD-KEYLESS.** Fetch `dist/v6/ATLAS-latest.yaml` monthly (matching
ATLAS's real release cadence, not weekly — no point re-fetching between monthly releases), parse
out `case-studies` and `relationships`, and render them as their own standalone AI-incident
timeline/technique-breakdown feature, explicitly separate from the CVE/KEV tables. The one real
engineering cost is that this needs *some* YAML parsing (stdlib Python has no YAML module), plus
handling this session's evidence that the current monthly file is large enough to need
streaming/chunked handling rather than a single `read()` — both solvable, neither a reason to
stay manual-only. This applies the same "own standalone series" logic to AVID (§2.2, ADD-KEYLESS
confirmed) and, pending endpoint retests, to AIID (§2.1) and OECD AIM (§2.5) — none of these
need a CVE crosswalk to be worth ingesting; they were always going to be additive AI-specific
sections of the page, not enrichment columns on the existing KEV-centric tables.
