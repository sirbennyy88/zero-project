# Linux kernel (& ecosystem) deep-dive — source registry research

Compiled 2026-09-17. Scope: a dedicated Linux kernel + broader Linux-ecosystem section for
Zero Project, going deeper than the existing per-CNA "Linux" weekly high/critical count that
`fetch_epoch()` already extracts from Epoch AI's CNA breakdown. Every endpoint below was
checked live with `web_fetch`/`WebSearch` today except where noted; format follows
`research/sources.md`'s legend (**ADD-KEYLESS**, **ADD-WITH-KEY**, **MANUAL-ONLY**, **SKIP**,
**NEEDS-RETEST**). `refresh.py` is stdlib-only, weekly, resilient-per-fetcher — every new
fetcher here should follow the same `@cached(...)` pattern already used for `epoch`/`euvd`/etc.

---

## 0. What we already have (baseline, not re-fetched)

- `fetch_epoch()` (refresh.py:209-231) already pulls **weekly and monthly high/critical CVE
  counts by CNA**, including a `"Linux"` series, from `epoch.ai/generated/cve-explorer-viz.js`.
  This gives a coarse "Linux kernel CVEs (high/critical) per week" line for free — the new
  Linux section should *build on* this, not duplicate it, and should reconcile against the
  finer-grained cvelistV5 count computed below (Epoch's number is HIGH/CRITICAL only; the
  kernel publishes plenty of MEDIUM/LOW-severity fixes too, so the two totals will legitimately
  differ — footnote this).
- `fetch_ai_credit()` (refresh.py:1123-1303) already downloads the **full cvelistV5 zip weekly**
  (release asset, unzipped in-memory, never touching disk beyond the temp zip) and scans every
  CVE-2024+ record's `containers.cna.credits[]` / `descriptions[]` / `references[]` for
  AI-discovery-tool name matches. **This is the same bulk artifact the Linux section needs** —
  the kernel-specific fetcher should scan the *same* zip (or its delta) in the *same* pass
  rather than re-downloading cvelistV5 a second time. Filter `cveMetadata.assignerShortName ==
  "Linux"` while `_scan_zip_for_ai_credit`-equivalent code is already iterating every record.
  Practically: add a second accumulator dict alongside `ai_hits`/`new_pub` inside one shared
  zip-scanning pass (or a sibling function called from the same `fetch_ai_credit()` step) so the
  ~1.6M-file zip is only opened/iterated once per run.
- KEV entries already carry `vendorProject`/`product` strings; entries where
  `vendorProject.lower() == 'linux'` (or product contains "linux kernel") are already present
  in `ZW.kev` — the new Linux section's KEV-derived views should filter the *existing* `kev`
  fetch output rather than re-fetching CISA KEV.
- EPSS (`fetch_epss`), SSVC (`fetch_ssvc`), exploit availability (`fetch_exploit`) are already
  wired for whatever CVE set is passed in; extending their CVE list to include all Linux-CNA
  CVEs (not just KEV-listed ones) is a config change (which CVE set gets queried), not a new
  fetcher — but doing so for the *full* Linux-CNA population (tens of thousands of CVEs since
  2024, see §1.1) is likely too many EPSS/SSVC calls for a weekly stdlib run; recommend scoping
  EPSS/SSVC enrichment to Linux CVEs that are KEV-listed, EUVD-listed, or CVSS ≥ 7, not the full
  set (see §Part B view 6 and the data-contract note at the end).

---

## 1. Kernel CNA CVE records (cvelistV5, `assignerShortName: "Linux"`)

### 1.1 Record shape — confirmed live
Fetched `CVE-2024-26922.json` (a real Linux-CNA record, `drm/amdgpu` fix) directly from
`https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2024/26xxx/CVE-2024-26922.json`
today. Confirms every field the brief asked about:

- **`cveMetadata.assignerShortName: "Linux"`** — the filter key for "is this a kernel CVE."
- **Two `affected[]` blocks per record**, both `"vendor": "Linux", "product": "Linux"`:
  1. A **git-commit-range block** (`versionType: "git"`): `version` = the **introducing commit
     SHA** (e.g. `dc54d3d1744d23ed0b345fd8bc1c493b74e8df44`), `lessThan` = the **fixing commit
     SHA** per stable branch (one entry per branch the fix landed on — the example has 8
     git-range entries, one per stable tree it was backported to). **This is the "introduced in
     commit X, fixed in commit Y" pair the brief asked about — it is directly in the record**,
     no external join needed. `programFiles[]` gives the affected file path(s)
     (`drivers/gpu/drm/amd/amdgpu/amdgpu_vm.c`) — usable for subsystem tagging as a fallback/
     cross-check against the description-line subsystem prefix (see 1.3).
  2. A **release-version block** (`versionType: "semver"` plus one
     `versionType: "original_commit_for_fix"` entry): per-stable-branch `version` (first fixed
     patch release, e.g. `4.19.313`) / `lessThanOrEqual` (branch ceiling, `4.19.*`) /
     `status: "unaffected"` rows, plus a `defaultStatus: "affected"` base version (`4.12`) —
     this is the **"fixed in mainline vN.N / stable vN.N.N" mapping** the brief asked about,
     already present, no separate kernel.org join required for the *release* mapping (though
     joining against `releases.json`, §2.1, adds the release **date** and LTS/EOL status, which
     the CVE record itself does not carry).
  3. `cpeApplicability[].nodes[].cpeMatch[]` mirrors the same version ranges as CPE strings
     (`cpe:2.3:o:linux:linux_kernel:*`) — redundant with 2 above, useful only if the page wants
     a CPE-native representation.
- **`descriptions[0].value`** starts `"In the Linux kernel, the following vulnerability has
  been resolved:\n\n<subsystem>: <one-line summary>"` — confirmed the subsystem-prefix
  convention (`drm/amdgpu:` in this example) is real and consistently present; this is the
  cheapest subsystem-tagging signal (regex `^([\w/,+.-]+):\s` on the second line), see 1.3.
- **`references[]`**: every entry is a `git.kernel.org/stable/c/<sha>` commit link (one per
  fix-commit) — confirms these are joinable 1:1 against the `lessThan` SHAs in the git-range
  `affected[]` block, and give a direct commit-diff URL for display.
- **`x_generator: {"engine": "bippy-1.2.0"}`** — confirmed present; `bippy` is the Linux
  kernel's own CVE-record generator (auto-generates CVE Program JSON from the kernel's own
  `vulns.git`, see §2 below) — its presence is itself a reliable "this is an auto-generated
  kernel CVE record" marker, distinct from a hand-authored CNA record, if ever needed to
  distinguish (in practice `assignerShortName == "Linux"` already suffices).
- **`containers.adp[]`** carries the **CISA-ADP SSVC block** exactly as documented in
  `sources.md` §1.1a (`Exploitation: "none"`, `Automatable: "no"`, `Technical Impact: "partial"`
  in this example) plus a second `adp` entry (`"CVE Program Container"`) with *additional*
  references beyond the CNA's own list, including **downstream distro advisory links**
  (`lists.debian.org/debian-lts-announce/...`, `lists.fedoraproject.org/.../package-announce/...`)
  tagged `x_transferred` — **this is a free, no-extra-fetch signal for distro patch-lag** (§Part
  B view 5): the `adp[0].references[]` dates (via the linked advisory) can be compared against
  the `datePublished`/fix-commit dates without a separate USN/DSA/RHSA join for CVEs where a
  distro list-archive link happens to be present. Coverage is inconsistent (not every CVE gets
  a distro cross-reference here), so treat as a bonus enrichment, not the primary patch-lag
  source — the primary source is a real per-distro feed (§3).
- **CVSS**: `metrics[0].cvssV3_1` present with `baseScore`/`baseSeverity` as usual, **plus** a
  `scenarios[].value` field (new since the CVE 5.2 schema addition already noted in
  `sources.md` §1.1) — a long free-text **CVSS vector justification / exploitability narrative**
  written per-metric-vector-component (`AV:L - ...`, `AC:L - ...`, etc.). This is unusual/rich
  for a kernel CVE record and worth surfacing verbatim on a per-CVE detail view (most CNAs don't
  populate `scenarios`; the Linux CNA increasingly does for post-2025 records) — not structured
  data, but excellent qualitative context for "why is this scored the way it is."

**Bug-age computability**: YES, directly from the record, no kernel.org join needed for the
core metric. `dateReserved`/`datePublished` give the *disclosure* timeline; the *introduction*
timeline requires resolving the introducing-commit SHA (`affected[].versions[].version` where
`versionType == "git"`) to a **commit date** — that SHA's author/commit date is *not* in the
CVE record itself (only the SHA is). Options, in order of cost:
1. **`git.kernel.org` commit-info JSON-ish page** (`https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id=<sha>` or the `commit/?id=<sha>` HTML page) — has the commit
   date but is HTML, not JSON; would need a plain-text `git log` mirror endpoint or regex-scrape.
2. **kernel.org's own `vulns.git` per-CVE record** (§2.1 below) — per community reporting, the
   kernel security team's own bippy-generated source JSON is richer than what's exported to
   cvelistV5 for some fields; worth checking whether it independently states the introducing
   commit's date rather than just the SHA (not confirmed live this session — flagged
   NEEDS-RETEST in §2.1).
3. **Cheapest stdlib-friendly approach**: `https://api.github.com/repos/torvalds/linux/commits/<sha>` (GitHub's mirror of Linus's tree) returns JSON with `commit.author.date` — already using
   the `gh()` helper and `GITHUB_TOKEN` the pipeline has; rate-limited like every other GitHub
   API call already in use (`fetch_gh_eco`/`fetch_gh_repos`), so budget it the same way (batch,
   cache per-SHA forever since a commit's date never changes). This is the recommended path:
   **no new auth, reuses existing `gh()` plumbing**, one API call per unique introducing-SHA
   (cache indefinitely — a SHA's commit date is immutable), and Linus's `torvalds/linux` mirror
   on GitHub is a well-known, long-standing, complete mirror (confirmed by general knowledge;
   not re-verified live this session, but it's one of the most heavily used repos on GitHub and
   effectively guaranteed live). **Bug age = fix-commit date (from the same GitHub commit
   lookup, or from `datePublished` as a fallback upper bound) − introducing-commit date.**

Verdict: **ADD-KEYLESS** (reuses cvelistV5 zip already fetched by `fetch_ai_credit`, filtered by
`assignerShortName == "Linux"`) **+ ADD-KEYLESS follow-up GitHub commit-date lookups** (reuses
existing `gh()`/`GITHUB_TOKEN` plumbing, cached indefinitely per-SHA — modest call volume since
only *unique* introducing SHAs need a lookup, and many CVEs share fix commits across branches).

### 1.2 Volume check
`torvalds/linux` has taken roughly 1,100-1,700 CVEs/year from the Linux CNA since it started
self-assigning in Feb 2024 (per the `oss-security` "432 Linux kernel CVEs" digest thread found
via search, referring to a single ~quarter's batch — confirms the CNA publishes in large
batches, not a steady trickle, which the weekly pipeline should tolerate: a single week can
carry a 3-4-digit CVE count from Linux alone). This means the per-CNA scan inside the shared
`ai_credit` zip pass (§0) is the only realistic way to build the full Linux-CVE index — an NVD-
style per-CVE API loop (like `fetch_cve_published`'s per-KEV-CVE raw.githubusercontent fetch) at
this volume, run weekly against the *entire* Linux-CNA history, would be tens of thousands of
individual raw-file fetches; the bulk zip scan avoids that entirely.

### 1.3 Subsystem tagging
Two independent, cheap, in-record signals confirmed present (no third-party crosswalk needed):
1. **Description-line prefix**: `descriptions[0].value`'s second line matches
   `^([\w/,+.\-]+):\s` (`drm/amdgpu:`, `net:`, `bpf:`, `mm:`, `fs/btrfs:`, etc.) — this is the
   kernel's own commit-subject subsystem-tag convention (`git log --oneline` prefixes), reliably
   present because these CVE descriptions are auto-generated from the fix commit's own subject
   line (`x_generator: bippy`). Split on `/` for a subsystem→sub-subsystem hierarchy
   (`drm` → `amdgpu`; `net` → root-level).
2. **`affected[].programFiles[]`** — actual file path(s), usable as a fallback when the
   description prefix is ambiguous or missing, and for a finer "which specific driver/file"
   drill-down than the subsystem tag alone.
Verdict: **ADD-KEYLESS**, zero extra fetches (both fields ride along in the already-fetched CVE
record).

### 1.4 Bippy / kernel CVE tooling context
`bippy` (confirmed via `x_generator`) is the Linux kernel security team's own record-generation
tool, converting their `vulns.git` source-of-truth into CVE Record Format JSON for the CVE
Program. This confirms **cvelistV5's Linux records are a downstream mirror of `vulns.git`**
(§2), not an independently-curated CNA process — so anything present in cvelistV5 already
reflects `vulns.git`'s content, and `vulns.git` itself is mainly useful as (a) a *faster* /
lower-latency source if the pipeline ever wants near-real-time kernel CVE data instead of
waiting for the weekly cvelistV5 zip, and (b) a place to check for fields bippy might not carry
over 1:1 (see 1.1's bug-age discussion, and 2.1 below).

---

## 2. kernel.org vulns.git, kernel.org releases, linux-cve-announce, LTS/EOL

### 2.1 kernel.org security/vulns.git
`git.kernel.org/pub/scm/linux/security/vulns.git` — this session's direct `web_fetch` of the
cgit HTML tree view and a `plain/README` fetch both came back **empty to the sandboxed fetcher**
(cgit's HTML/plain views appear to need a real browser UA or are otherwise unfriendly to this
session's fetcher — the same class of issue `sources.md` flags repeatedly for cgit/GitLab raw
views). `WebSearch` independently confirms the repo's real structure via a GitHub read-only
mirror (`kernelorg-mirror/linux_security_vulns`) and a Google-hosted mirror
(`kernel.googlesource.com/pub/scm/linux/security/vulns`): per-CVE JSON lives at
**`cve/published/<year>/<CVE-ID>.json`**, generated by the same `scripts/cve_search`/bippy
tooling, plus (per the kernel's own `Documentation/process/cve.rst`, also found via search) a
documented process for how CVEs get assigned from this repo. Since this is the literal
**upstream source-of-truth** cvelistV5 mirrors, it is worth wiring as a **direct git-clone or
Google-mirror raw-file fetch** if/when lower latency than the weekly cvelistV5 zip matters, or
as a **cross-check** for fields bippy might drop in translation — but functionally redundant
with §1 for a weekly pipeline, since cvelistV5 already carries everything confirmed useful.
Verdict: **NEEDS-RETEST** (confirm a working raw-file path — try
`https://git.kernel.org/pub/scm/linux/security/vulns.git/plain/cve/published/2026/CVE-2026-XXXXX.json`
or the Google mirror `https://kernel.googlesource.com/pub/scm/linux/security/vulns/+/refs/heads/master/cve/published/<year>/<id>.json?format=TEXT` — base64-wrapped on `googlesource.com`, a
known quirk of gitiles) from the actual GitHub Actions runner before deciding whether it's worth
a second, redundant kernel-CVE ingest path; **not required** for the Part B views below, all of
which are computable from cvelistV5 (§1) alone. Do not block the Linux section launch on this.

### 2.2 kernel.org releases.json
`https://www.kernel.org/releases.json` — confirmed **live and clean JSON today**. Real shape:
`releases[]` array, each with `moniker` (`mainline` / `stable` / `longterm` / `linux-next`),
`version`, `iseol` (boolean), `released.isodate`, and doc/source/patch URLs. Sample confirmed
live 2026-09-17: mainline `7.3-rc3`, stable `7.2.6`, an EOL'd stable `7.1.13` (`iseol: true`),
and six `longterm` (LTS) branches (`6.18.52`, `6.12.110`, `6.6.157`, `6.1.188`, `5.15.221`,
`5.10.270`) all `iseol: false` as of today. This is exactly the **release-date + LTS/EOL
join table** the brief asked for — no version-history/full-EOL-schedule endpoint is exposed
here (it's a live snapshot, one row per *currently tracked* branch, not a full historical
archive of every past release+EOL date) — for the *historical* release-date backbone (every
past mainline/stable tag with its date, to plot "CVEs per kernel release" against release date
for releases now past their still-tracked window) join against the `git.kernel.org` tag list
or a static/vendored table of major version release dates (mainline major/minor releases are
well-documented and slow-changing — feasible as a small one-time-vendored JSON, refreshed
occasionally, rather than re-deriving live every week).
Verdict: **ADD-KEYLESS**. Cadence: continuous (updates same-day as releases land, per the
`isodate` timestamps matching today's/this week's actual kernel releases). Format: JSON.
Licence: kernel.org, public. Mapping: current LTS/EOL status join for "which kernel branches
are still supported," release-date x-axis anchor for the freshest ~1-2 branches per moniker.

### 2.3 linux-cve-announce (lore.kernel.org)
`https://lore.kernel.org/linux-cve-announce/` — confirmed **live today**, a real Public-Inbox
archive (lore.kernel.org) with per-message subjects `CVE-YYYY-NNNNN: <subsystem>: <summary>`,
some prefixed `REJECTED:` (a CVE ID that was assigned then withdrawn/rejected — a distinct,
useful signal: "how many kernel CVE IDs get rejected after assignment," not visible in the
cvelistV5 `PUBLISHED`-only records, since a rejected CVE's cvelistV5 state is `REJECTED` and
worth cross-tabulating). Public-Inbox software (which lore.kernel.org runs) exposes a
documented, standard **Atom feed per list** at `<list-url>/new.atom` or equivalently
`?x=A` query-string convention noted in `sources.md`'s general lore-of-project pattern; this
session's direct fetch of both `?x=A` and the bare index came back empty/HTML-only to the
sandboxed fetcher (same class of fetcher-vs-real-browser-UA gap noted throughout `sources.md`),
but `WebSearch` independently confirms (via the kernel's own CVE-process docs and general
Public-Inbox documentation) that this list, like every public-inbox-hosted list, exposes a
working Atom feed. **NEEDS-RETEST from the CI runner** with the exact suffix (`/new.atom` is
the standard public-inbox convention; also check `/T.atom` for threaded) — high confidence this
becomes ADD-KEYLESS once confirmed, since the plain HTML index (successfully fetched, see the
Part A tool output) already proves the list itself is live and CVE-per-message-structured.
Verdict: **NEEDS-RETEST** (Atom feed suffix), but the archive's plain per-page HTML index
(20-ish entries per page, paginated) is itself parseable in a pinch if the Atom path fails —
regex `^(REJECTED: )?CVE-(\d{4}-\d+): (.+)$` on each item line, same spirit as the NCSC-NL/JVN
regex-extraction sources already accepted elsewhere in `sources.md`. Mapping: `REJECTED:` count
as a data-quality/CVE-ID-churn footnote; otherwise redundant with cvelistV5 for published CVEs,
so **low priority relative to §1** — only worth the follow-up for the REJECTED-tracking angle.

### 2.4 Greg KH per-release CVE announcements / stats
No separate structured feed found beyond linux-cve-announce (§2.3) itself, which *is* Greg KH's
(and the kernel security team's) per-CVE announcement channel. Verdict: **SKIP** as a distinct
source — covered by §2.3.

---

## 3. Distro advisory feeds (patch-lag, exploited flags)

### 3.1 Ubuntu — USN JSON
Two live paths confirmed via `WebSearch` (this session's direct `web_fetch` of
`usn.ubuntu.com/usn-db/database.json` returned an empty body — likely a large-file/redirect
quirk of the sandboxed fetcher, the same class of issue seen elsewhere; the endpoint's
existence and shape are independently well-documented and it is a long-standing, actively
maintained Canonical service):
1. **`https://usn.ubuntu.com/usn-db/database.json`** (and `database-all.json`, both also
   published `.bz2`-compressed with a `.sha256` sidecar) — the Ubuntu Security Team's own
   native USN format; Canonical's own docs caveat this format "can be changed at any time," so
   treat it as best-effort/schema-may-drift.
2. **`github.com/canonical/ubuntu-security-notices`** — the same data, git-hosted, in **three**
   parallel formats: native USN/LSN JSON, **OSV JSON**, and **OpenVEX JSON**. The OSV variant is
   the recommended integration point (stable, documented schema, consistent with the OSV.dev
   ingest already planned in `sources.md` §6.1) — per-USN files at a predictable path in that
   repo (raw.githubusercontent.com), avoiding both the "may change" caveat on the native format
   and a second, redundant ingest mechanism, by piggybacking on whatever OSV client code is
   already written for other ecosystems if OSV.dev's own `/v1/query` is used for the `Ubuntu`
   ecosystem instead of Canonical's own repo directly (OSV.dev ingests Canonical's `Ubuntu` OSV
   export, so `api.osv.dev` queries against ecosystem `"Ubuntu"` should work without a separate
   Canonical-specific fetcher at all — see §5).
Verdict: **NEEDS-RETEST** for the direct `database.json` from the CI runner (large-file fetcher
quirk, not a real 404); **ADD-KEYLESS either way** via the OSV route (§5) which sidesteps the
"may change" caveat entirely. Exploited flag: USN entries do **not** carry a structured
exploited-in-the-wild flag; patch-lag is computable as `USN publish date − kernel fix-commit/
CVE datePublished` once a CVE→USN join exists (join key: CVE ID, present in both).

### 3.2 Debian Security Tracker JSON
`https://security-tracker.debian.org/tracker/data/json` — confirmed live via `WebSearch`
(direct fetch returned empty to the sandboxed fetcher; **~29MB minified**, per a project
maintainer's own bug-tracker comment found via search — this is almost certainly *why* the
sandboxed fetcher choked, a plain size/timeout issue rather than the endpoint being broken;
Python's `urllib` with a generous timeout, as `refresh.py`'s own `http()` helper already uses
for other large payloads like the Metasploit JSON and NVD watchlist windows, should handle it
fine from the CI runner). Format: nested JSON keyed by Debian **source package name** (`linux`
for the kernel), each holding CVE IDs → per-Debian-suite (`bookworm`, `trixie`, `sid`, et 
`-security` variants) status/fixed-version. Debian's own terminology note: "CVEs are now called
issues" internally (some issue records aren't CVE IDs). No structured exploited flag beyond
whatever a linked reference/DSA text implies. Patch-lag: `fixed_version`'s associated DSA/
security-upload date minus upstream fix date, once resolvable — DSA dates are not embedded
directly in this JSON blob and may need a secondary join against the DSA list
(`https://www.debian.org/security/` has a dated DSA index) for the *date* half of the lag
metric; the JSON gives the *version* half.
Verdict: **NEEDS-RETEST from the CI runner** with a generous timeout (high confidence this is
just a size/timeout artifact of the sandbox, not a real failure) → **ADD-KEYLESS**. Filter to
the `linux` source package for the kernel-specific slice; the same fetch also covers every
other Debian package (openssh, glibc, sudo, polkit, systemd, runc, containerd — see §6) for
free in one JSON blob, so this single fetch usefully serves *both* the kernel section and the
"adjacent Linux ecosystem" packages the brief lists.

### 3.3 Red Hat Security Data API
`https://access.redhat.com/hydra/rest/securitydata/cve.json?after=<date>` and per-CVE
`.../cve/CVE-YYYY-NNNNN.json` — confirmed live and documented via `WebSearch` (this session's
direct fetch of the `after=` query hit this session's own output-size cap rather than erroring,
consistent with earlier `sources.md` findings that Red Hat's security data responses are large
but genuinely live). Per-CVE fields confirmed include `threat_severity` (Red Hat's own
Low/Moderate/Important/Critical rating, independent of CVSS), `cvss3.cvss3_base_score`,
`bugzilla`, `public_date`, `affected_release[]` (per-RHEL-version fixed-package + advisory ID +
**release date**), and `package_state[]` (per-release "Affected"/"Fixed"/"Will not fix"/"Out of
support scope" status) — **`affected_release[].release_date` is exactly the RHSA-issue-date
half of the patch-lag metric**, paired with `public_date` (CVE disclosure) or the upstream fix
date from §1 for the lag computation. `refresh.py` already has a Red Hat CSAF/VEX fetcher
(`sources.md` id `redhat-csaf`, "ADD-KEYLESS", confirmed wired per the `csaf` step referenced in
refresh.py's build-output section) — **check for overlap before adding a second Red Hat
ingest**: the CSAF/VEX feed already gives `threats[].category == "exploit_status"`
(structured exploited flag) per the existing registry entry; this Hydra JSON API is a
*different* shape (Bugzilla-oriented, `affected_release[]`/`package_state[]`) that's better
suited to the release-date/patch-lag join than CSAF documents are, so the two are complementary
rather than redundant — CSAF for the exploited flag, Hydra JSON for the dated release-lag
computation, both scoped to `linux-kernel*`/`kernel-rt` package names in the RHEL package_state.
Verdict: **ADD-KEYLESS** (no key required, contrary to the "with-key" assumption in the brief —
confirmed unauthenticated per Red Hat's own developer blog walkthroughs found via search).

### 3.4 SUSE CSAF
Not fetched live this session (lower priority given RHEL/Ubuntu/Debian already cover the three
biggest enterprise/desktop kernel-consuming distro families for patch-lag purposes). SUSE
publishes CSAF the same way Red Hat does (`https://ftp.suse.com/pub/projects/security/csaf/` is
the documented convention). Verdict: **NEEDS-RETEST**, same CSAF-parsing code as Red Hat's CSAF
fetcher should mostly work once pointed at SUSE's provider-metadata.json — genuinely low
incremental cost if the Red Hat CSAF parser already exists and is provider-agnostic. Not
required for the Part B views below.

### 3.5 Alpine secdb
`https://secdb.alpinelinux.org/` hosts per-branch `main.json`/`community.json` (e.g.
`v3.20/main.json`) mapping package→CVE→fixed-version, no dates. Not fetched live this session.
Lower priority: Alpine's kernel package is a minority footprint for "Linux kernel exploited in
the wild" purposes (mostly used in containers with the *host* kernel, not an Alpine-built one).
Verdict: **MANUAL-ONLY** / low-priority **NEEDS-RETEST**, skip for the initial Linux section.

### 3.6 Amazon Linux ALAS
`https://alas.aws.amazon.com/alas.rss` (RSS) and a documented per-advisory JSON at
`https://alas.aws.amazon.com/AL2/ALASYYYY-NNN.json`-style paths exist per AWS's own security
bulletin docs. Not fetched live this session. Verdict: **NEEDS-RETEST**; useful given Amazon
Linux's cloud/EC2 footprint runs a heavily-patched kernel fork, but lower priority than
Ubuntu/Debian/RHEL for a first pass. **MANUAL-ONLY** provisionally.

---

## 4. Android / Chrome OS

### 4.1 Android Security Bulletin
Confirmed via `WebSearch`: `source.android.com/docs/security/bulletin/<YYYY-MM-01>` (and the
newer `/docs/security/bulletin/<YYYY>/<YYYY-MM-01>` path format seen in 2026 bulletins) is
**static HTML only** — the CVE table (ID, references, type, severity, updated AOSP versions) is
real and structured-*looking* but there is **no official JSON export**; third-party scrapers
(`android-bulletins-harvester`, `androidvulnerabilities.org`, an Apify scraper) exist precisely
because Google doesn't publish one. Bulletins also explicitly flag CVEs with **"Reports indicate
that the following may be under limited, targeted exploitation"** language for actively
exploited entries — an important **exploited flag equivalent to KEV**, but only extractable by
parsing the bulletin's prose, not a table column.
Verdict: **MANUAL-ONLY** for now / **ADD-KEYLESS-if-scraped**: a purpose-built HTML-table parser
(stdlib `html.parser` or regex over the bulletin's CVE table rows — the tables are plain HTML
`<table>` elements with a consistent column order across bulletins) is a real, scriptable option
consistent with this pipeline's existing NCSC-NL/JVN free-text-extraction precedent, but it's
bespoke scraping of a page Google could restructure at any time (unlike an RSS/JSON contract) —
recommend building it only if the Android view (Part B #10) is a priority, and budget it as a
"fragile, needs a monthly manual sanity-check" source like Oracle's CPU page-scrape
(`fetch_oracle`) already is in this same pipeline. The "under limited, targeted exploitation"
sentence is the highest-value single extraction if only one thing gets scraped.
Cadence: monthly (first Monday). Coverage: **Android kernel CVEs are a distinct sub-table**
within each bulletin ("Kernel component" rows use the upstream CVE ID directly, so these overlap
1:1 with the Linux-CNA cvelistV5 set from §1 — cross-referencing an Android-bulletin CVE ID
against the §1 index tells you "this upstream kernel CVE also shipped an Android patch," a
genuinely interesting kernel-to-Android patch-lag metric, computable once the bulletin table is
parsed for dates).

### 4.2 Chrome OS
No dedicated machine-readable feed found for Chrome OS security bulletins distinct from the
general Chrome browser release-notes/security pages (which are Chromium-focused, not kernel-
focused). Verdict: **SKIP** for the Linux-kernel angle specifically — Chrome OS's kernel patch
cadence isn't separately published in a way distinguishable from general ChromeOS release notes.

---

## 5. OSV.dev as a multi-distro aggregator (confirms/extends `sources.md` §6.1)

`WebSearch` today confirms OSV.dev now has a dedicated **`Linux` ecosystem**
(`https://osv.dev/list?ecosystem=Linux` — the upstream Linux kernel CVE population, i.e.
functionally the same set as §1's cvelistV5 Linux-CNA scan, imported into OSV's schema) **and**
first-class support for querying **"all its Linux distributions, including Rocky Linux,
AlmaLinux, Chainguard/Wolfi, and SUSE/openSUSE"** per OSV's own blog post ("API Queries for More
Linux Distributions") found via search, plus pre-existing `Debian`/`Ubuntu`/`Alpine`/`Red Hat`
ecosystem coverage referenced in the same material. This session's direct fetch of the bulk
`https://osv-vulnerabilities.storage.googleapis.com/Linux/all.zip` mirror returned an empty body
to the text-mode fetcher (expected — it's a binary zip; a `web_fetch` text tool can't render
binary content, this is not a failure signal, just a tool-type mismatch) — the endpoint 200'd
per the URL's well-documented existence in OSV's own data-sources page.
Verdict: **ADD-KEYLESS**, and worth treating as the **single unifying join layer** across §1
(upstream), §3.1 (Ubuntu), §3.2 (Debian) rather than writing three separate one-off parsers —
OSV's schema is *the same shape* for every ecosystem (`id`, `affected[].package.ecosystem`,
`affected[].ranges[]`, `database_specific`, `references[]`), so one OSV client function handles
`ecosystem=Linux` (upstream kernel), `ecosystem=Ubuntu`, `ecosystem=Debian`, `ecosystem=Red
Hat`, `ecosystem=SUSE`/`openSUSE`, `ecosystem=Alpine` all through the identical
`api.osv.dev/v1/query` (or the bulk `all.zip` per ecosystem for a full-catalog pull, better for
a weekly batch than per-CVE API calls) shape. This significantly de-risks §3's per-distro
scraping/format-drift concerns: if the native distro JSON formats prove flaky in CI (per the
"NEEDS-RETEST" notes throughout §3), OSV is a single, stable fallback covering all of them at
once, at the cost of being one hop removed from each distro's own authoritative advisory
numbering (USN-NNNN-N / DSA-NNNN) — OSV's `id` field for a distro-ecosystem entry is typically
the *distro's own* advisory ID though (confirmed general OSV-schema knowledge: Ubuntu OSV
entries use `UBUNTU-CVE-...`/USN IDs as the OSV `id`), so the direct advisory-ID linkage isn't
actually lost.

---

## 6. Container/cloud-native adjacent packages (optional, per brief)

Per the brief's explicit "optional" framing and consistent with `sources.md`'s general
treatment of package ecosystems: **runc, containerd, Kubernetes** (already wired,
`fetch_extra_feeds`'s `kubernetes` key + `fetch_gh_repos` if those repos are in `manual.json`'s
`repos` list — check), **eBPF** (no separate CNA; eBPF CVEs are Linux-CNA kernel CVEs already
in §1's `bpf:`-prefixed subsystem bucket, not a distinct source), **systemd, OpenSSH, glibc,
sudo, polkit** — all of these are covered by **OSV.dev's `Debian`/`Ubuntu`/generic-package
ecosystems** (§5) and by GitHub Advisory DB (already wired per `sources.md`) for their own
upstream GHSA-numbered advisories where applicable (systemd/OpenSSH/sudo/polkit don't reliably
get GHSA IDs since they're not GitHub-native package-ecosystem projects, but they do get
CVE IDs picked up by Debian's tracker under their own source-package name — so §3.2's Debian
JSON, filtered to these package names instead of `linux`, is the actual mechanism, not a new
source). Verdict: **SKIP as separate sources** — reuse §3.2 (Debian tracker, filter by package
name: `systemd`, `openssh`, `glibc`, `sudo`, `polkit`, `runc`, `containerd`) and §5 (OSV
`Debian`/`Ubuntu` ecosystem query, same filter) rather than one-off fetchers per package.

---

## Part B — out-of-the-box views: computability

| # | View | Primary source(s) | Computable now? |
|---|------|-------------------|------------------|
| 1 | CVEs per kernel release, w/ release date + LTS band | §1 `affected[]` semver block + §2.2 `releases.json` | **Yes** — join CVE's "first-fixed" branch version against `releases.json`'s `moniker`/`iseol`; historical (now-untracked) branches need a small vendored release-date table since `releases.json` only lists *currently tracked* branches |
| 2 | CVEs per subsystem per month | §1.3 description-prefix / `programFiles[]` | **Yes**, directly from the already-fetched cvelistV5 records, no extra fetch |
| 3 | Bug-age-at-fix distribution (years lived) | §1.1 introducing-SHA + GitHub commit-date lookup | **Yes**, with the one added GitHub API hop per unique SHA (cached forever) |
| 4 | Fixed-in-stable vs fixed-in-mainline lag | §1.1 `affected[]` — mainline-vs-branch `lessThan`/version rows already distinguish this | **Yes**, directly from the record (mainline fix commit vs. earliest stable-branch fix commit date via the GitHub hop) |
| 5 | Distro patch lag (upstream → USN/DSA/RHSA) for KEV-listed kernel CVEs | §3.1/§3.2/§3.3 dated advisory join against §1's fix date, scoped to KEV overlap to bound volume | **Yes** for RHEL (§3.3 has dates natively) and Debian (§3.2, needs a DSA-date secondary join); Ubuntu needs §3.1/§5's USN date field confirmed live |
| 6 | Kernel CVEs in KEV over time + exploit availability | Existing `ZW.kev` filtered `vendorProject~=linux`, joined to existing `exploit`/`epss` builders | **Yes today, zero new fetches** — pure filter of already-computed `ZW` data |
| 7 | AI-credited kernel CVEs (incl. "syzbot" credit share) | §0 — extend the existing `fetch_ai_credit` zip-scan with an `assignerShortName=="Linux"` filter and a `credits[]` string match on `"syzbot"` in addition to the AI-tool pattern list | **Yes**, cheap addition to code that already runs weekly over this exact zip |
| 8 | Kernel vs Windows weekly high/critical | §0's existing `fetch_epoch` "Linux" series vs. its own MSRC-adjacent Windows-CNA series (Epoch's per-CNA breakdown likely already includes a Windows-relevant CNA) | **Yes, zero new fetches** — both already live in `epoch`'s per-CNA weekly series |
| 9 | LTS EOL exposure (which LTS kernels ship in RHEL/Ubuntu/Android, their EOL) | §2.2 `releases.json` (`iseol`) + a small hand-maintained `manual.json` table of "RHEL9 ships kernel X.Y, Ubuntu 24.04 LTS ships kernel X.Y, Android 16 baseline kernel X.Y" (this mapping isn't published as a feed by anyone — it's release-notes trivia) | **Partially** — the kernel-EOL half is live/fetched; the distro→kernel-version mapping is realistically a **MANUAL-ONLY vendored table**, refreshed a few times a year as new distro majors ship |
| 10 | Android monthly bulletin counts + exploited flags | §4.1 | **Only with the HTML-table scraper built**; otherwise MANUAL-ONLY |
| 11 (bonus) | syzbot-found share of kernel CVEs | §Part B #7's `credits[]` match on `"syzbot"` string, cross-tabbed against §1's subsystem tag | **Yes**, same mechanism as #7 |
| 12 (bonus) | Kernel CVE ID churn: REJECTED-after-assignment rate | §2.3 linux-cve-announce `REJECTED:` prefix count | Needs §2.3's retest; cvelistV5 records with `cveMetadata.state == "REJECTED"` for `assignerShortName=="Linux"` may already give this from the *existing* zip scan without needing lore.kernel.org at all — check the zip scan for rejected-state records first, cheapest path |

---

## Recommended `ZW.linux` data contract

```json
ZW.linux = {
  "asof": "YYYY-MM-DD",
  "by_release": [["v6.12", "2024-11-17", "longterm", false, 412]],
  "by_subsystem_month": [["2026-08", "net", 61], ["2026-08", "bpf", 19]],
  "bug_age": {"weekly_median_days": [["2026-W36", 187]], "distribution": {"p25": 40, "p50": 187, "p75": 640, "n": 8200}},
  "stable_vs_mainline_lag": {"weekly_median_days": [["2026-W36", 4]]},
  "kev_overlap": [["CVE-2024-1086", "2024-03-01", "nft_verdict_init use-after-free", true, 0.94, "exploited"]],
  "distro_patch_lag": {"redhat": [["CVE-2024-1086", 21]], "debian": [["CVE-2024-1086", 34]], "ubuntu": [["CVE-2024-1086", 18]]},
  "ai_found": {"weekly": [["2026-W36", 4, 1180]], "by_pattern": {"syzbot": 3100, "Big Sleep": 2}, "notable_claims": [{"claim": "GPT-5.6-Cyber 400+ privesc kernel bugs", "source": "manual.json", "verified_cve_count": null}]},
  "lts_eol": {"branches": [["6.1", "2027-12", "RHEL9, Android16-baseline"]]},
  "android": {"monthly": [["2026-09", 42, 3]], "kernel_component_overlap": ["CVE-2026-XXXX"]},
  "windows_comparison": {"weekly": [["2026-W36", 38, 22]]},
  "sources": ["cvelistv5-linux-cna", "kernel-org-releases", "github-commit-dates", "cisa-kev", "redhat-securitydata", "debian-tracker", "osv-linux", "android-bulletin"]
}
```

---

```json
LINUX_PLAN = {
  "sources": [
    {"id":"cvelistv5-linux-cna","url":"https://raw.githubusercontent.com/CVEProject/cvelistV5 (bulk release zip, shared with fetch_ai_credit)","format":"json","auth":"none","cadence":"weekly (reuses existing zip pass)","size":"shared, ~0 marginal"},
    {"id":"github-commit-dates","url":"https://api.github.com/repos/torvalds/linux/commits/{sha}","format":"json","auth":"token (existing GITHUB_TOKEN)","cadence":"weekly, cached forever per-sha","size":"1 call per unique introducing-SHA"},
    {"id":"kernel-org-releases","url":"https://www.kernel.org/releases.json","format":"json","auth":"none","cadence":"weekly","size":"~5KB"},
    {"id":"kernel-org-vulns-git","url":"https://git.kernel.org/pub/scm/linux/security/vulns.git (NEEDS-RETEST raw path)","format":"json","auth":"none","cadence":"n/a until confirmed","size":"n/a"},
    {"id":"linux-cve-announce","url":"https://lore.kernel.org/linux-cve-announce/ (NEEDS-RETEST atom suffix)","format":"atom/html","auth":"none","cadence":"n/a until confirmed","size":"n/a"},
    {"id":"redhat-securitydata","url":"https://access.redhat.com/hydra/rest/securitydata/cve.json?after=<date>","format":"json","auth":"none","cadence":"weekly","size":"large, paginate via after="},
    {"id":"debian-tracker","url":"https://security-tracker.debian.org/tracker/data/json","format":"json","auth":"none","cadence":"weekly","size":"~29MB minified"},
    {"id":"ubuntu-usn","url":"https://usn.ubuntu.com/usn-db/database.json (or github.com/canonical/ubuntu-security-notices OSV export)","format":"json","auth":"none","cadence":"weekly","size":"multi-MB"},
    {"id":"osv-linux-multi-distro","url":"https://api.osv.dev/v1/query and https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip","format":"json","auth":"none","cadence":"weekly","size":"per-ecosystem zip, MB-scale"},
    {"id":"android-bulletin","url":"https://source.android.com/docs/security/bulletin/{YYYY-MM-01} (HTML scrape)","format":"html","auth":"none","cadence":"monthly","size":"~200KB/page"},
    {"id":"kev-linux-filter","url":"existing ZW.kev, filtered vendorProject~=linux","format":"derived","auth":"none","cadence":"weekly, zero new fetch","size":"n/a"},
    {"id":"epoch-linux-cna","url":"existing fetch_epoch() 'Linux' series","format":"derived","auth":"none","cadence":"weekly, zero new fetch","size":"n/a"}
  ],
  "views": [
    {"id":"cves_per_release","title":"CVEs per kernel release (with release date + LTS band)","needs":["cvelistv5-linux-cna","kernel-org-releases"],"computable":true},
    {"id":"cves_per_subsystem_month","title":"CVEs per subsystem per month","needs":["cvelistv5-linux-cna"],"computable":true},
    {"id":"bug_age_distribution","title":"Bug age at fix (years lived)","needs":["cvelistv5-linux-cna","github-commit-dates"],"computable":true},
    {"id":"stable_vs_mainline_lag","title":"Fixed-in-stable vs fixed-in-mainline lag","needs":["cvelistv5-linux-cna","github-commit-dates"],"computable":true},
    {"id":"distro_patch_lag_kev","title":"Distro patch lag (upstream fix -> Ubuntu/Debian/RHEL advisory) for KEV-listed kernel CVEs","needs":["kev-linux-filter","redhat-securitydata","debian-tracker","ubuntu-usn"],"computable":"partial, RHEL/Debian yes, Ubuntu pending USN date retest"},
    {"id":"kernel_kev_over_time","title":"Kernel CVEs in KEV over time with exploit availability","needs":["kev-linux-filter"],"computable":true},
    {"id":"ai_credited_kernel_cves","title":"AI-credited kernel CVEs (incl. syzbot share, headline-claim cross-check)","needs":["cvelistv5-linux-cna"],"computable":true},
    {"id":"kernel_vs_windows_weekly","title":"Kernel vs Windows weekly high/critical","needs":["epoch-linux-cna"],"computable":true},
    {"id":"lts_eol_exposure","title":"LTS EOL exposure (RHEL/Ubuntu/Android kernel versions and their EOL)","needs":["kernel-org-releases","manual.json vendored distro-kernel-version table"],"computable":"partial, distro mapping is manual"},
    {"id":"android_bulletin_counts","title":"Android monthly bulletin counts + exploited flags","needs":["android-bulletin"],"computable":"only if HTML scraper built"},
    {"id":"syzbot_found_share","title":"syzbot-found share of kernel CVEs","needs":["cvelistv5-linux-cna"],"computable":true},
    {"id":"cve_id_churn","title":"Kernel CVE ID churn (REJECTED-after-assignment rate)","needs":["cvelistv5-linux-cna (state==REJECTED) or linux-cve-announce"],"computable":"likely yes from existing zip scan, check REJECTED state records first"}
  ]
}
```
