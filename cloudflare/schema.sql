-- Zero Project — D1 schema (Cloudflare free tier)
-- Apply with: wrangler d1 execute zero-project --remote --file cloudflare/schema.sql
--
-- 2026-09-06: dropped idx_vendor_weekly_cna and idx_p0_itw_cve -- the Worker
-- (cloudflare/worker/src/index.js) never queries by those columns, and every
-- index write counts against D1's free-tier rows_written budget. Kept
-- idx_kev_entries_date and idx_advisories_date (the Worker's /api/week and
-- /api/weeks routes need them) plus every PRIMARY KEY.
-- This is a schema change against the existing remote database: it needs a
-- one-time `wrangler d1 execute zero-project --remote --file cloudflare/schema.sql`
-- (DROP INDEX for the two removed indexes, since CREATE INDEX IF NOT EXISTS
-- won't remove them) -- do NOT run this today, D1 writes are rate-limited
-- until the daily rows_written quota resets 2026-09-08 00:00 UTC.

CREATE TABLE IF NOT EXISTS kev_entries (
  date_added   TEXT,
  cve          TEXT PRIMARY KEY,
  vendor       TEXT,
  product      TEXT,
  ransomware   TEXT,
  due          TEXT,
  name         TEXT,
  published    TEXT,
  category     TEXT,
  score        REAL,
  severity     TEXT
);
CREATE INDEX IF NOT EXISTS idx_kev_entries_date ON kev_entries(date_added);

CREATE TABLE IF NOT EXISTS kev_weekly (
  week         TEXT PRIMARY KEY,
  total        INTEGER,
  fresh        INTEGER,
  older        INTEGER,
  ransom       INTEGER,
  median_tte   REAL,
  edge         INTEGER
);

CREATE TABLE IF NOT EXISTS ledger_weekly (
  week          TEXT PRIMARY KEY,
  critical      INTEGER,
  high          INTEGER,
  medium        INTEGER,
  low           INTEGER,
  unassessed    INTEGER,
  commitments   INTEGER,
  patched       INTEGER
);

CREATE TABLE IF NOT EXISTS vendor_weekly (
  week          TEXT,
  cna           TEXT,
  high_critical INTEGER,
  PRIMARY KEY (week, cna)
);
-- idx_vendor_weekly_cna dropped 2026-09-06: no query filters by cna alone.

CREATE TABLE IF NOT EXISTS watchlist_monthly (
  product_id TEXT,
  month      TEXT,
  total      INTEGER,
  critical   INTEGER,
  high       INTEGER,
  medium     INTEGER,
  low        INTEGER,
  PRIMARY KEY (product_id, month)
);

CREATE TABLE IF NOT EXISTS patch_monthly (
  month           TEXT PRIMARY KEY,
  msrc_cves       INTEGER,
  oracle_patches  INTEGER,
  dotnet_advisories INTEGER
);

CREATE TABLE IF NOT EXISTS eco_monthly (
  ecosystem TEXT,
  month     TEXT,
  n         INTEGER,
  PRIMARY KEY (ecosystem, month)
);

CREATE TABLE IF NOT EXISTS repo_monthly (
  repo  TEXT,
  month TEXT,
  n     INTEGER,
  PRIMARY KEY (repo, month)
);

CREATE TABLE IF NOT EXISTS euvd_exploited (
  euvd_id         TEXT PRIMARY KEY,
  cve             TEXT,
  exploited_since TEXT,
  vendor          TEXT,
  product         TEXT,
  score           REAL
);

CREATE TABLE IF NOT EXISTS epss (
  cve        TEXT PRIMARY KEY,
  score      REAL,
  percentile REAL,
  asof       TEXT
);

CREATE TABLE IF NOT EXISTS exploit_signals (
  cve  TEXT PRIMARY KEY,
  msf  INTEGER,
  edb  INTEGER,
  poc  INTEGER
);

CREATE TABLE IF NOT EXISTS ssvc (
  cve          TEXT PRIMARY KEY,
  exploitation TEXT,
  automatable  TEXT,
  impact       TEXT
);

CREATE TABLE IF NOT EXISTS p0_itw (
  cve     TEXT,
  year    TEXT,
  vendor  TEXT,
  product TEXT,
  type    TEXT,
  in_kev  INTEGER
);
-- idx_p0_itw_cve dropped 2026-09-06: no query filters p0_itw by cve alone.

CREATE TABLE IF NOT EXISTS atlas_case_studies (
  id     TEXT PRIMARY KEY,
  date   TEXT,
  name   TEXT,
  target TEXT,
  actor  TEXT,
  techniques TEXT
);

CREATE TABLE IF NOT EXISTS advisories (
  source TEXT,
  date   TEXT,
  title  TEXT,
  url    TEXT,
  PRIMARY KEY (source, url)
);

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT
);
