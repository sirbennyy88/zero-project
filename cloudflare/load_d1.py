#!/usr/bin/env python3
"""
Zero Project — D1 loader (incremental).

Reads ../zeroweek-data.json and diffs it against cloudflare/d1_manifest.json
(committed; maps table -> {primary_key: sha1(row values)}). Only rows that
are new or changed get an INSERT ... ON CONFLICT DO UPDATE, and (for a
handful of small tables) rows whose key disappeared get a DELETE. Unchanged
rows are never re-written, so unchanged indexes are never re-written either.

This exists because Cloudflare D1's free tier caps rows_written at
100,000/day, and every index write also counts as a row write. The previous
loader did "INSERT OR REPLACE" for the *entire* dataset on every run
(REPLACE == DELETE + INSERT), so a couple of runs in a day was enough to
exhaust the daily budget.

Applies with:
    wrangler d1 execute zero-project --remote --file <file>

Usage:
    python cloudflare/load_d1.py                  # diff + apply
    python cloudflare/load_d1.py --dry-run         # diff + print planned counts only;
                                                    # no wrangler calls, manifest untouched
    python cloudflare/load_d1.py --max-writes N    # override the daily write budget
                                                    # (default 60000; leaves headroom under
                                                    # the 100k/day cap for other jobs/retries)

Budget guard: tables are processed in a fixed order (small/high-value first
-- see TABLE_ORDER). Once the running total of planned writes would exceed
--max-writes, remaining tables are deferred whole (never split mid-table)
and reported; the script exits 0 so the weekly workflow doesn't fail, and
the next run picks up exactly where this one left off (via the manifest).

The manifest is only updated for rows a SQL file was actually confirmed
applied for (wrangler exit code checked per file), so a failed apply never
marks rows as synced that D1 doesn't actually have.
"""
from __future__ import annotations
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DATA_FILE = ROOT / "zeroweek-data.json"
MANIFEST_FILE = HERE / "d1_manifest.json"
OUT_DIR = HERE / "out"
DB_NAME = "zero-project"
MAX_ROWS_PER_STMT = 500
MAX_BYTES_PER_FILE = 1_000_000
DEFAULT_MAX_WRITES = 60_000

# Processing order: small/important tables first, so a budget cutoff always
# finishes the cheap, high-value tables before the big ones (exploit_signals
# alone is ~27k rows). A cold load (empty manifest) that doesn't fit in one
# run's budget naturally spreads over the next 2-3 weekly runs, in this order.
TABLE_ORDER = [
    "meta", "kev_weekly", "kev_entries", "ledger_weekly", "epss",
    "exploit_signals", "ssvc", "euvd_exploited", "patch_monthly",
    "watchlist_monthly", "vendor_weekly", "eco_monthly", "repo_monthly",
    "advisories", "p0_itw",
]

# Primary key columns per table -- must match cloudflare/schema.sql.
# p0_itw has no natural PK in the schema, so it's handled as content-
# addressed (see diff_table): its "key" is the row's own hash.
TABLE_PK = {
    "kev_entries": ["cve"],
    "kev_weekly": ["week"],
    "ledger_weekly": ["week"],
    "vendor_weekly": ["week", "cna"],
    "watchlist_monthly": ["product_id", "month"],
    "patch_monthly": ["month"],
    "eco_monthly": ["ecosystem", "month"],
    "repo_monthly": ["repo", "month"],
    "euvd_exploited": ["euvd_id"],
    "epss": ["cve"],
    "exploit_signals": ["cve"],
    "ssvc": ["cve"],
    "p0_itw": None,
    "advisories": ["source", "url"],
    "meta": ["key"],
}

# Tables that never get a DELETE pass, even when a key drops out of the
# source data: p0_itw has no natural PK (content-addressed, append-only by
# construction), and KEV/advisories/EUVD are upstream feeds that in practice
# only grow -- diffing them for deletions every run would cost rows_written
# for a case that essentially never happens.
NO_DELETE_TABLES = {"p0_itw", "kev_entries", "advisories", "euvd_exploited"}

# Separator used to join composite primary-key values into one manifest
# string key. All PK columns in schema.sql are TEXT, so the round-trip
# through str() and back is exact.
PK_SEP = "\x1f"


def sql_quote(v):
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (int, float)):
        return repr(v)
    s = str(v)
    return "'" + s.replace("'", "''") + "'"


def row_hash(row):
    h = hashlib.sha1()
    for v in row:
        h.update(repr(v).encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


def pk_key(columns, row, pk_cols):
    idx = [columns.index(c) for c in pk_cols]
    return PK_SEP.join(str(row[i]) for i in idx)


def diff_table(table, columns, rows, manifest):
    """Compare current rows against the manifest's last-known hashes.

    Returns (upserts, deletes, current_hashes):
      upserts: list of (manifest_key, row, row_hash) for new/changed rows
      deletes: list of manifest_key strings for keys that disappeared
                (empty for NO_DELETE_TABLES)
      current_hashes: {manifest_key: row_hash} for every row in the current
                data -- becomes the new manifest entry for this table once
                the corresponding SQL is confirmed applied
    """
    pk_cols = TABLE_PK.get(table)
    old = manifest.get(table, {})
    current = {}
    upserts = []

    if pk_cols is None:
        # Content-addressed, append-only (p0_itw): the key IS the hash, so
        # "changed" is impossible -- a row is either already synced or new.
        for row in rows:
            h = row_hash(row)
            current[h] = h
            if h not in old:
                upserts.append((h, row, h))
        return upserts, [], current

    for row in rows:
        key = pk_key(columns, row, pk_cols)
        h = row_hash(row)
        current[key] = h
        if old.get(key) != h:
            upserts.append((key, row, h))

    if table in NO_DELETE_TABLES:
        deletes = []
    else:
        deletes = [key for key in old if key not in current]

    return upserts, deletes, current


def build_upsert_statements(table, columns, pk_cols, upserts):
    """Batch (key, row, hash) upserts into INSERT ... ON CONFLICT statements.

    Returns a list of (sql_statement, [(key, hash), ...]) so the caller can
    update the manifest only for the keys actually included in a given
    statement/file.
    """
    if not upserts:
        return []

    col_list = ", ".join(columns)
    if pk_cols:
        conflict_cols = ", ".join(pk_cols)
        update_cols = [c for c in columns if c not in pk_cols]
        if update_cols:
            set_clause = ", ".join(f"{c}=excluded.{c}" for c in update_cols)
            conflict_clause = f"ON CONFLICT({conflict_cols}) DO UPDATE SET {set_clause}"
        else:
            conflict_clause = f"ON CONFLICT({conflict_cols}) DO NOTHING"
    else:
        # p0_itw: no PK/unique constraint to conflict on -- plain insert.
        conflict_clause = ""

    out = []
    batch = []
    batch_keys = []

    def flush():
        if not batch:
            return
        stmt = f"INSERT INTO {table} ({col_list}) VALUES\n" + ",\n".join(batch)
        if conflict_clause:
            stmt += f"\n{conflict_clause}"
        stmt += ";"
        out.append((stmt, list(batch_keys)))
        batch.clear()
        batch_keys.clear()

    for key, row, h in upserts:
        if len(batch) >= MAX_ROWS_PER_STMT:
            flush()
        batch.append("(" + ", ".join(sql_quote(v) for v in row) + ")")
        batch_keys.append((key, h))
    flush()
    return out


def build_delete_statements(table, pk_cols, delete_keys):
    """Batch manifest keys that disappeared into DELETE statements.

    Returns a list of (sql_statement, [key, ...]).
    """
    if not delete_keys or not pk_cols:
        return []

    out = []
    batch = []

    def flush():
        if not batch:
            return
        if len(pk_cols) == 1:
            vals = ", ".join(sql_quote(k) for k in batch)
            stmt = f"DELETE FROM {table} WHERE {pk_cols[0]} IN ({vals});"
        else:
            col_list = ", ".join(pk_cols)
            rows = []
            for k in batch:
                parts = k.split(PK_SEP)
                rows.append("(" + ", ".join(sql_quote(p) for p in parts) + ")")
            stmt = f"DELETE FROM {table} WHERE ({col_list}) IN (VALUES {', '.join(rows)});"
        out.append((stmt, list(batch)))
        batch.clear()

    for key in delete_keys:
        if len(batch) >= MAX_ROWS_PER_STMT:
            flush()
        batch.append(key)
    flush()
    return out


def load(d):
    """Build {table: (columns, rows)} from the parsed zeroweek-data.json."""
    tables = {}

    # kev_entries / kev_weekly
    kev = d.get("kev", {})
    tables["kev_entries"] = (
        ["date_added", "cve", "vendor", "product", "ransomware", "due", "name", "published", "category", "score", "severity"],
        kev.get("entries", []),
    )
    tables["kev_weekly"] = (
        ["week", "total", "fresh", "older", "ransom", "median_tte", "edge"],
        kev.get("weekly", []),
    )

    # ledger_weekly
    ledger = d.get("ledger", {})
    tables["ledger_weekly"] = (
        ["week", "critical", "high", "medium", "low", "unassessed", "commitments", "patched"],
        ledger.get("weekly", []),
    )

    # vendor_weekly  (cna.series: {vendor: {week: n}})
    cna = d.get("cna", {}).get("series", {})
    vendor_rows = []
    for vendor, weeks in cna.items():
        for week, n in weeks.items():
            vendor_rows.append([week, vendor, n])
    tables["vendor_weekly"] = (["week", "cna", "high_critical"], vendor_rows)

    # watchlist_monthly ({product_id: {month: {total,critical,high,medium,low}}})
    monthly = d.get("watchlist", {}).get("monthly", {})
    wl_rows = []
    for pid, months in monthly.items():
        for month, v in months.items():
            wl_rows.append([pid, month, v.get("total"), v.get("critical"), v.get("high"), v.get("medium"), v.get("low")])
    tables["watchlist_monthly"] = (["product_id", "month", "total", "critical", "high", "medium", "low"], wl_rows)

    # patch_monthly (merge msrc / oracle / dotnet by month)
    patch = d.get("patch", {})
    msrc = dict(patch.get("msrc", {}))
    oracle = patch.get("oracle", {})
    dotnet = patch.get("dotnet", {})
    months = set(msrc) | set(oracle) | set(dotnet)
    patch_rows = []
    for month in months:
        oc = oracle.get(month)
        oracle_patches = oc.get("patches") if isinstance(oc, dict) else oc
        dn = dotnet.get(month)
        dotnet_advisories = dn.get("count") if isinstance(dn, dict) else dn
        patch_rows.append([month, msrc.get(month), oracle_patches, dotnet_advisories])
    tables["patch_monthly"] = (["month", "msrc_cves", "oracle_patches", "dotnet_advisories"], patch_rows)

    # eco_monthly ({ecosystem: {month: n}})
    eco = d.get("eco", {})
    eco_rows = []
    for ecosystem, months in eco.items():
        for month, n in months.items():
            eco_rows.append([ecosystem, month, n])
    tables["eco_monthly"] = (["ecosystem", "month", "n"], eco_rows)

    # repo_monthly ({repo: {months: {month: n}, ...}})
    repos = d.get("repos", {})
    repo_rows = []
    for repo, info in repos.items():
        for month, n in (info.get("months") or {}).items():
            repo_rows.append([repo, month, n])
    tables["repo_monthly"] = (["repo", "month", "n"], repo_rows)

    # euvd_exploited (entries: [date, euvd_id, [cves], vendor, product, score, note])
    euvd_entries = d.get("euvd", {}).get("entries", [])
    euvd_rows = []
    for e in euvd_entries:
        date, euvd_id = e[0], e[1]
        cves = e[2] if len(e) > 2 else []
        vendor = e[3] if len(e) > 3 else None
        product = e[4] if len(e) > 4 else None
        score = e[5] if len(e) > 5 else None
        cve = cves[0] if cves else None
        euvd_rows.append([euvd_id, cve, date, vendor, product, score])
    tables["euvd_exploited"] = (["euvd_id", "cve", "exploited_since", "vendor", "product", "score"], euvd_rows)

    # epss (by_cve: {cve: [score, percentile]}, asof: date string)
    epss = d.get("epss", {})
    asof = epss.get("asof")
    epss_rows = [[cve, v[0], v[1] if len(v) > 1 else None, asof] for cve, v in epss.get("by_cve", {}).items()]
    tables["epss"] = (["cve", "score", "percentile", "asof"], epss_rows)

    # exploit_signals (by_cve: {cve: {msf,edb,poc}})
    exploit = d.get("exploit", {}).get("by_cve", {})
    exploit_rows = [[cve, v.get("msf"), v.get("edb"), v.get("poc")] for cve, v in exploit.items()]
    tables["exploit_signals"] = (["cve", "msf", "edb", "poc"], exploit_rows)

    # ssvc ({cve: {exploitation,automatable,impact}})
    ssvc = d.get("ssvc", {})
    ssvc_rows = [[cve, v.get("exploitation"), v.get("automatable"), v.get("impact")] for cve, v in ssvc.items()]
    tables["ssvc"] = (["cve", "exploitation", "automatable", "impact"], ssvc_rows)

    # p0_itw (entries: [year, cve, vendor, product, type, in_kev]) -- no natural PK
    p0_entries = d.get("p0", {}).get("entries", [])
    p0_rows = []
    for e in p0_entries:
        year = e[0] if len(e) > 0 else None
        cve = e[1] if len(e) > 1 else None
        vendor = e[2] if len(e) > 2 else None
        product = e[3] if len(e) > 3 else None
        typ = e[4] if len(e) > 4 else None
        in_kev = e[5] if len(e) > 5 else None
        p0_rows.append([cve, year, vendor, product, typ, in_kev])
    tables["p0_itw"] = (["cve", "year", "vendor", "product", "type", "in_kev"], p0_rows)

    # advisories ({source: [[date, source, title, url], ...]})
    advisories = d.get("advisories", {})
    adv_rows = []
    for source, items in advisories.items():
        for item in items:
            if len(item) >= 4:
                date, src, title, url = item[0], item[1], item[2], item[3]
            else:
                continue
            adv_rows.append([src, date, title, url])
    tables["advisories"] = (["source", "date", "title", "url"], adv_rows)

    # meta (flatten meta dict, json-encode nested values)
    meta = d.get("meta", {})
    meta_rows = []
    for k, v in meta.items():
        if isinstance(v, (dict, list)):
            v = json.dumps(v, ensure_ascii=False)
        meta_rows.append([k, v])
    meta_rows.append(["last_refresh", meta.get("generated")])
    tables["meta"] = (["key", "value"], meta_rows)

    return tables


def load_manifest():
    if MANIFEST_FILE.exists():
        return json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
    return {}


def save_manifest(manifest):
    MANIFEST_FILE.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def main():
    argv = sys.argv[1:]
    dry_run = "--dry-run" in argv
    max_writes = DEFAULT_MAX_WRITES
    if "--max-writes" in argv:
        i = argv.index("--max-writes")
        max_writes = int(argv[i + 1])

    if not DATA_FILE.exists():
        print(f"ERROR: {DATA_FILE} not found", file=sys.stderr)
        sys.exit(1)

    d = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    tables = load(d)
    manifest = load_manifest()

    if OUT_DIR.exists():
        for f in OUT_DIR.glob("*.sql"):
            try:
                f.unlink()
            except OSError:
                pass  # stale file from a previous run; will be overwritten if reused

    order = [t for t in TABLE_ORDER if t in tables] + [t for t in tables if t not in TABLE_ORDER]

    planned = 0
    deferred = []
    report = []
    # (path, table, upsert_keys[(key,hash)], delete_keys[str])
    file_plans = []

    for table in order:
        columns, rows = tables[table]
        if not rows:
            continue

        pk_cols = TABLE_PK.get(table)
        upserts, deletes, current = diff_table(table, columns, rows, manifest)
        table_total = len(upserts) + len(deletes)

        if table_total == 0:
            report.append((table, 0, 0, 0, False))
            continue

        if planned + table_total > max_writes:
            deferred.append(table)
            report.append((table, len(upserts), len(deletes), 0, True))
            continue

        planned += table_total
        report.append((table, len(upserts), len(deletes), table_total, False))

        upsert_stmts = build_upsert_statements(table, columns, pk_cols, upserts)
        delete_stmts = build_delete_statements(table, pk_cols, deletes)

        idx = 0
        buf, buf_bytes, buf_keys, buf_dels = [], 0, [], []

        def flush_file():
            nonlocal buf, buf_bytes, idx, buf_keys, buf_dels
            if not buf:
                return
            idx += 1
            OUT_DIR.mkdir(parents=True, exist_ok=True)
            path = OUT_DIR / f"{table}_{idx:03d}.sql"
            path.write_text("\n".join(buf) + "\n", encoding="utf-8")
            file_plans.append((path, table, list(buf_keys), list(buf_dels)))
            buf, buf_bytes, buf_keys, buf_dels = [], 0, [], []

        for stmt, keys in upsert_stmts:
            b = len(stmt.encode("utf-8"))
            if buf and buf_bytes + b > MAX_BYTES_PER_FILE:
                flush_file()
            buf.append(stmt)
            buf_bytes += b
            buf_keys.extend(keys)
        for stmt, keys in delete_stmts:
            b = len(stmt.encode("utf-8"))
            if buf and buf_bytes + b > MAX_BYTES_PER_FILE:
                flush_file()
            buf.append(stmt)
            buf_bytes += b
            buf_dels.extend(keys)
        flush_file()

    print("Planned writes per table (rows_written; upsert + delete):")
    for table, up, de, total, is_deferred in report:
        tag = " -- DEFERRED (budget)" if is_deferred else ""
        print(f"  {table:18s} upsert={up:6d} delete={de:6d} planned={total:6d}{tag}")
    print(f"\nTotal planned writes: {planned} (budget {max_writes})")
    if deferred:
        print("Deferred tables (picked up automatically next run):", ", ".join(deferred))

    if dry_run:
        print(f"\nDry run: wrote {len(file_plans)} SQL file(s) to {OUT_DIR}, not applied, manifest untouched.")
        return

    for path, table, keys, dels in file_plans:
        print(f"Applying {path.name} ...")
        result = subprocess.run(
            ["npx", "wrangler@4", "d1", "execute", DB_NAME, "--remote", "--file", str(path)],
            cwd=str(ROOT),
            shell=(os.name == "nt"),
        )
        if result.returncode != 0:
            print(f"ERROR applying {path}", file=sys.stderr)
            save_manifest(manifest)  # keep whatever succeeded so far
            sys.exit(result.returncode)

        # Only now -- confirmed applied -- update the manifest for this file's rows.
        tbl_manifest = manifest.setdefault(table, {})
        for key, h in keys:
            tbl_manifest[key] = h
        for key in dels:
            tbl_manifest.pop(key, None)

    save_manifest(manifest)
    print(f"\nDone: applied {len(file_plans)} file(s) to D1 database '{DB_NAME}'.")


if __name__ == "__main__":
    main()
