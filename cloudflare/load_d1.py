#!/usr/bin/env python3
"""
Zero Project — D1 loader.

Reads ../zeroweek-data.json, converts every dataset into batched
"INSERT OR REPLACE" SQL files (<=500 rows / statement, ~1MB / file) under
cloudflare/out/*.sql, then runs each file sequentially with:

    wrangler d1 execute zero-project --remote --file <file>

Idempotent: safe to re-run; every row is (re)written by primary key.

Usage:
    python cloudflare/load_d1.py            # generate + apply
    python cloudflare/load_d1.py --dry-run  # generate only, do not apply
"""
from __future__ import annotations
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DATA_FILE = ROOT / "zeroweek-data.json"
OUT_DIR = HERE / "out"
DB_NAME = "zero-project"
MAX_ROWS_PER_STMT = 500
MAX_BYTES_PER_FILE = 1_000_000


def sql_quote(v):
    if v is None:
        return "NULL"
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, (int, float)):
        return repr(v)
    s = str(v)
    return "'" + s.replace("'", "''") + "'"


def rows_to_statements(table, columns, rows):
    """Yield full INSERT OR REPLACE statements, batched by row/byte limits."""
    stmts = []
    batch = []
    batch_bytes = 0
    col_list = ", ".join(columns)

    def flush():
        nonlocal batch, batch_bytes
        if not batch:
            return
        stmt = f"INSERT OR REPLACE INTO {table} ({col_list}) VALUES\n" + ",\n".join(batch) + ";"
        stmts.append(stmt)
        batch = []
        batch_bytes = 0

    for row in rows:
        vals = "(" + ", ".join(sql_quote(v) for v in row) + ")"
        if len(batch) >= MAX_ROWS_PER_STMT:
            flush()
        batch.append(vals)
        batch_bytes += len(vals)
    flush()
    return stmts


def write_out_files(all_statements, prefix):
    """Split a list of SQL statements into files under MAX_BYTES_PER_FILE."""
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    files = []
    buf = []
    buf_bytes = 0
    idx = 0

    def flush():
        nonlocal buf, buf_bytes, idx
        if not buf:
            return
        idx += 1
        path = OUT_DIR / f"{prefix}_{idx:03d}.sql"
        path.write_text("\n".join(buf) + "\n", encoding="utf-8")
        files.append(path)
        buf = []
        buf_bytes = 0

    for stmt in all_statements:
        b = len(stmt.encode("utf-8"))
        if buf and buf_bytes + b > MAX_BYTES_PER_FILE:
            flush()
        buf.append(stmt)
        buf_bytes += b
    flush()
    return files


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

    # p0_itw (entries: [year, cve, vendor, product, type, in_kev]) -- no natural PK, full reload
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


def main():
    dry_run = "--dry-run" in sys.argv

    if not DATA_FILE.exists():
        print(f"ERROR: {DATA_FILE} not found", file=sys.stderr)
        sys.exit(1)

    d = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    tables = load(d)

    # clear stale out/ files from a previous run
    if OUT_DIR.exists():
        for f in OUT_DIR.glob("*.sql"):
            f.unlink()

    all_files = []
    # p0_itw has no natural primary key -- wipe + reload each run for idempotency
    wipe_and_reload = {"p0_itw"}

    for table, (columns, rows) in tables.items():
        if not rows:
            continue
        stmts = []
        if table in wipe_and_reload:
            stmts.append(f"DELETE FROM {table};")
        stmts.extend(rows_to_statements(table, columns, rows))
        files = write_out_files(stmts, table)
        all_files.extend(files)
        print(f"{table}: {len(rows)} rows -> {len(files)} file(s)")

    if dry_run:
        print(f"\nDry run: wrote {len(all_files)} SQL file(s) to {OUT_DIR}, not applied.")
        return

    for f in all_files:
        print(f"Applying {f.name} ...")
        result = subprocess.run(
            ["npx", "wrangler@4", "d1", "execute", DB_NAME, "--remote", "--file", str(f)],
            cwd=str(ROOT),
            shell=(os.name == "nt"),
        )
        if result.returncode != 0:
            print(f"ERROR applying {f}", file=sys.stderr)
            sys.exit(result.returncode)

    print(f"\nDone: applied {len(all_files)} file(s) to D1 database '{DB_NAME}'.")


if __name__ == "__main__":
    main()
