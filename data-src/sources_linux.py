#!/usr/bin/env python3
"""Zero Project -- Linux kernel & ecosystem data module (stdlib only).

Self-contained sibling module to refresh.py. Reuses the cvelistV5 bulk zip that
fetch_ai_credit() already downloads/scans weekly (see data-src/research/linux.md) via a
tiny extra-scanner hook registered into refresh.py's EXTRA_SCANNERS list -- this module
never downloads cvelistV5 itself. Everything else (kernel.org releases.json, GitHub
commit-date lookups for bug-age, Red Hat/Ubuntu patch-lag, Android bulletin) is fetched
here directly using the http()/gh() helpers refresh.py passes in via `ctx`.

Public entry points called from refresh.py (see the `# --- linux module` markers there):
    register(extra_scanners)       -- append this module's zip-record hook once, before
                                       fetch_ai_credit() runs so the hook sees every scanned record.
    fetch(ctx) -> dict             -- run() target in main(); does the network-side work.
    build(ctx, lx, ZW) -> dict     -- ZW['linux'] contract (see linux.md's ZW.linux block).
    csv_rows(zw_linux) -> [[...]]  -- extra rows appended to zeroweek-data.csv.

Caches: data-src/cache/linux_index.json, linux_releases.json, linux_commit_dates.json,
linux_distro_lag.json, linux_android.json.
"""
import json, math, pathlib, re, statistics, time, datetime as dt

HERE = pathlib.Path(__file__).resolve().parent
CACHE = HERE / 'cache'; CACHE.mkdir(exist_ok=True)
try:
    MANUAL = json.loads((HERE / 'manual.json').read_text(encoding='utf-8'))
except Exception:
    MANUAL = {}

# ---------------------------------------------------------------- subsystem tagging
_FALLBACK_SUBSYSTEMS = {
    'drm': 'drivers/gpu', 'gpu': 'drivers/gpu', 'fs': 'fs', 'bpf': 'bpf', 'mm': 'mm',
    'sched': 'sched', 'usb': 'usb', 'wifi': 'wifi', 'bluetooth': 'bluetooth', 'media': 'media',
    'sound': 'sound', 'arm': 'arch', 'x86': 'arch', 'crypto': 'crypto', 'kvm': 'kvm',
    'io_uring': 'io_uring', 'net': 'net', 'block': 'block', 'tracing': 'tracing', 'drivers': 'drivers',
}
_SUBSYS_MAP = MANUAL.get('linux_subsystems') or _FALLBACK_SUBSYSTEMS
_SUBSYS_ITEMS = list(_SUBSYS_MAP.items())  # preserves manual.json order -> specific keys checked first

def _subsystem(prefix):
    p = (prefix or '').lower()
    for key, grp in _SUBSYS_ITEMS:
        if key in p:
            return grp
    return 'other'

def _first_line_prefix(desc):
    for line in (desc or '').split('\n')[1:]:
        line = line.strip()
        if not line:
            continue
        m = re.match(r'^([\w/,+.\-]+):\s', line)
        return m.group(1) if m else None
    return None

# ---------------------------------------------------------------- persistent zip-scan index
GIT_SHA_RE = re.compile(r'^[0-9a-f]{40}$', re.I)
_INDEX = {}
_LOADED = False

def _load_json(name, default):
    p = CACHE / name
    if p.exists():
        try:
            return json.loads(p.read_text(encoding='utf-8'))
        except Exception:
            return default
    return default

def _save_json(name, obj):
    try:
        (CACHE / name).write_text(json.dumps(obj, ensure_ascii=False), encoding='utf-8')
    except Exception:
        pass

def _load_index():
    global _LOADED
    if _LOADED:
        return
    _INDEX.update(_load_json('linux_index.json', {}))
    _LOADED = True

def _extract_record(j):
    meta = j.get('cveMetadata') or {}
    cna = (j.get('containers') or {}).get('cna') or {}
    pub = (meta.get('datePublished') or '')[:10]
    state = meta.get('state') or 'PUBLISHED'
    descs = cna.get('descriptions') or []
    desc_text = next((d.get('value') for d in descs if (d.get('lang') or 'en').lower().startswith('en')), '') or ''
    prefix = _first_line_prefix(desc_text)
    intro_sha = None
    fix_shas = []
    fixed_versions = set()
    for aff in (cna.get('affected') or []):
        if (aff.get('vendor') or '').strip().lower() != 'linux':
            continue
        for v in (aff.get('versions') or []):
            vt = v.get('versionType') or ''
            if vt == 'git':
                ver = v.get('version') or ''
                if GIT_SHA_RE.match(ver) and not intro_sha:
                    intro_sha = ver
                lt = v.get('lessThan') or ''
                if GIT_SHA_RE.match(lt) and lt not in fix_shas:
                    fix_shas.append(lt)
            elif vt in ('semver', 'original_commit_for_fix') and (v.get('status') == 'unaffected'):
                ver = v.get('version') or ''
                if re.match(r'^\d+\.\d+', ver):
                    fixed_versions.add(ver)
    score = sev = None
    for met in (cna.get('metrics') or []):
        for key in ('cvssV3_1', 'cvssV4_0', 'cvssV3_0'):
            if key in met:
                score = met[key].get('baseScore'); sev = met[key].get('baseSeverity'); break
        if score is not None:
            break
    if score is None:
        for adp in ((j.get('containers') or {}).get('adp') or []):
            for met in (adp.get('metrics') or []):
                for key in ('cvssV3_1', 'cvssV4_0'):
                    if key in met:
                        score = met[key].get('baseScore'); sev = met[key].get('baseSeverity'); break
                if score is not None:
                    break
            if score is not None:
                break
    credit_text = ' '.join(str(c.get('value') or c.get('description') or '') for c in (cna.get('credits') or []))
    syzbot = bool(re.search(r'syzbot|syzkaller', credit_text, re.I)) or bool(re.search(r'syzbot|syzkaller', desc_text, re.I))
    return {
        'pub': pub, 'state': state, 'rejected': state == 'REJECTED',
        'subsystem': _subsystem(prefix), 'prefix': prefix,
        'intro_sha': intro_sha, 'fix_shas': fix_shas, 'fixed_in': sorted(fixed_versions),
        'cvss_score': score, 'cvss_sev': sev, 'syzbot': syzbot,
    }

def _hook(cid, j):
    """Called for every CVE-2024+ record the shared cvelistV5 zip scan sees (see
    refresh.py's `# --- linux module` marker inside _scan_zip_for_ai_credit)."""
    meta = j.get('cveMetadata') or {}
    if (meta.get('assignerShortName') or '') != 'Linux':
        return
    try:
        _INDEX[cid] = _extract_record(j)
    except Exception:
        pass

def register(extra_scanners):
    """Call once from refresh.py's main(), before fetch_ai_credit() runs."""
    _load_index()
    extra_scanners.append(_hook)

# ---------------------------------------------------------------- fetch (network-side)
def _pctl(vals, q):
    if not vals:
        return None
    v = sorted(vals)
    if len(v) == 1:
        return v[0]
    k = (len(v) - 1) * (q / 100.0); f = math.floor(k); c = math.ceil(k)
    if f == c:
        return v[int(k)]
    return v[f] + (v[c] - v[f]) * (k - f)

def fetch(ctx):
    log = ctx.get('log') or (lambda *a: None)
    _load_index()
    _save_json('linux_index.json', _INDEX)  # persist whatever this run's shared zip scan saw

    if ctx.get('offline'):
        log('[linux] offline -> cache')
        return {
            'index': dict(_INDEX),
            'releases': _load_json('linux_releases.json', {}),
            'commit_dates': _load_json('linux_commit_dates.json', {}),
            'distro_lag': _load_json('linux_distro_lag.json', {}),
            'android': _load_json('linux_android.json', {}),
        }

    http = ctx['http']; gh = ctx.get('gh')

    # 1. kernel.org releases.json -- current mainline/stable/longterm branches + EOL flag
    releases = _load_json('linux_releases.json', {})
    try:
        releases = json.loads(http('https://www.kernel.org/releases.json', timeout=30))
        _save_json('linux_releases.json', releases)
        log(f"[linux] releases.json ok ({len(releases.get('releases') or [])} branches)")
    except Exception as ex:
        log(f'[linux] releases.json FAILED: {ex!r} -> cache')

    # 2. bug age: GitHub commit-date lookups for KEV kernel CVEs + up to 400 most-recent kernel CVEs
    commit_dates = _load_json('linux_commit_dates.json', {})
    kev_entries = ctx.get('kev_entries') or []
    kev_linux_cves = {e[1] for e in kev_entries if 'linux' in f'{e[2]} {e[3]}'.lower()}
    recs_by_pub = sorted(((cid, r) for cid, r in _INDEX.items() if r.get('pub') and not r.get('rejected')),
                          key=lambda x: x[1]['pub'], reverse=True)
    sample_cids = set(kev_linux_cves) | {cid for cid, _ in recs_by_pub[:400]}
    shas_needed = set()
    for cid in sample_cids:
        r = _INDEX.get(cid) or {}
        if r.get('intro_sha'):
            shas_needed.add(r['intro_sha'])
        if r.get('fix_shas'):
            shas_needed.add(r['fix_shas'][0])  # earliest-listed (mainline) fix commit only
    missing_shas = [s for s in shas_needed if s not in commit_dates]
    log(f'[linux] bug-age: {len(missing_shas)} commit dates to fetch of {len(shas_needed)} needed ({len(sample_cids)} sampled CVEs)')
    if gh and missing_shas:
        for i, sha in enumerate(missing_shas):
            try:
                j, _h = gh(f'https://api.github.com/repos/torvalds/linux/commits/{sha}')
                d = ((j.get('commit') or {}).get('author') or {}).get('date') or ''
                commit_dates[sha] = d[:10] or None
            except Exception as ex:
                commit_dates.setdefault(sha, None)
                if i % 50 == 0:
                    log(f'[linux] commit {sha[:12]} FAILED: {ex!r}')
            if (i + 1) % 100 == 0:
                _save_json('linux_commit_dates.json', commit_dates)
                log(f'[linux] commit-date progress {i + 1}/{len(missing_shas)}')
            time.sleep(0.2)
        _save_json('linux_commit_dates.json', commit_dates)
    elif missing_shas:
        log('[linux] no gh() helper / no GITHUB_TOKEN plumbing -> skipping commit-date lookups this run')

    # 3. distro patch lag for KEV-listed kernel CVEs (Red Hat + Ubuntu; Debian skipped -- ~29MB
    #    tracker JSON is too slow for a per-CVE join in a weekly stdlib run, per linux.md 3.2)
    distro_lag = _load_json('linux_distro_lag.json', {})
    for cid in sorted(kev_linux_cves):
        entry = dict(distro_lag.get(cid) or {})
        rec = _INDEX.get(cid) or {}
        if 'redhat' not in entry:
            try:
                rj = json.loads(http(f'https://access.redhat.com/hydra/rest/securitydata/cve/{cid}.json', timeout=20))
                dates = [ar.get('release_date') for ar in (rj.get('affected_release') or []) if ar.get('release_date')]
                entry['redhat'] = min(dates)[:10] if dates else None
            except Exception:
                entry.setdefault('redhat', None)
            time.sleep(0.15)
        if 'ubuntu' not in entry:
            try:
                uj = json.loads(http(f'https://ubuntu.com/security/cves/{cid}.json', timeout=20))
                entry['ubuntu'] = (uj.get('published') or uj.get('public_date') or '')[:10] or None
            except Exception:
                entry.setdefault('ubuntu', None)
            time.sleep(0.15)
        entry.setdefault('debian', None)
        entry['upstream'] = rec.get('pub')
        distro_lag[cid] = entry
    _save_json('linux_distro_lag.json', distro_lag)
    log(f'[linux] distro_lag: {len(distro_lag)} KEV kernel CVEs tracked')

    # 4. Android Security Bulletin -- best effort, current month only, skip gracefully on any failure
    android = _load_json('linux_android.json', {})
    try:
        ym = ctx['TODAY'].strftime('%Y-%m')
        page = http(f'https://source.android.com/docs/security/bulletin/{ym}-01', timeout=20)
        cve_ids = set(re.findall(r'(CVE-\d{4}-\d{4,7})', page))
        exploited = len(re.findall(r'under limited,\s*targeted exploitation', page, re.I))
        critical = len(re.findall(r'(CVE-\d{4}-\d{4,7})[^\n]{0,300}?\bCritical\b', page))
        if cve_ids:
            android[ym] = {'total': len(cve_ids), 'critical': critical, 'exploited': exploited}
            _save_json('linux_android.json', android)
            log(f'[linux] android bulletin {ym}: {len(cve_ids)} CVEs, {exploited} exploited-flagged')
        else:
            log(f'[linux] android bulletin {ym}: no CVE rows parsed, skipping')
    except Exception as ex:
        log(f'[linux] android bulletin FAILED (skip): {ex!r}')

    return {'index': dict(_INDEX), 'releases': releases, 'commit_dates': commit_dates,
            'distro_lag': distro_lag, 'android': android}

# ---------------------------------------------------------------- build (ZW.linux contract)
def build(ctx, lx, ZW):
    lx = lx or {}
    idx = lx.get('index') or {}
    releases = lx.get('releases') or {}
    commit_dates = lx.get('commit_dates') or {}
    distro_lag = lx.get('distro_lag') or {}
    android = lx.get('android') or {}

    monthly_map = {}
    subsystems_seen = set()
    for r in idx.values():
        pub = r.get('pub')
        if not pub:
            continue
        m = pub[:7]
        b = monthly_map.setdefault(m, {'total': 0, 'subsystems': {}, 'rejected': 0})
        if r.get('rejected'):
            b['rejected'] += 1
            continue
        b['total'] += 1
        s = r.get('subsystem') or 'other'
        subsystems_seen.add(s)
        b['subsystems'][s] = b['subsystems'].get(s, 0) + 1
    monthly = [{'month': m, 'total': v['total'], 'subsystems': v['subsystems'], 'rejected': v['rejected']}
               for m, v in sorted(monthly_map.items())]

    release_dates = {}
    for rel in (releases.get('releases') or []):
        mm = re.match(r'^(\d+\.\d+)', rel.get('version') or '')
        if mm and mm.group(1) not in release_dates:
            release_dates[mm.group(1)] = (rel.get('released') or {}).get('isodate')
    by_release = {}
    for r in idx.values():
        if r.get('rejected'):
            continue
        seen = set()
        for ver in (r.get('fixed_in') or []):
            mm = re.match(r'^(\d+\.\d+)', ver)
            if not mm or mm.group(1) in seen:
                continue
            seen.add(mm.group(1))
            e = by_release.setdefault(mm.group(1), {'n': 0, 'date': release_dates.get(mm.group(1))})
            e['n'] += 1

    by_year_ages = {}
    n_sample = 0
    for r in idx.values():
        if r.get('rejected'):
            continue
        intro_d = commit_dates.get(r.get('intro_sha')) if r.get('intro_sha') else None
        fix_d = None
        for s in (r.get('fix_shas') or []):
            d = commit_dates.get(s)
            if d:
                fix_d = d
                break
        fix_d = fix_d or r.get('pub')
        if not (intro_d and fix_d):
            continue
        try:
            age = (dt.date.fromisoformat(fix_d) - dt.date.fromisoformat(intro_d)).days
        except Exception:
            continue
        if age < 0:
            continue
        by_year_ages.setdefault(fix_d[:4], []).append(age)
        n_sample += 1
    bug_age_by_year = {}
    for y, ages in sorted(by_year_ages.items()):
        bug_age_by_year[y] = {
            'median': round(statistics.median(ages), 1), 'p25': round(_pctl(ages, 25), 1),
            'p75': round(_pctl(ages, 75), 1), 'n': len(ages),
            'share_gt5y': round(sum(1 for a in ages if a > 1825) / len(ages), 3),
            'share_gt10y': round(sum(1 for a in ages if a > 3650) / len(ages), 3),
        }

    branches = [{'version': rel.get('version'), 'type': rel.get('moniker'),
                 'date': (rel.get('released') or {}).get('isodate'), 'eol': None,
                 'iseol': bool(rel.get('iseol'))} for rel in (releases.get('releases') or [])]

    epss_by_cve = (ZW.get('epss') or {}).get('by_cve') or {}
    exploit_by_cve = (ZW.get('exploit') or {}).get('by_cve') or {}
    kev_rows = []
    for e in (ZW.get('kev') or {}).get('entries') or []:
        d, cve, ven, prod = e[0], e[1], e[2], e[3]
        if 'linux' not in f'{ven} {prod}'.lower() and 'android' not in f'{ven} {prod}'.lower():
            continue
        name = e[6] if len(e) > 6 else ''
        epss = epss_by_cve.get(cve)
        exp = exploit_by_cve.get(cve) or {}
        flags = [k for k in ('msf', 'edb', 'poc') if exp.get(k)]
        kev_rows.append([d, cve, prod, name, (epss[0] if epss else None), flags])

    distro_rows = []
    for cve, e in sorted(distro_lag.items()):
        up = e.get('upstream')
        valid = [d for d in (e.get('redhat'), e.get('ubuntu'), e.get('debian')) if d]
        lag_min = None
        if up and valid:
            try:
                lag_min = min((dt.date.fromisoformat(d) - dt.date.fromisoformat(up)).days for d in valid)
            except Exception:
                lag_min = None
        distro_rows.append([cve, up, e.get('redhat'), e.get('ubuntu'), e.get('debian'), lag_min])

    year_totals, syzbot_by_year = {}, {}
    for r in idx.values():
        if r.get('rejected') or not r.get('pub'):
            continue
        y = r['pub'][:4]
        year_totals[y] = year_totals.get(y, 0) + 1
        if r.get('syzbot'):
            syzbot_by_year[y] = syzbot_by_year.get(y, 0) + 1
    syzbot_share = {y: round(syzbot_by_year.get(y, 0) / n, 3) for y, n in year_totals.items() if n}

    ai_index = (ZW.get('ai_found') or {}).get('index') or {}
    ai_credited = []
    for cve, rec in ai_index.items():
        if (rec.get('cna') or '') != 'Linux':
            continue
        r = idx.get(cve) or {}
        ai_credited.append([cve, rec.get('pub') or r.get('pub'), r.get('subsystem') or 'other', rec.get('matched') or []])
    ai_credited.sort(key=lambda x: x[1] or '')

    android_monthly = [{'month': m, 'total': v.get('total'), 'critical': v.get('critical'), 'exploited': v.get('exploited')}
                        for m, v in sorted(android.items())]

    return {
        'asof': ctx['TODAY'].isoformat(),
        'monthly': monthly,
        'subsystems': sorted(subsystems_seen),
        'by_release': by_release,
        'bug_age': {'by_year': bug_age_by_year, 'sample_n': n_sample},
        'branches': branches,
        'kev': kev_rows,
        'distro_lag': distro_rows,
        'syzbot_share': {'by_year': syzbot_share},
        'ai_credited': ai_credited,
        'android': {'monthly': android_monthly},
    }

def csv_rows(zwl):
    rows = []
    zwl = zwl or {}
    for m in zwl.get('monthly') or []:
        rows.append(['linux_monthly', m['month'], 'total', '', 'Linux kernel CNA', '', m['total'], f"rejected={m['rejected']}"])
        for sub, n in (m.get('subsystems') or {}).items():
            rows.append(['linux_subsystem_monthly', m['month'], sub, '', 'Linux kernel CNA', '', n, ''])
    for y, s in (zwl.get('bug_age') or {}).get('by_year', {}).items():
        for k, v in s.items():
            rows.append(['linux_bug_age', y, k, '', 'Linux kernel CNA', '', v, ''])
    for cve, up, rh, ub, db, lag in zwl.get('distro_lag') or []:
        rows.append(['linux_distro_lag', up or '', 'lag_days_min', cve, 'Linux kernel CNA', '', lag, f'redhat={rh} ubuntu={ub} debian={db}'])
    return rows
