#!/usr/bin/env python3
"""Microsoft / .NET data module for the Zero Project pipeline (stdlib only).

Self-contained: refresh.py imports this module and calls fetch(ctx) then build(ctx, ms, ZW),
passing a small context dict of helpers/globals so this file never imports refresh.py back
(refresh.py imports us, so the reverse import would be circular).

ctx keys used here: http, cache_get, cache_put, cached, log, gh, MANUAL, START, TODAY,
months_between, weeks_between, monday, statistics, dt, json, re, time, urllib_parse.
"""
import datetime as dt
import json
import re
import statistics
import time
import urllib.parse

SUG_BASE = 'https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability'
# NB: the SUG API's WAF returns HTTP 999 (empty body) whenever a request carries a $select
# param at all -- confirmed live: $filter alone works, $select alone or combined with $filter
# both 999. So every page is fetched full-row (with description/articles/etc.) and only the
# flat fields below are kept when caching, to bound cache size.
MON = {m: i for i, m in enumerate(
    ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'], 1)}

FAMILIES = ['Windows', 'Windows Server', 'Office', '.NET/ASP.NET Core/Visual Studio', 'Azure/cloud',
            'SQL Server', 'Exchange', 'SharePoint', 'Edge/Chromium', 'Dynamics/Copilot/AI', 'other']

COMPONENT_PATTERNS = {
    'blazor': re.compile(r'\bblazor\b', re.I),
    'signalr': re.compile(r'\bsignalr\b', re.I),
    'aspnetcore': re.compile(r'\basp\.net core\b', re.I),
    'efcore': re.compile(r'\bentity framework\b|\bef ?core\b', re.I),
    'kestrel': re.compile(r'\bkestrel\b', re.I),
    'maui': re.compile(r'\.net maui\b|\bmaui\b', re.I),
    'wpf': re.compile(r'\bwpf\b', re.I),
    'winforms': re.compile(r'\bwinforms\b|\bwindows forms\b', re.I),
}


def month_key(release, date_fallback):
    """Normalize a SUG releaseNumber (e.g. '2026-Sep', or an out-of-band '2017-May-B') to
    'YYYY-MM', folding any OOB suffix into the same base month. Falls back to releaseDate."""
    if release:
        m = re.match(r'(\d{4})-([A-Za-z]{3})', release)
        if m:
            mon = MON.get(m.group(2).title())
            if mon:
                return f'{m.group(1)}-{mon:02d}'
    return (date_fallback or '')[:7]


def classify_family(tag, title=''):
    t = (tag or '').lower()
    ti = (title or '').lower()
    hay = t + ' ' + ti
    if 'sharepoint' in hay: return 'SharePoint'
    if 'exchange' in hay: return 'Exchange'
    if 'sql' in hay: return 'SQL Server'
    if 'edge' in hay or 'chromium' in hay: return 'Edge/Chromium'
    if 'dynamics' in hay or 'copilot' in hay or 'power platform' in hay: return 'Dynamics/Copilot/AI'
    if 'azure' in hay or 'cloud' in hay: return 'Azure/cloud'
    if '.net' in hay or 'visual studio' in hay or 'asp.net' in hay: return '.NET/ASP.NET Core/Visual Studio'
    if 'office' in hay: return 'Office'
    if 'windows server' in hay: return 'Windows Server'
    if 'windows' in hay: return 'Windows'
    return 'other'


# ---------------------------------------------------------------- MSRC SUG API v2.0
def _fetch_sug(ctx):
    log = ctx['log']; http = ctx['http']; cache_get = ctx['cache_get']; START = ctx['START']; TODAY = ctx['TODAY']
    prev = cache_get('microsoft_sug') or {}
    out = dict(prev)
    since = START if not prev else max(START, TODAY - dt.timedelta(days=90))
    filt = f"releaseDate ge {since.isoformat()}T00:00:00Z"
    url = SUG_BASE + '?' + urllib.parse.urlencode({'$filter': filt, '$top': 250})
    pages = 0
    while url:
        try:
            j = json.loads(http(url, timeout=60))
        except Exception as ex:
            log(f'[microsoft_sug] page {pages} FAILED: {ex!r}, stopping pagination'); break
        for row in j.get('value', []) or []:
            cve = row.get('cveNumber')
            if not cve: continue
            score = row.get('baseScore')
            try: score = float(score) if score not in (None, '') else None
            except Exception: score = None
            # cveTitle rarely names Blazor/SignalR/Kestrel/EF Core/MAUI directly (MSRC titles
            # are generic, e.g. "ASP.NET Core..."); the component name usually only appears in
            # the free-text description, so a stripped/truncated copy is kept for that regex.
            desc = re.sub(r'<[^>]+>', ' ', row.get('description') or '')
            desc = re.sub(r'\s+', ' ', desc).strip()[:400]
            out[cve] = {
                'title': row.get('cveTitle') or '',
                'desc': desc,
                'date': (row.get('releaseDate') or '')[:10],
                'release': row.get('releaseNumber') or '',
                'tag': row.get('tag') or '',
                'severity': row.get('severity') or '',
                'impact': row.get('impact') or '',
                'exploited': row.get('exploited') or '',
                'disclosed': row.get('publiclyDisclosed') or '',
                'likelihood': row.get('latestSoftwareRelease') or '',
                'cvss': score,
                'vector': row.get('vectorString') or '',
                'cwe': row.get('cweList') or [],
            }
        pages += 1
        url = j.get('@odata.nextLink')
        if url: time.sleep(0.25)
    log(f'[microsoft_sug] {pages} pages, {len(out)} CVEs cached (since {since.isoformat()})')
    return out


def fetch_sug(ctx):
    return ctx['cached']('microsoft_sug')(_fetch_sug)(ctx)


# ---------------------------------------------------------------- .NET releases + EOL
def _fetch_dotnet_core(ctx):
    log = ctx['log']; http = ctx['http']
    channels = []
    try:
        idx = json.loads(http('https://raw.githubusercontent.com/dotnet/core/main/release-notes/releases-index.json', timeout=60))
    except Exception as ex:
        log(f'[microsoft_dotnet] releases-index FAILED: {ex!r}'); idx = {'releases-index': []}
    for row in idx.get('releases-index', []) or []:
        ch = {
            'channel': row.get('channel-version'),
            'latest': row.get('latest-release'),
            'latest_date': row.get('latest-release-date'),
            'security': bool(row.get('security')),
            'support': row.get('support-phase'),
            'release_type': row.get('release-type'),
            'eol': row.get('eol-date'),
            'security_releases': [],
        }
        rj_url = row.get('releases.json')
        if rj_url:
            try:
                rj = json.loads(http(rj_url, timeout=90))
                for rel in rj.get('releases', []) or []:
                    if not rel.get('security'): continue
                    cves = [c.get('cve-id') for c in (rel.get('cve-list') or []) if c.get('cve-id')]
                    ch['security_releases'].append([rel.get('release-date'), rel.get('release-version'), cves])
            except Exception as ex:
                log(f"[microsoft_dotnet] {ch['channel']} releases.json FAILED: {ex!r}")
            time.sleep(0.15)
        channels.append(ch)
    eol = {}
    for key, url in (
        ('dotnet', 'https://endoflife.date/api/dotnet.json'),
        ('windows', 'https://endoflife.date/api/windows.json'),
        ('windows_server', 'https://endoflife.date/api/windows-server.json'),
    ):
        try:
            eol[key] = json.loads(http(url, timeout=30))
        except Exception as ex:
            log(f'[microsoft_dotnet] eol {key} FAILED: {ex!r}'); eol[key] = []
        time.sleep(0.15)
    return {'channels': channels, 'eol': eol}


def fetch_dotnet_core(ctx):
    return ctx['cached']('microsoft_dotnet')(_fetch_dotnet_core)(ctx)


# ---------------------------------------------------------------- extra dotnet repo advisories
# (dotnet/efcore, dotnet/sdk, dotnet/maui, dotnet/wpf, dotnet/winforms -- NOT added to
# manual.json's existing "repos" array per the module boundary; fetched independently here
# with the same cursor-pagination pattern as refresh.fetch_gh_repos.)
def _fetch_dotnet_repo_advisories(ctx):
    log = ctx['log']; gh = ctx['gh']; MANUAL = ctx['MANUAL']; START = ctx['START']
    repos = MANUAL.get('dotnet_repos', [])
    out = {}
    for rp in repos:
        months = {}
        next_url = f'https://api.github.com/repos/{rp}/security-advisories'
        params = {'state': 'published', 'per_page': 100, 'sort': 'published', 'direction': 'desc'}
        pages = 0; stop = False
        while True:
            try:
                j, hdr = gh(next_url, params); params = None
            except Exception as ex:
                log(f'[microsoft_dotnet_repos] {rp} FAILED: {ex!r}'); break
            pages += 1
            if not j: break
            for a in j:
                d = (a.get('published_at') or '')[:10]
                if d < START.isoformat(): stop = True; break
                months[d[:7]] = months.get(d[:7], 0) + 1
            if stop or len(j) < 100 or pages >= 20: break
            m = re.search(r'<([^>]+)>;\s*rel="next"', hdr.get('Link', ''))
            if not m: break
            next_url = m.group(1); time.sleep(0.3)
        out[rp] = months
    return out


def fetch_dotnet_repo_advisories(ctx):
    return ctx['cached']('microsoft_dotnet_repos')(_fetch_dotnet_repo_advisories)(ctx)


# ---------------------------------------------------------------- orchestration
def fetch(ctx):
    """Entry point called from refresh.main(): ms = run('microsoft', lambda: fetch(ctx))."""
    sug = fetch_sug(ctx)
    dotnet = fetch_dotnet_core(ctx)
    dotnet_repos = fetch_dotnet_repo_advisories(ctx)
    return {'sug': sug, 'dotnet': dotnet, 'dotnet_repos': dotnet_repos}


def _components_from_titles(titles):
    """titles: iterable of (date, cve_or_id, title, cvss, severity, search_text) rows --
    search_text is title+description, since Blazor/SignalR/Kestrel/EF Core/MAUI names usually
    only appear in the description (see _fetch_sug). Returns {component: [[date, cve, title,
    cvss, severity], ...]} plus a residual 'runtime' bucket for unmatched .NET-tagged rows."""
    comp = {k: [] for k in COMPONENT_PATTERNS}
    comp['runtime'] = []
    for row in titles:
        date, cve, title, cvss, sev, hay = row
        matched = False
        for name, pat in COMPONENT_PATTERNS.items():
            if pat.search(hay or ''):
                comp[name].append([date, cve, title, cvss, sev]); matched = True
        if not matched:
            comp['runtime'].append([date, cve, title, cvss, sev])
    return comp


def build(ctx, ms, ZW):
    """ms: return value of fetch(ctx) (or None on total failure -- reconstructed from the
    sub-fetchers' own caches). ZW: the in-progress ZW dict from refresh.build(), already
    populated with 'kev' and 'ai_found' by the time this is called."""
    cache_get = ctx['cache_get']; TODAY = ctx['TODAY']
    if not ms:
        ms = {'sug': cache_get('microsoft_sug') or {}, 'dotnet': cache_get('microsoft_dotnet') or {'channels': [], 'eol': {}},
              'dotnet_repos': cache_get('microsoft_dotnet_repos') or {}}
    sug = ms.get('sug') or {}
    dotnet_raw = ms.get('dotnet') or {'channels': [], 'eol': {}}
    dotnet_repos = ms.get('dotnet_repos') or {}

    kev_cve_set = {e[1] for e in (ZW.get('kev') or {}).get('entries', [])}
    kev_by_cve = {e[1]: e for e in (ZW.get('kev') or {}).get('entries', [])}
    ai_index = (ZW.get('ai_found') or {}).get('index') or {}

    monthly = {}
    likelihood_by_year = {}
    bug_age_ages = {}
    zero_days = []
    ai_credited = []
    azure_cloud_cves = []
    copilot_ai = []
    dotnet_family_titles = []  # for component classification

    for cve, row in sug.items():
        m = re.fullmatch(r'CVE-(\d{4})-(\d+)', cve)
        cve_year = int(m.group(1)) if m else None
        title = row.get('title') or ''
        tag = row.get('tag') or ''
        family = classify_family(tag, title)
        date = row.get('date') or ''
        mkey = month_key(row.get('release'), date)
        if not mkey: continue
        bucket = monthly.setdefault(mkey, {'total': 0, 'families': {}, 'severity': {}, 'impact': {},
                                            'exploited': 0, 'disclosed': 0, 'more_likely': 0})
        bucket['total'] += 1
        bucket['families'][family] = bucket['families'].get(family, 0) + 1
        sev = row.get('severity') or 'Unknown'; bucket['severity'][sev] = bucket['severity'].get(sev, 0) + 1
        imp = row.get('impact') or 'Unknown'; bucket['impact'][imp] = bucket['impact'].get(imp, 0) + 1
        if row.get('exploited') == 'Yes': bucket['exploited'] += 1
        if row.get('disclosed') == 'Yes': bucket['disclosed'] += 1
        likely = row.get('likelihood') or ''
        release_year = date[:4]
        if 'more likely' in likely.lower():
            bucket['more_likely'] += 1
            y = likely and release_year
            if y:
                ly = likelihood_by_year.setdefault(y, {'more_likely': 0, 'became_kev': 0})
                ly['more_likely'] += 1
                if cve in kev_cve_set: ly['became_kev'] += 1
        if row.get('exploited') == 'Yes':
            zero_days.append([date, cve, family, title, row.get('cvss')])
        if cve_year and release_year.isdigit():
            age = int(release_year) - cve_year
            bug_age_ages.setdefault(release_year, []).append(age)
        if cve in ai_index:
            rec = ai_index[cve]
            cna = (rec.get('cna') or '').lower()
            if 'microsoft' in cna or rec.get('matched'):
                ai_credited.append([cve, date, family, rec.get('matched') or []])
        if family == 'Azure/cloud':
            azure_cloud_cves.append([date, cve, tag, title])
        if family == 'Dynamics/Copilot/AI':
            copilot_ai.append([date, cve, tag, title])
        if '.net' in tag.lower() or 'asp.net' in tag.lower() or 'visual studio' in tag.lower():
            hay = (title + ' ' + (row.get('desc') or '')).strip()
            dotnet_family_titles.append((date, cve, title, row.get('cvss'), sev, hay))

    monthly_list = [{'month': k, 'total': v['total'], 'families': v['families'], 'severity': v['severity'],
                      'impact': v['impact'], 'exploited': v['exploited'], 'disclosed': v['disclosed'],
                      'more_likely': v['more_likely']} for k, v in sorted(monthly.items())]

    for y, d in likelihood_by_year.items():
        d['rate'] = round(d['became_kev'] / d['more_likely'], 4) if d['more_likely'] else None

    pt_to_kev = {}
    pt_lags = {}
    for cve, row in sug.items():
        if cve not in kev_by_cve or not row.get('date'): continue
        e = kev_by_cve[cve]
        try:
            release_d = dt.date.fromisoformat(row['date']); added_d = dt.date.fromisoformat(e[0])
        except Exception:
            continue
        lag = (added_d - release_d).days
        if lag < 0: continue
        pt_lags.setdefault(e[0][:4], []).append(lag)
    for y, lags in pt_lags.items():
        pt_to_kev[y] = {'median_days': round(statistics.median(lags), 1), 'n': len(lags)}

    bug_age = {y: {'median': round(statistics.median(v), 2), 'mean': round(sum(v) / len(v), 2), 'n': len(v)}
               for y, v in bug_age_ages.items()}

    records = sorted(((m['month'], m['total']) for m in monthly_list), key=lambda r: -r[1])[:12]

    components = _components_from_titles(dotnet_family_titles)

    channels_out = []
    for ch in dotnet_raw.get('channels', []):
        channels_out.append({
            'channel': ch.get('channel'), 'eol': ch.get('eol'), 'support': ch.get('support'),
            'latest': ch.get('latest'), 'latest_date': ch.get('latest_date'),
            'release_type': ch.get('release_type'), 'security': ch.get('security'),
            'security_releases': ch.get('security_releases') or [],
        })

    dotnet_out = {
        'channels': channels_out,
        'components': {k: v for k, v in components.items()},
        'eol': dotnet_raw.get('eol') or {},
        'extra_repo_advisories': dotnet_repos,
    }

    families_used = sorted({f for m in monthly_list for f in m['families']}) or list(FAMILIES)

    return {
        'asof': TODAY.isoformat(),
        'monthly': monthly_list,
        'families': families_used,
        'likelihood_hit_rate': {'by_year': dict(sorted(likelihood_by_year.items()))},
        'zero_days': sorted(zero_days),
        'pt_to_kev': {'by_year': dict(sorted(pt_to_kev.items()))},
        'bug_age': {'by_year': dict(sorted(bug_age.items()))},
        'records': records,
        'ai_credited': ai_credited,
        'dotnet': dotnet_out,
        'azure_cloud_cves': azure_cloud_cves,
        'copilot_ai': copilot_ai,
        'source_count': len(sug),
    }


# ---------------------------------------------------------------- CSV rows
def csv_rows(built):
    """[dataset, period, series, id, vendor_or_project, product_or_class, value, note] rows
    for microsoft_monthly, microsoft_family_monthly, dotnet_security_release, dotnet_component_cve."""
    if not built: return []
    rows = []
    for m in built.get('monthly', []):
        rows.append(['microsoft_monthly', m['month'], 'total', '', 'Microsoft', '', m['total'],
                     f"exploited={m['exploited']} disclosed={m['disclosed']} more_likely={m['more_likely']}"])
        for fam, n in m['families'].items():
            rows.append(['microsoft_family_monthly', m['month'], 'count', '', 'Microsoft', fam, n, ''])
    for ch in (built.get('dotnet') or {}).get('channels', []):
        for date, version, cves in ch.get('security_releases', []):
            rows.append(['dotnet_security_release', date, 'security_release', version, '.NET', ch.get('channel'),
                         len(cves), 'cves=' + ','.join(cves)])
    for comp, entries in ((built.get('dotnet') or {}).get('components') or {}).items():
        for date, cve, title, cvss, sev in entries:
            rows.append(['dotnet_component_cve', date, comp, cve, '.NET', comp, cvss if cvss is not None else '',
                         f'{sev}: {title}'])
    return rows
