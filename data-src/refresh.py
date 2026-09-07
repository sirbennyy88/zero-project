#!/usr/bin/env python3
"""Zeroweek weekly refresh pipeline (stdlib only, Python 3.10+).

Pulls every primary feed, rebuilds zeroweek-data.js / .json / .csv and feed.xml in the site root.

    python data-src/refresh.py            # full refresh (uses cache for slow/rate-limited sources)
    python data-src/refresh.py --offline  # rebuild outputs from cache only, no network
    GITHUB_TOKEN=ghp_... python data-src/refresh.py   # enables per-ecosystem monthly counts (many requests)

Every fetcher is independent: if one source is down, the previous cached result is used and the run still succeeds.
"""
import argparse, csv, datetime as dt, gzip, io, json, math, os, pathlib, re, statistics, sys, time, urllib.request, urllib.parse, urllib.error, html as htmlmod, zipfile
import xml.etree.ElementTree as ET

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
CACHE = HERE / 'cache'; CACHE.mkdir(exist_ok=True)
MANUAL = json.loads((HERE / 'manual.json').read_text(encoding='utf-8'))
TODAY = dt.date.today()
START = dt.date(2016, 1, 1)                  # 10-year scope (default; overridable via --since)
UA = {'User-Agent': 'zeroweek-refresh/1.0 (+https://zero.propulse.tech)', 'Accept-Encoding': 'gzip'}
TOKEN = os.environ.get('GITHUB_TOKEN', '')
NVD_KEY = os.environ.get('NVD_API_KEY', '')
NVD_SLEEP = 0.7 if NVD_KEY else 6.5
ARGS = None
LOG = []
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass
BROWSER_UA = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0 Safari/537.36', 'Accept': 'text/html,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.9'}

def log(*a):
    s = ' '.join(str(x) for x in a); LOG.append(s); print(s, flush=True)

def http(url, headers=None, timeout=120, raw=False):
    h = dict(UA); h.update(headers or {})
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
        if r.headers.get('Content-Encoding') == 'gzip': data = gzip.decompress(data)
        return (data, r.headers) if raw else data.decode('utf-8', 'replace')

def cache_get(name):
    p = CACHE / f'{name}.json'
    return json.loads(p.read_text(encoding='utf-8')) if p.exists() else None

def cache_put(name, obj):
    (CACHE / f'{name}.json').write_text(json.dumps(obj, ensure_ascii=False), encoding='utf-8')

def cached(name):
    """Decorator: run fetcher unless --offline; on any failure fall back to cache."""
    def deco(fn):
        def wrap(*a, **k):
            if ARGS.offline:
                c = cache_get(name); log(f'[{name}] offline -> cache'); return c
            try:
                out = fn(*a, **k); cache_put(name, out); log(f'[{name}] ok'); return out
            except Exception as e:
                log(f'[{name}] FAILED ({e!r}) -> cache'); return cache_get(name)
        return wrap
    return deco

def monday(d):
    d = d if isinstance(d, dt.date) else dt.date.fromisoformat(str(d)[:10])
    return d - dt.timedelta(days=d.weekday())

def weeks_between(a, b):
    w = monday(a); out = []
    while w <= b: out.append(w.isoformat()); w += dt.timedelta(days=7)
    return out

def months_between(a, b):
    y, m = a.year, a.month; out = []
    while (y, m) <= (b.year, b.month):
        out.append(f'{y:04d}-{m:02d}'); m += 1
        if m == 13: y, m = y + 1, 1
    return out

def date_windows(a, b, days=120):
    """List of (start, end) date tuples covering [a, b] in `days`-day windows."""
    out = []; d = a
    while d <= b:
        we = min(d + dt.timedelta(days=days - 1), b)
        out.append((d, we)); d = we + dt.timedelta(days=1)
    return out

def pctl(vals, q):
    """Linear-interpolation percentile (q in 0..100) over a list of numbers."""
    if not vals: return None
    v = sorted(vals)
    if len(v) == 1: return v[0]
    k = (len(v) - 1) * (q / 100.0); f = math.floor(k); c = math.ceil(k)
    if f == c: return v[int(k)]
    return v[f] + (v[c] - v[f]) * (k - f)

def categorize(vendor, product, kev_categories):
    hay = f'{vendor} {product}'.lower()
    for key, cat in kev_categories.items():
        if key in hay: return cat
    return 'other'

# ---------------------------------------------------------------- 1. CISA KEV
@cached('kev')
def fetch_kev():
    j = json.loads(http('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'))
    ents = []
    for v in j['vulnerabilities']:
        if v['dateAdded'] < START.isoformat(): continue
        ents.append([v['dateAdded'], v['cveID'], v['vendorProject'].strip(), v['product'].strip(),
                     'K' if v.get('knownRansomwareCampaignUse') == 'Known' else 'U', v.get('dueDate', ''),
                     (v.get('vulnerabilityName') or '')[:110]])
    ents.sort(key=lambda r: (r[0], r[1]))
    return {'released': j.get('dateReleased'), 'count': j.get('count'), 'entries': ents}

def kev_weekly(entries):
    """entries: enriched KEV rows [date,cve,vendor,product,K/U,due,name,published,category,score,severity]."""
    first = max(START, dt.date(2021, 11, 1))
    weeks = weeks_between(first, TODAY); idx = {w: i for i, w in enumerate(weeks)}
    buckets = [{'total': 0, 'fresh': 0, 'older': 0, 'ransom': 0, 'tte': [], 'edge': 0} for _ in weeks]
    for d, cve, ven, prod, k, due, name, pub, cat, score, sev, *_ in entries:
        w = monday(d).isoformat()
        if w not in idx: continue
        b = buckets[idx[w]]; b['total'] += 1
        if int(cve.split('-')[1]) >= int(d[:4]): b['fresh'] += 1
        else: b['older'] += 1
        if k == 'K': b['ransom'] += 1
        if cat == 'edge_appliance': b['edge'] += 1
        if pub:
            try:
                delta = (dt.date.fromisoformat(d) - dt.date.fromisoformat(pub)).days
                if delta >= 0: b['tte'].append(delta)
            except Exception: pass
    rows = []
    for w, b in zip(weeks, buckets):
        median_tte = round(statistics.median(b['tte']), 1) if b['tte'] else None
        rows.append([w, b['total'], b['fresh'], b['older'], b['ransom'], median_tte, b['edge']])
    return rows

def compute_tte(entries):
    by_year, by_month = {}, {}
    for d, cve, ven, prod, k, due, name, pub, cat, score, sev, *_ in entries:
        if not pub: continue
        try:
            delta = (dt.date.fromisoformat(d) - dt.date.fromisoformat(pub)).days
        except Exception:
            continue
        if delta < 0: continue
        by_year.setdefault(d[:4], []).append(delta); by_month.setdefault(d[:7], []).append(delta)
    def stats(vals):
        return {'median': round(statistics.median(vals), 1), 'p25': round(pctl(vals, 25), 1), 'p75': round(pctl(vals, 75), 1), 'n': len(vals)}
    return {'by_year': {y: stats(v) for y, v in sorted(by_year.items())},
            'by_month': {m: stats(v) for m, v in sorted(by_month.items())}}

def kev_by_category(entries):
    out = {}
    for d, cve, ven, prod, k, due, name, pub, cat, score, sev, *_ in entries:
        y = d[:4]; out.setdefault(y, {}); out[y][cat] = out[y].get(cat, 0) + 1
    return out

# ---------------------------------------------------------------- 2. Anthropic ledger
@cached('ledger')
def fetch_ledger():
    L = json.loads(http('https://red.anthropic.com/2026/cvd/data/ledger.json'))
    sev_of = lambda e: e.get('vendor_severity') or e.get('maintainer_severity') or e.get('claude_severity') or 'unassessed'
    disc, com, pat = {}, {}, {}
    old_patched_this_year = 0; revealed = []
    for e in L:
        if e.get('withdrawn'): continue
        c = e.get('committed_at')
        if c: com[monday(c).isoformat()] = com.get(monday(c).isoformat(), 0) + 1
        p = e.get('patched_at')
        if p: pat[monday(p).isoformat()] = pat.get(monday(p).isoformat(), 0) + 1
        d = e.get('discovered_on')
        if d:
            w = monday(d).isoformat(); s = sev_of(e)
            disc.setdefault(w, {}); disc[w][s] = disc[w].get(s, 0) + 1
            if d[:4] < str(TODAY.year) and p and p[:4] == str(TODAY.year): old_patched_this_year += 1
        if e.get('revealed') and (e.get('cve_ids') or e.get('ghsa_ids')):
            ids = (e.get('corrected_cve_ids') or e.get('cve_ids') or []) + (e.get('corrected_ghsa_ids') or e.get('ghsa_ids') or [])
            revealed.append({'ids': ids, 'project': e.get('project'), 'bug_class': e.get('bug_class'), 'severity': sev_of(e), 'discovered_on': d, 'patched_at': p, 'status': e.get('status')})
    weeks = sorted(set(disc) | set(com) | set(pat))
    rows = []
    for w in weeks:
        s = disc.get(w, {})
        rows.append([w, s.get('critical', 0), s.get('high', 0), s.get('medium', 0), s.get('low', 0), s.get('unassessed', 0), com.get(w, 0), pat.get(w, 0)])
    proj, cls = {}, {}
    for e in L:
        if e.get('withdrawn'): continue
        proj[e.get('project') or 'sealed'] = proj.get(e.get('project') or 'sealed', 0) + 1
        cls[e.get('bug_class') or 'sealed'] = cls.get(e.get('bug_class') or 'sealed', 0) + 1
    totals = dict(MANUAL['ledger_totals_fallback']); totals['entries'] = len(L)
    try:
        pl = json.loads(http('https://red.anthropic.com/2026/cvd/data/payload.json'))
        for k in ('disclosed', 'patched', 'candidates', 'reviewed', 'confirmed', 'reported', 'acknowledged', 'projects', 'cves', 'ghsas', 'identifiers'):
            for kk, vv in (pl.items() if isinstance(pl, dict) else []):
                if k in kk.lower() and isinstance(vv, (int, float)): totals[kk] = vv
        totals['as_of'] = str(pl.get('generated_at') or pl.get('snapshot') or totals.get('as_of'))[:10]
    except Exception as ex:
        log('[ledger] payload.json not parsed:', ex)
    return {'weekly': rows, 'totals': totals, 'top_projects': dict(sorted(proj.items(), key=lambda x: -x[1])[:25]),
            'bug_classes': dict(sorted(cls.items(), key=lambda x: -x[1])[:25]), 'revealed': revealed,
            'old_found_patched_this_year': old_patched_this_year, 'entries': len(L)}

# ---------------------------------------------------------------- 3. Epoch AI explorer (cve.org by CNA)
@cached('epoch')
def fetch_epoch():
    t = http('https://epoch.ai/generated/cve-explorer-viz.js', timeout=300)
    def grab(marker):
        i = t.index(marker); s = t.index('[', i); depth = 0
        for j in range(s, len(t)):
            if t[j] == '[': depth += 1
            elif t[j] == ']':
                depth -= 1
                if depth == 0: return json.loads(t[s:j + 1])
    W = grab('var cve_weekly_by_cna_'); M = grab('var cve_monthly_by_cna_')
    series = {}; weeks = set()
    for r in W:
        if r['week'] < START.isoformat() or r['severity'] not in ('HIGH', 'CRITICAL'): continue
        c = 'Other CNAs' if r['cna'] == 'Other' else r['cna']
        series.setdefault(c, {}); series[c][r['week']] = series[c].get(r['week'], 0) + int(r['count']); weeks.add(r['week'])
    monthly = {}
    for r in M:
        if r['month'] < START.isoformat()[:7] or r['cna'] == 'Other': continue
        m = monthly.setdefault(r['month'], {'critical': 0, 'high': 0})
        if r['severity'] == 'CRITICAL': m['critical'] += int(r['count'])
        elif r['severity'] == 'HIGH': m['high'] += int(r['count'])
    return {'weeks': sorted(weeks), 'series': series, 'monthly_notable': [[k, v['critical'], v['high']] for k, v in sorted(monthly.items())]}

# ---------------------------------------------------------------- 4. MSRC Patch Tuesday
MON = {m: i for i, m in enumerate(['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'], 1)}
@cached('msrc')
def fetch_msrc():
    prev = cache_get('msrc') or {}
    ups = json.loads(http('https://api.msrc.microsoft.com/cvrf/v3.0/updates', headers={'Accept': 'application/json'}))['value']
    out = dict(prev)
    for u in ups:
        m = re.fullmatch(r'(\d{4})-([A-Za-z]{3})', u['ID'])
        if not m or int(m.group(1)) < START.year: continue
        key = f'{m.group(1)}-{MON[m.group(2).title()]:02d}'
        fresh = key >= (TODAY.replace(day=1) - dt.timedelta(days=62)).isoformat()[:7]
        if key in out and not fresh: continue
        doc = json.loads(http(u['CvrfUrl'], headers={'Accept': 'application/json'}, timeout=300))
        n = 0
        for v in doc.get('Vulnerability', []):
            cve = v.get('CVE', ''); title = (v.get('Title') or {}).get('Value', '') if isinstance(v.get('Title'), dict) else str(v.get('Title') or '')
            if not cve.startswith('CVE-'): continue
            if title.lower().startswith('chromium'): continue
            n += 1
        out[key] = n; time.sleep(0.3)
    return out

# ---------------------------------------------------------------- 5. Oracle CPU
def _oracle_links(url):
    """cpu<mon><year>[optional 'v<n>' revision suffix].html links from an Oracle index page."""
    idx = http(url, headers=BROWSER_UA)
    return sorted(set(re.findall(r'/security-alerts/(cpu[a-z]{3}20\d\d(?:v\d+)?\.html)', idx)))

@cached('oracle')
def fetch_oracle():
    prev = cache_get('oracle') or {}
    links = _oracle_links('https://www.oracle.com/security-alerts/')
    if START.year < 2021:
        # the current index only lists CPUs since 2021; earlier ones (back to 2010) are on the archive page
        try:
            links += _oracle_links('https://www.oracle.com/security-alerts/cpuarchive.html')
        except Exception as ex:
            log(f'[oracle] cpuarchive.html FAILED: {ex!r}')
    links = sorted(set(links))
    out = dict(prev)
    for l in links:
        mm = re.match(r'cpu([a-z]{3})(20\d\d)', l); key = f'{mm.group(2)}-{MON[mm.group(1).title()]:02d}'
        if int(mm.group(2)) < START.year or key in out: continue
        page = http('https://www.oracle.com/security-alerts/' + l, headers=BROWSER_UA, timeout=120)
        m = re.search(r'contains\s+([\d,]+)\s+new\s+security\s+patches', page, re.I)
        m2 = re.search(r'([\d,]+)\s+(?:unique\s+)?CVEs', page)
        out[key] = {'patches': int(m.group(1).replace(',', '')) if m else None, 'cves': int(m2.group(1).replace(',', '')) if m2 else None}
        time.sleep(0.5)
    return out

# ---------------------------------------------------------------- 6. GitHub
def gh(url, params=None):
    h = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
    if TOKEN: h['Authorization'] = 'Bearer ' + TOKEN
    if params: url += ('&' if '?' in url else '?') + urllib.parse.urlencode(params)
    for attempt in range(4):
        try:
            data, hdr = http(url, headers=h, raw=True); return json.loads(data.decode('utf-8')), hdr
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                reset = int(e.headers.get('X-RateLimit-Reset', time.time() + 60)); wait = max(5, min(120, reset - time.time()))
                log(f'[github] rate limited, sleeping {wait:.0f}s'); time.sleep(wait); continue
            raise
    raise RuntimeError('github: too many retries')

@cached('gh_eco')
def fetch_gh_eco():
    prev = cache_get('gh_eco') or {}
    if not TOKEN and not ARGS.force_eco:
        if prev: log('[gh_eco] no GITHUB_TOKEN -> keeping cache'); return prev
        raise RuntimeError('GITHUB_TOKEN required for first ecosystem pull')
    out = {e: dict(prev.get(e, {})) for e in MANUAL['ecosystems']}
    months = months_between(START, TODAY); recent = months[-3:]
    for eco in MANUAL['ecosystems']:
        for m in months:
            if m in out[eco] and m not in recent: continue
            y, mo = map(int, m.split('-')); last = (dt.date(y + (mo == 12), (mo % 12) + 1, 1) - dt.timedelta(days=1)).day
            j, hdr = gh('https://api.github.com/advisories', {'ecosystem': eco, 'published': f'{m}-01..{m}-{last:02d}', 'per_page': 100, 'page': 1})
            n = len(j)
            link = hdr.get('Link', '')
            lm = re.search(r'[?&]page=(\d+)>; rel="last"', link)
            if lm:
                lastp = int(lm.group(1)); jl, _ = gh('https://api.github.com/advisories', {'ecosystem': eco, 'published': f'{m}-01..{m}-{last:02d}', 'per_page': 100, 'page': lastp})
                n = (lastp - 1) * 100 + len(jl)
            out[eco][m] = n; time.sleep(0.25)
    return out

@cached('gh_repos')
def fetch_gh_repos():
    # NB: /repos/{owner}/{repo}/security-advisories is cursor-paginated (before/after);
    # it has no "page" param, so a manual page=N loop just re-fetches page 1 forever.
    # Follow the Link: rel="next" header instead.
    out = {}
    for rp in MANUAL['repos']:
        months, sev_year = {}, {}; stop = False; capped = False; total_since_start = 0
        next_url = f'https://api.github.com/repos/{rp}/security-advisories'
        params = {'state': 'published', 'per_page': 100, 'sort': 'published', 'direction': 'desc'}
        pages = 0
        while True:
            j, hdr = gh(next_url, params); params = None
            pages += 1
            if not j: break
            for a in j:
                d = (a.get('published_at') or '')[:10]
                if d < START.isoformat(): stop = True; break
                months[d[:7]] = months.get(d[:7], 0) + 1; total_since_start += 1
                sy = sev_year.setdefault(d[:4], {}); sy[a.get('severity') or 'unknown'] = sy.get(a.get('severity') or 'unknown', 0) + 1
            if stop or len(j) < 100: break
            m = re.search(r'<([^>]+)>;\s*rel="next"', hdr.get('Link', ''))
            if not m: break
            if pages >= 60: capped = True; break
            next_url = m.group(1); time.sleep(0.3)
        out[rp] = {'months': months, 'severity_by_year': sev_year, 'total_since_start': total_since_start}
        if capped: out[rp]['capped'] = True
    return out

@cached('dotnet')
def fetch_dotnet():
    items = []
    for y in range(START.year, TODAY.year + 1):
        page = 1
        while page <= 10:
            q = f'repo:dotnet/announcements is:issue "Security Advisory" in:title created:{y}-01-01..{y}-12-31'
            j, _ = gh('https://api.github.com/search/issues', {'q': q, 'per_page': 100, 'page': page, 'sort': 'created', 'order': 'asc'})
            for it in j.get('items', []):
                t = re.sub(r'^Microsoft Security Advisory\s*', '', it['title']); t = re.sub(r'\s*[|–-]\s*', '|', t, count=1)
                items.append([it['created_at'][:10], t.split('|')[0].strip(), '|'.join(t.split('|')[1:]).strip()])
            if len(j.get('items', [])) < 100: break
            page += 1; time.sleep(2)
        time.sleep(2)
    items.sort()
    monthly = {}
    for d, *_ in items: monthly[d[:7]] = monthly.get(d[:7], 0) + 1
    return {'items': items, 'monthly': monthly}

# ---------------------------------------------------------------- 7. CVE publish dates + CVSS (cvelistV5)
@cached('cve_pub')
def fetch_cve_published(kev):
    prev = cache_get('cve_pub') or {}
    out = dict(prev)
    cves = sorted({e[1] for e in (kev or {}).get('entries', [])})
    missing = [c for c in cves if c not in out]
    log(f'[cve_pub] {len(missing)} missing of {len(cves)} KEV CVEs')
    for i, cve in enumerate(missing):
        m = re.fullmatch(r'CVE-(\d{4})-(\d+)', cve)
        if not m:
            out[cve] = {'pub': None, 'score': None, 'sev': None}; continue
        year, num = m.group(1), m.group(2)
        bucket = f'{int(num) // 1000}xxx'
        url = f'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}/{cve}.json'
        try:
            j = json.loads(http(url, timeout=30))
            pub = ((j.get('cveMetadata') or {}).get('datePublished') or '')[:10] or None
            score = sev = None
            for met in (((j.get('containers') or {}).get('cna') or {}).get('metrics') or []):
                for key in ('cvssV3_1', 'cvssV4_0'):
                    if key in met:
                        score = met[key].get('baseScore'); sev = met[key].get('baseSeverity'); break
                if score is not None: break
            out[cve] = {'pub': pub, 'score': score, 'sev': sev}
        except Exception as ex:
            out[cve] = out.get(cve) or {'pub': None, 'score': None, 'sev': None}
            if i % 200 == 0: log(f'[cve_pub] ({i+1}/{len(missing)}) {cve}: {ex!r}')
        if (i + 1) % 250 == 0: log(f'[cve_pub] progress {i+1}/{len(missing)}')
        time.sleep(0.15)
    return out

# ---------------------------------------------------------------- 8. NVD watchlist (product CVE history)
def nvd_query(url, headers):
    for attempt in range(4):
        try:
            return json.loads(http(url, headers=headers, timeout=60))
        except urllib.error.HTTPError as e:
            if e.code in (403, 429, 503):
                wait = (2 ** attempt) * 5
                log(f'[nvd_watchlist] HTTP {e.code}, backoff {wait}s (attempt {attempt + 1}/4)'); time.sleep(wait); continue
            raise
    raise RuntimeError('nvd_watchlist: too many retries')

@cached('nvd_watchlist')
def fetch_nvd_watchlist():
    prev = cache_get('nvd_watchlist') or {}
    products = MANUAL.get('watchlist', [])
    if ARGS.watchlist_limit: products = products[:ARGS.watchlist_limit]
    out = dict(prev)
    cutoff = TODAY - dt.timedelta(days=130)
    headers = {'apiKey': NVD_KEY} if NVD_KEY else {}
    windows = date_windows(START, TODAY, 120)
    for i, prod in enumerate(products):
        pid = prod['id']
        if not prod.get('cpes'):
            log(f'[nvd_watchlist] ({i+1}/{len(products)}) {pid}: no CPEs, skip'); continue
        prod_cache = dict(prev.get(pid, {}))
        try:
            for cpe in prod['cpes']:
                for ws, we in windows:
                    wkey = f'{cpe}|{ws.isoformat()}_{we.isoformat()}'
                    if wkey in prod_cache and we <= cutoff: continue
                    pstart = ws.strftime('%Y-%m-%dT00:00:00.000'); pend = we.strftime('%Y-%m-%dT23:59:59.999')
                    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?' + urllib.parse.urlencode(
                        {'virtualMatchString': cpe, 'pubStartDate': pstart, 'pubEndDate': pend, 'resultsPerPage': 2000})
                    j = nvd_query(url, headers)
                    recs = []
                    for v in j.get('vulnerabilities', []):
                        c = v.get('cve', {})
                        pub = (c.get('published') or '')[:10]; cid = c.get('id')
                        score = sev = None
                        metrics = c.get('metrics', {}) or {}
                        for key in ('cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30', 'cvssMetricV2'):
                            if metrics.get(key):
                                cd = metrics[key][0].get('cvssData', {}) or {}
                                score = cd.get('baseScore')
                                sev = cd.get('baseSeverity') or metrics[key][0].get('baseSeverity')
                                break
                        desc = ''
                        for d_ in c.get('descriptions', []):
                            if d_.get('lang') == 'en': desc = d_.get('value', ''); break
                        recs.append([pub, cid, score, (sev or 'UNKNOWN').upper(), desc[:120]])
                    prod_cache[wkey] = recs
                    time.sleep(NVD_SLEEP)
            out[pid] = prod_cache
            log(f'[nvd_watchlist] ({i+1}/{len(products)}) {pid}: ok, {sum(len(v) for v in prod_cache.values())} cached records')
        except Exception as ex:
            log(f'[nvd_watchlist] ({i+1}/{len(products)}) {pid}: FAILED ({ex!r}), keeping cache')
            out[pid] = prev.get(pid, prod_cache)
    return out

# ---------------------------------------------------------------- 9. Extra product feeds (Kubernetes, Node.js, Grafana)
@cached('extra_feeds')
def fetch_extra_feeds():
    out = {}
    try:
        j = json.loads(http('https://kubernetes.io/docs/reference/issues-security/official-cve-feed/index.json', timeout=30))
        items = j if isinstance(j, list) else (j.get('items') or j.get('cves') or [])
        rows = []
        for it in items:
            date = it.get('date_published') or it.get('date_added') or it.get('datePublished') or it.get('published') or ''
            cid = it.get('id') or it.get('cve_id') or ''
            title = (it.get('summary') or it.get('title') or '')[:200]
            link = it.get('url') or it.get('link') or ''
            if cid: rows.append([str(date)[:10], cid, title, '', link])
        rows.sort(key=lambda r: r[0], reverse=True)
        out['kubernetes'] = rows[:100]
    except Exception as ex:
        log('[extra_feeds] kubernetes FAILED:', repr(ex))
    time.sleep(0.3)
    try:
        xml_text = http('https://nodejs.org/en/feed/vulnerability.xml', timeout=30)
        root = ET.fromstring(xml_text)
        rows = []
        for item in root.iter('item'):
            title = (item.findtext('title') or '')[:200]; link = item.findtext('link') or ''
            pub = item.findtext('pubDate') or ''
            try: d_ = dt.datetime.strptime(pub[:25].strip(), '%a, %d %b %Y %H:%M:%S').date().isoformat()
            except Exception: d_ = pub[:10]
            guid = item.findtext('guid') or link
            rows.append([d_, guid, title, '', link])
        rows.sort(key=lambda r: r[0], reverse=True)
        out['nodejs'] = rows[:100]
    except Exception as ex:
        log('[extra_feeds] nodejs FAILED:', repr(ex))
    time.sleep(0.3)
    try:
        page = http('https://grafana.com/security/security-advisories/', headers=BROWSER_UA, timeout=30)
        rows = []
        for m in re.finditer(r'<a[^>]+href="(/security/security-advisories/[^"]+)"[^>]*>([^<]{5,150})</a>', page):
            rows.append(['', '', htmlmod.unescape(m.group(2)).strip(), '', 'https://grafana.com' + m.group(1)])
        if rows: out['grafana'] = rows[:100]
        else: log('[extra_feeds] grafana: no machine-readable advisories found, skipping')
    except Exception as ex:
        log('[extra_feeds] grafana FAILED (skip):', repr(ex))
    return out

def build_watchlist(nvd_watchlist, extra_feeds, kev_entries):
    products = MANUAL.get('watchlist', [])
    nvd_watchlist = nvd_watchlist or {}; extra_feeds = extra_feeds or {}
    kev_by_cve = {e[1]: e for e in kev_entries}
    monthly, latest, kev_hits, feed_items = {}, {}, {}, {}
    for prod in products:
        pid = prod['id']; name_words = [w for w in re.split(r'[\s/]+', prod['name'].lower()) if len(w) > 3]
        recs = {}
        for rows in (nvd_watchlist.get(pid) or {}).values():
            for r in rows:
                pub, cid, score, sev, desc = r
                if not cid: continue
                if cid not in recs or (pub and pub > (recs[cid][0] or '')): recs[cid] = r
        recs_list = sorted(recs.values(), key=lambda r: r[0] or '', reverse=True)
        m = {}
        for pub, cid, score, sev, desc in recs_list:
            if not pub: continue
            b = m.setdefault(pub[:7], {'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0})
            b['total'] += 1
            sevl = (sev or '').upper()
            if sevl in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'): b[sevl.lower()] += 1
        if m: monthly[pid] = m
        if recs_list: latest[pid] = recs_list[:12]
        hits = set()
        for cve, e in kev_by_cve.items():
            ven_prod = f'{e[2]} {e[3]}'.lower()
            if any(w in ven_prod for w in name_words): hits.add(cve)
        for cid in recs:
            if cid in kev_by_cve: hits.add(cid)
        if hits: kev_hits[pid] = sorted(hits)
        fi = extra_feeds.get(pid)
        if fi: feed_items[pid] = fi
    return {'products': products, 'monthly': monthly, 'kev_hits': kev_hits, 'latest': latest, 'feed_items': feed_items}

# ---------------------------------------------------------------- 10. ENISA EUVD
def _euvd_date(raw):
    if not raw: return ''
    raw = str(raw)
    if re.match(r'^\d{4}-\d{2}-\d{2}', raw): return raw[:10]
    for fmt in ('%b %d, %Y, %I:%M:%S %p', '%b %d, %Y'):
        try: return dt.datetime.strptime(raw.strip(), fmt).date().isoformat()
        except Exception: continue
    m = re.search(r'[A-Za-z]{3}\s+\d{1,2},\s*\d{4}', raw)
    if m:
        try: return dt.datetime.strptime(m.group(0), '%b %d, %Y').date().isoformat()
        except Exception: pass
    return raw[:10]

def _euvd_entry(v):
    aliases = v.get('aliases') or ''
    if isinstance(aliases, str): alias_list = re.split(r'[\s,;]+', aliases)
    elif isinstance(aliases, list): alias_list = aliases
    else: alias_list = []
    cves = sorted({a for a in alias_list if re.fullmatch(r'CVE-\d{4}-\d{4,7}', str(a))})
    vendor = ''
    ev = v.get('enisaIdVendor') or v.get('vendors') or []
    if isinstance(ev, list) and ev:
        first = ev[0]
        vendor = first.get('vendor', {}).get('name', '') if isinstance(first, dict) and isinstance(first.get('vendor'), dict) else (first.get('name', '') if isinstance(first, dict) else str(first))
    vendor = vendor or v.get('vendor', '') or ''
    product = v.get('product', '') or ''
    date = _euvd_date(v.get('exploitedSince') or v.get('datePublished') or v.get('dateUpdated') or '')
    return [date, v.get('id', ''), cves, vendor.strip(), product.strip(), v.get('baseScore'), (v.get('description') or '')[:120]]

@cached('euvd')
def fetch_euvd():
    exp = json.loads(http('https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities', timeout=60))
    exp = exp if isinstance(exp, list) else (exp.get('items') or exp.get('result') or [])
    entries = [_euvd_entry(v) for v in exp]
    entries = [e for e in entries if e[0]]
    entries.sort(key=lambda r: (r[0], r[1]))
    return {'entries': entries}

def build_euvd(euvd, kev_entries):
    entries = (euvd or {}).get('entries') or []
    weeks = weeks_between(dt.date.fromisoformat(min((e[0] for e in entries), default=TODAY.isoformat())), TODAY) if entries else []
    counts = {}
    for e in entries:
        try: w = monday(e[0]).isoformat()
        except Exception: continue
        counts[w] = counts.get(w, 0) + 1
    weekly = [[w, counts.get(w, 0)] for w in weeks]
    kev_cves = {e[1] for e in kev_entries}
    euvd_cves = set()
    for e in entries: euvd_cves.update(e[2])
    only_in_euvd = sorted(euvd_cves - kev_cves)
    only_in_kev = sorted(kev_cves - euvd_cves)
    return {'weekly': weekly, 'entries': entries, 'only_in_euvd': only_in_euvd, 'only_in_kev': only_in_kev}

# ---------------------------------------------------------------- 11. FIRST EPSS
@cached('epss')
def fetch_epss(cves):
    prev = cache_get('epss') or {}
    by_cve = dict(prev.get('by_cve') or {})
    cves = sorted(set(cves))
    for i in range(0, len(cves), 100):
        batch = cves[i:i + 100]
        try:
            j = json.loads(http('https://api.first.org/data/v1/epss?cve=' + ','.join(batch), timeout=30))
            for d in j.get('data', []):
                by_cve[d['cve']] = [float(d['epss']), float(d['percentile'])]
        except Exception as ex:
            log(f'[epss] batch {i // 100} FAILED: {ex!r}')
        time.sleep(0.2)
    asof = TODAY.isoformat()
    dist = dict(prev.get('dist') or {'ge50': None, 'ge90': None, 'total': None})
    for back in range(0, 4):
        d = TODAY - dt.timedelta(days=back)
        try:
            raw = http(f'https://epss.cyentia.com/epss_scores-{d.isoformat()}.csv.gz', timeout=60, raw=True)[0]
            text = gzip.decompress(raw).decode('utf-8', 'replace')
            rows = list(csv.reader(io.StringIO(text)))
            rows = [r for r in rows if r and not r[0].startswith('#') and r[0] != 'cve']
            scores = [float(r[1]) for r in rows if len(r) > 1]
            dist = {'ge50': sum(1 for s in scores if s >= 0.5), 'ge90': sum(1 for s in scores if s >= 0.9), 'total': len(scores)}
            asof = d.isoformat()
            break
        except Exception as ex:
            log(f'[epss] daily CSV {d.isoformat()} FAILED: {ex!r}')
    return {'by_cve': by_cve, 'asof': asof, 'dist': dist}

# ---------------------------------------------------------------- 12. Google Project Zero 0day In the Wild
P0_COLS = ['cve', 'vendor', 'product', 'type', 'description', 'date discovered', 'date patched', 'advisory', 'analysis url', 'root cause analysis', 'reported by']
@cached('p0')
def fetch_p0():
    sid = '1lkNJ0uQwbeC1ZTRrxdtuPLCIl7mlUreoKfSIgajnSyY'
    html_ = http(f'https://docs.google.com/spreadsheets/d/{sid}/htmlview', timeout=30)
    gids = sorted(set(re.findall(r'gid[=:]"?(\d+)', html_)))
    entries = []
    for g in gids:
        try:
            text = http(f'https://docs.google.com/spreadsheets/d/{sid}/gviz/tq?tqx=out:csv&gid={g}', timeout=30)
            rows = list(csv.reader(io.StringIO(text)))
            if not rows: continue
            header = [h.strip().lower() for h in rows[0]]
            if 'cve' not in header: continue
            idx = {c: header.index(c) for c in P0_COLS if c in header}
            for r in rows[1:]:
                if not r or len(r) <= idx.get('cve', 0): continue
                cve = r[idx['cve']].strip()
                if not re.fullmatch(r'CVE-\d{4}-\d{4,7}', cve): continue
                get = lambda k: (r[idx[k]].strip() if k in idx and idx[k] < len(r) else '')
                entries.append([get('date discovered')[:10], cve, get('vendor'), get('product'), get('type'), get('date patched')[:10]])
        except Exception as ex:
            log(f'[p0] gid {g} FAILED: {ex!r}')
        time.sleep(0.2)
    seen = {}
    for e in entries: seen[e[1]] = e
    entries = sorted(seen.values(), key=lambda r: (r[0] or '', r[1]))
    yearly = {}
    for d, cve, *_ in entries:
        y = d[:4] if re.fullmatch(r'\d{4}', d[:4] or '') else cve.split('-')[1]
        yearly[y] = yearly.get(y, 0) + 1
    return {'entries': entries, 'yearly': dict(sorted(yearly.items()))}

def build_p0(p0, kev_cves):
    entries = (p0 or {}).get('entries') or []
    out = [[d, cve, ven, prod, typ, cve in kev_cves] for d, cve, ven, prod, typ, patched in entries]
    return {'yearly': (p0 or {}).get('yearly') or {}, 'entries': out}

# ---------------------------------------------------------------- 13. Exploit availability
@cached('exploit')
def fetch_exploit(cves):
    msf_by_cve = {}
    try:
        j = json.loads(http('https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json', timeout=180))
        for mod in j.values():
            for ref in (mod.get('references') or []):
                cve = None
                if isinstance(ref, list) and len(ref) == 2 and str(ref[0]).upper() == 'CVE':
                    cve = 'CVE-' + str(ref[1])
                elif isinstance(ref, str) and re.fullmatch(r'CVE-\d{4}-\d{4,7}', ref):
                    cve = ref
                if cve:
                    prev_m = msf_by_cve.get(cve)
                    if not prev_m or (mod.get('disclosure_date') or '') > (prev_m.get('disclosure_date') or ''):
                        msf_by_cve[cve] = {'name': mod.get('name'), 'disclosure_date': mod.get('disclosure_date'), 'rank': mod.get('rank')}
        log(f'[exploit] metasploit: {len(msf_by_cve)} CVEs mapped')
    except Exception as ex:
        log(f'[exploit] metasploit FAILED: {ex!r}')
        prev = cache_get('exploit') or {}
        msf_by_cve = prev.get('msf_by_cve') or {}
    edb_cves = set(); edb_yearly = {}
    try:
        text = http('https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv', timeout=120)
        for row in csv.reader(io.StringIO(text)):
            if len(row) > 11:
                edb_cves.update(re.findall(r'CVE-\d{4}-\d{4,7}', row[11]))
                pub = (row[3] if len(row) > 3 else '')[:4]
                if re.fullmatch(r'20\d\d', pub): edb_yearly[pub] = edb_yearly.get(pub, 0) + 1
        log(f'[exploit] exploit-db: {len(edb_cves)} CVEs mapped, {sum(edb_yearly.values())} dated entries')
    except Exception as ex:
        log(f'[exploit] exploit-db FAILED: {ex!r}')
        prev = cache_get('exploit') or {}
        edb_cves = set(prev.get('edb_cves') or [])
        edb_yearly = dict(prev.get('edb_yearly') or {})
    prev = cache_get('exploit') or {}
    poc_counts = dict(prev.get('poc_counts') or {})
    cves = sorted(set(cves))
    missing = [c for c in cves if c not in poc_counts]
    log(f'[poc-in-github] {len(missing)} missing of {len(cves)} tracked CVEs')
    for i, cve in enumerate(missing):
        m = re.fullmatch(r'CVE-(\d{4})-(\d+)', cve)
        if not m: poc_counts[cve] = 0; continue
        url = f'https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{m.group(1)}/{cve}.json'
        try:
            j = json.loads(http(url, timeout=20))
            poc_counts[cve] = len(j) if isinstance(j, list) else 0
        except urllib.error.HTTPError as e:
            poc_counts[cve] = 0 if e.code == 404 else poc_counts.get(cve, 0)
        except Exception as ex:
            if i % 200 == 0: log(f'[poc-in-github] ({i + 1}/{len(missing)}) {cve}: {ex!r}')
        if (i + 1) % 250 == 0: log(f'[poc-in-github] progress {i + 1}/{len(missing)}')
        time.sleep(0.12)
    return {'msf_by_cve': msf_by_cve, 'edb_cves': sorted(edb_cves), 'poc_counts': poc_counts, 'edb_yearly': edb_yearly}

def build_exploit(exploit, kev_entries):
    exploit = exploit or {}
    msf = exploit.get('msf_by_cve') or {}
    edb = set(exploit.get('edb_cves') or [])
    poc = exploit.get('poc_counts') or {}
    msf_yearly = {}
    for info in msf.values():
        y = (info.get('disclosure_date') or '')[:4]
        if re.fullmatch(r'20\d\d', y): msf_yearly[y] = msf_yearly.get(y, 0) + 1
    edb_yearly = exploit.get('edb_yearly') or {}
    years = sorted(set(edb_yearly) | set(msf_yearly))
    yearly_published = [[y, msf_yearly.get(y, 0), edb_yearly.get(y, 0)] for y in years if y >= str(START.year)]
    by_cve = {}
    for cve in {e[1] for e in kev_entries} | set(poc) | set(msf) | edb:
        by_cve[cve] = {'msf': cve in msf, 'edb': cve in edb, 'poc': poc.get(cve, 0)}
    weeks = weeks_between(START, TODAY); idx = {w: i for i, w in enumerate(weeks)}
    tot = [0] * len(weeks); has = [0] * len(weeks)
    for e in kev_entries:
        w = monday(e[0]).isoformat()
        if w not in idx: continue
        i = idx[w]; tot[i] += 1
        info = by_cve.get(e[1]) or {}
        if info.get('msf') or info.get('edb') or info.get('poc'): has[i] += 1
    weekly_share = [[w, round(has[i] / tot[i], 3) if tot[i] else None] for i, w in enumerate(weeks)]
    return {'by_cve': by_cve, 'weekly_share': weekly_share, 'yearly_published': yearly_published}

# ---------------------------------------------------------------- 14. CVE.org (cveawg) SSVC enrichment
@cached('ssvc')
def fetch_ssvc(cves):
    prev = cache_get('ssvc') or {}
    out = dict(prev)
    cves = sorted(set(cves))
    missing = [c for c in cves if c not in out]
    log(f'[ssvc] {len(missing)} missing of {len(cves)} KEV CVEs')
    for i, cve in enumerate(missing):
        try:
            j = json.loads(http(f'https://cveawg.mitre.org/api/cve/{cve}', timeout=20))
            rec = {'exploitation': None, 'automatable': None, 'impact': None}
            for adp in (j.get('containers', {}).get('adp') or []):
                for met in (adp.get('metrics') or []):
                    other = met.get('other') or {}
                    if other.get('type') != 'ssvc': continue
                    content = other.get('content') or {}
                    opts = content.get('options') if isinstance(content, dict) else None
                    combined = {}
                    if isinstance(opts, list):
                        for o in opts:
                            if isinstance(o, dict): combined.update(o)
                    elif isinstance(content, dict):
                        combined = content
                    if combined.get('Exploitation'): rec['exploitation'] = combined.get('Exploitation')
                    if combined.get('Automatable'): rec['automatable'] = combined.get('Automatable')
                    if combined.get('Technical Impact'): rec['impact'] = combined.get('Technical Impact')
            out[cve] = rec
        except urllib.error.HTTPError as e:
            out[cve] = out.get(cve) or {'exploitation': None, 'automatable': None, 'impact': None}
        except Exception as ex:
            out[cve] = out.get(cve) or {'exploitation': None, 'automatable': None, 'impact': None}
            if i % 200 == 0: log(f'[ssvc] ({i + 1}/{len(missing)}) {cve}: {ex!r}')
        if (i + 1) % 250 == 0: log(f'[ssvc] progress {i + 1}/{len(missing)}')
        time.sleep(0.2)
    return out

# ---------------------------------------------------------------- 15. Advisory RSS feeds
ADVISORY_FEEDS = [
    # (id, name, org, url, is_pure_security_feed) -- ids match data-src/research/sources.md SOURCES_REGISTRY
    ('zdi-rss', 'ZDI published advisories', 'Trend Micro Zero Day Initiative', 'https://www.zerodayinitiative.com/rss/published/', True),
    ('ncsc-nl', 'NCSC-NL advisories', 'NCSC-NL', 'https://advisories.ncsc.nl/rss/advisories', True),
    ('jvn-rss', 'JVN/JPCERT', 'JPCERT/CC + IPA', 'https://jvn.jp/rss/jvn.rdf', True),
    ('cert-fr', 'CERT-FR (ANSSI)', 'ANSSI', 'https://cert.ssi.gouv.fr/feed/', True),
    ('cyber-gc-ca', 'Canadian Centre for Cyber Security alerts', 'Canadian Centre for Cyber Security', 'https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts&lang=en', True),
    ('cisa-alerts', 'CISA alerts', 'CISA', 'https://www.cisa.gov/cybersecurity-advisories/rss.xml', True),
    ('talos-blog', 'Cisco Talos vulnerability reports', 'Cisco Talos', 'https://blog.talosintelligence.com/rss/', False),
    ('msrc-blog', 'Microsoft MSRC blog', 'Microsoft MSRC', 'https://msrc.microsoft.com/blog/rss.xml', False),
    ('gtig-blog', 'Google Threat Intelligence blog', 'Google Threat Intelligence Group', 'https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v', False),
    ('rapid7-blog', 'Rapid7 blog', 'Rapid7', 'https://blog.rapid7.com/rss/', False),
    ('crowdstrike-blog', 'CrowdStrike blog', 'CrowdStrike', 'https://www.crowdstrike.com/blog/feed/', False),
    ('unit42-blog', 'Unit 42', 'Palo Alto Networks Unit 42', 'https://unit42.paloaltonetworks.com/feed/', False),
]
SEC_KEYWORDS = re.compile(r'vulnerab|exploit|advisor|cve-|zero.day|0.day|patch tuesday|security update|rce|remote code|privilege escalation|proof.of.concept|threat|malware|ransomware|breach|attack', re.I)

def _feed_items(xml_text, limit=100):
    items = []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return items
    for node in root.iter():
        tag = node.tag.split('}')[-1]
        if tag not in ('item', 'entry'): continue
        title = ''; link = ''; date = ''
        for child in node:
            ctag = child.tag.split('}')[-1]
            if ctag == 'title' and not title: title = (child.text or '').strip()
            elif ctag == 'link' and not link: link = child.get('href') or (child.text or '').strip()
            elif ctag in ('pubDate', 'date', 'updated', 'published') and not date: date = (child.text or '').strip()
        if title: items.append((date, title, link))
        if len(items) >= limit: break
    return items

def _rss_date(s):
    import email.utils
    s = (s or '').strip()
    try:
        d = email.utils.parsedate_to_datetime(s)
        if d: return d.date().isoformat()
    except Exception: pass
    for fmt in ('%Y-%m-%dT%H:%M:%S%z', '%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%d %H:%M:%S'):
        try: return dt.datetime.strptime(s, fmt).date().isoformat()
        except Exception: continue
    m = re.search(r'\d{4}-\d{2}-\d{2}', s)
    return m.group(0) if m else s[:10]

@cached('advisories')
def fetch_advisories():
    out = {}; status = {}
    prev = cache_get('advisories') or {}
    for sid, name, org, url, is_pure in ADVISORY_FEEDS:
        try:
            text = http(url, headers=BROWSER_UA, timeout=30)
            items = _feed_items(text)
            rows = []
            for date, title, link in items:
                if not is_pure and not SEC_KEYWORDS.search(title): continue
                rows.append([_rss_date(date), sid, title[:200], link])
            rows.sort(key=lambda r: r[0], reverse=True)
            rows = rows[:100]
            out[sid] = rows
            status[sid] = {'ok': True, 'last': rows[0][0] if rows else None, 'items': len(rows), 'note': ''}
            log(f'[advisories:{sid}] ok, {len(rows)} items')
        except Exception as ex:
            cached_rows = (prev.get(sid) if isinstance(prev.get(sid), list) else []) or []
            out[sid] = cached_rows
            status[sid] = {'ok': False, 'last': (cached_rows[0][0] if cached_rows else None), 'items': len(cached_rows), 'note': str(ex)[:150]}
            log(f'[advisories:{sid}] FAILED: {ex!r}')
        time.sleep(0.3)
    out['__status__'] = status
    return out

# ---------------------------------------------------------------- 16. MITRE ATLAS (AI attack case studies)
# dist/v6/ATLAS-latest.yaml is a git symlink: raw.githubusercontent serves the *target filename*
# (e.g. "ATLAS-2026.08.yaml"), not the document, so the fetcher follows it once.
# There is no YAML parser in the stdlib, so the three blocks we need are scanned by indent/regex.
ATLAS_BASE = 'https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/v6/'

def _atlas_val(raw):
    """Strip YAML scalar quoting from the right-hand side of a `key: value` line."""
    v = (raw or '').strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in '\'"': v = v[1:-1].replace("''", "'")
    return v.strip()

def _atlas_blocks(text):
    """{top-level key: block body} for lines like `case-studies:` with no value."""
    heads = [(m.group(1), m.start(), m.end()) for m in re.finditer(r'(?m)^([a-z-]+):[ \t]*$', text)]
    out = {}
    for i, (name, s, e) in enumerate(heads):
        out[name] = text[e:heads[i + 1][1] if i + 1 < len(heads) else len(text)]
    return out

def _atlas_records(block):
    """{id: record body} for 2-space-indent child keys (`  AML.CS0000:`) inside a block.

    Sub-technique ids (AML.T0000.001) are flat siblings of their parent in this dist file,
    so the dotted form is simply allowed in the id pattern.
    """
    heads = [(m.group(1), m.start(), m.end()) for m in re.finditer(r'(?m)^  ([A-Za-z0-9.]+):[ \t]*$', block)]
    out = {}
    for i, (rid, s, e) in enumerate(heads):
        out[rid] = block[e:heads[i + 1][1] if i + 1 < len(heads) else len(block)]
    return out

def _atlas_field(body, key):
    m = re.search(r'(?m)^    %s:(.*)$' % re.escape(key), body)
    return _atlas_val(m.group(1)) if m else ''

@cached('atlas')
def fetch_atlas():
    prev = cache_get('atlas') or {}
    empty = {'version': None, 'techniques': [], 'case_studies': []}
    try:
        text = http(ATLAS_BASE + 'ATLAS-latest.yaml', timeout=300)
        if len(text) < 200 and text.strip().lower().endswith('.yaml'):
            text = http(ATLAS_BASE + text.strip(), timeout=300)
    except Exception as ex:
        log(f'[atlas] fetch FAILED: {ex!r} -> cache'); return prev or empty
    try:
        blocks = _atlas_blocks(text)
    except Exception as ex:
        log(f'[atlas] block scan FAILED: {ex!r} -> cache'); return prev or empty
    m = re.search(r'(?m)^  version:(.*)$', blocks.get('collection', ''))
    version = _atlas_val(m.group(1)) if m else None
    tactic_names = {}
    for tid, body in _atlas_records(blocks.get('tactics', '')).items():
        try: tactic_names[tid] = _atlas_field(body, 'name')
        except Exception: continue
    # relationships[caseId].employs[] links a case study to the techniques/tactics it used
    employs, tactic_of = {}, {}
    for rid, body in _atlas_records(blocks.get('relationships', '')).items():
        try:
            seg = re.search(r'(?ms)^    employs:[ \t]*$(.*?)(?=^    [a-z-]+:|\Z)', body)
            if not seg: continue
            targets = []
            for item in re.split(r'(?m)^    - (?=source:)', seg.group(1)):
                tm = re.search(r'(?m)^      target:(.*)$', item)
                if not tm: continue
                tv = _atlas_val(tm.group(1))
                if not tv: continue
                if tv not in targets: targets.append(tv)
                ta = re.search(r'(?m)^      tactic:(.*)$', item)
                if ta and tv not in tactic_of: tactic_of[tv] = _atlas_val(ta.group(1))
            if targets: employs[rid] = targets
        except Exception as ex:
            log(f'[atlas] relationships {rid} skipped: {ex!r}')
    techniques = []
    for tid, body in _atlas_records(blocks.get('techniques', '')).items():
        try:
            if not tid.startswith('AML.T'): continue
            tac = tactic_of.get(tid, '')
            techniques.append({'id': tid, 'name': _atlas_field(body, 'name'), 'tactic': tactic_names.get(tac, tac)})
        except Exception as ex:
            log(f'[atlas] technique {tid} skipped: {ex!r}')
    case_studies = []
    for cid, body in _atlas_records(blocks.get('case-studies', '')).items():
        try:
            if not cid.startswith('AML.CS'): continue
            case_studies.append([_atlas_field(body, 'date')[:10], cid, _atlas_field(body, 'name'),
                                 _atlas_field(body, 'target'), _atlas_field(body, 'actor'),
                                 employs.get(cid, []), 'https://atlas.mitre.org/studies/' + cid])
        except Exception as ex:
            log(f'[atlas] case study {cid} skipped: {ex!r}')
    case_studies.sort(key=lambda r: (r[0], r[1]))
    if not case_studies and prev.get('case_studies'):
        log('[atlas] parsed 0 case studies -> keeping cache'); return prev
    log(f'[atlas] {len(case_studies)} case studies, {len(techniques)} techniques')
    return {'version': version, 'techniques': techniques, 'case_studies': case_studies}

# ---------------------------------------------------------------- 17. AVID (AI Vulnerability Database)
AVID_RAW = 'https://raw.githubusercontent.com/avidml/avid-db/main/reports/'
AVID_HTML = 'https://github.com/avidml/avid-db/blob/main/reports/'
AVID_MAX_FETCH = 100                  # per-run request budget; cache fills in over successive runs

@cached('avid')
def fetch_avid():
    prev = cache_get('avid') or {}
    records = dict(prev.get('records') or {})
    try:
        years, _ = gh('https://api.github.com/repos/avidml/avid-db/contents/reports')
    except Exception as ex:
        log(f'[avid] year listing FAILED: {ex!r}'); years = []
    ydirs = sorted((x.get('name') for x in years if isinstance(x, dict) and x.get('type') == 'dir'
                    and re.fullmatch(r'\d{4}', x.get('name') or '')), reverse=True)[:2]
    wanted = []
    for yd in ydirs:
        try:
            files, _ = gh(f'https://api.github.com/repos/avidml/avid-db/contents/reports/{yd}')
        except Exception as ex:
            log(f'[avid] {yd} listing FAILED: {ex!r}'); continue
        for x in files:
            n = (x.get('name') or '') if isinstance(x, dict) else ''
            if n.endswith('.json'): wanted.append(f'{yd}/{n}')
        time.sleep(0.2)
    wanted.sort(reverse=True)
    missing = [k for k in wanted if k not in records][:AVID_MAX_FETCH]
    log(f'[avid] {len(missing)} to fetch of {len(wanted)} report files ({len(records)} cached)')
    for key in missing:
        try:
            raw = http(AVID_RAW + key, timeout=30)
            j = json.loads(raw)
            rid = ((j.get('metadata') or {}).get('report_id')) or key.split('/')[-1][:-5]
            date = str(j.get('reported_date') or j.get('published_date') or j.get('last_modified_date') or '')[:10]
            pt = j.get('problemtype') or {}
            desc = pt.get('description') if isinstance(pt, dict) else None
            title = (desc.get('value') if isinstance(desc, dict) else desc) or j.get('description') or ''
            cves = sorted(set(re.findall(r'CVE-\d{4}-\d{4,7}', raw)))
            records[key] = [date, rid, str(title).strip()[:160], AVID_HTML + key, cves]
        except Exception as ex:
            log(f'[avid] {key} FAILED: {ex!r}')
        time.sleep(0.12)
    rows = sorted((r for r in records.values() if r and r[0]), key=lambda r: (r[0], r[1]), reverse=True)
    by_month = {}
    for r in rows: by_month[r[0][:7]] = by_month.get(r[0][:7], 0) + 1
    latest = [[r[0], r[1], r[2], r[3]] for r in rows[:50]]
    log(f'[avid] {len(rows)} reports across {len(by_month)} months')
    return {'records': records, 'by_month': dict(sorted(by_month.items())), 'latest': latest}

# ---------------------------------------------------------------- 18. OWASP AI/LLM taxonomies (static)
# Fixed, annually-revised taxonomies -- vendored once rather than fetched weekly (see
# data-src/research/ai-frameworks-data.md sections 3.1/3.2/3.5). Every URL below was confirmed live.
OWASP_LLM_TOP10_2025 = [
    {'id': 'LLM01:2025', 'name': 'Prompt Injection', 'url': 'https://genai.owasp.org/llmrisk/llm01-prompt-injection/'},
    {'id': 'LLM02:2025', 'name': 'Sensitive Information Disclosure', 'url': 'https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/'},
    {'id': 'LLM03:2025', 'name': 'Supply Chain', 'url': 'https://genai.owasp.org/llmrisk/llm032025-supply-chain/'},
    {'id': 'LLM04:2025', 'name': 'Data and Model Poisoning', 'url': 'https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/'},
    {'id': 'LLM05:2025', 'name': 'Improper Output Handling', 'url': 'https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/'},
    {'id': 'LLM06:2025', 'name': 'Excessive Agency', 'url': 'https://genai.owasp.org/llmrisk/llm062025-excessive-agency/'},
    {'id': 'LLM07:2025', 'name': 'System Prompt Leakage', 'url': 'https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/'},
    {'id': 'LLM08:2025', 'name': 'Vector and Embedding Weaknesses', 'url': 'https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/'},
    {'id': 'LLM09:2025', 'name': 'Misinformation', 'url': 'https://genai.owasp.org/llmrisk/llm092025-misinformation/'},
    {'id': 'LLM10:2025', 'name': 'Unbounded Consumption', 'url': 'https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/'},
]
# OWASP Top 10 for Agentic Applications: risk IDs not confirmed against a live OWASP source
# (research/ai-frameworks-data.md 3.2 leaves them unverified), so ship it empty rather than invent names.
OWASP_AGENTIC_TOP10 = []
_OWASP_ML_DOC = 'https://owasp.org/www-project-machine-learning-security-top-10/docs/'
OWASP_ML_TOP10 = [
    {'id': 'ML01:2023', 'name': 'Input Manipulation Attack', 'url': _OWASP_ML_DOC + 'ML01_2023-Input_Manipulation_Attack.html'},
    {'id': 'ML02:2023', 'name': 'Data Poisoning Attack', 'url': _OWASP_ML_DOC + 'ML02_2023-Data_Poisoning_Attack.html'},
    {'id': 'ML03:2023', 'name': 'Model Inversion Attack', 'url': _OWASP_ML_DOC + 'ML03_2023-Model_Inversion_Attack.html'},
    {'id': 'ML04:2023', 'name': 'Membership Inference Attack', 'url': _OWASP_ML_DOC + 'ML04_2023-Membership_Inference_Attack.html'},
    {'id': 'ML05:2023', 'name': 'Model Theft', 'url': _OWASP_ML_DOC + 'ML05_2023-Model_Theft.html'},
    {'id': 'ML06:2023', 'name': 'AI Supply Chain Attacks', 'url': _OWASP_ML_DOC + 'ML06_2023-AI_Supply_Chain_Attacks.html'},
    {'id': 'ML07:2023', 'name': 'Transfer Learning Attack', 'url': _OWASP_ML_DOC + 'ML07_2023-Transfer_Learning_Attack.html'},
    {'id': 'ML08:2023', 'name': 'Model Skewing', 'url': _OWASP_ML_DOC + 'ML08_2023-Model_Skewing.html'},
    {'id': 'ML09:2023', 'name': 'Output Integrity Attack', 'url': _OWASP_ML_DOC + 'ML09_2023-Output_Integrity_Attack.html'},
    {'id': 'ML10:2023', 'name': 'Model Poisoning', 'url': _OWASP_ML_DOC + 'ML10_2023-Model_Poisoning.html'},
]

# ---------------------------------------------------------------- 19. CSAF 2.0 (BSI aggregator + Red Hat)
BSI_AGGREGATOR = 'https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json'
REDHAT_CSAF_META = 'https://security.access.redhat.com/data/csaf/v2/provider-metadata.json'
REDHAT_CSAF_MAX = 20                  # per-run advisory sample; the year index alone is ~7 MB

@cached('csaf')
def fetch_csaf():
    prev = cache_get('csaf') or {}
    providers = list(prev.get('providers') or [])
    try:
        ag = json.loads(http(BSI_AGGREGATOR, timeout=60))
        found = []
        for key, default_role in (('csaf_providers', 'csaf_provider'), ('csaf_publishers', 'csaf_publisher')):
            for p in (ag.get(key) or []):
                try:
                    md = (p.get('metadata') or {}) if isinstance(p, dict) else {}
                    pub = md.get('publisher') or {}
                    url = md.get('url') or ''
                    name = pub.get('name') or pub.get('namespace') or url
                    base = re.sub(r'^https?://(www\.)?', '', (pub.get('namespace') or name or '')).lower()
                    pid = re.sub(r'[^a-z0-9]+', '-', base).strip('-')[:60]
                    found.append({'id': pid, 'name': name, 'url': url, 'status': 'ok',
                                  'role': md.get('role') or default_role, 'last_updated': str(md.get('last_updated') or '')[:10]})
                except Exception as ex:
                    log(f'[csaf] provider entry skipped: {ex!r}')
        if found: providers = found
        log(f'[csaf] BSI aggregator: {len(providers)} providers')
    except Exception as ex:
        log(f'[csaf] BSI aggregator FAILED: {ex!r} -> keeping {len(providers)} cached providers')
    records = dict(prev.get('records') or {})
    try:
        meta = json.loads(http(REDHAT_CSAF_META, timeout=60))
        dir_url = ''
        for d_ in (meta.get('distributions') or []):
            u = (d_ or {}).get('directory_url') or ''
            if u.rstrip('/').endswith('/advisories'): dir_url = u.rstrip('/'); break
        if not dir_url: raise RuntimeError('no advisories directory_url in Red Hat provider-metadata')
        year_url = f'{dir_url}/{TODAY.year}/'
        idx = http(year_url, timeout=300)
        # sort by the numeric advisory serial, not the string (rhsa-2026_10234 > rhsa-2026_9874)
        names = sorted({n.lower() for n in re.findall(r'rhsa-\d{4}_\d+\.json', idx, re.I)},
                       key=lambda n: int(n.rsplit('_', 1)[1].split('.')[0]))
        if not names: raise RuntimeError('no RHSA advisory filenames in Red Hat year index')
        log(f'[csaf] redhat {TODAY.year}: {len(names)} RHSA files, sampling newest {REDHAT_CSAF_MAX} by serial')
        for n in names[-REDHAT_CSAF_MAX:]:
            try:
                a = json.loads(http(year_url + n, timeout=30))
                doc = a.get('document') or {}; tr = doc.get('tracking') or {}
                aid = tr.get('id') or n[:-5].upper()
                date = str(tr.get('initial_release_date') or tr.get('current_release_date') or '')[:10]
                title = re.sub(r'^Red Hat Security Advisory:\s*', '', str(doc.get('title') or ''))[:160]
                flagged = 0
                for v in (a.get('vulnerabilities') or []):
                    for th in (v.get('threats') or []):
                        if (th or {}).get('category') == 'exploit_status': flagged = 1
                records[aid] = [date, aid, title, 'https://access.redhat.com/errata/' + aid.replace(' ', ''),
                                flagged, tr.get('status') or '']
            except Exception as ex:
                log(f'[csaf] redhat {n} FAILED: {ex!r}')
            time.sleep(0.15)
    except Exception as ex:
        log(f'[csaf] Red Hat CSAF FAILED: {ex!r} -> BSI providers only')
    rows = sorted((r for r in records.values() if r and r[0]), key=lambda r: (r[0], r[1]))
    counts = {}
    for r in rows:
        try: w = monday(r[0]).isoformat()
        except Exception: continue
        b = counts.setdefault(w, [0, 0]); b[0] += 1; b[1] += 1 if r[4] else 0
    weekly = [[w, n, x] for w, (n, x) in sorted(counts.items())]
    latest = [[r[0], r[1], r[2], r[3]] for r in rows[::-1][:50]]
    log(f'[csaf] {len(providers)} providers, {len(rows)} Red Hat advisories, {len(weekly)} weeks')
    return {'providers': providers, 'records': records, 'weekly': weekly, 'latest': latest}

# ---------------------------------------------------------------- 20. AI-credited CVEs (cvelistV5 credits scan)
# "How many vulnerabilities are AI-found?" Source of truth: containers.cna.credits[]
# (value/description), containers.cna.descriptions and references[] in the cvelistV5 JSON
# records, matched against manual.json's ai_credit_patterns/ai_credit_exclusions.
# Bulk fetch is a GitHub *release* asset (the full cvelistV5 zip), scanned in-memory with
# zipfile+json -- never extracted to disk. Weekly refreshes scan only the release's delta
# zip and merge into the cached index, so the multi-hundred-MB full zip is fetched once.
CVELIST_ZIP = CACHE / 'cvelist_all.zip'
CVELIST_DELTA_ZIP = CACHE / 'cvelist_delta.zip'
AI_SCAN_START_YEAR = 2024

def _ai_patterns():
    pats = MANUAL.get('ai_credit_patterns', [])
    excl = MANUAL.get('ai_credit_exclusions', [])
    compiled = [(p, re.compile(r'\b' + re.escape(p) + r'\b', re.I)) for p in pats]
    excl_re = [re.compile(r'\b' + re.escape(e) + r'\b', re.I) for e in excl]
    return compiled, excl_re

# A CVE description or reference naming an AI vendor/product is very often just describing
# the *affected* software (e.g. "the AI ChatBot plugin ... uploads files to a linked OpenAI
# account" -- CVE-2024-0452, credited to a human finder) rather than crediting an AI with the
# discovery. containers.cna.credits[] is an explicit finder-attribution field, so a match
# there is trusted at face value; a description/reference match is only counted when a
# discovery verb sits within DISCOVERY_CONTEXT_WINDOW characters of it.
DISCOVERY_CONTEXT_RE = re.compile(
    r'\b(found|discover(?:ed|y)?|identif(?:ied|y|ies)|generat(?:ed|es)\s+by|assist(?:ed|s)\s+(?:discovery|by)|'
    r'detect(?:ed|s)\s+by|flagg(?:ed)?\s+by|surfac(?:ed)?\s+by|uncover(?:ed)?|'
    r'produc(?:ed|es)\s+by|autonomous(?:ly)?|vulnerability\s+research\s+agent|automated\s+vulnerability)\b', re.I)
DISCOVERY_CONTEXT_WINDOW = 60

def _ai_scan_text(text, compiled, excl_re, require_context=False):
    """[(pattern, matched substring), ...] for AI-credit patterns in text; a match whose
    span an exclusion phrase fully covers (e.g. an affected-product mention of
    "OpenAI Codex") is voided -- "AI" alone is never in the pattern list, so it never matches.
    When require_context is set (description/reference fields), a match is also voided unless
    a discovery verb (found/discovered/identified/generated/...) appears within
    DISCOVERY_CONTEXT_WINDOW characters, so a CVE merely *about* an AI product doesn't count."""
    if not text: return []
    excl_spans = [(m.start(), m.end()) for er in excl_re for m in er.finditer(text)]
    ctx_spans = [(m.start(), m.end()) for m in DISCOVERY_CONTEXT_RE.finditer(text)] if require_context else None
    hits = []
    for p, cre in compiled:
        for m in cre.finditer(text):
            if any(s <= m.start() and m.end() <= e for s, e in excl_spans): continue
            if ctx_spans is not None:
                lo, hi = m.start() - DISCOVERY_CONTEXT_WINDOW, m.end() + DISCOVERY_CONTEXT_WINDOW
                if not any(cs < hi and ce > lo for cs, ce in ctx_spans): continue
            hits.append((p, m.group(0)))
    return hits

def _scan_cve_record(j, compiled, excl_re):
    """One CVE JSON 5 record -> {'pub','matched','field','cna'} or None.
    Checked in order of authority: credits (explicit discovery credit, trusted at face value)
    > descriptions (only counted near a discovery verb) > references (title/url of a writeup,
    same context requirement)."""
    cna_container = ((j.get('containers') or {}).get('cna') or {})
    cna_name = ((j.get('cveMetadata') or {}).get('assignerShortName')) or ''
    pub = ((j.get('cveMetadata') or {}).get('datePublished') or '')[:10]
    for field, require_context, texts in (
        ('credits', False, [' '.join(str(c.get(k) or '') for k in ('value', 'description') if c.get(k)) for c in (cna_container.get('credits') or [])]),
        ('description', True, [d.get('value') or '' for d in (cna_container.get('descriptions') or []) if (d.get('lang') or 'en').lower().startswith('en')]),
        ('reference', True, [f"{r.get('name') or ''} {r.get('url') or ''}" for r in (cna_container.get('references') or [])]),
    ):
        matched = []
        for text in texts:
            matched.extend(h[0] for h in _ai_scan_text(text, compiled, excl_re, require_context))
        if matched:
            return {'pub': pub, 'matched': sorted(set(matched)), 'field': field, 'cna': cna_name}
    return None

def _gh_release_asset(patterns, repo='CVEProject/cvelistV5', scan_releases=8):
    """First asset matching any regex in `patterns`, searching the `scan_releases` most recent
    releases newest-first (cvelistV5 publishes hourly delta releases plus a periodic full "all
    CVEs" dump; the single most-recent release does not always carry the full-dump asset, e.g.
    its once-daily "at_end_of_day" release ships only that day's cumulative delta)."""
    h = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
    if TOKEN: h['Authorization'] = 'Bearer ' + TOKEN
    releases = json.loads(http(f'https://api.github.com/repos/{repo}/releases?per_page={scan_releases}', headers=h, timeout=60))
    latest_tag = releases[0].get('tag_name') if releases else None
    for j in releases:
        assets = j.get('assets') or []
        log(f"[ai_credit] release {j.get('tag_name')}: assets = {[a.get('name') for a in assets]}")
        for pat in patterns:
            cre = re.compile(pat, re.I)
            for a in assets:
                if cre.search(a.get('name') or ''):
                    return a.get('browser_download_url'), a.get('name'), j.get('tag_name')
    return None, None, latest_tag

def _download_to(url, dest, timeout=900):
    h = dict(UA)
    if TOKEN: h['Authorization'] = 'Bearer ' + TOKEN
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r, open(dest, 'wb') as f:
        while True:
            chunk = r.read(1 << 20)
            if not chunk: break
            f.write(chunk)

def _open_cve_zip(zip_path):
    """cvelistV5's "all CVEs" release asset is a zip that wraps a single inner cves.zip
    (hence the doubled .zip.zip filename) holding cves/YYYY/Nxxx/CVE-YYYY-NNNNN.json; a
    plain delta zip has the CVE JSON files directly at its top level. Returns a ZipFile
    open on whichever one actually holds the CVE records, plus a cleanup callback."""
    outer = zipfile.ZipFile(zip_path)
    names = outer.namelist()
    inner_name = next((n for n in names if n.rsplit('/', 1)[-1] == 'cves.zip'), None)
    if inner_name and len(names) <= 3:
        data = outer.read(inner_name)
        outer.close()
        return zipfile.ZipFile(io.BytesIO(data)), (lambda: None)
    return outer, outer.close

def _scan_zip_for_ai_credit(zip_path, compiled, excl_re, known_pub, min_year=AI_SCAN_START_YEAR):
    """Scan every CVE-YYYY-NNNN.json in zip_path (year >= min_year) without extracting to disk
    (transparently unwrapping the nested cves.zip -- see _open_cve_zip). Returns
    (ai_hits: {cve: rec}, new_pub: {cve: datePublished}) -- new_pub only contains CVE ids not
    already present in `known_pub`, so re-scanning an updated record in a delta zip does not
    double count it in the weekly "all CVEs published" total."""
    ai_hits, new_pub = {}, {}
    n_seen = n_scanned = 0
    z, close = _open_cve_zip(zip_path)
    try:
        for info in z.infolist():
            m = re.search(r'(CVE-(\d{4})-\d{4,7})\.json$', info.filename)
            if not m or info.is_dir(): continue
            cid, year = m.group(1), int(m.group(2))
            if year < min_year: continue
            n_seen += 1
            try:
                with z.open(info) as f:
                    j = json.loads(f.read().decode('utf-8', 'replace'))
            except Exception as ex:
                if n_seen % 5000 == 0: log(f'[ai_credit] {cid} parse FAILED: {ex!r}')
                continue
            n_scanned += 1
            pub = ((j.get('cveMetadata') or {}).get('datePublished') or '')[:10]
            if pub and cid not in known_pub and cid not in new_pub: new_pub[cid] = pub
            rec = _scan_cve_record(j, compiled, excl_re)
            if rec: ai_hits[cid] = rec
            if n_seen % 20000 == 0: log(f'[ai_credit] progress {n_seen} CVE-{min_year}+ records seen, {len(ai_hits)} AI-credited so far')
    finally:
        close()
    log(f'[ai_credit] {zip_path.name}: scanned {n_scanned}/{n_seen} CVE-{min_year}+ records, {len(ai_hits)} AI-credited, {len(new_pub)} newly-seen publish dates')
    return ai_hits, new_pub

@cached('ai_credit')
def fetch_ai_credit():
    prev = cache_get('ai_credit') or {}
    compiled, excl_re = _ai_patterns()
    index = {k: dict(v) for k, v in (prev.get('index') or {}).items()}
    pub_totals = dict(prev.get('pub_totals') or {})
    last_tag = prev.get('last_full_tag')
    full = (not index) or getattr(ARGS, 'ai_credit_full', False)
    if full:
        url, name, tag = _gh_release_asset([r'all[_-]?cves?.*midnight.*\.zip$', r'^\d{4}[_-]?\d{2}[_-]?\d{2}.*all.*cve.*\.zip$', r'all[_-]?cves?.*\.zip$'])
        if not url:
            raise RuntimeError(f'no full cvelistV5 zip asset found in latest release (tag {tag})')
        log(f'[ai_credit] full scan: downloading {name} ({tag}) -> {CVELIST_ZIP.name}')
        _download_to(url, CVELIST_ZIP)
        try:
            index, pub_totals = _scan_zip_for_ai_credit(CVELIST_ZIP, compiled, excl_re, {})
        finally:
            try: CVELIST_ZIP.unlink()
            except Exception: pass
        last_tag = tag
    else:
        url, name, tag = _gh_release_asset([r'delta.*\.zip$'])
        if url:
            log(f'[ai_credit] incremental scan: downloading delta {name} ({tag}) -> {CVELIST_DELTA_ZIP.name}')
            _download_to(url, CVELIST_DELTA_ZIP)
            try:
                delta_hits, new_pub = _scan_zip_for_ai_credit(CVELIST_DELTA_ZIP, compiled, excl_re, pub_totals)
            finally:
                try: CVELIST_DELTA_ZIP.unlink()
                except Exception: pass
            index.update(delta_hits); pub_totals.update(new_pub); last_tag = tag
        else:
            log('[ai_credit] no delta zip asset found in latest release; keeping cached index unchanged')
    return {'index': index, 'pub_totals': pub_totals, 'patterns': MANUAL.get('ai_credit_patterns', []),
            'exclusions': MANUAL.get('ai_credit_exclusions', []), 'asof': TODAY.isoformat(), 'last_full_tag': last_tag}

def merge_ai_credit_index(ai_credit, revealed_manual):
    """Union the cvelistV5 credits-scan index with Anthropic ledger 'revealed' findings that
    carry a CVE id, tagged source=anthropic-ledger (per spec: ZW.ai_found unions these in)."""
    index = {k: dict(v) for k, v in ((ai_credit or {}).get('index') or {}).items()}
    for rec in index.values(): rec.setdefault('source', 'cvelistv5-credits')
    for m in (revealed_manual or []):
        cid = (m.get('id') or '').strip()
        if not re.fullmatch(r'CVE-\d{4}-\d{4,7}', cid): continue
        if cid in index:
            index[cid].setdefault('ledger', True)
        else:
            index[cid] = {'pub': None, 'matched': [], 'field': 'anthropic-ledger', 'cna': 'anthropic-ledger', 'source': 'anthropic-ledger', 'ledger': True}
    return index

def build_ai_found(ai_credit, merged_index, kev_entries, euvd_built):
    """ZW.ai_found data contract (see README/manual.json ai_credit_patterns for methodology)."""
    ai_credit = ai_credit or {}
    pub_totals = dict(ai_credit.get('pub_totals') or {})
    patterns = ai_credit.get('patterns') or MANUAL.get('ai_credit_patterns', [])
    ai_cves = set(merged_index)
    ledger_ids = {c for c, rec in merged_index.items() if rec.get('ledger')}

    kev_overlap = [[e[1], e[0], e[2], e[3], merged_index.get(e[1], {}).get('matched') or []]
                   for e in kev_entries if len(e) > 11 and e[11]]
    euvd_cves = set()
    for e in (euvd_built or {}).get('entries') or []: euvd_cves.update(e[2])
    euvd_overlap = sorted(ai_cves & euvd_cves)

    weeks = weeks_between(dt.date(2024, 1, 1), TODAY)
    ai_by_week, total_by_week = {}, {}
    for cid, rec in merged_index.items():
        pub = rec.get('pub') or pub_totals.get(cid)
        if not pub: continue
        try: w = monday(pub).isoformat()
        except Exception: continue
        ai_by_week[w] = ai_by_week.get(w, 0) + 1
    for cid, pub in pub_totals.items():
        try: w = monday(pub).isoformat()
        except Exception: continue
        total_by_week[w] = total_by_week.get(w, 0) + 1
    weekly = [[w, ai_by_week.get(w, 0), total_by_week.get(w, 0)] for w in weeks]

    by_cna, by_pattern = {}, {}
    for rec in merged_index.values():
        c = rec.get('cna') or 'unknown'; by_cna[c] = by_cna.get(c, 0) + 1
        for p in (rec.get('matched') or []): by_pattern[p] = by_pattern.get(p, 0) + 1
    by_cna = dict(sorted(by_cna.items(), key=lambda x: -x[1])[:25])
    by_pattern = dict(sorted(by_pattern.items(), key=lambda x: -x[1]))

    year = str(TODAY.year)
    ai_this_year = sum(1 for c in ai_cves if c.split('-')[1] == year)
    total_this_year = sum(1 for c, p in pub_totals.items() if (p or '').startswith(year))
    share = round(ai_this_year / total_this_year, 4) if total_this_year else None

    return {'asof': ai_credit.get('asof') or TODAY.isoformat(), 'patterns': patterns, 'weekly': weekly,
            'by_cna': by_cna, 'by_pattern': by_pattern, 'kev_overlap': kev_overlap, 'euvd_overlap': euvd_overlap,
            'totals': {'ai_credited': len(ai_cves), 'in_kev': len(kev_overlap), 'in_euvd': len(euvd_overlap),
                       'mythos_ledger_revealed': len(ledger_ids), 'share_of_2026_cves': share},
            'index': merged_index}

# ---------------------------------------------------------------- build outputs
def load_sources_registry():
    text = (HERE / 'research' / 'sources.md').read_text(encoding='utf-8')
    m = re.search(r'SOURCES_REGISTRY\s*=\s*(\[.*\])', text, re.S)
    if not m: return []
    return json.loads(m.group(1))

def build(kev, ledger, epoch, msrc, oracle, eco, repos, dotnet, cve_pub, nvd_watchlist, extra_feeds,
          euvd=None, epss=None, p0=None, exploit=None, ssvc=None, advisories=None,
          atlas=None, avid=None, csaf=None, ai_credit=None):
    data_through = max(e[0] for e in kev['entries']) if kev else TODAY.isoformat()
    cve_pub = cve_pub or {}
    kev_categories = MANUAL.get('kev_categories', {})
    kev_entries = []
    for d, cve, ven, prod, k, due, name in (kev['entries'] if kev else []):
        info = cve_pub.get(cve) or {}
        kev_entries.append([d, cve, ven, prod, k, due, name, info.get('pub') or '', categorize(ven, prod, kev_categories), info.get('score'), info.get('sev') or ''])
    kw = kev_weekly(kev_entries) if kev_entries else []
    watchlist = build_watchlist(nvd_watchlist, extra_feeds, kev_entries)
    kev_cves = {e[1] for e in kev_entries}
    euvd_built = build_euvd(euvd, kev_entries)
    p0_built = build_p0(p0, kev_cves)
    exploit_built = build_exploit(exploit, kev_entries)
    epss = epss or {}
    ssvc = ssvc or {}
    advisories = advisories or {}
    advisory_status = advisories.get('__status__') or {}
    advisories_out = {k: v for k, v in advisories.items() if k != '__status__'}
    atlas = atlas or {}
    atlas_cs = atlas.get('case_studies') or []
    atlas_by_year, atlas_by_technique = {}, {}
    for cs in atlas_cs:
        try:
            y = (cs[0] or '')[:4]
            if y: atlas_by_year[y] = atlas_by_year.get(y, 0) + 1
            for tid in (cs[5] or []): atlas_by_technique[tid] = atlas_by_technique.get(tid, 0) + 1
        except Exception: continue
    avid = avid or {}
    avid_latest = avid.get('latest') or []
    csaf = csaf or {}
    csaf_providers = csaf.get('providers') or []
    csaf_weekly = csaf.get('weekly') or []
    csaf_latest = csaf.get('latest') or []
    sources_registry = load_sources_registry()
    source_status = {}
    for sid, status in advisory_status.items(): source_status[sid] = status
    def _st(sid, ok, items, last=None, note=''):
        source_status[sid] = {'ok': bool(ok), 'last': last, 'items': items, 'note': note}
    _st('kev', bool(kev), (kev or {}).get('count'), data_through)
    _st('enisa-euvd-exploited', bool(euvd), len(euvd_built['entries']), euvd_built['entries'][-1][0] if euvd_built['entries'] else None)
    _st('epss', bool(epss.get('by_cve')), len(epss.get('by_cve') or {}), epss.get('asof'))
    _st('p0-0day-sheet', bool(p0), len(p0_built['entries']))
    _st('metasploit-modules', bool((exploit or {}).get('msf_by_cve')), len((exploit or {}).get('msf_by_cve') or {}))
    _st('exploitdb-csv', bool((exploit or {}).get('edb_cves')), len((exploit or {}).get('edb_cves') or []))
    _st('poc-in-github', bool((exploit or {}).get('poc_counts')), len((exploit or {}).get('poc_counts') or {}))
    _st('cisa-adp-ssvc-kev', bool(ssvc), sum(1 for v in ssvc.values() if v.get('exploitation') or v.get('automatable') or v.get('impact')))
    _st('atlas-data', bool(atlas_cs), len(atlas_cs), max((c[0] for c in atlas_cs if c[0]), default=None), f"ATLAS {atlas.get('version') or '?'}")
    _st('avid-db', bool(avid_latest), len(avid_latest), avid_latest[0][0] if avid_latest else None)
    _st('bsi-csaf-aggregator', bool(csaf_providers), len(csaf_providers), max((p.get('last_updated') or '' for p in csaf_providers), default=None) or None)
    _st('redhat-csaf', bool(csaf_latest), len(csaf_latest), csaf_latest[0][0] if csaf_latest else None)
    _st('ai-credit-cvelistv5', bool((ai_credit or {}).get('index')), len((ai_credit or {}).get('index') or {}), (ai_credit or {}).get('asof'), (ai_credit or {}).get('last_full_tag') or '')
    events = [{'date': e['date'], 'label': e['label'], 'week': monday(e['date']).isoformat(), 'frac': round((dt.date.fromisoformat(e['date']).weekday() + .5) / 7, 2)} for e in MANUAL['events']]
    revealed_manual = []
    for line in (HERE / 'mythos_cves_raw.txt').read_text(encoding='utf-8').splitlines():
        if line.strip():
            i, proj, cls, sev, title = line.split('|'); revealed_manual.append({'id': i, 'project': proj, 'bug_class': cls, 'severity': sev, 'title': title})
    ai_index = merge_ai_credit_index(ai_credit, revealed_manual)
    ai_cve_set = set(ai_index)
    for row in kev_entries: row.append(row[1] in ai_cve_set)   # ai_found: index 11, appended so earlier indexes are stable
    ai_found_built = build_ai_found(ai_credit, ai_index, kev_entries, euvd_built)
    ZW = {
        'meta': {'generated': dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'), 'data_through': data_through, 'scope_start': START.isoformat(),
                 'scope_note': f'Scope: {START.year} → today; KEV since Nov 2021, P0 since 2014',
                 'kev_released': kev.get('released') if kev else None, 'kev_catalog_size': kev.get('count') if kev else None,
                 'ledger_entries': ledger.get('entries') if ledger else None, 'site': MANUAL['site'], 'log': LOG[-40:]},
        'events': events,
        'timeline': MANUAL['timeline'],
        'notable_weeks': MANUAL['notable_weeks'],
        'kev': {'entries': kev_entries, 'weekly': kw},
        'ledger': ledger or {},
        'ledger_revealed_curated': revealed_manual,
        'cna': {'weeks': epoch['weeks'], 'series': epoch['series']} if epoch else {'weeks': [], 'series': {}},
        'epoch_monthly': epoch['monthly_notable'] if epoch else [],
        'patch': {'msrc': msrc or {}, 'oracle': oracle or {}, 'dotnet': (dotnet or {}).get('monthly', {}), 'dotnet_items': (dotnet or {}).get('items', [])},
        'eco': eco or {},
        'repos': repos or {},
        'gtig_zero_days_by_year': MANUAL['gtig_zero_days_by_year'], 'gtig_note': MANUAL['gtig_note'],
        'long_lived_bugs': MANUAL['long_lived_bugs'],
        'vendor_statements': MANUAL['vendor_statements'], 'glasswing_launch_partners': MANUAL['glasswing_launch_partners'], 'glasswing_partners': MANUAL['glasswing_partners'],
        'framework_facts': MANUAL['framework_facts'],
        'similar_trackers': MANUAL['similar_trackers'], 'sources': MANUAL['sources'],
        'watchlist': watchlist,
        'frameworks': MANUAL.get('frameworks', []), 'metrics': MANUAL.get('metrics', []),
        'ciso_kpis': MANUAL.get('ciso_kpis', []), 'bod': MANUAL.get('bod', {}),
        'kev_categories': kev_categories,
        'tte': compute_tte(kev_entries),
        'kev_by_category': kev_by_category(kev_entries),
        'euvd': euvd_built,
        'epss': epss,
        'p0': p0_built,
        'exploit': exploit_built,
        'ssvc': ssvc,
        'advisories': advisories_out,
        'atlas': {'version': atlas.get('version'), 'techniques': atlas.get('techniques') or [], 'case_studies': atlas_cs,
                  'by_year': dict(sorted(atlas_by_year.items())),
                  'by_technique': dict(sorted(atlas_by_technique.items(), key=lambda x: (-x[1], x[0])))},
        'ai_incidents': {'source': 'AVID (avidml/avid-db)', 'by_month': avid.get('by_month') or {}, 'latest': avid_latest},
        'owasp': {'llm_top10_2025': OWASP_LLM_TOP10_2025, 'agentic_top10': OWASP_AGENTIC_TOP10, 'ml_top10': OWASP_ML_TOP10},
        'csaf': {'providers': csaf_providers, 'weekly': csaf_weekly, 'latest': csaf_latest},
        'ai_found': ai_found_built,
        'sources_registry': sources_registry,
        'source_status': source_status,
    }
    (ROOT / 'zeroweek-data.js').write_text('window.ZW=' + json.dumps(ZW, ensure_ascii=False, separators=(',', ':')) + ';\n', encoding='utf-8')
    (ROOT / 'zeroweek-data.json').write_text(json.dumps(ZW, ensure_ascii=False, indent=1), encoding='utf-8')
    # tidy CSV
    rows = []
    add = lambda *r: rows.append(list(r))
    for d, cve, ven, prod, k, due, name, pub, cat, score, sev, *_ai in ZW['kev']['entries']:
        ai_found = _ai[0] if _ai else False
        note = ('same-year CVE; ' if int(cve.split('-')[1]) >= int(d[:4]) else 'older CVE; ') + ('ransomware; ' if k == 'K' else '') + name
        note += f' | published={pub} category={cat} score={score if score is not None else ""} severity={sev} ai_found={ai_found}'
        add('kev_entry', d, 'exploited_in_wild', cve, ven, prod, 1, note)
    for w, t, f, o, r, tte, edge in kw:
        for k, v in (('total', t), ('same_year_cve', f), ('older_cve', o), ('ransomware_linked', r), ('median_tte_days', tte), ('edge_appliance_count', edge)): add('kev_weekly', w, k, '', 'CISA KEV', '', v, '')
    for pid, months in ZW['watchlist']['monthly'].items():
        for ym, s in sorted(months.items()):
            for k, v in (('total', s['total']), ('critical', s['critical']), ('high', s['high']), ('medium', s['medium']), ('low', s['low'])): add('watchlist_monthly', ym, k, pid, '', '', v, '')
    for y, s in sorted(ZW['tte']['by_year'].items()):
        for k, v in s.items(): add('tte_by_year', y, k, '', '', '', v, '')
    for r in (ledger or {}).get('weekly', []):
        for k, v in zip(['discovered_critical', 'discovered_high', 'discovered_medium', 'discovered_low', 'discovered_unassessed', 'hash_commitments', 'patched_upstream'], r[1:]): add('mythos_ledger_weekly', r[0], k, '', 'Anthropic CVD ledger', '', v, '')
    for m in revealed_manual: add('mythos_revealed_finding', '', 'disclosed_and_revealed', m['id'], m['project'], m['bug_class'], 1, m['severity'] + ': ' + m['title'])
    for c, s in ZW['cna']['series'].items():
        for w, v in sorted(s.items()): add('vendor_weekly_high_critical_cves', w, 'high+critical', '', c, '', v, '')
    for m, c, h in ZW['epoch_monthly']: add('epoch_monthly', m, 'critical', '', '21 notable CNAs', '', c, ''); add('epoch_monthly', m, 'high', '', '21 notable CNAs', '', h, '')
    for m, v in sorted((msrc or {}).items()): add('patch_cycle', m, 'patch_tuesday_cves', '', 'Microsoft', '', v, '')
    for m, v in sorted((oracle or {}).items()): add('patch_cycle', m, 'cpu_patches', '', 'Oracle', '', v.get('patches'), f"cves={v.get('cves')}")
    for m, v in sorted(ZW['patch']['dotnet'].items()): add('patch_cycle', m, 'security_advisories', '', '.NET', '', v, '')
    for d, c, t in ZW['patch']['dotnet_items']: add('dotnet_advisory', d, 'security_advisory', c, 'Microsoft .NET', t, 1, '')
    for e, s in (eco or {}).items():
        for m, v in sorted(s.items()): add('github_advisories_monthly', m, 'reviewed_advisories', '', e, '', v, '')
    for rp, v in (repos or {}).items():
        for m, n in sorted(v.get('months', {}).items()): add('repo_advisories_monthly', m, 'published_advisories', '', rp, '', n, '')
    for y, n in MANUAL['gtig_zero_days_by_year'].items(): add('gtig_yearly', y, 'zero_days_exploited_in_wild', '', 'Google TIG', '', n, '')
    for f in MANUAL['framework_facts']: add('framework_fact', f['date'], f['framework'], '', f['vendor'], '', f['count'], f['note'])
    for t in MANUAL['timeline']: add('timeline', t['date'], 'event', '', '', '', 1, t['event'])
    for c, s in MANUAL['vendor_statements'].items(): add('vendor_statement', '', 'statement', '', c, '', 1, s)
    for w, n in euvd_built['weekly']: add('euvd_weekly', w, 'exploited_added', '', 'ENISA EUVD', '', n, '')
    for d, eid, cves, ven, prod, score, desc in euvd_built['entries']: add('euvd_entry', d, 'exploited_in_wild', eid, ven, prod, 1, ('CVE:' + ','.join(cves) if cves else '') + ' | ' + desc)
    for cve in euvd_built['only_in_euvd']: add('euvd_delta', '', 'only_in_euvd_not_kev', cve, 'ENISA EUVD', '', 1, '')
    for cve in euvd_built['only_in_kev']: add('euvd_delta', '', 'only_in_kev_not_euvd', cve, 'CISA KEV', '', 1, '')
    for cve, (score, pct) in epss.get('by_cve', {}).items(): add('epss', epss.get('asof', ''), 'score_percentile', cve, 'FIRST.org', '', score, f'percentile={pct}')
    for y, n in p0_built['yearly'].items(): add('p0_yearly', y, 'zero_days_itw', '', 'Google Project Zero', '', n, '')
    for d, cve, ven, prod, typ, in_kev in p0_built['entries']: add('p0_entry', d, 'zero_day_itw', cve, ven, prod, 1, f'type={typ} in_kev={in_kev}')
    for w, share in exploit_built['weekly_share']: add('exploit_weekly_share', w, 'share_with_public_exploit', '', 'Metasploit/Exploit-DB/PoC-in-GitHub', '', share, '')
    for y, msf_n, edb_n in exploit_built.get('yearly_published', []): add('exploit_yearly_published', y, 'metasploit_modules', '', 'Metasploit', '', msf_n, f'exploitdb={edb_n}'); add('exploit_yearly_published', y, 'exploitdb_files', '', 'Exploit-DB', '', edb_n, f'metasploit={msf_n}')
    for cve, info in exploit_built['by_cve'].items(): add('exploit_availability', '', 'msf_edb_poc', cve, '', '', 1, f"msf={info['msf']} edb={info['edb']} poc={info['poc']}")
    for cve, rec in ssvc.items():
        if rec.get('exploitation') or rec.get('automatable') or rec.get('impact'): add('ssvc', '', 'decision', cve, 'CISA-ADP', '', 1, f"exploitation={rec.get('exploitation')} automatable={rec.get('automatable')} impact={rec.get('impact')}")
    for d, cid, name, target, actor, tids, url in ZW['atlas']['case_studies']: add('atlas_case_study', d, 'ai_attack_case_study', cid, actor, target, 1, f"{name} | techniques={','.join(tids)}")
    for d, rid, title, url in ZW['ai_incidents']['latest']: add('avid_incident', d, 'ai_incident_report', rid, 'AVID', '', 1, title)
    for w, n, nx in ZW['csaf']['weekly']: add('csaf_weekly', w, 'advisories', '', 'Red Hat CSAF', '', n, f'exploit_status_flagged={nx}')
    for w, n_ai, n_total in ZW['ai_found']['weekly']: add('ai_found_weekly', w, 'ai_credited_vs_total_published', '', 'cvelistV5 credits scan', '', n_ai, f'total_published={n_total}')
    for cve, d, ven, prod, matched in ZW['ai_found']['kev_overlap']: add('ai_found_exploited', d, 'ai_credited_and_kev', cve, ven, prod, 1, 'patterns=' + ','.join(matched))
    for cve, rec in ZW['ai_found']['index'].items(): add('ai_found_entry', rec.get('pub') or '', rec.get('field') or '', cve, rec.get('cna') or '', rec.get('source') or '', 1, 'patterns=' + ','.join(rec.get('matched') or []))
    for sid, rows_ in advisories_out.items():
        for d, s, title, link in rows_: add('advisory', d, sid, '', dict((r['id'], r.get('org')) for r in sources_registry).get(sid, sid), '', 1, title)
    with open(ROOT / 'zeroweek-data.csv', 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['dataset', 'period', 'series', 'id', 'vendor_or_project', 'product_or_class', 'value', 'note']); w.writerows(rows)
    write_feed(ZW)
    log(f'built: {len(ZW["kev"]["entries"])} KEV entries, {len(kw)} weeks, {len(rows)} csv rows, data through {data_through}')

def write_feed(ZW):
    site = ZW['meta']['site']['url']
    by_week = {}
    for e in ZW['kev']['entries']: by_week.setdefault(monday(e[0]).isoformat(), []).append(e)
    weeks = [w for w, *_ in ZW['kev']['weekly']][-12:][::-1]
    items = []
    for w in weeks:
        es = by_week.get(w, []); fresh = sum(1 for e in es if int(e[1].split('-')[1]) >= int(e[0][:4]))
        end = (dt.date.fromisoformat(w) + dt.timedelta(days=6)).isoformat()
        title = f'Week of {w}: {len(es)} exploited CVEs added to KEV ({fresh} fresh)'
        body = '<ul>' + ''.join(f'<li>{htmlmod.escape(e[0])} · <a href="https://nvd.nist.gov/vuln/detail/{e[1]}">{e[1]}</a> · {htmlmod.escape(e[2])} {htmlmod.escape(e[3])} — {htmlmod.escape(e[6])}</li>' for e in es) + '</ul>'
        pub = dt.datetime.fromisoformat(end).replace(tzinfo=dt.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
        items.append(f'<item><title>{htmlmod.escape(title)}</title><link>{site}#week={w}</link><guid isPermaLink="false">zeroweek-{w}</guid><pubDate>{pub}</pubDate><description>{htmlmod.escape(body)}</description></item>')
    now = dt.datetime.now(dt.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')
    xml = f'<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>Zeroweek</title><link>{site}</link><description>Zero-days exploited in the wild, AI-found vulnerabilities and vendor patch volumes — one ISO week at a time.</description><lastBuildDate>{now}</lastBuildDate>{"".join(items)}</channel></rss>'
    (ROOT / 'feed.xml').write_text(xml, encoding='utf-8')

def main():
    global ARGS, START
    ap = argparse.ArgumentParser(); ap.add_argument('--offline', action='store_true'); ap.add_argument('--force-eco', action='store_true', help='pull ecosystem counts even without a token (slow, rate-limited)')
    ap.add_argument('--skip', default='', help='comma list of fetchers to skip: kev,ledger,epoch,msrc,oracle,gh_eco,gh_repos,dotnet,cve_pub,nvd_watchlist,extra_feeds,euvd,epss,p0,exploit,ssvc,advisories,atlas,avid,csaf,ai_credit')
    ap.add_argument('--watchlist-limit', type=int, default=None, help='only process the first N watchlist products in fetch_nvd_watchlist (first full run is slow: ~51 products x ~18 windows x 6.5s unkeyed)')
    ap.add_argument('--ai-credit-full', action='store_true', help='force a full cvelistV5 zip rescan for fetch_ai_credit instead of the incremental delta scan')
    ap.add_argument('--since', default='2016-01-01', help='earliest date scoped into every fetcher (default 2016-01-01, i.e. a 10-year window); KEV weekly still starts at the later of this and Nov 2021 (catalog start), and the P0 sheet independently supplies 2014+')
    ARGS = ap.parse_args(); skip = set(x.strip() for x in ARGS.skip.split(',') if x.strip())
    START = dt.date.fromisoformat(ARGS.since)
    log(f'[scope] START={START.isoformat()} (--since={ARGS.since})')
    run = lambda name, fn, *a: (cache_get(name) if name in skip else fn(*a))
    kev = run('kev', fetch_kev); ledger = run('ledger', fetch_ledger); epoch = run('epoch', fetch_epoch)
    msrc = run('msrc', fetch_msrc); oracle = run('oracle', fetch_oracle)
    eco = run('gh_eco', fetch_gh_eco); repos = run('gh_repos', fetch_gh_repos); dotnet = run('dotnet', fetch_dotnet)
    cve_pub = run('cve_pub', fetch_cve_published, kev)
    nvd_watchlist = run('nvd_watchlist', fetch_nvd_watchlist)
    extra_feeds = run('extra_feeds', fetch_extra_feeds)
    if not kev: sys.exit('no KEV data (network and cache both unavailable)')
    euvd = run('euvd', fetch_euvd)
    kev_cves_for_epss = {e[1] for e in (kev or {}).get('entries', [])}
    euvd_cves_for_epss = set()
    for e in (euvd or {}).get('entries', []): euvd_cves_for_epss.update(e[2])
    epss = run('epss', fetch_epss, sorted(kev_cves_for_epss | euvd_cves_for_epss))
    p0 = run('p0', fetch_p0)
    exploit = run('exploit', fetch_exploit, sorted(kev_cves_for_epss))
    ssvc = run('ssvc', fetch_ssvc, sorted(kev_cves_for_epss))
    advisories = run('advisories', fetch_advisories)
    atlas = run('atlas', fetch_atlas)
    avid = run('avid', fetch_avid)
    csaf = run('csaf', fetch_csaf)
    ai_credit = run('ai_credit', fetch_ai_credit)
    build(kev, ledger, epoch, msrc, oracle, eco, repos, dotnet, cve_pub, nvd_watchlist, extra_feeds,
          euvd, epss, p0, exploit, ssvc, advisories, atlas, avid, csaf, ai_credit)
    (CACHE / 'last_run.log').write_text('\n'.join(LOG), encoding='utf-8')

if __name__ == '__main__':
    main()
