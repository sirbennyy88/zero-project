#!/usr/bin/env python3
"""Zeroweek weekly refresh pipeline (stdlib only, Python 3.10+).

Pulls every primary feed, rebuilds zeroweek-data.js / .json / .csv and feed.xml in the site root.

    python data-src/refresh.py            # full refresh (uses cache for slow/rate-limited sources)
    python data-src/refresh.py --offline  # rebuild outputs from cache only, no network
    GITHUB_TOKEN=ghp_... python data-src/refresh.py   # enables per-ecosystem monthly counts (many requests)

Every fetcher is independent: if one source is down, the previous cached result is used and the run still succeeds.
"""
import argparse, csv, datetime as dt, gzip, io, json, math, os, pathlib, re, statistics, sys, time, urllib.request, urllib.parse, urllib.error, html as htmlmod
import xml.etree.ElementTree as ET

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
CACHE = HERE / 'cache'; CACHE.mkdir(exist_ok=True)
MANUAL = json.loads((HERE / 'manual.json').read_text(encoding='utf-8'))
TODAY = dt.date.today()
START = dt.date(2021, 1, 1)                  # 5-year scope
UA = {'User-Agent': 'zeroweek-refresh/1.0 (+https://zeroweek.peries.ca)', 'Accept-Encoding': 'gzip'}
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
    for d, cve, ven, prod, k, due, name, pub, cat, score, sev in entries:
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
    for d, cve, ven, prod, k, due, name, pub, cat, score, sev in entries:
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
    for d, cve, ven, prod, k, due, name, pub, cat, score, sev in entries:
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
@cached('oracle')
def fetch_oracle():
    prev = cache_get('oracle') or {}
    idx = http('https://www.oracle.com/security-alerts/', headers=BROWSER_UA)
    links = sorted(set(re.findall(r'/security-alerts/(cpu[a-z]{3}20\d\d\.html)', idx)))
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

# ---------------------------------------------------------------- build outputs
def build(kev, ledger, epoch, msrc, oracle, eco, repos, dotnet, cve_pub, nvd_watchlist, extra_feeds):
    data_through = max(e[0] for e in kev['entries']) if kev else TODAY.isoformat()
    cve_pub = cve_pub or {}
    kev_categories = MANUAL.get('kev_categories', {})
    kev_entries = []
    for d, cve, ven, prod, k, due, name in (kev['entries'] if kev else []):
        info = cve_pub.get(cve) or {}
        kev_entries.append([d, cve, ven, prod, k, due, name, info.get('pub') or '', categorize(ven, prod, kev_categories), info.get('score'), info.get('sev') or ''])
    kw = kev_weekly(kev_entries) if kev_entries else []
    watchlist = build_watchlist(nvd_watchlist, extra_feeds, kev_entries)
    events = [{'date': e['date'], 'label': e['label'], 'week': monday(e['date']).isoformat(), 'frac': round((dt.date.fromisoformat(e['date']).weekday() + .5) / 7, 2)} for e in MANUAL['events']]
    revealed_manual = []
    for line in (HERE / 'mythos_cves_raw.txt').read_text(encoding='utf-8').splitlines():
        if line.strip():
            i, proj, cls, sev, title = line.split('|'); revealed_manual.append({'id': i, 'project': proj, 'bug_class': cls, 'severity': sev, 'title': title})
    ZW = {
        'meta': {'generated': dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds'), 'data_through': data_through, 'scope_start': START.isoformat(),
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
    }
    (ROOT / 'zeroweek-data.js').write_text('window.ZW=' + json.dumps(ZW, ensure_ascii=False, separators=(',', ':')) + ';\n', encoding='utf-8')
    (ROOT / 'zeroweek-data.json').write_text(json.dumps(ZW, ensure_ascii=False, indent=1), encoding='utf-8')
    # tidy CSV
    rows = []
    add = lambda *r: rows.append(list(r))
    for d, cve, ven, prod, k, due, name, pub, cat, score, sev in ZW['kev']['entries']:
        note = ('same-year CVE; ' if int(cve.split('-')[1]) >= int(d[:4]) else 'older CVE; ') + ('ransomware; ' if k == 'K' else '') + name
        note += f' | published={pub} category={cat} score={score if score is not None else ""} severity={sev}'
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
    global ARGS
    ap = argparse.ArgumentParser(); ap.add_argument('--offline', action='store_true'); ap.add_argument('--force-eco', action='store_true', help='pull ecosystem counts even without a token (slow, rate-limited)')
    ap.add_argument('--skip', default='', help='comma list of fetchers to skip: kev,ledger,epoch,msrc,oracle,gh_eco,gh_repos,dotnet,cve_pub,nvd_watchlist,extra_feeds')
    ap.add_argument('--watchlist-limit', type=int, default=None, help='only process the first N watchlist products in fetch_nvd_watchlist (first full run is slow: ~51 products x ~18 windows x 6.5s unkeyed)')
    ARGS = ap.parse_args(); skip = set(x.strip() for x in ARGS.skip.split(',') if x.strip())
    run = lambda name, fn, *a: (cache_get(name) if name in skip else fn(*a))
    kev = run('kev', fetch_kev); ledger = run('ledger', fetch_ledger); epoch = run('epoch', fetch_epoch)
    msrc = run('msrc', fetch_msrc); oracle = run('oracle', fetch_oracle)
    eco = run('gh_eco', fetch_gh_eco); repos = run('gh_repos', fetch_gh_repos); dotnet = run('dotnet', fetch_dotnet)
    cve_pub = run('cve_pub', fetch_cve_published, kev)
    nvd_watchlist = run('nvd_watchlist', fetch_nvd_watchlist)
    extra_feeds = run('extra_feeds', fetch_extra_feeds)
    if not kev: sys.exit('no KEV data (network and cache both unavailable)')
    build(kev, ledger, epoch, msrc, oracle, eco, repos, dotnet, cve_pub, nvd_watchlist, extra_feeds)
    (CACHE / 'last_run.log').write_text('\n'.join(LOG), encoding='utf-8')

if __name__ == '__main__':
    main()
