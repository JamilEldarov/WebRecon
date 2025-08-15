#!/usr/bin/env python3
"""
WebReconX — compact web recon helper for coursework/web pentesting demos.

Features (pick via --mode):
  • dir         — directory enumeration with threads + status filtering
  • admin       — admin/login panel finder
  • tech        — lightweight tech & CMS fingerprint from headers + HTML
  • js          — scrape JS files, extract endpoints/keys
  • params      — basic parameter fuzz (LFI/SQLi/XSS hints + reflection)
  • all         — run everything above in a sane order

Outputs:
  • Pretty console output
  • Optional JSON report: --out report.json
  • Optional CSV for dir/admin hits: --csv hits.csv

Dependencies: only Python 3.8+, standard libs + requests, beautifulsoup4 (optional but used for HTML parsing).

Safe defaults: timeouts, polite rate limiting, and scope control to the target host.
This tool is for educational use against systems you have permission to test.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import hashlib
import json
import os
import queue
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlencode, urlsplit, urlunsplit, parse_qsl

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except Exception as e:
    print("[!] This script needs 'requests'. Install with: pip install requests", file=sys.stderr)
    raise

try:
    from bs4 import BeautifulSoup  # type: ignore
except Exception:
    BeautifulSoup = None  # we can still run without it

# -------------- Utility --------------

def normalize_base(url: str) -> str:
    if not re.match(r'^https?://', url):
        url = 'http://' + url
    parsed = urlsplit(url)
    # remove path/query/fragment for base
    return urlunsplit((parsed.scheme, parsed.netloc, '/', '', ''))


def make_session(timeout: int = 10, retries: int = 2) -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=0.3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
    s.mount('http://', adapter)
    s.mount('https://', adapter)
    s.headers.update({
        'User-Agent': 'WebReconX/1.0 (+educational)'
    })
    s.request_timeout = timeout  # custom attr
    return s


def safe_get(session: requests.Session, url: str, **kw):
    try:
        return session.get(url, timeout=session.request_timeout, allow_redirects=True, **kw)
    except requests.RequestException:
        return None


# -------------- Data structures --------------

@dataclass
class Hit:
    url: str
    status: int
    length: int
    title: Optional[str] = None

@dataclass
class Report:
    base: str
    dir_hits: List[Hit] = field(default_factory=list)
    admin_hits: List[Hit] = field(default_factory=list)
    tech: Dict[str, str] = field(default_factory=dict)
    cms_hints: Set[str] = field(default_factory=set)
    js_endpoints: Set[str] = field(default_factory=set)
    js_suspects: Set[str] = field(default_factory=set)
    param_reflections: List[Tuple[str, str]] = field(default_factory=list)  # (url, param)
    lfi_hints: List[str] = field(default_factory=list)
    sqli_hints: List[str] = field(default_factory=list)

    def to_json(self) -> str:
        def hit_to_dict(h: Hit):
            return {"url": h.url, "status": h.status, "length": h.length, "title": h.title}
        return json.dumps({
            "base": self.base,
            "dir_hits": [hit_to_dict(h) for h in self.dir_hits],
            "admin_hits": [hit_to_dict(h) for h in self.admin_hits],
            "tech": self.tech,
            "cms_hints": sorted(self.cms_hints),
            "js_endpoints": sorted(self.js_endpoints),
            "js_suspects": sorted(self.js_suspects),
            "param_reflections": self.param_reflections,
            "lfi_hints": self.lfi_hints,
            "sqli_hints": self.sqli_hints,
        }, indent=2)

# -------------- Pretty printing --------------

class Color:
    try:
        from colorama import Fore, Style  # type: ignore
        OK = Fore.GREEN
        INFO = Fore.CYAN
        WARN = Fore.YELLOW
        BAD = Fore.RED
        DIM = Style.DIM
        RESET = Style.RESET_ALL
    except Exception:
        OK = INFO = WARN = BAD = DIM = RESET = ''


def brief_title(html: str) -> Optional[str]:
    if not html:
        return None
    m = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
    if m:
        title = re.sub(r'\s+', ' ', m.group(1)).strip()
        return title[:120]
    return None

# -------------- Wordlists --------------

ADMIN_WORDS = [
    'admin', 'administrator', 'login', 'dashboard', 'cpanel', 'wp-admin', 'wp-login.php',
    'user', 'manage', 'backend', 'panel', 'auth', 'signin', 'account', 'staff', 'secret',
]

COMMON_PARAMS = [
    'id', 'page', 'q', 'search', 'file', 'path', 'lang', 'redirect', 'next', 'url', 'view', 'cat', 'dir'
]

LFI_PAYLOADS = [
    '../../etc/passwd', '../etc/passwd', '/etc/passwd', '..%2f..%2fetc%2fpasswd'
]

SQLI_PAYLOADS = ["'", '"', '1 OR 1=1', "1' OR '1'='1", '1) OR (1=1']

JS_ENDPOINT_REGEX = re.compile(r"(?:(?:https?://|/)[\w\-./%?#=&]+)")
API_KEY_REGEXES = [
    re.compile(r'(?:api[_-]?key|apikey|x-api-key)\s*[:=]\s*[\"\']?([A-Za-z0-9_\-]{16,})', re.I),
    re.compile(r'(?:sk_live|sk_test|pk_live|pk_test)_[A-Za-z0-9]{10,}', re.I),  # Stripe-like
    re.compile(r'AKIA[0-9A-Z]{16}'),  # AWS key id pattern
]

CMS_HINTS = [
    ('WordPress', ['/wp-content/', '/wp-includes/', 'wp-json']),
    ('Joomla', ['/administrator/', '/templates/']),
    ('Drupal', ['/sites/default/', 'drupal.js']),
]

# -------------- Core tasks --------------

def enumerate_paths(base: str, session: requests.Session, words: List[str], threads: int, status_keep: Set[int], delay: float) -> List[Hit]:
    hits: List[Hit] = []
    lock = threading.Lock()

    def worker(path: str):
        url = urljoin(base, path.lstrip('/'))
        r = safe_get(session, url)
        if not r:
            return
        if r.status_code in status_keep or (200 <= r.status_code < 400):
            h = Hit(url=url, status=r.status_code, length=len(r.content), title=brief_title(r.text or ''))
            with lock:
                hits.append(h)
                print(f"{Color.OK}[HIT]{Color.RESET} {h.status} {h.length:6d} {h.url} {('- ' + h.title) if h.title else ''}")
        if delay:
            time.sleep(delay)

    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        for w in words:
            if not w:
                continue
            if not w.startswith('/'):
                w = '/' + w
            ex.submit(worker, w)
    return hits


def admin_finder(base: str, session: requests.Session, extra: Optional[List[str]] = None) -> List[Hit]:
    words = ADMIN_WORDS.copy()
    if extra:
        words.extend(extra)
    return enumerate_paths(base, session, words, threads=10, status_keep={200, 302, 401, 403}, delay=0.0)


def tech_fingerprint(base: str, session: requests.Session) -> Tuple[Dict[str, str], Set[str]]:
    tech: Dict[str, str] = {}
    cms: Set[str] = set()
    r = safe_get(session, base)
    if not r:
        return tech, cms

    # Headers
    for k in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Drupal-Cache", "X-Generator"]:
        if k in r.headers:
            tech[k] = r.headers.get(k, '')

    # Cookies hints
    cookies = ",".join(r.cookies.keys())
    if cookies:
        tech["Cookies"] = cookies

    # HTML meta generator
    if r.text and BeautifulSoup:
        soup = BeautifulSoup(r.text, 'html.parser')
        gen = soup.find('meta', attrs={'name': re.compile('generator', re.I)})
        if gen and gen.get('content'):
            tech['Generator'] = gen['content']
        # quick title
        t = soup.find('title')
        if t and t.text:
            tech['Title'] = re.sub(r'\s+', ' ', t.text).strip()[:120]

    # CMS path-based hints
    for name, markers in CMS_HINTS:
        for m in markers:
            url = urljoin(base, m.lstrip('/'))
            rr = safe_get(session, url)
            if rr and rr.status_code in (200, 301, 302, 403):
                cms.add(name)
                break

    return tech, cms


def scrape_js_and_extract(base: str, session: requests.Session) -> Tuple[Set[str], Set[str]]:
    endpoints: Set[str] = set()
    suspects: Set[str] = set()

    r = safe_get(session, base)
    if not r or not r.text:
        return endpoints, suspects

    html = r.text
    # find script src
    srcs: Set[str] = set()
    if BeautifulSoup:
        soup = BeautifulSoup(html, 'html.parser')
        for s in soup.find_all('script'):
            src = s.get('src')
            if src:
                srcs.add(urljoin(base, src))
    else:
        srcs.update(re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I))
        srcs = {urljoin(base, s) for s in srcs}

    # include main page inline JS too
    to_scan = [(base, html)]

    # fetch external js
    for s in sorted(srcs):
        rr = safe_get(session, s)
        if rr and rr.text:
            to_scan.append((s, rr.text))

    for origin, text in to_scan:
        for m in JS_ENDPOINT_REGEX.findall(text):
            # keep in-scope endpoints only (same host or relative)
            if m.startswith('http'):
                if urlsplit(m).netloc == urlsplit(base).netloc:
                    endpoints.add(m)
            else:
                endpoints.add(urljoin(base, m))
        for rgx in API_KEY_REGEXES:
            for k in rgx.findall(text):
                if isinstance(k, tuple):
                    k = k[0]
                suspects.add(f"{origin} :: {str(k)[:80]}")

    return endpoints, suspects


def param_fuzz(base: str, session: requests.Session, paths: Optional[List[str]] = None, sample: int = 10) -> Tuple[List[Tuple[str, str]], List[str], List[str]]:
    reflections: List[Tuple[str, str]] = []
    lfi_hints: List[str] = []
    sqli_hints: List[str] = []

    targets: List[str] = []

    # Use root and common pages; add from enumeration paths if given
    candidates = ['/', 'index.php', 'index.html', 'home', 'search', 'view', 'page']
    if paths:
        candidates.extend([urlsplit(p).path for p in paths])
    seen = set()
    for c in candidates:
        url = urljoin(base, c.lstrip('/'))
        if url not in seen:
            targets.append(url)
            seen.add(url)
    targets = targets[:max(sample, 1)]

    for t in targets:
        for param in COMMON_PARAMS:
            payload = "wrxTEST123"
            q = dict(parse_qsl(urlsplit(t).query))
            q[param] = payload
            url_with = urlunsplit((*urlsplit(t)[:3], urlencode(q), ''))
            r = safe_get(session, url_with)
            if not r or not r.text:
                continue
            body = r.text
            if payload in body:
                reflections.append((url_with, param))
            # LFI quick check
            if param in ('file', 'path', 'dir'):
                for lf in LFI_PAYLOADS:
                    q[param] = lf
                    url_lfi = urlunsplit((*urlsplit(t)[:3], urlencode(q), ''))
                    rr = safe_get(session, url_lfi)
                    if rr and rr.text and ('root:x:0:0:' in rr.text or '/bin/bash' in rr.text):
                        lfi_hints.append(url_lfi)
                        break
            # SQLi quick check: look for DB error signatures
            if param in ('id', 'page', 'cat', 'view'):
                for sp in SQLI_PAYLOADS:
                    q[param] = sp
                    url_sql = urlunsplit((*urlsplit(t)[:3], urlencode(q), ''))
                    rr = safe_get(session, url_sql)
                    if rr and rr.text and re.search(r"(SQL syntax|sqlite error|PDOException|mysql_fetch|ODBC|pg_query)", rr.text, re.I):
                        sqli_hints.append(url_sql)
                        break

    return reflections, lfi_hints, sqli_hints

# -------------- Robots.txt (bonus) --------------

def parse_robots(base: str, session: requests.Session) -> List[str]:
    robots_url = urljoin(base, '/robots.txt')
    r = safe_get(session, robots_url)
    found: List[str] = []
    if not r or r.status_code >= 400 or not r.text:
        return found
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        m = re.match(r'(?:Disallow|Allow):\s*(\S+)', line, re.I)
        if m:
            path = m.group(1)
            if path and path != '/':
                found.append(path)
    return found

# -------------- CSV helper --------------

def save_csv(path: str, hits: List[Hit]):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['url', 'status', 'length', 'title'])
        for h in hits:
            w.writerow([h.url, h.status, h.length, h.title or ''])

# -------------- Main runner --------------

def run(args):
    base = normalize_base(args.url)
    session = make_session(timeout=args.timeout, retries=args.retries)

    report = Report(base=base)

    # robots hints can feed dir enumeration
    robots_paths = parse_robots(base, session)
    if robots_paths:
        print(f"{Color.INFO}[i]{Color.RESET} robots.txt hints: {', '.join(robots_paths[:10])}{' ...' if len(robots_paths) > 10 else ''}")

    # load wordlist
    words: List[str] = []
    if args.wordlist and os.path.exists(args.wordlist):
        with open(args.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                w = line.strip()
                if w and not w.startswith('#'):
                    words.append(w)
    else:
        # small built-in list as fallback
        words = [
            'admin', 'login', 'uploads', 'images', 'css', 'js', 'api', 'dashboard', 'backup', 'old', 'test',
            'vendor', 'server-status', '.git/', '.svn/', 'config', 'phpinfo.php', 'sitemap.xml', 'robots.txt',
        ]

    # merge robots paths to words
    words.extend([p.lstrip('/') for p in robots_paths])

    def do_dir():
        print(f"\n{Color.INFO}[i]{Color.RESET} Running directory enumeration on {base} with {args.threads} threads ...")
        hits = enumerate_paths(base, session, words, threads=args.threads, status_keep={200, 204, 301, 302, 307, 401, 403}, delay=args.delay)
        report.dir_hits.extend(hits)
        if args.csv:
            save_csv(args.csv, hits)
            print(f"{Color.INFO}[i]{Color.RESET} Saved CSV hits to {args.csv}")

    def do_admin():
        print(f"\n{Color.INFO}[i]{Color.RESET} Finding admin/login panels ...")
        a_hits = admin_finder(base, session)
        report.admin_hits.extend(a_hits)

    def do_tech():
        print(f"\n{Color.INFO}[i]{Color.RESET} Fingerprinting technology ...")
        tech, cms = tech_fingerprint(base, session)
        report.tech.update(tech)
        report.cms_hints.update(cms)
        if tech:
            for k, v in tech.items():
                print(f"  {k}: {v}")
        if cms:
            print(f"  CMS hints: {', '.join(sorted(cms))}")

    def do_js():
        print(f"\n{Color.INFO}[i]{Color.RESET} Scraping JS and extracting endpoints/keys ...")
        eps, sus = scrape_js_and_extract(base, session)
        report.js_endpoints.update(eps)
        report.js_suspects.update(sus)
        if eps:
            print(f"  Endpoints ({len(eps)}):")
            for e in sorted(list(eps))[:50]:
                print(f"    - {e}")
            if len(eps) > 50:
                print("    ... (truncated)")
        if sus:
            print("  Suspected keys/tokens:")
            for s in list(sus)[:30]:
                print(f"    - {s}")
            if len(sus) > 30:
                print("    ... (truncated)")

    def do_params():
        print(f"\n{Color.INFO}[i]{Color.RESET} Parameter fuzzing (reflection/LFI/SQLi hints) ...")
        sample_from = [h.url for h in report.dir_hits][:15] if report.dir_hits else None
        refl, lfi, sqli = param_fuzz(base, session, sample_from, sample=args.sample)
        report.param_reflections.extend(refl)
        report.lfi_hints.extend(lfi)
        report.sqli_hints.extend(sqli)
        if refl:
            print("  Reflections:")
            for u, p in refl:
                print(f"    - {p} reflected at {u}")
        if lfi:
            print("  LFI error/content hints:")
            for u in lfi:
                print(f"    - {u}")
        if sqli:
            print("  SQL error hints:")
            for u in sqli:
                print(f"    - {u}")

    # orchestrate
    if args.mode == 'dir':
        do_dir()
    elif args.mode == 'admin':
        do_admin()
    elif args.mode == 'tech':
        do_tech()
    elif args.mode == 'js':
        do_js()
    elif args.mode == 'params':
        do_params()
    elif args.mode == 'all':
        do_tech(); do_dir(); do_admin(); do_js(); do_params()
    else:
        print("Unknown mode", file=sys.stderr)
        sys.exit(2)

    if args.out:
        with open(args.out, 'w', encoding='utf-8') as f:
            f.write(report.to_json())
        print(f"\n{Color.INFO}[i]{Color.RESET} Saved JSON report to {args.out}")


def main():
    p = argparse.ArgumentParser(description='WebReconX — compact web recon helper for coursework demos')
    p.add_argument('--url', required=True, help='Target base URL (e.g., https://example.com)')
    p.add_argument('--mode', choices=['dir', 'admin', 'tech', 'js', 'params', 'all'], default='all', help='Which module to run')
    p.add_argument('--wordlist', help='Path wordlist for dir enum (default: small built-in)')
    p.add_argument('--threads', type=int, default=20, help='Threads for dir enum (default: 20)')
    p.add_argument('--timeout', type=int, default=10, help='Per-request timeout seconds (default: 10)')
    p.add_argument('--retries', type=int, default=2, help='HTTP retry count (default: 2)')
    p.add_argument('--delay', type=float, default=0.0, help='Optional delay between requests in dir enum (seconds)')
    p.add_argument('--sample', type=int, default=10, help='Max pages to probe in param fuzz (default: 10)')
    p.add_argument('--out', help='Save JSON report path')
    p.add_argument('--csv', help='Save CSV of dir/admin hits')

    args = p.parse_args()
    try:
        run(args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")


if __name__ == '__main__':
    main()
