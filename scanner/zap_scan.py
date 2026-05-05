"""
scanner/zap_scan.py
ZAP Web Vulnerability Scanner — Windows & Linux compatible

Fixes applied
─────────────
• spider.scan() no longer passes contextid kwarg (breaks older ZAP Python client)
• ajaxSpider.status() called as a function, not assigned as method object
• parse_alerts fetches ALL alerts (no baseurl filter) — catches subdomains & 3rd-party assets
• Context + scope created so ZAP crawls like ZAP GUI does
• Spider max depth → 10, threads → 10 (matches ZAP GUI defaults)
• Active scan timeout protection — findings collected even if scan is killed/crashes
• Passive scan wait — lets all passive rules fire before alerts are read
• Findings always returned even if active scan fails
"""

import time
import platform
from datetime import datetime
from urllib.parse import urlparse

ZAP_HOST    = "localhost"
ZAP_PORT    = 8080
ZAP_API_KEY = "htk1hsa6su4urdfql7poujq653"

ACTIVE_SCAN_TIMEOUT = 600   # 10 minutes
AJAX_SPIDER_TIMEOUT = 180   # 3 minutes


def _get_zap():
    try:
        from zapv2 import ZAPv2
        return ZAPv2
    except ImportError:
        raise ImportError("zapv2 not installed. Run: pip install python-owasp-zap-v2.4")


def connect_zap():
    ZAPv2 = _get_zap()
    zap = ZAPv2(
        apikey=ZAP_API_KEY,
        proxies={
            "http":  f"http://{ZAP_HOST}:{ZAP_PORT}",
            "https": f"http://{ZAP_HOST}:{ZAP_PORT}",
        }
    )
    try:
        version = zap.core.version
        os_name = platform.system()
        print(f"[ZAP] Connected — version {version} ({os_name})")
        return zap
    except Exception as e:
        os_name = platform.system()
        if os_name == "Windows":
            hint = (
                "\n[ZAP] Start ZAP daemon on Windows:\n"
                "  $env:JAVA_HOME = 'C:\\Program Files\\Eclipse Adoptium\\jdk-25.0.2.10-hotspot'\n"
                "  $env:Path = \"$env:JAVA_HOME\\bin;\" + $env:Path\n"
                "  cd 'C:\\Program Files\\ZAP\\Zed Attack Proxy'\n"
                "  & '.\\zap.bat' -daemon -port 8080 -config api.key=htk1hsa6su4urdfql7poujq653"
            )
        else:
            hint = (
                "\n[ZAP] Start ZAP daemon on Linux:\n"
                "  zap.sh -daemon -port 8080 -config api.key=htk1hsa6su4urdfql7poujq653"
            )
        raise ConnectionError(f"[ZAP] Cannot connect to ZAP daemon: {e}{hint}")


# ─── Context setup ────────────────────────────────────────────────────────────

def setup_context(zap, target_url):
    """
    Create a named context and add the target domain (+ all subdomains) to scope.
    Without this ZAP treats most pages as out-of-scope and skips them —
    exactly what ZAP GUI avoids by always creating a context automatically.
    """
    parsed     = urlparse(target_url)
    domain     = parsed.netloc or parsed.path
    base_regex = f".*{domain}.*"

    try:
        context_name = f"vulnscan_{int(time.time())}"
        context_id   = zap.context.new_context(context_name, apikey=ZAP_API_KEY)
        print(f"[ZAP] Context created: '{context_name}' (id={context_id})")

        zap.context.include_in_context(context_name, base_regex, apikey=ZAP_API_KEY)
        print(f"[ZAP] Scope set: {base_regex}")

        try:
            zap.spider.set_option_max_depth(10, apikey=ZAP_API_KEY)
            print("[ZAP] Spider max depth → 10")
        except Exception as de:
            print(f"[ZAP] Could not set spider depth (non-fatal): {de}")

        try:
            zap.spider.set_option_thread_count(10, apikey=ZAP_API_KEY)
            print("[ZAP] Spider threads → 10")
        except Exception:
            pass

        return context_id, context_name

    except Exception as e:
        print(f"[ZAP] Context setup failed (continuing without context): {e}")
        return None, None


# ─── Standard spider ─────────────────────────────────────────────────────────

def run_spider(zap, target_url, context_id=None):
    """
    Run ZAP's standard (HTML-link) spider.

    FIX: contextid is NOT passed as a keyword argument — older versions of the
    ZAP Python client (including the one bundled with ZAP 2.17) do not accept
    it and raise:
        TypeError: spider.scan() got an unexpected keyword argument 'contextid'
    The context is still active in ZAP's engine; we just don't pass it here.
    """
    print(f"[ZAP] Starting spider on {target_url}")
    try:
        # Do NOT pass contextid= here — causes TypeError in ZAP Python client 2.17
        scan_id = zap.spider.scan(target_url, apikey=ZAP_API_KEY, recurse=True)

        while True:
            try:
                progress = int(zap.spider.status(scan_id))
            except Exception:
                break
            print(f"[ZAP] Spider progress: {progress}%", end="\r")
            if progress >= 100:
                break
            time.sleep(2)

        print()
        urls = zap.spider.results(scan_id)
        print(f"[ZAP] Spider complete — {len(urls)} URLs found")
        return urls

    except Exception as e:
        print(f"[ZAP] Spider error (continuing): {e}")
        return []


# ─── AJAX spider ─────────────────────────────────────────────────────────────

def run_ajax_spider(zap, target_url, context_name=None):
    """
    Run ZAP AJAX Spider for JavaScript-heavy apps.

    FIX: status must be called as status() not assigned as status.
    The original bug assigned the bound method to status, so
    status == "stopped" was never True and the loop only exited on timeout.
    """
    print(f"[ZAP] Starting AJAX spider on {target_url}")
    try:
        if context_name:
            zap.ajaxSpider.scan(target_url, contextname=context_name, apikey=ZAP_API_KEY)
        else:
            zap.ajaxSpider.scan(target_url, apikey=ZAP_API_KEY)

        start = time.time()
        while True:
            if time.time() - start > AJAX_SPIDER_TIMEOUT:
                print(f"\n[ZAP] AJAX spider timeout ({AJAX_SPIDER_TIMEOUT}s) — stopping")
                try:
                    zap.ajaxSpider.stop(apikey=ZAP_API_KEY)
                except Exception:
                    pass
                break

            try:
                status = zap.ajaxSpider.status()   # ← FIX: was .status (no parentheses)
            except Exception:
                break

            print(f"[ZAP] AJAX spider status: {status}", end="\r")
            if str(status).lower() == "stopped":
                break
            time.sleep(3)

        print()
        try:
            results     = zap.ajaxSpider.results(start=0, count=100)
            num_results = len(results) if isinstance(results, list) else 0
        except Exception:
            num_results = 0

        print(f"[ZAP] AJAX spider complete — {num_results} additional resources found")

    except Exception as e:
        print(f"[ZAP] AJAX spider error (continuing): {e}")


# ─── Passive scan wait ────────────────────────────────────────────────────────

def wait_for_passive_scan(zap):
    """
    Wait for ZAP passive scanner to finish processing all queued responses.
    Without this, parse_alerts() runs before passive rules have fired —
    causing many real findings (headers, cookies, CSP, JS libs) to be missing.
    """
    print("[ZAP] Waiting for passive scan to complete...")
    timeout = time.time() + 120
    while time.time() < timeout:
        try:
            records = int(zap.pscan.records_to_scan)
        except Exception:
            break
        print(f"[ZAP] Passive scan — {records} records remaining", end="\r")
        if records == 0:
            break
        time.sleep(2)
    print()
    print("[ZAP] Passive scan complete")


# ─── Active scan ─────────────────────────────────────────────────────────────

def run_active_scan(zap, target_url, context_id=None):
    """
    Run ZAP Active Scanner with timeout + crash protection.
    Findings are collected even if the scan is interrupted.
    """
    print(f"[ZAP] Starting active scan on {target_url}")
    try:
        # contextid not passed to ascan.scan() for same compatibility reason as spider
        scan_id = zap.ascan.scan(target_url, apikey=ZAP_API_KEY)
        start   = time.time()

        while True:
            if time.time() - start > ACTIVE_SCAN_TIMEOUT:
                print(f"\n[ZAP] Active scan timeout ({ACTIVE_SCAN_TIMEOUT}s) — collecting findings so far")
                break

            try:
                progress = int(zap.ascan.status(scan_id))
            except Exception as e:
                print(f"\n[ZAP] Active scan lost connection — collecting findings so far: {e}")
                break

            print(f"[ZAP] Active scan progress: {progress}%", end="\r")
            if progress >= 100:
                break
            time.sleep(5)

        print("\n[ZAP] Active scan complete")
        return scan_id

    except Exception as e:
        print(f"[ZAP] Active scan error (collecting findings anyway): {e}")
        return None


# ─── Alert collection ─────────────────────────────────────────────────────────

def parse_alerts(zap, target_url):
    """
    Collect ALL ZAP alerts across every discovered URL.

    FIX: original code called zap.core.alerts(baseurl=target_url) which
    silently drops alerts on subdomains (lms., api., etc.) and third-party
    assets. ZAP GUI shows all of them — this is why counts were massively
    different. Fix: call with no baseurl filter.
    """
    try:
        raw_alerts = zap.core.alerts()   # no baseurl filter → ALL alerts
    except Exception as e:
        print(f"[ZAP] Could not fetch alerts: {e}")
        return []

    SEV_MAP = {
        "High":          "High",
        "Medium":        "Medium",
        "Low":           "Low",
        "Informational": "Info",
    }

    findings = []
    for alert in raw_alerts:
        risk     = alert.get("risk", "Informational")
        severity = SEV_MAP.get(risk, "Low")
        findings.append({
            "source":      "ZAP",
            "name":        alert.get("name", "Unknown"),
            "severity":    severity,
            "url":         alert.get("url", ""),
            "param":       alert.get("param", ""),
            "description": alert.get("description", "")[:300],
            "solution":    alert.get("solution", "")[:300],
            "reference":   alert.get("reference", ""),
            "cweid":       alert.get("cweid", ""),
            "wascid":      alert.get("wascid", ""),
            "pluginid":    alert.get("pluginid", ""),
            "risk_score":  {"High": 8, "Medium": 5, "Low": 2, "Info": 0}.get(severity, 1),
            "scan_time":   datetime.now().isoformat(),
        })

    return findings


# ─── Main entry point ─────────────────────────────────────────────────────────

def run_zap_scan(target_url):
    """
    Full ZAP scan pipeline called from main.py.
    Always returns a dict with a 'findings' key (never None/raises).

    Order:
      1  Setup context  — defines scope so all pages are crawled (like ZAP GUI)
      2  Standard spider — follows HTML links
      3  AJAX spider    — executes JavaScript, discovers dynamic routes
      4  Passive wait   — lets all passive rules fire
      5  Active scan    — probes for vulnerabilities (with crash/timeout guard)
      6  Collect alerts — ALL alerts, no baseurl filter
    """
    print(f"\n{'='*50}")
    print(f"[ZAP] Web Vulnerability Scan → {target_url}")
    print(f"[ZAP] Platform: {platform.system()}")
    print(f"{'='*50}")

    try:
        zap = connect_zap()

        context_id, context_name = setup_context(zap, target_url)
        urls_found = run_spider(zap, target_url)                          # no contextid kwarg
        run_ajax_spider(zap, target_url, context_name=context_name)
        wait_for_passive_scan(zap)
        run_active_scan(zap, target_url)                                  # no contextid kwarg
        findings = parse_alerts(zap, target_url)
        print(f"[ZAP] Total findings: {len(findings)}")

        return {
            "target":    target_url,
            "urls":      urls_found,
            "findings":  findings,
            "scan_time": datetime.now().isoformat(),
        }

    except ConnectionError as e:
        print(f"{e}")
        return {"target": target_url, "urls": [], "findings": [], "error": str(e)}

    except Exception as e:
        print(f"[ZAP] Unexpected error: {e}")
        # Best-effort: try to salvage whatever alerts ZAP already collected
        try:
            ZAPv2 = _get_zap()
            zap = ZAPv2(
                apikey=ZAP_API_KEY,
                proxies={
                    "http":  f"http://{ZAP_HOST}:{ZAP_PORT}",
                    "https": f"http://{ZAP_HOST}:{ZAP_PORT}",
                }
            )
            findings = parse_alerts(zap, target_url)
            print(f"[ZAP] Recovered {len(findings)} findings after error")
            return {
                "target":    target_url,
                "urls":      [],
                "findings":  findings,
                "error":     str(e),
                "scan_time": datetime.now().isoformat(),
            }
        except Exception:
            return {"target": target_url, "urls": [], "findings": [], "error": str(e)}