"""
scanner/zap_scan.py
ZAP Web Vulnerability Scanner — Windows & Linux compatible
Fixes:
  - ZAP daemon crash mid-scan: alerts collected before scan 100% check
  - Progress printed cleanly (no rich.Progress interference)
  - Timeout protection on active scan polling
  - Findings always returned even if active scan fails
"""

import time
import platform
from datetime import datetime

ZAP_HOST    = "localhost"
ZAP_PORT    = 8080
ZAP_API_KEY = "htk1hsa6su4urdfql7poujq653"

# Active scan timeout — 10 minutes max
ACTIVE_SCAN_TIMEOUT = 600


def _get_zap():
    """Import zapv2 here to give clear error if not installed."""
    try:
        from zapv2 import ZAPv2
        return ZAPv2
    except ImportError:
        raise ImportError(
            "zapv2 not installed. Run: pip install python-owasp-zap-v2.4"
        )


def connect_zap():
    """Connect to running ZAP daemon and verify connection."""
    ZAPv2 = _get_zap()
    zap = ZAPv2(
        apikey=ZAP_API_KEY,
        proxies={
            "http":  f"http://{ZAP_HOST}:{ZAP_PORT}",
            "https": f"http://{ZAP_HOST}:{ZAP_PORT}"
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
                "  zap.sh -daemon -port 8080 -config api.key=htk1hsa6su4urdfql7poujq653\n"
                "  OR: zaproxy -daemon -port 8080 -config api.key=htk1hsa6su4urdfql7poujq653"
            )
        raise ConnectionError(f"[ZAP] Cannot connect to ZAP daemon: {e}{hint}")


def run_spider(zap, target_url):
    """Run ZAP Spider to crawl the target."""
    print(f"[ZAP] Starting spider on {target_url}")
    try:
        scan_id = zap.spider.scan(target_url, apikey=ZAP_API_KEY)
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


def run_active_scan(zap, target_url):
    """
    Run ZAP Active Scanner.
    Returns scan_id or None on error.
    Includes timeout so the process does not hang forever.
    """
    print(f"[ZAP] Starting active scan on {target_url}")
    try:
        scan_id   = zap.ascan.scan(target_url, apikey=ZAP_API_KEY)
        start     = time.time()

        while True:
            # Timeout guard
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


def parse_alerts(zap, target_url):
    """Collect and normalize all ZAP alerts regardless of scan status."""
    try:
        raw_alerts = zap.core.alerts(baseurl=target_url)
    except Exception as e:
        print(f"[ZAP] Could not fetch alerts: {e}")
        return []

    severity_map = {
        "High":          "High",
        "Medium":        "Medium",
        "Low":           "Low",
        "Informational": "Info"
    }

    findings = []
    for alert in raw_alerts:
        risk     = alert.get("risk", "Informational")
        severity = severity_map.get(risk, "Low")
        findings.append({
            "source":      "ZAP",
            "name":        alert.get("name", "Unknown"),
            "severity":    severity,
            "url":         alert.get("url", ""),
            "param":       alert.get("param", ""),
            "description": alert.get("description", "")[:300],
            "solution":    alert.get("solution", "")[:300],
            "reference":   alert.get("reference", ""),
            "cwe":         alert.get("cweid", ""),
            "wasc":        alert.get("wascid", ""),
            "risk_score":  {"High": 8, "Medium": 5, "Low": 2, "Info": 0}.get(severity, 1),
            "scan_time":   datetime.now().isoformat()
        })

    return findings


def run_zap_scan(target_url):
    """
    Main ZAP scan entry point called from main.py.
    Always returns a dict with 'findings' key (never None).
    """
    print(f"\n{'='*50}")
    print(f"[ZAP] Web Vulnerability Scan → {target_url}")
    print(f"[ZAP] Platform: {platform.system()}")
    print(f"{'='*50}")

    try:
        zap = connect_zap()

        # Spider first
        urls_found = run_spider(zap, target_url)

        # Active scan (with crash/timeout protection)
        run_active_scan(zap, target_url)

        # Collect ALL alerts — even if active scan died mid-way
        findings = parse_alerts(zap, target_url)
        print(f"[ZAP] Total findings: {len(findings)}")

        return {
            "target":    target_url,
            "urls":      urls_found,
            "findings":  findings,
            "scan_time": datetime.now().isoformat()
        }

    except ConnectionError as e:
        print(f"{e}")
        return {"target": target_url, "urls": [], "findings": [], "error": str(e)}

    except Exception as e:
        print(f"[ZAP] Unexpected error: {e}")
        # Still try to collect whatever alerts exist
        try:
            ZAPv2 = _get_zap()
            zap = ZAPv2(
                apikey=ZAP_API_KEY,
                proxies={
                    "http":  f"http://{ZAP_HOST}:{ZAP_PORT}",
                    "https": f"http://{ZAP_HOST}:{ZAP_PORT}"
                }
            )
            findings = parse_alerts(zap, target_url)
            print(f"[ZAP] Recovered {len(findings)} findings after error")
            return {
                "target":   target_url,
                "urls":     [],
                "findings": findings,
                "error":    str(e),
                "scan_time": datetime.now().isoformat()
            }
        except Exception:
            return {"target": target_url, "urls": [], "findings": [], "error": str(e)}