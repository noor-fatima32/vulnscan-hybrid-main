import json
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from rich.console import Console

console = Console()


def generate_html_report(json_file):
    base_name   = os.path.basename(json_file).replace(".json", ".html")
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)
    html_output = os.path.join(reports_dir, base_name)
    console.print(f"[+] Generating HTML report: {json_file} → {html_output}")
    generate_report(json_file, html_output)


def generate_report(json_file, html_output):
    with open(json_file, "r", encoding="utf-8") as f:
        scan_data = json.load(f)

    if not scan_data:
        console.print("[red]No scan data found.[/red]")
        return

    target_ip = scan_data[0].get("target", "Unknown")

    # ── CVE findings ──────────────────────────────────────────────────────────
    all_vulns = []
    for result in scan_data:
        for cve in result.get("cves", []):
            all_vulns.append(cve)

    critical_count = len([v for v in all_vulns if v.get("severity") == "Critical"])
    high_count     = len([v for v in all_vulns if v.get("severity") == "High"])
    medium_count   = len([v for v in all_vulns if v.get("severity") == "Medium"])
    low_count      = len([v for v in all_vulns if v.get("severity") == "Low"])

    # ── ZAP findings ─────────────────────────────────────────────────────────
    SEV_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    SEV_MAP   = {
        "high":           "High",
        "medium":         "Medium",
        "low":            "Low",
        "informational":  "Info",
        "info":           "Info",
        "false positive": "Info",
    }

    all_zap = []
    for result in scan_data:
        zap_block = result.get("zap")
        if not zap_block or not isinstance(zap_block, dict):
            continue
        tgt = result.get("target", target_ip)
        for finding in zap_block.get("findings", []):
            raw_sev  = str(finding.get("severity", "Info")).strip()
            norm_sev = SEV_MAP.get(raw_sev.lower(), raw_sev)
            f = dict(finding)
            f["severity"] = norm_sev
            if not f.get("target"):
                f["target"] = tgt
            url = f.get("url", "")
            f["url_display"] = url if len(url) <= 80 else url[:77] + "…"
            all_zap.append(f)

    # ── Deduplicate ZAP findings by (name, url) ───────────────────────────────
    seen_zap = set()
    deduped_zap = []
    duplicates_removed = 0
    for f in all_zap:
        key = (f.get("name", ""), f.get("url", ""))
        if key in seen_zap:
            duplicates_removed += 1
            continue
        seen_zap.add(key)
        deduped_zap.append(f)
    all_zap = deduped_zap

    if duplicates_removed:
        console.print(f"[yellow]  Deduplication: removed {duplicates_removed} duplicate ZAP findings[/yellow]")

    # Sort: High → Medium → Low → Info, then alphabetically by name
    all_zap.sort(key=lambda x: (SEV_ORDER.get(x.get("severity", "Info"), 9),
                                 x.get("name", "").lower()))

    zap_high_count   = sum(1 for f in all_zap if f.get("severity") == "High")
    zap_medium_count = sum(1 for f in all_zap if f.get("severity") == "Medium")
    zap_low_count    = sum(1 for f in all_zap if f.get("severity") == "Low")
    zap_info_count   = sum(1 for f in all_zap if f.get("severity") == "Info")

    console.print(f"[cyan]  CVE findings: {len(all_vulns)} | ZAP findings: {len(all_zap)} (unique)[/cyan]")

    # ── CVSS calculator dropdown options ──────────────────────────────────────
    cvss_options = {
        "AV": [("N", "Network"), ("A", "Adjacent"), ("L", "Local"), ("P", "Physical")],
        "AC": [("L", "Low"), ("H", "High")],
        "PR": [("N", "None"), ("L", "Low"), ("H", "High")],
        "UI": [("N", "None"), ("R", "Required")],
        "S":  [("U", "Unchanged"), ("C", "Changed")],
        "C":  [("N", "None"), ("L", "Low"), ("H", "High")],
        "I":  [("N", "None"), ("L", "Low"), ("H", "High")],
        "A":  [("N", "None"), ("L", "Low"), ("H", "High")],
    }

    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    env          = Environment(loader=FileSystemLoader(template_dir))
    template     = env.get_template("report.html")

    html_content = template.render(
        target_ip        = target_ip,
        vulnerabilities  = all_vulns,
        vuln_count       = len(all_vulns),
        critical_count   = critical_count,
        high_count       = high_count,
        medium_count     = medium_count,
        low_count        = low_count,
        zap_findings     = all_zap,
        zap_count        = len(all_zap),
        zap_high_count   = zap_high_count,
        zap_medium_count = zap_medium_count,
        zap_low_count    = zap_low_count,
        zap_info_count   = zap_info_count,
        cvss_options     = cvss_options,
        timestamp        = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    )

    with open(html_output, "w", encoding="utf-8") as f:
        f.write(html_content)

    console.print(f"✅ HTML Report COMPLETE → {html_output}")