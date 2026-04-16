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

    # --- CVE findings ---
    all_vulns = []
    for result in scan_data:
        for cve in result.get("cves", []):
            all_vulns.append(cve)

    critical_count = len([v for v in all_vulns if v.get("severity") == "Critical"])
    high_count     = len([v for v in all_vulns if v.get("severity") == "High"])
    medium_count   = len([v for v in all_vulns if v.get("severity") == "Medium"])
    low_count      = len([v for v in all_vulns if v.get("severity") == "Low"])

    # --- ZAP findings ---
    all_zap = []
    for result in scan_data:
        zap = result.get("zap")
        if zap and isinstance(zap, dict):
            for finding in zap.get("findings", []):
                all_zap.append(finding)

    zap_high_count   = len([f for f in all_zap if f.get("severity") == "High"])
    zap_medium_count = len([f for f in all_zap if f.get("severity") == "Medium"])
    zap_low_count    = len([f for f in all_zap if f.get("severity") == "Low"])
    zap_info_count   = len([f for f in all_zap if f.get("severity") == "Info"])

    console.print(f"[cyan]  CVE findings: {len(all_vulns)} | ZAP findings: {len(all_zap)}[/cyan]")

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
        timestamp        = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    )

    with open(html_output, "w", encoding="utf-8") as f:
        f.write(html_content)

    console.print(f"✅ HTML Report COMPLETE → {html_output}")