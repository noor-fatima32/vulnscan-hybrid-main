#!/usr/bin/env python3
"""
vulnscan-hybrid v2.1 - Professional Vulnerability Scanner
Usage: python main.py -t scanme.nmap.org --rate 500
       python main.py -t https://example.com --web
       python main.py -t scanme.nmap.org --rate 500 --web
"""

import argparse
import sys
import socket
import ipaddress
import os
from pathlib import Path
from datetime import datetime
from scanner import run_scan, enumerate_services, check_cves
from scanner.zap_scan import run_zap_scan
from reporting import generate_html_report
import json

from rich.console import Console

console = Console()


# -------------------------------------------------
# Connectivity Check
# -------------------------------------------------

def check_internet_connectivity():
    test_hosts = ["8.8.8.8:53", "1.1.1.1:53", "scanme.nmap.org:80"]
    print("[*] Testing external connectivity...")

    for host_port in test_hosts:
        host, port = host_port.split(":")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((host, int(port)))
            sock.close()
            if result == 0:
                print(f"✅ External connectivity OK → {host}")
                return True
        except Exception:
            continue

    print("❌ No external connectivity. Check your network/firewall.")
    return False


# -------------------------------------------------
# Target Parsing
# -------------------------------------------------

def parse_targets(target_input):
    targets = set()
    targets.add(target_input.strip())

    try:
        network = ipaddress.ip_network(target_input, strict=False)
        cidr_hosts = list(network.hosts())
        targets.update(str(ip) for ip in cidr_hosts)
        print(f"[+] Expanded CIDR {target_input} → {len(cidr_hosts)} hosts")
    except Exception:
        pass

    target_file = Path(target_input)
    if target_file.exists() and target_file.suffix in [".txt", ".list", ".targets"]:
        with open(target_file, "r", encoding="utf-8-sig") as f:
            lines = f.readlines()
        clean_targets = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
        targets.update(clean_targets)
        print(f"[+] Loaded {len(clean_targets)} targets from {target_input}")

    return sorted(list(targets))


# -------------------------------------------------
# Argument Parser
# -------------------------------------------------

def create_parser():
    parser = argparse.ArgumentParser(
        description="🔍 vulnscan-hybrid v2.1 - Professional Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-t", "--targets", required=True,
                        help="Target: IP, CIDR, hostname, or targets.txt file")
    parser.add_argument("--rate", type=int, default=1000,
                        help="Scan rate (packets/sec, default: 1000)")
    parser.add_argument("--ports", default="top-1000",
                        help="Ports: top-1000, common, 1-65535 (default: top-1000)")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Verbose output (-v, -vv)")
    parser.add_argument("--json", action="store_true",
                        help="Save JSON output (always saved by default)")
    parser.add_argument("--no-report", action="store_true",
                        help="Skip HTML report generation")
    parser.add_argument("--web", action="store_true",
                        help="Enable ZAP web vulnerability scan (requires ZAP daemon on port 8080)")
    return parser


# -------------------------------------------------
# Main
# -------------------------------------------------

def main():
    args = create_parser().parse_args()

    if not check_internet_connectivity():
        sys.exit(1)

    targets = parse_targets(args.targets)

    console.print(f"\n🚀 Scanning {len(targets)} targets at {args.rate} pkts/sec\n")

    if args.web:
        console.print("[yellow]⚡ ZAP Web Scan enabled — make sure ZAP daemon is running on port 8080[/yellow]\n")

    all_results = []

    for i, target in enumerate(targets, 1):
        console.print(f"[cyan][{i}/{len(targets)}] Scanning → {target}[/cyan]")

        try:
            # --- Nmap scan ---
            scan_result = run_scan(target, rate_limit=args.rate)
            services    = enumerate_services(scan_result)
            cves        = check_cves(services)

            result = {
                "target":    target,
                "scan":      scan_result,
                "services":  services,
                "cves":      cves,
                "scan_time": datetime.now().isoformat(),
                "zap":       None
            }

            if args.verbose:
                console.print(f"[green]✔ {target}: {len(cves)} potential CVEs found[/green]")

            # --- ZAP web scan (runs OUTSIDE rich Progress) ---
            if args.web:
                web_target = target if target.startswith("http") else f"http://{target}"
                zap_result = run_zap_scan(web_target)
                result["zap"] = zap_result

                findings_count = len(zap_result.get("findings", []))
                if zap_result.get("error"):
                    console.print(f"[red]⚠ ZAP error for {target}: {zap_result['error']}[/red]")
                else:
                    console.print(f"[blue]🌐 ZAP → {target}: {findings_count} web findings[/blue]")

            all_results.append(result)

        except KeyboardInterrupt:
            console.print("\n[red][!] Scan interrupted by user[/red]")
            break
        except Exception as e:
            console.print(f"[red][!] Error scanning {target}: {e}[/red]")

    if not all_results:
        console.print("[red][!] No results collected. Exiting.[/red]")
        sys.exit(1)

    # -------------------------------------------------
    # Save JSON
    # -------------------------------------------------
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs("output", exist_ok=True)
    output_file = f"output/vulnscan-hybrid_{timestamp}.json"

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)

    console.print(f"\n💾 [cyan]JSON results → {output_file}[/cyan]")

    # -------------------------------------------------
    # Generate HTML Report
    # -------------------------------------------------
    if not args.no_report:
        try:
            generate_html_report(output_file)
            console.print("[cyan]📄 HTML report generated successfully[/cyan]")
        except Exception as e:
            console.print(f"[red][!] Failed to generate HTML report: {e}[/red]")

    # -------------------------------------------------
    # Summary
    # -------------------------------------------------
    total_cves = sum(len(r["cves"]) for r in all_results)
    console.print(f"\n✅ Complete! Scanned {len(targets)} targets")
    console.print(f"📊 {total_cves} total CVE findings")

    if args.web:
        total_web = sum(
            len(r["zap"].get("findings", []))
            for r in all_results
            if r.get("zap") and isinstance(r["zap"], dict)
        )
        console.print(f"🌐 {total_web} total web vulnerability findings (ZAP)")


if __name__ == "__main__":
    main()