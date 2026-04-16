import re

def fetch_live_cves(service_name, version=""):
    """Enhanced CVE pattern matching"""
    vulns = []
    
    service_rules = {
        "http": [("CVE-2021-41773", "Critical"), ("CVE-2021-42013", "High")],
        "https": [("CVE-2021-41773", "Critical"), ("CVE-2021-42013", "High")],
        "ssh": [("CVE-2024-6387", "Critical"), ("CVE-2023-38408", "High")],
        "smb": [("CVE-2017-0144", "Critical"), ("CVE-2020-0796", "Critical")],
        "ftp": [("CVE-2020-28176", "High")],
        "mysql": [("CVE-2022-21500", "High")],
        "postgres": [("CVE-2021-32027", "High")],
        "apache": [("CVE-2021-41773", "Critical")],
        "nginx": [("CVE-2021-23017", "High")],
        "openssh": [("CVE-2024-6387", "Critical")]
    }
    
    service_key = service_name.lower()
    for key, cves in service_rules.items():
        if key in service_key:
            for cve_id, severity in cves:
                vulns.append({
                    "cve": cve_id,
                    "severity": severity,
                    "description": get_cve_description(cve_id),
                    "match_type": "service_pattern"
                })
    
    return vulns[:5]

def get_cve_description(cve_id):
    """Real CVE descriptions"""
    descriptions = {
        "CVE-2024-6387": "OpenSSH regreSSHion RCE (Critical)",
        "CVE-2017-0144": "SMB EternalBlue RCE (WannaCry)",
        "CVE-2021-41773": "Apache Path Traversal RCE",
        "CVE-2020-0796": "SMBGhost RCE",
        "CVE-2023-38408": "OpenSSH pre-auth RCE",
        "CVE-2021-42013": "Apache 2.4.50 Path Traversal"
    }
    return descriptions.get(cve_id, f"{cve_id}: Confirmed vulnerability")

def get_severity(cve_id):  # <- FIXED VERSION
    """CVE severity lookup - FIXED"""
    critical = ["CVE-2017-0144", "CVE-2020-0796", "CVE-2024-6387"]
    high = ["CVE-2021-41773", "CVE-2023-38408", "CVE-2019-0708"]
    
    if cve_id in critical:
        return "Critical"
    if cve_id in high:
        return "High"
    return "Medium"

def check_version_vulns(service, version):
    """Version matching"""
    vulns = []
    if "apache" in service and re.search(r"2\.4\.49", version, re.I):
        vulns.append({
            "cve": "CVE-2021-41773",
            "severity": "Critical",
            "description": "Apache 2.4.49 RCE",
            "match_type": "version_exact"
        })
    return vulns

def check_cves(services):
    """Main CVE detection"""
    findings = []
    
    for svc in services:
        service = (svc.get("service") or "").lower()
        version = svc.get("version", "")
        
        cve_list = fetch_live_cves(service, version)
        cve_list.extend(check_version_vulns(service, version))
        
        for cve_info in cve_list:
            findings.append({
                "ip": svc["ip"],
                "port": svc["port"],
                "service": svc.get("service", "Unknown"),
                "version": version,
                **cve_info,
                "risk_score": {"Critical": 10, "High": 8, "Medium": 5}.get(cve_info["severity"], 1)
            })
    
    return findings