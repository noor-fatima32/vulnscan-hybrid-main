def enumerate_services(scan_data):
    results = []

    SERVICE_MAP = {
        21: ("FTP Service", "High"),
        22: ("Remote Access (SSH)", "Medium"),
        23: ("Remote Access (Telnet)", "High"),
        25: ("Mail Service", "Medium"),
        80: ("Web Service (HTTP)", "Medium"),
        443: ("Web Service (HTTPS)", "Medium"),
        445: ("File Sharing (SMB)", "Critical"),
        3389: ("Remote Desktop (RDP)", "Critical"),
    }

    for host in scan_data.get("hosts", []):
        ip = host.get("ip")

        for svc in host.get("services", []):
            port = svc.get("port")
            service_name = svc.get("service")
            product = svc.get("product", "")
            version = svc.get("version", "")

            category, risk = SERVICE_MAP.get(
                port,
                ("Unknown Service", "Low")
            )

            results.append({
                "ip": ip,
                "port": port,
                "service": service_name,
                "version": f"{product} {version}".strip(),
                "category": category,
                "risk_hint": risk
            })

    return results
