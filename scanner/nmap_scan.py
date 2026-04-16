import nmap
import time
from datetime import datetime

class RateLimiter:
    def __init__(self, rate=1000):
        self.rate = rate
        self.interval = 1.0 / rate
        self.last_scan = 0
    
    def wait(self):
        now = time.time()
        elapsed = now - self.last_scan
        sleep_time = self.interval - elapsed
        if sleep_time > 0:
            time.sleep(sleep_time)
        self.last_scan = time.time()

def run_scan(target, rate_limit=1000):
    """Rate-limited Nmap scan for external networks"""
    limiter = RateLimiter(rate_limit)
    scanner = nmap.PortScanner()
    
    print(f"[+] Scanning {target} ({rate_limit} pkts/sec)")
    limiter.wait()  # First scan delay
    
    # Professional Nmap args for external scanning
    nmap_args = "-sS -sV -Pn -T4 --top-ports 1000 --max-rate {}".format(rate_limit)
    scanner.scan(hosts=target, arguments=nmap_args)
    
    scan_data = {
        "target": target,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hosts": []
    }

    for host in scanner.all_hosts():
        host_info = {
            "ip": host,
            "state": scanner[host].state(),
            "services": []
        }

        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in sorted(ports):
                service = scanner[host][proto][port]
                host_info["services"].append({
                    "port": port,
                    "protocol": proto,
                    "service": service.get("name", "unknown"),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "state": service.get("state", "unknown")
                })

        scan_data["hosts"].append(host_info)

    return scan_data