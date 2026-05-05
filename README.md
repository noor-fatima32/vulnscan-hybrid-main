# 🔥 VulnScan Hybrid

A modular, hybrid vulnerability assessment tool built in Python — combining high-speed network reconnaissance with CVE intelligence and optional OWASP ZAP web scanning.

---

## 🔍 Introduction

VulnScan Hybrid is a hybrid vulnerability scanning framework engineered to simulate real-world security assessment workflows. It combines high-speed network scanning with structured CVE intelligence and optional OWASP ZAP integration to identify potential security weaknesses in target systems.

Built with a modular architecture, the tool separates scanning, vulnerability correlation, and reporting logic into independent components. This design ensures scalability, maintainability, and future extensibility.

The scanner generates machine-readable JSON output for automation and structured HTML reports for professional security review. It is designed for educational use, research, and authorized penetration testing environments.

---

## 🚀 Core Features

- ⚡ High-speed target scanning with configurable rate control
- 🔎 Service enumeration & CVE correlation via NVD API
- 🌐 Optional OWASP ZAP integration for web vulnerability scanning
- 📊 Severity classification (Critical, High, Medium, Low)
- 🧾 Structured JSON output for automation
- 📄 Professional dark-themed HTML report generation with CVSS hover tooltips
- 🧩 Modular and extensible architecture
- 🎯 Designed for controlled lab environments and authorized targets

---

## 📂 Project Structure

```
vulnscan-hybrid/
│
├── output/            # Raw JSON scan results
├── reports/           # Generated HTML reports
├── scanner/           # Scanning & enumeration modules
│   ├── __init__.py
│   ├── cve_checker.py
│   ├── nmap_scan.py
│   ├── service_enum.py
│   └── zap_scan.py
├── reporting/         # Report generation engine
├── main.py            # Application entry point
├── setup_env.py       # Environment setup script
├── setup.py
├── targets.txt        # Target list (one per line)
└── requirements.txt
```

---

## ⚙️ Installation

```bash
git clone https://github.com/noor-fatima32/vulnscan-hybrid-main.git
cd vulnscan-hybrid
pip install -r requirements.txt
```

Or use the automated setup:

```bash
python setup_env.py
```

---

## 🧪 Usage

### Standard Scan (Nmap + CVE)

```bash
python main.py -t <target_ip> -v --rate 500
```

### Web Scan (with OWASP ZAP)

```bash
python main.py -t <target_ip> --web
```

### Parameters

| Flag | Description |
|------|-------------|
| `-t` | Target IP or CIDR range |
| `-v` | Enable verbose output |
| `--rate` | Packet rate for scanning (default: 500) |
| `--web` | Enable OWASP ZAP web vulnerability scan |

---

## 🌐 Running OWASP ZAP (Required for `--web`)

Before running a web scan, start ZAP in daemon mode:

**Windows (PowerShell):**
```powershell
$env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-25.0.2.10-hotspot"
$env:Path = "$env:JAVA_HOME\bin;" + $env:Path
cd "C:\Program Files\ZAP\Zed Attack Proxy"
& ".\zap.bat" -daemon -port 8080 -config api.key=htk1hsa6su4urdfql7poujq653
```

> ⚠️ ZAP must be running on port `8080` before launching a web scan. The API key above is configured in `zap_scan.py`.

---

## 📄 Output

- **JSON Results** → `output/`
- **HTML Reports** → `reports/`

Reports include:
- Target summary & scan metadata
- Total vulnerabilities found
- Severity breakdown (Critical / High / Medium / Low)
- Detailed CVE listings with CVSS scores
- ZAP web findings (if `--web` flag used)

---

## ⚠️ Disclaimer

VulnScan Hybrid is intended strictly for **educational purposes** and **authorized security testing only**.

> Do **not** scan systems without explicit written permission from the system owner. Unauthorized scanning may be illegal and is strictly prohibited.

---

## 👨‍💻 Project Creators

### 🔹 Hadi Faheem (CyberReaper)
-  Developer —VulnScan Hybrid
- GitHub: [CyberReaper-1](https://github.com/CyberReaper-1)

### 🔹 Noor Fatima
-Developer —VulnScan Hybrid
- GitHub: [noor-fatima32](https://github.com/noor-fatima32)

---

## 🤝 About This Project

VulnScan Hybrid is a collaborative initiative focused on exploring how modern vulnerability scanners operate internally. This tool reflects hands-on research, experimentation, and structured tool development in controlled lab environments built as part of an active cybersecurity learning.