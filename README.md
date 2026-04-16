# 🔥 VulnScan Hybrid

A lightweight, modular vulnerability assessment tool built in Python for efficient network reconnaissance and CVE-based vulnerability analysis.

---

## 🔍 Introduction

VulnScan Hybrid is a hybrid vulnerability scanning framework engineered to simulate real-world security assessment workflows. It combines high-speed network scanning with structured CVE intelligence to identify potential security weaknesses in target systems.

Built with a modular architecture, the tool separates scanning, vulnerability correlation, and reporting logic into independent components. This design ensures scalability, maintainability, and future extensibility.

The scanner generates machine-readable JSON output for automation and structured HTML reports for professional security review. It is designed for educational use, research, and authorized penetration testing environments.

---

## 🚀 Core Features

- ⚡ High-speed target scanning with rate control
- 🔎 Service enumeration & CVE correlation
- 📊 Severity classification (Critical, High, Medium, Low)
- 🧾 Structured JSON output for automation
- 📄 Clean and professional HTML report generation
- 🧩 Modular and extensible architecture
- 🎯 Designed for controlled lab environments

---

## 📂 Project Structure

```
vulnscan-hybrid/
│
├── output/        # Raw JSON scan results
├── reports/       # Generated HTML reports
├── scanner/       # Scanning & enumeration modules
├── reporting/     # Report generation engine
├── main.py        # Application entry point
├── requirements.txt
```

---

## ⚙️ Installation

```bash
git clone https://github.com/CyberReaper-1/vulnscan-hybrid.git
cd vulnscan-hybrid
pip install -r requirements.txt
```

---

## 🧪 Usage

```bash
python main.py -t target ip -v --rate 500
```

### Parameters

- `-t` → Target IP or CIDR
- `-v` → Verbose output
- `--rate` → Packet rate for scanning

---

## 📄 Output

- **JSON Results** → `output/`
- **HTML Reports** → `reports/`

Reports include:
- Target summary
- Total vulnerabilities found
- Severity breakdown
- Detailed CVE listings

---

## ⚠️ Disclaimer

VulnScan Hybrid is intended strictly for educational purposes and authorized security testing.  
Do not scan systems without proper permission.

---

## 👨‍💻 Project Creators

### 🔹 Hadi Faheem (CyberReaper)
- Developer  VulnScan Hybrid
- GitHub: https://github.com/CyberReaper-1

### 🔹 Noor Fatima
- Developer 
- GitHub: https://github.com/noor-fatima32

---

## 🤝 About This Project

VulnScan Hybrid is a collaborative initiative focused on exploring how modern vulnerability scanners operate internally.  
This tool reflects hands-on research, experimentation, and structured tool development in controlled lab environments.

