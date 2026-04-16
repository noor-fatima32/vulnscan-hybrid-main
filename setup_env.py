#!/usr/bin/env python3
"""
setup_env.py — VulnScan-Hybrid one-command setup

WHY THIS FILE EXISTS:
    After cloning the repo, users had no automated way to get the tool running.
    They had to manually: create venv, install deps, check system tools, create
    output dirs. This file collapses all of that into a single command.

USAGE:
    python setup_env.py

Works on Linux and Windows (Python 3.8+).
"""

import sys
import os
import subprocess
import platform
import shutil
from pathlib import Path


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def step(msg):
    print(f"\n{'─'*55}")
    print(f"  {msg}")
    print(f"{'─'*55}")


def ok(msg):
    print(f"  ✅  {msg}")


def warn(msg):
    print(f"  ⚠️   {msg}")


def fail(msg):
    print(f"  ❌  {msg}")


def info(msg):
    print(f"  ℹ️   {msg}")


# ─────────────────────────────────────────────
# Step 0: Python version check
# ─────────────────────────────────────────────

def check_python_version():
    step("Checking Python version")
    major, minor = sys.version_info[:2]
    if major < 3 or (major == 3 and minor < 8):
        fail(f"Python 3.8+ required. You have {major}.{minor}")
        sys.exit(1)
    ok(f"Python {major}.{minor} detected")


# ─────────────────────────────────────────────
# Step 1: Create virtual environment
# ─────────────────────────────────────────────

def create_virtualenv():
    step("Creating virtual environment (venv/)")
    venv_path = Path("venv")

    if venv_path.exists():
        ok("venv/ already exists — skipping creation")
        return

    try:
        subprocess.run(
            [sys.executable, "-m", "venv", "venv"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        ok("venv/ created successfully")
    except subprocess.CalledProcessError as e:
        fail(f"Failed to create venv: {e}")
        sys.exit(1)


# ─────────────────────────────────────────────
# Step 2: Resolve pip path cross-platform
# ─────────────────────────────────────────────

def get_pip_path():
    """
    Return the pip executable inside the venv.
    Linux/Mac: venv/bin/pip
    Windows:   venv\\Scripts\\pip.exe
    """
    if platform.system() == "Windows":
        pip = Path("venv") / "Scripts" / "pip.exe"
    else:
        pip = Path("venv") / "bin" / "pip"

    if not pip.exists():
        fail(f"pip not found at {pip}. venv may be corrupt — delete venv/ and retry.")
        sys.exit(1)

    return str(pip)


# ─────────────────────────────────────────────
# Step 3: Install Python dependencies
# ─────────────────────────────────────────────

def install_dependencies():
    step("Installing Python dependencies from requirements.txt")

    req_file = Path("requirements.txt")
    if not req_file.exists():
        fail("requirements.txt not found. Are you in the project root?")
        sys.exit(1)

    pip = get_pip_path()

    try:
        subprocess.run(
            [pip, "install", "-r", "requirements.txt", "--quiet"],
            check=True
        )
        ok("All Python dependencies installed")
    except subprocess.CalledProcessError as e:
        fail(f"pip install failed: {e}")
        sys.exit(1)


# ─────────────────────────────────────────────
# Step 4: Check system tools (nmap, java, zap)
# ─────────────────────────────────────────────

def check_system_tools():
    step("Checking system tool availability")
    is_windows = platform.system() == "Windows"

    # ── nmap ──────────────────────────────────
    if shutil.which("nmap"):
        ok("nmap found on PATH")
    else:
        warn("nmap NOT found on PATH")
        if is_windows:
            info("Install nmap: https://nmap.org/download.html#windows")
            info("Add nmap to PATH after install (installer option available)")
        else:
            info("Install nmap: sudo apt install nmap   (Debian/Ubuntu/Kali)")
            info("            : sudo dnf install nmap   (Fedora/RHEL)")

    # ── java (required by ZAP) ────────────────
    if shutil.which("java"):
        ok("java found on PATH (required by ZAP)")
    else:
        warn("java NOT found on PATH — ZAP requires Java 11+")
        if is_windows:
            info("Install Java: https://adoptium.net/")
        else:
            info("Install Java: sudo apt install default-jre")

    # ── ZAP ───────────────────────────────────
    zap_found = False
    if is_windows:
        # Common Windows ZAP install paths
        candidates = [
            Path(r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"),
            Path(r"C:\Program Files (x86)\ZAP\Zed Attack Proxy\zap.bat"),
        ]
        for c in candidates:
            if c.exists():
                ok(f"ZAP found → {c}")
                zap_found = True
                break
    else:
        if shutil.which("zap.sh"):
            ok("zap.sh found on PATH")
            zap_found = True

    if not zap_found:
        warn("ZAP not found — web scanning (--web) will not work without it")
        info("Download ZAP: https://www.zaproxy.org/download/")
        if is_windows:
            info("Start ZAP daemon:")
            info('  cd "C:\\Program Files\\ZAP\\Zed Attack Proxy"')
            info('  .\\zap.bat -daemon -port 8080 -config api.key=htk1hsa6su4urdfql7poujq653')
        else:
            info("Start ZAP daemon:")
            info("  zap.sh -daemon -port 8080 -config api.key=htk1hsa6su4urdfql7poujq653")


# ─────────────────────────────────────────────
# Step 5: Create required directories
# ─────────────────────────────────────────────

def create_directories():
    step("Creating output directories")
    for d in ["output", "reports"]:
        Path(d).mkdir(exist_ok=True)
        ok(f"{d}/ ready")


# ─────────────────────────────────────────────
# Step 6: Print run instructions
# ─────────────────────────────────────────────

def print_run_instructions():
    is_windows = platform.system() == "Windows"
    activate = r"venv\Scripts\activate" if is_windows else "source venv/bin/activate"
    python   = r"venv\Scripts\python"   if is_windows else "venv/bin/python"

    step("Setup complete — how to run VulnScan-Hybrid")

    print(f"""
  1. Activate the virtual environment:
       {activate}

  2. Network scan only:
       {python} main.py -t scanme.nmap.org --rate 500

  3. Web + network scan (start ZAP first — see ZAP note above):
       {python} main.py -t http://testphp.vulnweb.com --web

  4. Full scan (network + web + verbose):
       {python} main.py -t scanme.nmap.org --rate 500 --web -v

  5. Scan from targets file:
       {python} main.py -t targets.txt --rate 500 --web

  Options:
    --rate N          Nmap packet rate (default 1000)
    --web             Enable ZAP web vulnerability scan
    --zap-key KEY     ZAP API key (default: htk1hsa6su4urdfql7poujq653)
    --zap-host HOST   ZAP host (default: localhost)
    --zap-port PORT   ZAP port (default: 8080)
    --no-report       Skip HTML report generation
    -v / -vv / -vvv   Verbose output levels

  Output:
    JSON results  → output/
    HTML reports  → reports/
""")


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n🔧 VulnScan-Hybrid — Environment Setup")
    print("=" * 55)

    check_python_version()
    create_virtualenv()
    install_dependencies()
    check_system_tools()
    create_directories()
    print_run_instructions()

    print("✅ Setup complete!\n")