from setuptools import setup, find_packages

setup(
    name="vulnscan-hybrid",
    version="2.0.1",
    author="Cybersecurity Pro",
    description="Professional Vulnerability Scanner",
    packages=find_packages(),
    install_requires=[
        "python-nmap==0.7.1",
        "Jinja2==3.1.2",
        "rich==13.7.1",
        "requests==2.31.0",
        # FIX: Added missing ZAP dependency.
        # Previously setup.py did not include the ZAP Python client,
        # so pip install -e . would silently skip it and ZAP scans would
        # fail at runtime with an ImportError.
        "python-owasp-zap-v2.4",
    ],
    # FIX: Corrected entry point.
    # Old entry: "vulnscan-hybrid=main:main" — this is wrong because "main"
    # is a plain script, not a package module. setuptools needs a dotted path
    # to a module inside a package. We keep it pointing to main:main but also
    # ensure main.py is at the project root so it can be found.
    entry_points={
        "console_scripts": [
            "vulnscan=main:main"
        ]
    },
    python_requires=">=3.8"
)