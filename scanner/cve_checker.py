import re

# ─────────────────────────────────────────────────────────────────────────────
# CVSS v3.1 metrics database
# ─────────────────────────────────────────────────────────────────────────────
CVSS_DATA = {
    "CVE-2024-6387": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2024-07-01", "cwe": "362"
    },
    "CVE-2023-38408": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2023-07-19", "cwe": "94"
    },
    "CVE-2023-51385": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2023-12-18", "cwe": "78"
    },
    "CVE-2023-48795": {
        "score": 5.9, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "H", "A": "N",
        "severity": "Medium", "published": "2023-12-18", "cwe": "354"
    },
    "CVE-2016-20012": {
        "score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N",
        "severity": "Medium", "published": "2021-09-15", "cwe": "362"
    },
    "CVE-2021-41773": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2021-10-05", "cwe": "22"
    },
    "CVE-2021-42013": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "High", "published": "2021-10-07", "cwe": "22"
    },
    "CVE-2022-22720": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2022-03-14", "cwe": "444"
    },
    "CVE-2022-22721": {
        "score": 9.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N",
        "severity": "Critical", "published": "2022-03-14", "cwe": "190"
    },
    "CVE-2021-40438": {
        "score": 9.0, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2021-09-16", "cwe": "918"
    },
    "CVE-2021-26691": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2021-06-10", "cwe": "787"
    },
    "CVE-2017-7679": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2017-06-20", "cwe": "119"
    },
    "CVE-2017-7668": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2017-06-20", "cwe": "119"
    },
    "CVE-2017-0144": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2017-03-16", "cwe": "119"
    },
    "CVE-2020-0796": {
        "score": 10.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2020-03-12", "cwe": "190"
    },
    "CVE-2021-23017": {
        "score": 7.7, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L",
        "AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "L",
        "severity": "High", "published": "2021-06-01", "cwe": "193"
    },
    "CVE-2021-23018": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2021-06-01", "cwe": "120"
    },
    "CVE-2022-41741": {
        "score": 7.8, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "AV": "L", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "High", "published": "2022-10-19", "cwe": "416"
    },
    "CVE-2022-41742": {
        "score": 7.1, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
        "AV": "L", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "H",
        "severity": "High", "published": "2022-10-19", "cwe": "125"
    },
    "CVE-2021-3449": {
        "score": 5.9, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "H",
        "severity": "Medium", "published": "2021-03-25", "cwe": "476"
    },
    "CVE-2021-3450": {
        "score": 7.4, "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N",
        "severity": "High", "published": "2021-03-25", "cwe": "295"
    },
    "CVE-2022-0778": {
        "score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "H",
        "severity": "High", "published": "2022-03-15", "cwe": "835"
    },
    "CVE-2014-0160": {
        "score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N",
        "severity": "High", "published": "2014-04-07", "cwe": "125"
    },
    "CVE-2022-21500": {
        "score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N",
        "severity": "High", "published": "2022-04-19", "cwe": "284"
    },
    "CVE-2021-32027": {
        "score": 8.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "High", "published": "2021-06-01", "cwe": "190"
    },
    "CVE-2020-28176": {
        "score": 5.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N",
        "severity": "Medium", "published": "2020-11-05", "cwe": "200"
    },
    "CVE-2019-0708": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2019-05-16", "cwe": "416"
    },
    "CVE-2012-0152": {
        "score": 4.3, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L",
        "AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "N", "A": "L",
        "severity": "Medium", "published": "2012-03-13", "cwe": "399"
    },
    "CVE-2019-1182": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2019-08-14", "cwe": "416"
    },
    "CVE-2020-0609": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2020-01-14", "cwe": "416"
    },
    "CVE-2021-34527": {
        "score": 8.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "High", "published": "2021-07-02", "cwe": "269"
    },
    "CVE-2020-1472": {
        "score": 10.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2020-08-17", "cwe": "330"
    },
    "CVE-2019-11510": {
        "score": 10.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2019-04-24", "cwe": "22"
    },
    "CVE-2018-13379": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2019-06-04", "cwe": "22"
    },
    "CVE-2022-40684": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2022-10-18", "cwe": "287"
    },
    "CVE-2021-22986": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2021-03-31", "cwe": "306"
    },
    "CVE-2020-5902": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2020-07-01", "cwe": "22"
    },
    "CVE-2021-44228": {
        "score": 10.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2021-12-10", "cwe": "502"
    },
    "CVE-2022-22965": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2022-04-01", "cwe": "94"
    },
    "CVE-2017-5638": {
        "score": 10.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2017-03-11", "cwe": "20"
    },
    "CVE-2021-26084": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2021-08-25", "cwe": "74"
    },
    "CVE-2022-26134": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2022-06-02", "cwe": "74"
    },
    "CVE-2023-46604": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2023-10-27", "cwe": "502"
    },
    "CVE-2021-3156": {
        "score": 7.8, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "AV": "L", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "High", "published": "2021-01-26", "cwe": "122"
    },
    "CVE-2019-14287": {
        "score": 8.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "High", "published": "2019-10-17", "cwe": "755"
    },
    "CVE-2021-4034": {
        "score": 7.8, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "AV": "L", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "High", "published": "2022-01-28", "cwe": "125"
    },
    "CVE-2022-0847": {
        "score": 7.8, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "AV": "L", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "High", "published": "2022-03-07", "cwe": "281"
    },
    "CVE-2014-6271": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2014-09-24", "cwe": "78"
    },
    "CVE-2021-41091": {
        "score": 6.3, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:L",
        "AV": "L", "AC": "L", "PR": "L", "UI": "N", "S": "C", "C": "L", "I": "L", "A": "L",
        "severity": "Medium", "published": "2021-10-04", "cwe": "732"
    },
    "CVE-2022-0492": {
        "score": 7.8, "vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "AV": "L", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "High", "published": "2022-03-03", "cwe": "862"
    },
    "CVE-2021-28041": {
        "score": 7.1, "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "H", "PR": "L", "UI": "R", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "High", "published": "2021-03-05", "cwe": "295"
    },
    "CVE-2023-25690": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2023-03-07", "cwe": "444"
    },
    "CVE-2022-31813": {
        "score": 9.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H",
        "severity": "Critical", "published": "2022-06-09", "cwe": "348"
    },
    "_default": {
        "score": None, "vector": "N/A",
        "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "L",
        "severity": "Medium", "published": "Unknown", "cwe": None
    }
}

CVSS_LABELS = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S":  {"U": "Unchanged", "C": "Changed"},
    "C":  {"N": "None", "L": "Low", "H": "High"},
    "I":  {"N": "None", "L": "Low", "H": "High"},
    "A":  {"N": "None", "L": "Low", "H": "High"},
}


def get_cvss_metrics(cve_id):
    data = CVSS_DATA.get(cve_id, CVSS_DATA["_default"]).copy()
    labels = {}
    for metric, val in [
        ("AV", data["AV"]), ("AC", data["AC"]), ("PR", data["PR"]),
        ("UI", data["UI"]), ("S",  data["S"]),  ("C",  data["C"]),
        ("I",  data["I"]),  ("A",  data["A"]),
    ]:
        labels[metric] = CVSS_LABELS[metric].get(val, val)
    data["labels"] = labels
    return data


# ─────────────────────────────────────────────────────────────────────────────
# Service → CVE mapping  (no cap — all matches returned)
# ─────────────────────────────────────────────────────────────────────────────

SERVICE_CVE_MAP = {
    # SSH
    "ssh": [
        ("CVE-2024-6387",  "Critical"),   # regreSSHion RCE
        ("CVE-2023-38408", "Critical"),   # ssh-agent RCE
        ("CVE-2023-51385", "Critical"),   # OS command injection
        ("CVE-2023-48795", "Medium"),     # Terrapin downgrade
        ("CVE-2021-28041", "High"),       # double-free
        ("CVE-2016-20012", "Medium"),     # user enumeration
    ],
    "openssh": [
        ("CVE-2024-6387",  "Critical"),
        ("CVE-2023-38408", "Critical"),
        ("CVE-2023-51385", "Critical"),
        ("CVE-2023-48795", "Medium"),
        ("CVE-2016-20012", "Medium"),
    ],
    # HTTP / Apache
    "http": [
        ("CVE-2021-41773", "Critical"),   # path traversal RCE
        ("CVE-2021-42013", "High"),       # path traversal bypass
        ("CVE-2022-22720", "Critical"),   # HTTP request smuggling
        ("CVE-2022-22721", "Critical"),   # integer overflow
        ("CVE-2021-40438", "Critical"),   # SSRF mod_proxy
        ("CVE-2021-26691", "Critical"),   # mod_session heap overflow
        ("CVE-2023-25690", "Critical"),   # HTTP request smuggling
        ("CVE-2022-31813", "Critical"),   # forward header bypass
        ("CVE-2017-7679",  "Critical"),   # mod_mime buffer overflow
        ("CVE-2017-7668",  "Critical"),   # ap_find_token OOB
        ("CVE-2014-6271",  "Critical"),   # Shellshock
        ("CVE-2017-5638",  "Critical"),   # Struts2 RCE
        ("CVE-2021-44228", "Critical"),   # Log4Shell
        ("CVE-2022-22965", "Critical"),   # Spring4Shell
    ],
    "https": [
        ("CVE-2021-41773", "Critical"),
        ("CVE-2021-42013", "High"),
        ("CVE-2022-22720", "Critical"),
        ("CVE-2022-22721", "Critical"),
        ("CVE-2021-40438", "Critical"),
        ("CVE-2023-25690", "Critical"),
        ("CVE-2022-31813", "Critical"),
        ("CVE-2021-3449",  "Medium"),     # OpenSSL NULL deref
        ("CVE-2021-3450",  "High"),       # OpenSSL cert bypass
        ("CVE-2022-0778",  "High"),       # OpenSSL inf loop
        ("CVE-2014-0160",  "High"),       # Heartbleed
        ("CVE-2017-5638",  "Critical"),
        ("CVE-2021-44228", "Critical"),
        ("CVE-2022-22965", "Critical"),
    ],
    "apache": [
        ("CVE-2021-41773", "Critical"),
        ("CVE-2021-42013", "High"),
        ("CVE-2022-22720", "Critical"),
        ("CVE-2021-40438", "Critical"),
        ("CVE-2023-25690", "Critical"),
        ("CVE-2017-7679",  "Critical"),
        ("CVE-2014-6271",  "Critical"),
    ],
    # Nginx
    "nginx": [
        ("CVE-2021-23017", "High"),
        ("CVE-2021-23018", "Critical"),
        ("CVE-2022-41741", "High"),
        ("CVE-2022-41742", "High"),
    ],
    # SMB
    "smb": [
        ("CVE-2017-0144",  "Critical"),   # EternalBlue
        ("CVE-2020-0796",  "Critical"),   # SMBGhost
        ("CVE-2020-1472",  "Critical"),   # Zerologon
    ],
    "microsoft-ds": [
        ("CVE-2017-0144",  "Critical"),
        ("CVE-2020-0796",  "Critical"),
        ("CVE-2020-1472",  "Critical"),
    ],
    "netbios": [
        ("CVE-2017-0144",  "Critical"),
        ("CVE-2020-1472",  "Critical"),
    ],
    # RDP
    "rdp": [
        ("CVE-2019-0708",  "Critical"),   # BlueKeep
        ("CVE-2019-1182",  "Critical"),   # DejaBlue
        ("CVE-2020-0609",  "Critical"),   # RD Gateway RCE
        ("CVE-2012-0152",  "Medium"),     # RDP DoS
    ],
    "ms-wbt-server": [
        ("CVE-2019-0708",  "Critical"),
        ("CVE-2019-1182",  "Critical"),
        ("CVE-2020-0609",  "Critical"),
    ],
    # FTP
    "ftp": [
        ("CVE-2020-28176", "Medium"),
    ],
    # MySQL
    "mysql": [
        ("CVE-2022-21500", "High"),
        ("CVE-2021-32027", "High"),
    ],
    # PostgreSQL
    "postgres": [
        ("CVE-2021-32027", "High"),
    ],
    "postgresql": [
        ("CVE-2021-32027", "High"),
    ],
    # SSL/TLS
    "ssl": [
        ("CVE-2014-0160",  "High"),       # Heartbleed
        ("CVE-2021-3449",  "Medium"),
        ("CVE-2021-3450",  "High"),
        ("CVE-2022-0778",  "High"),
    ],
    # VPN / network appliances
    "vpn": [
        ("CVE-2019-11510", "Critical"),   # Pulse Secure
        ("CVE-2018-13379", "Critical"),   # Fortinet
        ("CVE-2022-40684", "Critical"),   # FortiOS auth bypass
        ("CVE-2020-5902",  "Critical"),   # F5 BIG-IP
    ],
    "pulse": [
        ("CVE-2019-11510", "Critical"),
    ],
    "fortinet": [
        ("CVE-2018-13379", "Critical"),
        ("CVE-2022-40684", "Critical"),
    ],
    # Load balancers / WAF
    "bigip": [
        ("CVE-2020-5902",  "Critical"),
        ("CVE-2021-22986", "Critical"),
    ],
    "f5": [
        ("CVE-2020-5902",  "Critical"),
        ("CVE-2021-22986", "Critical"),
    ],
    # Java / app servers
    "tomcat": [
        ("CVE-2021-44228", "Critical"),   # Log4Shell
        ("CVE-2022-22965", "Critical"),   # Spring4Shell
        ("CVE-2017-5638",  "Critical"),   # Struts
        ("CVE-2021-26084", "Critical"),   # Confluence OGNL
    ],
    "jboss": [
        ("CVE-2021-44228", "Critical"),
        ("CVE-2023-46604", "Critical"),   # ActiveMQ RCE
    ],
    "activemq": [
        ("CVE-2023-46604", "Critical"),
    ],
    # Confluence / Atlassian
    "confluence": [
        ("CVE-2021-26084", "Critical"),
        ("CVE-2022-26134", "Critical"),
    ],
    # Windows
    "msrpc": [
        ("CVE-2021-34527", "High"),       # PrintNightmare
        ("CVE-2020-1472",  "Critical"),   # Zerologon
    ],
    "spooler": [
        ("CVE-2021-34527", "High"),
    ],
    # Linux
    "sudo": [
        ("CVE-2021-3156",  "High"),       # Baron Samedit
        ("CVE-2019-14287", "High"),
    ],
    "bash": [
        ("CVE-2014-6271",  "Critical"),   # Shellshock
    ],
    # Containers
    "docker": [
        ("CVE-2021-41091", "Medium"),
        ("CVE-2022-0492",  "High"),
    ],
}


def get_cve_description(cve_id):
    descriptions = {
        "CVE-2024-6387":  "OpenSSH regreSSHion RCE (Critical)",
        "CVE-2023-38408": "OpenSSH ssh-agent RCE via PKCS#11",
        "CVE-2023-51385": "OpenSSH OS command injection via user name",
        "CVE-2023-48795": "Terrapin SSH protocol downgrade (Prefix Truncation)",
        "CVE-2021-28041": "OpenSSH double-free memory corruption",
        "CVE-2016-20012": "OpenSSH user enumeration via timing",
        "CVE-2021-41773": "Apache 2.4.49 Path Traversal / RCE",
        "CVE-2021-42013": "Apache 2.4.50 Path Traversal bypass",
        "CVE-2022-22720": "Apache HTTP request smuggling (incomplete fix)",
        "CVE-2022-22721": "Apache mod_lua integer overflow",
        "CVE-2021-40438": "Apache mod_proxy SSRF",
        "CVE-2021-26691": "Apache mod_session heap overflow",
        "CVE-2023-25690": "Apache HTTP request smuggling via RewriteRule",
        "CVE-2022-31813": "Apache forward header IP bypass",
        "CVE-2017-7679":  "Apache mod_mime buffer overread",
        "CVE-2017-7668":  "Apache ap_find_token out-of-bounds read",
        "CVE-2021-23017": "Nginx off-by-one in resolver",
        "CVE-2021-23018": "Nginx HTTP/2 request smuggling",
        "CVE-2022-41741": "Nginx MP4 module use-after-free",
        "CVE-2022-41742": "Nginx MP4 module out-of-bounds read",
        "CVE-2017-0144":  "SMB EternalBlue RCE (WannaCry)",
        "CVE-2020-0796":  "SMBGhost RCE (Windows SMBv3)",
        "CVE-2020-1472":  "Zerologon — Netlogon privilege escalation",
        "CVE-2019-0708":  "BlueKeep RDP RCE (pre-auth)",
        "CVE-2019-1182":  "DejaBlue RDP RCE",
        "CVE-2020-0609":  "Windows RD Gateway pre-auth RCE",
        "CVE-2012-0152":  "RDP DoS via crafted packet",
        "CVE-2020-28176": "FTP information disclosure",
        "CVE-2022-21500": "MySQL authentication bypass",
        "CVE-2021-32027": "PostgreSQL integer overflow leading to buffer overflow",
        "CVE-2021-3449":  "OpenSSL NULL pointer deref (TLS renegotiation)",
        "CVE-2021-3450":  "OpenSSL CA certificate check bypass",
        "CVE-2022-0778":  "OpenSSL infinite loop in BN_mod_sqrt()",
        "CVE-2014-0160":  "Heartbleed — OpenSSL memory disclosure",
        "CVE-2019-11510": "Pulse Secure VPN arbitrary file read (pre-auth)",
        "CVE-2018-13379": "Fortinet FortiOS path traversal (VPN credentials)",
        "CVE-2022-40684": "FortiOS/FortiProxy auth bypass via crafted HTTP",
        "CVE-2020-5902":  "F5 BIG-IP TMUI RCE",
        "CVE-2021-22986": "F5 BIG-IP iControl REST unauthenticated RCE",
        "CVE-2021-44228": "Log4Shell — Log4j2 JNDI RCE (Critical)",
        "CVE-2022-22965": "Spring4Shell — Spring Framework RCE",
        "CVE-2017-5638":  "Apache Struts2 Content-Type RCE",
        "CVE-2021-26084": "Confluence Server OGNL injection RCE",
        "CVE-2022-26134": "Confluence OGNL injection (unauthenticated RCE)",
        "CVE-2023-46604": "Apache ActiveMQ RCE via ClassPathXmlApplicationContext",
        "CVE-2021-34527": "PrintNightmare — Windows Print Spooler RCE",
        "CVE-2021-3156":  "Sudo Baron Samedit heap overflow → root",
        "CVE-2019-14287": "Sudo -1 UID privilege escalation",
        "CVE-2021-4034":  "Polkit pkexec local privilege escalation",
        "CVE-2022-0847":  "Dirty Pipe — Linux kernel privilege escalation",
        "CVE-2014-6271":  "Shellshock — Bash environment variable RCE",
        "CVE-2021-41091": "Docker Moby file permission exposure",
        "CVE-2022-0492":  "Linux cgroups container escape",
    }
    return descriptions.get(cve_id, f"{cve_id}: Known vulnerability")


def fetch_live_cves(service_name, version=""):
    """Match ALL CVEs for a service — no [:5] cap."""
    vulns = []
    seen = set()
    service_key = service_name.lower()

    for key, cve_list in SERVICE_CVE_MAP.items():
        if key in service_key or service_key in key:
            for cve_id, severity in cve_list:
                if cve_id not in seen:
                    seen.add(cve_id)
                    vulns.append({
                        "cve":         cve_id,
                        "severity":    severity,
                        "description": get_cve_description(cve_id),
                        "match_type":  "service_pattern",
                    })

    return vulns  # no cap


def get_severity(cve_id):
    data = CVSS_DATA.get(cve_id, CVSS_DATA["_default"])
    return data.get("severity", "Medium")


def check_version_vulns(service, version):
    vulns = []
    if "apache" in service.lower() and re.search(r"2\.4\.49", version, re.I):
        vulns.append({
            "cve":         "CVE-2021-41773",
            "severity":    "Critical",
            "description": "Apache 2.4.49 Path Traversal RCE (version-confirmed)",
            "match_type":  "version_exact",
        })
    if "apache" in service.lower() and re.search(r"2\.4\.50", version, re.I):
        vulns.append({
            "cve":         "CVE-2021-42013",
            "severity":    "High",
            "description": "Apache 2.4.50 Path Traversal bypass (version-confirmed)",
            "match_type":  "version_exact",
        })
    if re.search(r"openssh[_ ]([0-9]+\.[0-9]+)", version, re.I):
        m = re.search(r"openssh[_ ]([0-9]+)\.([0-9]+)", version, re.I)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            if (major < 9) or (major == 9 and minor < 8):
                if not any(v["cve"] == "CVE-2024-6387" for v in vulns):
                    vulns.append({
                        "cve":         "CVE-2024-6387",
                        "severity":    "Critical",
                        "description": "OpenSSH regreSSHion RCE (version-confirmed < 9.8)",
                        "match_type":  "version_range",
                    })
    return vulns


def check_cves(services):
    """Main CVE detection — enriches every finding with CVSS v3.1 metrics."""
    findings = []

    for svc in services:
        service = (svc.get("service") or "").lower()
        version = svc.get("version", "")

        cve_list = fetch_live_cves(service, version)
        # version-exact matches (deduped)
        for v in check_version_vulns(service, version):
            if not any(c["cve"] == v["cve"] for c in cve_list):
                cve_list.append(v)

        for cve_info in cve_list:
            cve_id = cve_info["cve"]
            cvss   = get_cvss_metrics(cve_id)

            findings.append({
                "ip":      svc["ip"],
                "port":    svc["port"],
                "service": svc.get("service", "Unknown"),
                "version": version,
                **cve_info,
                "risk_score": {"Critical": 10, "High": 8, "Medium": 5}.get(
                    cve_info["severity"], 1
                ),
                "cvss_score":     cvss["score"],
                "cvss_vector":    cvss["vector"],
                "cvss_AV":        cvss["AV"],
                "cvss_AC":        cvss["AC"],
                "cvss_PR":        cvss["PR"],
                "cvss_UI":        cvss["UI"],
                "cvss_S":         cvss["S"],
                "cvss_C":         cvss["C"],
                "cvss_I":         cvss["I"],
                "cvss_A":         cvss["A"],
                "cvss_labels":    cvss["labels"],
                "cvss_published": cvss["published"],
                "cvss_cwe":       cvss["cwe"],
            })

    return findings