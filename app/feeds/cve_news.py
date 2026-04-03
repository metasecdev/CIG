"""
Comprehensive CVE News Feed
Fetches CVEs from NVD covering day/week/month and historical data going back 5 years
"""

import logging
import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import defaultdict

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from app.models.database import Database
from app.core.config import settings
from app.mitre.attack_mapper import MITREAttackMapper

logger = logging.getLogger(__name__)


class CVENewsFeed:
    """Comprehensive CVE news feed with historical data"""

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CACHE_TTL_SECONDS = 600  # 10 minutes
    MIN_SEVERITY = 7.0  # CVSS 7.0+ (High/Critical)

    # Historical date range (5 years back from now)
    START_DATE = "2021-01-01"
    END_DATE = "2026-03-31"

    def __init__(self, db: Database = None):
        self.db = db
        self.cache_path = Path(__file__).parents[2] / "data" / "cve_news_cache.db"
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_cache_table()
        self.last_fetch = None
        self.news_items: List[Dict] = []
        self._historical_cache: Dict[str, List[Dict]] = {
            "day": [],
            "week": [],
            "month": [],
            "year": [],
            "historical": [],
        }
        # Get NVD API key from settings
        self.nvd_api_key = getattr(settings, "nvd_api_key", "") or ""

    def _ensure_cache_table(self):
        conn = sqlite3.connect(str(self.cache_path))
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS cve_news_cache (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS cve_history_cache (
                id TEXT PRIMARY KEY,
                time_period TEXT NOT NULL,
                payload TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def _cache_items(self, news_items):
        conn = sqlite3.connect(str(self.cache_path))
        c = conn.cursor()
        c.execute("DELETE FROM cve_news_cache")
        now = datetime.utcnow().isoformat()
        for item in news_items:
            c.execute(
                "INSERT OR REPLACE INTO cve_news_cache (id, payload, updated_at) VALUES (?, ?, ?)",
                (item["id"], json.dumps(item), now),
            )
        conn.commit()
        conn.close()

    def _cache_historical_items(self, time_period: str, news_items: List[Dict]):
        conn = sqlite3.connect(str(self.cache_path))
        c = conn.cursor()
        c.execute(
            f"DELETE FROM cve_history_cache WHERE time_period = ?", (time_period,)
        )
        now = datetime.utcnow().isoformat()
        for item in news_items:
            c.execute(
                "INSERT OR REPLACE INTO cve_history_cache (id, time_period, payload, updated_at) VALUES (?, ?, ?, ?)",
                (item["id"], time_period, json.dumps(item), now),
            )
        conn.commit()
        conn.close()

    def _cached_items(self, time_period: str = "all"):
        conn = sqlite3.connect(str(self.cache_path))
        c = conn.cursor()

        if time_period == "all":
            c.execute(
                "SELECT payload, updated_at FROM cve_news_cache ORDER BY updated_at DESC"
            )
        else:
            c.execute(
                "SELECT payload, updated_at FROM cve_history_cache WHERE time_period = ? ORDER BY updated_at DESC",
                (time_period,),
            )

        rows = c.fetchall()
        conn.close()

        if not rows:
            return []

        last_updated = datetime.fromisoformat(rows[0][1])
        if datetime.utcnow() - last_updated > timedelta(seconds=self.CACHE_TTL_SECONDS):
            return []

        return [json.loads(row[0]) for row in rows]

    def _map_cwe_to_mitre(self, cwes: List[str]) -> List[str]:
        """Map CWE identifiers to MITRE ATT&CK technique IDs"""
        cwe_to_mitre = {
            "CWE-94": "T1059",
            "CWE-78": "T1059",
            "CWE-79": "T1189",
            "CWE-89": "T1190",
            "CWE-287": "T1078",
            "CWE-502": "T1059",
            "CWE-119": "T1486",
            "CWE-200": "T1041",
            "CWE-306": "T1078",
            "CWE-416": "T1183",
            "CWE-522": "T1110",
            "CWE-918": "T1189",
            "CWE-434": "T1105",
            "CWE-798": "T1110",
            "CWE-77": "T1059",
            "CWE-125": "T1490",
            "CWE-190": "T1490",
            "CWE-352": "T1054",
            "CWE-264": "T1098",
            "CWE-400": "T1498",
            "CWE-404": "T1490",
            "CWE-295": "T1187",
            "CWE-427": "T1014",
            "CWE-603": "T1037",
            "CWE-862": "T1078",
            "CWE-276": "T1078",
            "CWE-639": "T1078",
            "CWE-611": "T1190",
            "CWE-122": "T1059",
            "CWE-123": "T1059",
            "CWE-124": "T1490",
            "CWE-131": "T1490",
            "CWE-79": "T1189",
            "CWE-22": "T1083",
            "CWE-23": "T1083",
            "CWE-36": "T1083",
            "CWE-59": "T1083",
            "CWE-98": "T1059",
            "CWE-117": "T1070",
            "CWE-264": "T1098",
            "CWE-269": "T1068",
            "CWE-287": "T1078",
            "CWE-310": "T1110",
            "CWE-311": "T1040",
            "CWE-318": "T1005",
            "CWE-345": "T1200",
            "CWE-346": "T1200",
            "CWE-347": "T1200",
            "CWE-348": "T1200",
            "CWE-349": "T1200",
            "CWE-350": "T1200",
            "CWE-351": "T1200",
            "CWE-362": "T1006",
            "CWE-367": "T1497",
            "CWE-377": "T1106",
            "CWE-378": "T1497",
            "CWE-379": "T1106",
            "CWE-381": "T1218",
            "CWE-384": "T1056",
            "CWE-385": "T1056",
            "CWE-386": "T1006",
            "CWE-389": "T1076",
            "CWE-390": "T1040",
            "CWE-391": "T1006",
            "CWE-394": "T1006",
            "CWE-395": "T1006",
            "CWE-396": "T1006",
            "CWE-397": "T1006",
            "CWE-400": "T1498",
            "CWE-401": "T1490",
            "CWE-403": "T1490",
            "CWE-406": "T1195",
            "CWE-407": "T1195",
            "CWE-408": "T1195",
            "CWE-409": "T1195",
            "CWE-415": "T1218",
            "CWE-416": "T1183",
            "CWE-417": "T1082",
            "CWE-418": "T1082",
            "CWE-419": "T1082",
            "CWE-420": "T1082",
            "CWE-421": "T1192",
            "CWE-422": "T1192",
            "CWE-423": "T1187",
            "CWE-424": "T1187",
            "CWE-425": "T1082",
            "CWE-426": "T1053",
            "CWE-428": "T1027",
            "CWE-431": "T1027",
            "CWE-432": "T1027",
            "CWE-433": "T1027",
            "CWE-434": "T1105",
            "CWE-435": "T1092",
            "CWE-436": "T1092",
            "CWE-437": "T1092",
            "CWE-438": "T1092",
            "CWE-439": "T1092",
            "CWE-440": "T1082",
            "CWE-441": "T1092",
            "CWE-442": "T1092",
            "CWE-443": "T1078",
            "CWE-444": "T1078",
            "CWE-446": "T1006",
            "CWE-447": "T1200",
            "CWE-448": "T1200",
            "CWE-449": "T1200",
            "CWE-450": "T1200",
            "CWE-451": "T1078",
            "CWE-453": "T1078",
            "CWE-454": "T1078",
            "CWE-455": "T1078",
            "CWE-456": "T1078",
            "CWE-457": "T1078",
            "CWE-458": "T1078",
            "CWE-459": "T1078",
            "CWE-460": "T1078",
            "CWE-461": "T1082",
            "CWE-462": "T1082",
            "CWE-463": "T1082",
            "CWE-464": "T1098",
            "CWE-466": "T1098",
            "CWE-467": "T1006",
            "CWE-468": "T1006",
            "CWE-469": "T1098",
            "CWE-470": "T1078",
            "CWE-471": "T1006",
            "CWE-472": "T1078",
            "CWE-473": "T1078",
            "CWE-474": "T1078",
            "CWE-475": "T1078",
            "CWE-476": "T1078",
            "CWE-477": "T1078",
            "CWE-478": "T1078",
            "CWE-479": "T1078",
            "CWE-480": "T1006",
            "CWE-481": "T1006",
            "CWE-482": "T1006",
            "CWE-483": "T1006",
            "CWE-484": "T1006",
            "CWE-485": "T1006",
            "CWE-486": "T1078",
            "CWE-488": "T1078",
            "CWE-489": "T1078",
            "CWE-491": "T1068",
            "CWE-492": "T1068",
            "CWE-493": "T1068",
            "CWE-494": "T1068",
            "CWE-495": "T1068",
            "CWE-496": "T1068",
            "CWE-497": "T1041",
            "CWE-498": "T1041",
            "CWE-499": "T1041",
            "CWE-500": "T1070",
            "CWE-501": "T1070",
            "CWE-503": "T1070",
            "CWE-506": "T1070",
            "CWE-507": "T1070",
            "CWE-508": "T1070",
            "CWE-509": "T1070",
            "CWE-510": "T1070",
            "CWE-511": "T1070",
            "CWE-514": "T1040",
            "CWE-515": "T1040",
            "CWE-518": "T1082",
            "CWE-519": "T1082",
            "CWE-520": "T1082",
            "CWE-521": "T1110",
            "CWE-522": "T1110",
            "CWE-523": "T1110",
            "CWE-524": "T1082",
            "CWE-525": "T1082",
            "CWE-526": "T1082",
            "CWE-527": "T1082",
            "CWE-528": "T1082",
            "CWE-529": "T1082",
            "CWE-530": "T1082",
            "CWE-531": "T1082",
            "CWE-532": "T1082",
            "CWE-533": "T1082",
            "CWE-534": "T1082",
            "CWE-535": "T1082",
            "CWE-536": "T1082",
            "CWE-537": "T1082",
            "CWE-538": "T1082",
            "CWE-539": "T1082",
        }
        technique_names = {
            "T1059": "Command and Scripting Interpreter",
            "T1189": "Drive-by Compromise",
            "T1190": "Exploit Public-Facing Application",
            "T1078": "Valid Accounts",
            "T1486": "Data Encrypted for Impact",
            "T1041": "Exfiltration Over C2 Channel",
            "T1183": "Image File Execution Options Injection",
            "T1110": "Brute Force",
            "T1105": "Ingress Tool Transfer",
            "T1490": "Inhibit System Recovery",
            "T1054": "Indicator Removal",
            "T1098": "Account Manipulation",
            "T1498": "Network Denial of Service",
            "T1187": "Forced Authentication",
            "T1014": "Rootkit",
            "T1037": "Boot or Logon Autostart Execution",
            "T1195": "Supply Chain Compromise",
            "T1083": "File and Directory Discovery",
            "T1070": "Indicator Removal",
            "T1068": "Exploitation for Privilege Escalation",
            "T1040": "Network Sniffing",
            "T1005": "Data from Local System",
            "T1200": "Adversary-in-the-Middle",
            "T1006": "Direct Volume Access",
            "T1497": "Virtualization/Sandbox Evasion",
            "T1106": "Native API",
            "T1218": "Signed Binary Proxy Execution",
            "T1056": "Input Capture",
            "T1076": "Remote Desktop Protocol",
            "T1027": "Obfuscated Files or Information",
            "T1092": "Replication Through Removable Media",
            "T1082": "System Information Discovery",
            "T1053": "Scheduled Task/Job",
            "T1192": "Spearphishing Link",
            "T1083": "OS Credential Dumping",
            "T1110": "Credential Stuffing",
        }
        mitre_tactics = []
        for cwe in cwes:
            if cwe in cwe_to_mitre:
                technique_id = cwe_to_mitre[cwe]
                technique_name = technique_names.get(technique_id, technique_id)
                mitre_tactics.append(f"{technique_id}: {technique_name}")
        return list(set(mitre_tactics))

    def _generate_signatures(self, cve_id: str, description: str) -> List[str]:
        """Generate detection signatures for the CVE"""
        signatures = []
        cve_year = cve_id.split("-")[1] if "-" in cve_id else "2024"
        cve_num = cve_id.replace("CVE-", "").replace("-", "_")

        signatures.append(
            f'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"CVE-{cve_id} {description[:30]}"; '
            f'content:"{cve_id}"; nocase; sid:{cve_year}0001; rev:1;)'
        )
        signatures.append(
            f'alert http any any -> $HOME_NET any (msg:"CVE-{cve_id} Exploit Detected"; '
            f'content:"{cve_id}"; http_uri; sid:{cve_year}0002; rev:1;)'
        )
        signatures.append(
            f'rule CVE_{cve_num} {{ strings: $a = "{cve_id}" condition: $a }}'
        )
        signatures.append(
            f'alert tcp $EXTERNAL_NET any -> $HOME_NET [80,443,8080,8443] (msg:"CVE-{cve_id} HTTP Exploit"; '
            f'content:"{cve_id}"; http_header; sid:{cve_year}0003; rev:1;)'
        )
        signatures.append(
            f'alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:"CVE-{cve_id} UDP Exploit Attempt"; '
            f'content:"{cve_id}"; sid:{cve_year}0004; rev:1;)'
        )
        signatures.append(
            f'alert dns $HOME_NET any -> any any (msg:"CVE-{cve_id} DNS Exfiltration"; '
            f'content:"{cve_id}"; dns_query; sid:{cve_year}0005; rev:1;)'
        )
        signatures.append(f'event log "Security" ID 4698 - CVE-{cve_id}')
        signatures.append(f"Suricata: ET SCAN CVE-{cve_id} Exploit Attempt")

        if "RCE" in description or "remote code" in description.lower():
            signatures.append(
                f'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"CVE-{cve_id} RCE Detected"; '
                f'pcre:"/({cve_id}.*|exec|shellcmd)/i"; sid:{cve_year}0010; rev:1;)'
            )

        if "SQL" in description or "sql injection" in description.lower():
            signatures.append(
                f'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"CVE-{cve_id} SQL Injection"; '
                f'content:"union"; http_uri; content:"select"; http_uri; sid:{cve_year}0011; rev:1;)'
            )

        if "XSS" in description or "cross-site" in description.lower():
            signatures.append(
                f'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"CVE-{cve_id} XSS Attempt"; '
                f'content:"<script>"; http_uri; sid:{cve_year}0012; rev:1;)'
            )

        if "LFI" in description or "local file" in description.lower():
            signatures.append(
                f'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"CVE-{cve_id} LFI Attempt"; '
                f'content:"../"; http_uri; content:"etc/passwd"; http_uri; sid:{cve_year}0013; rev:1;)'
            )

        if "SSRF" in description or "server-side request" in description.lower():
            signatures.append(
                f'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"CVE-{cve_id} SSRF Attempt"; '
                f'pcre:"/(http|https|ftp):\/\/[a-zA-Z0-9]/i"; http_uri; sid:{cve_year}0014; rev:1;)'
            )

        return signatures[:15]

    def _generate_mitigations(
        self, vendor: str, product: str, description: str
    ) -> List[str]:
        """Generate mitigation recommendations"""
        mitigations = []
        mitigations.append(f"Apply vendor patches for {vendor} {product}")
        mitigations.append("Monitor for Indicators of Compromise (IOCs)")
        mitigations.append("Review vendor security advisory")

        if "RCE" in description or "remote code execution" in description.lower():
            mitigations.append("Restrict network access to affected service")
            mitigations.append("Enable WAF rules for exploit patterns")
            mitigations.append("Disable unnecessary remote services")
            mitigations.append("Implement application sandboxing")

        if "authentication" in description.lower() or "auth" in description.lower():
            mitigations.append("Enforce multi-factor authentication")
            mitigations.append("Review and rotate credentials")
            mitigations.append("Implement account lockout policies")
            mitigations.append("Use strong password policies")

        if "SQL" in description or "sql injection" in description.lower():
            mitigations.append("Use parameterized queries")
            mitigations.append("Enable input validation")
            mitigations.append("Implement least privilege database accounts")
            mitigations.append("Use WAF SQL injection rules")

        if "XSS" in description.lower() or "cross-site" in description.lower():
            mitigations.append("Sanitize user inputs")
            mitigations.append("Enable Content Security Policy")
            mitigations.append("Use output encoding")
            mitigations.append("Implement HTTPOnly cookies")

        if (
            "LFI" in description
            or "local file" in description.lower()
            or "directory traversal" in description.lower()
        ):
            mitigations.append("Validate and sanitize file paths")
            mitigations.append("Implement allowlist for file access")
            mitigations.append("Disable directory listing")

        if "SSRF" in description or "server-side request" in description.lower():
            mitigations.append("Validate URLs against allowlists")
            mitigations.append("Disable unnecessary URL fetching")
            mitigations.append("Use network segmentation")

        if (
            "privilege escalation" in description.lower()
            or "privilege" in description.lower()
        ):
            mitigations.append("Apply principle of least privilege")
            mitigations.append("Review user permissions regularly")
            mitigations.append("Implement just-in-time admin access")

        if (
            "buffer overflow" in description.lower()
            or "overflow" in description.lower()
        ):
            mitigations.append("Enable DEP/ASLR security features")
            mitigations.append("Use secure coding practices")
            mitigations.append("Update affected libraries")

        return mitigations[:10]

    def _parse_cve_entry(self, vuln: Dict, base_score: float) -> Optional[Dict]:
        """Parse a CVE entry from NVD response"""
        try:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")

            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            metrics = cve.get("metrics", {})
            cvss_data = metrics.get("cvssMetricV31", [metrics.get("cvssMetricV30", [])])
            if cvss_data:
                cvss = cvss_data[0].get("cvssData", {})
                base_score = cvss.get("baseScore", base_score)
                attack_vector = cvss.get("attackVector", "")
                attack_complexity = cvss.get("attackComplexity", "")
                privileges_required = cvss.get("privilegesRequired", "")
                user_interaction = cvss.get("userInteraction", "")
            else:
                attack_vector = ""
                attack_complexity = ""
                privileges_required = ""
                user_interaction = ""

            configurations = cve.get("configurations", [])
            vendors = []
            products = []
            for config in configurations:
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        criteria = match.get("criteria", "")
                        parts = criteria.split(":") if criteria else []
                        if len(parts) > 4:
                            vendors.append(parts[3])
                            products.append(parts[4])

            vendor = vendors[0] if vendors else "Unknown"
            product = products[0] if products else "Unknown"

            weaknesses = cve.get("weaknesses", [])
            cwes = []
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    if desc.get("lang") == "en" and desc.get("value", "").startswith(
                        "CWE-"
                    ):
                        cwes.append(desc.get("value", ""))

            mitre_techniques = self._map_cwe_to_mitre(cwes)
            signatures = self._generate_signatures(cve_id, description)
            mitigations = self._generate_mitigations(vendor, product, description)

            import re

            iocs = []
            ips = re.findall(
                r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
                description,
            )
            iocs.extend(ips[:5])
            urls = re.findall(r"https?://[^\s<>\"']+", description)
            iocs.extend(urls[:3])
            domains = re.findall(
                r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|io|xyz|cc|info|biz|edu|gov|mil|co|ai|app|dev|cloud|online|site|top|xyz|live|pro|ws|tk|ml|ga|cf|gq|pw|cc|ws|su|onion)\b",
                description,
                re.IGNORECASE,
            )
            for d in domains[:3]:
                if d not in str(urls):
                    iocs.append(d)
            hashes = re.findall(r"\b[a-fA-F0-9]{32}\b", description)
            iocs.extend([h for h in hashes[:3] if not any(ip in h for ip in ips)])
            md5_hashes = re.findall(r"\b[a-fA-F0-9]{32}\b", description)
            sha256_hashes = re.findall(r"\b[a-fA-F0-9]{64}\b", description)
            iocs.extend(md5_hashes[:2])
            iocs.extend(sha256_hashes[:2])
            emails = re.findall(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", description
            )
            iocs.extend(emails[:2])
            file_paths = re.findall(
                r"(?:/etc/passwd|/etc/shadow|/windows/system32|/Users/[\w]+/[\w.]+|C:\\\\[^\s]+)",
                description,
            )
            iocs.extend(file_paths[:2])

            # Determine severity label
            severity_label = "low"
            if base_score >= 9.0:
                severity_label = "critical"
            elif base_score >= 7.0:
                severity_label = "high"
            elif base_score >= 4.0:
                severity_label = "medium"

            return {
                "id": f"cve-news-{cve_id}",
                "title": f"CVSS {base_score:.1f} {severity_label.upper()}: {vendor} {product}",
                "summary": description[:300] + "..."
                if len(description) > 300
                else description,
                "source": "nvd",
                "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "cve": cve_id,
                "cve_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "published_at": cve.get("published", datetime.utcnow().isoformat()),
                "iocs": iocs,
                "signatures": signatures,
                "mitigations": mitigations,
                "mitre_techniques": mitre_techniques,
                "cvss_score": base_score,
                "attack_vector": attack_vector,
                "attack_complexity": attack_complexity,
                "privileges_required": privileges_required,
                "user_interaction": user_interaction,
                "vendor": vendor,
                "product": product,
                "cwes": cwes,
                "severity": severity_label,
            }
        except Exception as e:
            logger.debug(f"Failed to parse CVE entry: {e}")
            return None

    def _fetch_cve_chunk(
        self, start_date: str, end_date: str, results_per_page: int = 100
    ) -> List[Dict]:
        """Fetch a single chunk of CVEs for a date range"""
        if not HAS_REQUESTS:
            return []

        try:
            params = {
                "pubStartDate": start_date,
                "pubEndDate": end_date,
                "resultsPerPage": results_per_page,
            }

            headers = {
                "User-Agent": "CIG/1.0 - Cyber Intelligence Gateway",
                "Accept": "application/json",
            }

            if self.nvd_api_key:
                headers["X-API-Key"] = self.nvd_api_key

            response = requests.get(
                self.NVD_API_URL, params=params, headers=headers, timeout=120
            )
            response.raise_for_status()

            data = response.json()
            return data.get("vulnerabilities", [])

        except Exception as e:
            logger.error(
                f"Failed to fetch CVE chunk for {start_date} to {end_date}: {e}"
            )
            return []

    def _fetch_cves_with_retry(
        self, start_date: str, end_date: str, limit: int = 2000, max_retries: int = 3
    ) -> List[Dict]:
        """Fetch CVEs with retry logic and smaller chunks to avoid rate limiting"""
        if not HAS_REQUESTS:
            return []

        all_items = []
        max_days_per_chunk = 30  # Smaller chunks to avoid rate limits
        min_days_per_chunk = 20  # Minimum chunk size

        try:
            from datetime import datetime

            start_obj = datetime.fromisoformat(start_date.replace("+00:00", ""))
            end_obj = datetime.fromisoformat(end_date.replace("+00:00", ""))
            date_range = (end_obj - start_obj).days

            # Calculate number of chunks needed
            num_chunks = max(1, (date_range // max_days_per_chunk) + 1)
            days_per_chunk = max(min_days_per_chunk, date_range // num_chunks)

            current_start = start_obj

            for _ in range(num_chunks):
                if len(all_items) >= limit:
                    break

                chunk_end = min(current_start + timedelta(days=days_per_chunk), end_obj)
                chunk_start_str = current_start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
                chunk_end_str = chunk_end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")

                for retry in range(max_retries):
                    try:
                        # Try with severity filter first (for shorter ranges)
                        use_filter = days_per_chunk <= 20
                        params = {
                            "pubStartDate": chunk_start_str,
                            "pubEndDate": chunk_end_str,
                            "resultsPerPage": min(limit - len(all_items), 500),
                        }
                        if use_filter:
                            params["cvssV3Severity"] = ["CRITICAL", "HIGH"]

                        headers = {
                            "User-Agent": "CIG/1.0 - Cyber Intelligence Gateway",
                            "Accept": "application/json",
                        }
                        if self.nvd_api_key:
                            headers["X-API-Key"] = self.nvd_api_key

                        response = requests.get(
                            self.NVD_API_URL, params=params, headers=headers, timeout=60
                        )
                        response.raise_for_status()

                        data = response.json()
                        if not isinstance(data, dict):
                            logger.warning(f"Unexpected response type: {type(data)}")
                            break
                        vulnerabilities = data.get("vulnerabilities", [])

                        for vuln in vulnerabilities:
                            if not isinstance(vuln, dict):
                                continue
                            cve_data = vuln.get("cve", {})
                            if not isinstance(cve_data, dict):
                                continue
                            metrics = cve_data.get("metrics", {})
                            if not isinstance(metrics, dict):
                                continue
                            cvss_data = metrics.get("cvssMetricV31") or metrics.get(
                                "cvssMetricV30"
                            )
                            base_score = 0
                            if (
                                cvss_data
                                and isinstance(cvss_data, list)
                                and len(cvss_data) > 0
                            ):
                                cvss_entry = cvss_data[0]
                                if isinstance(cvss_entry, dict):
                                    base_score = cvss_entry.get("cvssData", {}).get(
                                        "baseScore", 0
                                    )

                            if base_score >= self.MIN_SEVERITY:
                                parsed = self._parse_cve_entry(vuln, base_score)
                                if parsed:
                                    all_items.append(parsed)

                        break  # Success, exit retry loop

                    except requests.exceptions.RequestException as e:
                        if retry < max_retries - 1:
                            wait_time = (retry + 1) * 3  # Wait 3, 6 seconds
                            logger.warning(f"Rate limited, retrying in {wait_time}s...")
                            import time

                            time.sleep(wait_time)
                        else:
                            logger.error(
                                f"Failed to fetch chunk after {max_retries} retries: {e}"
                            )

                current_start = chunk_end + timedelta(days=1)
                if current_start >= end_obj:
                    break

        except Exception as e:
            import traceback

            logger.error(f"Error in _fetch_cves_with_retry: {e}")
            logger.debug(traceback.format_exc())

        return all_items[:limit]

    def _fetch_cves_by_date_range(
        self, start_date: str, end_date: str, limit: int = 2000
    ) -> List[Dict]:
        """Fetch CVEs by date range from NVD using API 2.0 format"""
        if not HAS_REQUESTS:
            return []

        all_items = []
        start_idx = 0
        results_per_page = min(limit, 2000)

        try:
            while len(all_items) < limit:
                # NVD API 2.0 requires ISO 8601 format with timezone offset (e.g., +00:00)
                # Use pubStartDate/pubEndDate (published date)
                # For longer ranges (>60 days), API returns 404 - need to chunk requests
                start_dt = start_date
                end_dt = end_date

                # Calculate date range in days
                from datetime import datetime

                try:
                    start_date_obj = datetime.fromisoformat(
                        start_dt.replace("+00:00", "")
                    )
                    end_date_obj = datetime.fromisoformat(end_dt.replace("+00:00", ""))
                    date_range_days = (end_date_obj - start_date_obj).days
                except:
                    date_range_days = 0

                # Determine if we need to chunk the request
                # API works for ~60 days, longer ranges need multiple requests
                max_days_per_request = 55  # Leave buffer for rate limiting

                if date_range_days > max_days_per_request:
                    # Chunk into smaller date ranges
                    period_items = []
                    current_start = start_date_obj
                    chunks = (date_range_days // max_days_per_request) + 1
                    days_per_chunk = date_range_days // chunks + 1

                    for i in range(chunks):
                        chunk_start = current_start + timedelta(days=i * days_per_chunk)
                        chunk_end = min(
                            chunk_start + timedelta(days=days_per_chunk), end_date_obj
                        )

                        if chunk_start >= end_date_obj:
                            break

                        chunk_start_str = chunk_start.strftime(
                            "%Y-%m-%dT%H:%M:%S.000+00:00"
                        )
                        chunk_end_str = chunk_end.strftime(
                            "%Y-%m-%dT%H:%M:%S.000+00:00"
                        )

                        chunk_items = self._fetch_cve_chunk(
                            chunk_start_str, chunk_end_str, results_per_page
                        )
                        period_items.extend(chunk_items)

                        # Check if we have enough
                        if len(period_items) >= limit:
                            break

                    # Process all collected items
                    for vuln in period_items:
                        if not isinstance(vuln, dict):
                            continue
                        metrics = vuln.get("cve", {}).get("metrics", {})
                        cvss_data = metrics.get(
                            "cvssMetricV31", [metrics.get("cvssMetricV30", [])]
                        )
                        base_score = 0
                        if cvss_data:
                            base_score = (
                                cvss_data[0].get("cvssData", {}).get("baseScore", 0)
                            )

                        if base_score >= self.MIN_SEVERITY:
                            parsed = self._parse_cve_entry(vuln, base_score)
                            if parsed:
                                all_items.append(parsed)

                    break  # Exit the while loop since we handled all chunks
                else:
                    # Single request for smaller ranges
                    use_severity_filter = date_range_days <= 30

                    params = {
                        "pubStartDate": start_dt,
                        "pubEndDate": end_dt,
                        "startIndex": start_idx,
                        "resultsPerPage": results_per_page,
                    }

                    if use_severity_filter:
                        params["cvssV3Severity"] = ["CRITICAL", "HIGH"]

                    headers = {
                        "User-Agent": "CIG/1.0 - Cyber Intelligence Gateway",
                        "Accept": "application/json",
                    }

                    if self.nvd_api_key:
                        headers["X-API-Key"] = self.nvd_api_key

                    response = requests.get(
                        self.NVD_API_URL, params=params, headers=headers, timeout=120
                    )
                    response.raise_for_status()

                    data = response.json()
                    vulnerabilities = data.get("vulnerabilities", [])

                    if not vulnerabilities:
                        break

                    for vuln in vulnerabilities:
                        metrics = vuln.get("cve", {}).get("metrics", {})
                        cvss_data = metrics.get(
                            "cvssMetricV31", [metrics.get("cvssMetricV30", [])]
                        )
                        base_score = 0
                        if cvss_data:
                            base_score = (
                                cvss_data[0].get("cvssData", {}).get("baseScore", 0)
                            )

                        if use_severity_filter or base_score >= self.MIN_SEVERITY:
                            parsed = self._parse_cve_entry(vuln, base_score)
                            if parsed:
                                all_items.append(parsed)

                    start_idx += results_per_page

                    total_results = data.get("totalResults", 0)
                    if start_idx >= total_results:
                        break

                # Check if there are more results
                total_results = data.get("totalResults", 0)
                if start_idx >= total_results:
                    break

        except Exception as e:
            logger.error(f"Failed to fetch CVEs for {start_date} to {end_date}: {e}")

        return all_items[:limit]

    def fetch_all_periods(self) -> Dict[str, int]:
        """Fetch CVEs for all time periods"""
        counts = {}
        now = datetime.utcnow()

        # Day (last 24 hours) - use ISO 8601 format with milliseconds and timezone offset
        day_start = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
        day_end = now.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
        day_items = self._fetch_cves_by_date_range(day_start, day_end, limit=500)
        self._historical_cache["day"] = day_items
        self._cache_historical_items("day", day_items)
        counts["day"] = len(day_items)

        # Week (last 7 days)
        week_start = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
        week_items = self._fetch_cves_by_date_range(week_start, day_end, limit=1000)
        self._historical_cache["week"] = week_items
        self._cache_historical_items("week", week_items)
        counts["week"] = len(week_items)

        # Month (last 30 days) - fetch in chunks to avoid rate limiting
        month_start = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")

        # Split month into 2 chunks of ~15 days each
        month_chunks = []
        for i in range(2):
            chunk_start = now - timedelta(days=30) + timedelta(days=i * 15)
            chunk_end = min(chunk_start + timedelta(days=15), now)
            month_chunks.append(
                (
                    chunk_start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
                    chunk_end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
                )
            )

        month_items = []
        for cs, ce in month_chunks:
            chunk_cves = self._fetch_cves_by_date_range(cs, ce, limit=1000)
            month_items.extend(chunk_cves)

        self._historical_cache["month"] = month_items
        self._cache_historical_items("month", month_items)
        counts["month"] = len(month_items)

        # Year (last 365 days) - fetch in chunks of ~30 days with delays
        year_start = (now - timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
        year_items = self._fetch_cves_with_retry(year_start, day_end, limit=2000)
        self._historical_cache["year"] = year_items
        self._cache_historical_items("year", year_items)
        counts["year"] = len(year_items)

        # Historical (past year) - skip due to rate limiting
        historical_start = "2025-04-03T00:00:00.000+00:00"
        historical_items = []  # Skip due to NVD API rate limits
        self._historical_cache["historical"] = historical_items
        self._cache_historical_items("historical", historical_items)
        counts["historical"] = len(historical_items)

        self.news_items = day_items + week_items + month_items
        self._cache_items(self.news_items)
        self.last_fetch = now

        logger.info(
            f"CVE News: day={counts['day']}, week={counts['week']}, month={counts['month']}, year={counts['year']}, historical={counts['historical']}"
        )
        return counts

    def get_by_period(self, period: str = "all") -> List[Dict]:
        """Get CVEs by time period"""
        if period == "all":
            return self.get_latest(50)

        # Try cache first
        cached = self._cached_items(period)
        if cached:
            self._historical_cache[period] = cached
            return cached

        # Return from memory
        return self._historical_cache.get(period, [])

    def fetch_high_level_cves(self, days: int = 7, limit: int = 50) -> int:
        """Legacy method - fetches recent CVEs"""
        counts = self.fetch_all_periods()
        return counts.get("day", 0)

    def get_latest(self, limit: int = 10):
        """Get latest CVE news items"""
        cached = self._cached_items("all")
        if cached:
            self.news_items = cached
            return cached[:limit]

        if self.news_items:
            return self.news_items[:limit]

        return self.get_by_period("day")[:limit]

    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all time periods - checks both memory and cache"""
        # First check in-memory cache
        day_count = len(self._historical_cache.get("day", []))
        week_count = len(self._historical_cache.get("week", []))
        month_count = len(self._historical_cache.get("month", []))
        year_count = len(self._historical_cache.get("year", []))
        historical_count = len(self._historical_cache.get("historical", []))

        # If memory is empty, check SQLite cache
        if day_count == 0:
            day_cached = self._cached_items("day")
            day_count = len(day_cached)
        if week_count == 0:
            week_cached = self._cached_items("week")
            week_count = len(week_cached)
        if month_count == 0:
            month_cached = self._cached_items("month")
            month_count = len(month_cached)
        if year_count == 0:
            year_cached = self._cached_items("year")
            year_count = len(year_cached)

        # Get last_update from cache if not in memory
        last_update = self.last_fetch.isoformat() if self.last_fetch else None
        if not last_update:
            year_cached = self._cached_items("year")
            if year_cached:
                # Get the updated_at from first item via SQLite query
                import sqlite3

                try:
                    conn = sqlite3.connect(str(self.cache_path))
                    c = conn.cursor()
                    c.execute(
                        "SELECT updated_at FROM cve_history_cache WHERE time_period = 'year' ORDER BY updated_at DESC LIMIT 1"
                    )
                    row = c.fetchone()
                    if row:
                        last_update = row[0]
                    conn.close()
                except:
                    pass

        return {
            "day_count": day_count,
            "week_count": week_count,
            "month_count": month_count,
            "year_count": year_count,
            "historical_count": historical_count,
            "last_update": last_update,
        }

    def get_by_severity(
        self, severity: str = "critical", limit: int = 50
    ) -> List[Dict]:
        """Get CVEs by severity level (critical, high, medium)"""
        severity_lower = severity.lower()

        # Collect all items from all sources - in-memory cache AND SQLite cache
        all_items = []
        all_items.extend(self._historical_cache.get("day", []))
        all_items.extend(self._historical_cache.get("week", []))
        all_items.extend(self._historical_cache.get("month", []))
        all_items.extend(self._historical_cache.get("year", []))

        # Also check SQLite cache if in-memory is empty
        if not all_items:
            for period in ["day", "week", "month", "year"]:
                cached = self._cached_items(period)
                if cached:
                    all_items.extend(cached)

        if not all_items:
            return []

        # Filter by severity
        filtered = [
            item
            for item in all_items
            if item.get("severity", "").lower() == severity_lower
        ]

        # Sort by CVSS score (highest first)
        filtered.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)

        return filtered[:limit]

    def get_all_severities(self, limit_per_severity: int = 50) -> Dict[str, List[Dict]]:
        """Get last 50 CVEs for each severity level"""
        return {
            "critical": self.get_by_severity("critical", limit_per_severity),
            "high": self.get_by_severity("high", limit_per_severity),
            "medium": self.get_by_severity("medium", limit_per_severity),
        }


def get_cve_feed():
    """Get CVE news feed instance"""
    return CVENewsFeed()
