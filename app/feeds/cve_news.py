"""
High-Level CVE News Feed
Fetches critical and high severity CVEs from NVD and creates news items with IOCs, signatures, and MITRE mappings
"""

import logging
import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional

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
    """Fetches high-level CVEs and creates intelligence news items"""

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CACHE_TTL_SECONDS = 600  # 10 minutes
    MIN_SEVERITY = 7.0  # CVSS 7.0+ (High/Critical)

    def __init__(self, db: Database = None):
        self.db = db
        self.cache_path = Path(__file__).parents[2] / "data" / "cve_news_cache.db"
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_cache_table()
        self.last_fetch = None
        self.news_items: List[Dict] = []

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

    def _cached_items(self):
        conn = sqlite3.connect(str(self.cache_path))
        c = conn.cursor()
        c.execute(
            "SELECT payload, updated_at FROM cve_news_cache ORDER BY updated_at DESC"
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
            "CWE-94": "T1059",  # Command and Scripting Interpreter
            "CWE-78": "T1059",  # OS Command Execution
            "CWE-79": "T1189",  # Drive-by Compromise (XSS)
            "CWE-89": "T1190",  # Exploit Public-Facing Application (SQLi)
            "CWE-287": "T1078",  # Valid Accounts
            "CWE-502": "T1059",  # Deserialization
            "CWE-119": "T1486",  # Data Encrypted for Impact
            "CWE-200": "T1041",  # Exfiltration Over C2 Channel
            "CWE-306": "T1078",  # Missing Authentication
            "CWE-416": "T1183",  # Exploitation for Privilege Escalation
            "CWE-522": "T1110",  # Brute Force
            "CWE-918": "T1189",  # Server-Side Request Forgery
            "CWE-434": "T1105",  # Ingress Tool Transfer
            "CWE-798": "T1110",  # Use of Hard-coded Credentials
            "CWE-77": "T1059",  # Command Injection
            "CWE-125": "T1490",  # Inhibit System Recovery
            "CWE-190": "T1490",  # Integer Overflow
            "CWE-352": "T1054",  # Exploitation for Defense Evasion
            "CWE-264": "T1098",  # Account Manipulation
            "CWE-400": "T1498",  # Network Denial of Service
            "CWE-404": "T1490",  # Resource Destruction
            "CWE-295": "T1187",  # Exploit Public-Facing Application
            "CWE-427": "T1014",  # Registry Run Keys
            "CWE-603": "T1037",  # Boot or Logon Autostart Execution
        }

        mitre_tactics = []
        for cwe in cwes:
            if cwe in cwe_to_mitre:
                mitre_tactics.append(cwe_to_mitre[cwe])
        return list(set(mitre_tactics))

    def _generate_signatures(self, cve_id: str, description: str) -> List[str]:
        """Generate detection signatures for the CVE"""
        signatures = []

        cve_year = cve_id.split("-")[1] if "-" in cve_id else "2024"

        # Snort signature
        signatures.append(
            f'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"CVE-{cve_id} {description[:30]}"; '
            f'content:"{cve_id}"; nocase; sid:{cve_year}0001; rev:1;)'
        )

        # Suricata signature
        signatures.append(
            f'alert http any any -> $HOME_NET any (msg:"CVE-{cve_id} Exploit Detected"; '
            f'content:"{cve_id}"; http_uri; sid:{cve_year}0002; rev:1;)'
        )

        # YARA rule
        signatures.append(
            f'rule CVE_{cve_id.replace("-", "_")} {{ strings: $a = "{cve_id}" condition: $a }}'
        )

        return signatures

    def _generate_mitigations(
        self, vendor: str, product: str, description: str
    ) -> List[str]:
        """Generate mitigation recommendations"""
        mitigations = []

        mitigations.append(f"Apply vendor patches for {vendor} {product}")

        if "RCE" in description or "remote code execution" in description.lower():
            mitigations.append("Restrict network access to affected service")
            mitigations.append("Enable WAF rules for exploit patterns")

        if "authentication" in description.lower() or "auth" in description.lower():
            mitigations.append("Enforce multi-factor authentication")
            mitigations.append("Review and rotate credentials")

        if "SQL" in description or "sql injection" in description.lower():
            mitigations.append("Use parameterized queries")
            mitigations.append("Enable input validation")

        if "XSS" in description or "cross-site" in description.lower():
            mitigations.append("Sanitize user inputs")
            mitigations.append("Enable Content Security Policy")

        mitigations.append("Monitor for Indicators of Compromise (IOCs)")
        mitigations.append("Review vendor security advisory")

        return mitigations[:6]  # Limit to 6 mitigations

    def fetch_high_level_cves(self, days: int = 7, limit: int = 50) -> int:
        """Fetch high severity CVEs from NVD"""
        if not HAS_REQUESTS:
            logger.warning("requests library not available")
            return 0

        count = 0
        try:
            # Calculate date range
            pub_start = (datetime.utcnow() - timedelta(days=days)).strftime(
                "%Y-%m-%dT00:00:00UTC"
            )
            pub_end = datetime.utcnow().strftime("%Y-%m-%dT23:59:59UTC")

            params = {
                "pubStartDate": pub_start,
                "pubEndDate": pub_end,
                "cvssV3Severity": "CRITICAL",
                "resultsPerPage": min(limit, 50),
            }

            headers = {"User-Agent": "CIG/1.0 - Cyber Intelligence Gateway"}

            response = requests.get(
                self.NVD_API_URL, params=params, headers=headers, timeout=60
            )
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            news_items = []
            for vuln in vulnerabilities:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")

                # Get description
                descriptions = cve.get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break

                # Get CVSS score
                metrics = cve.get("metrics", {})
                cvss_data = metrics.get(
                    "cvssMetricV31", [metrics.get("cvssMetricV30", [])]
                )
                if cvss_data:
                    cvss = cvss_data[0].get("cvssData", {})
                    base_score = cvss.get("baseScore", 0)
                    attack_vector = cvss.get("attackVector", "")
                    attack_complexity = cvss.get("attackComplexity", "")
                else:
                    base_score = 0
                    attack_vector = ""
                    attack_complexity = ""

                # Skip low severity
                if base_score < self.MIN_SEVERITY:
                    continue

                # Get affected configurations
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

                # Get CWEs
                weaknesses = cve.get("weaknesses", [])
                cwes = []
                for weakness in weaknesses:
                    for desc in weakness.get("description", []):
                        if desc.get("lang") == "en" and desc.get(
                            "value", ""
                        ).startswith("CWE-"):
                            cwes.append(desc.get("value", ""))

                # Map to MITRE ATT&CK
                mitre_techniques = self._map_cwe_to_mitre(cwes)

                # Generate signatures and mitigations
                signatures = self._generate_signatures(cve_id, description)
                mitigations = self._generate_mitigations(vendor, product, description)

                # Extract potential IOCs from description
                iocs = []
                import re

                # Extract IP addresses
                ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", description)
                iocs.extend(ips[:3])
                # Extract domains
                domains = re.findall(
                    r"\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b", description
                )
                iocs.extend(domains[:3])
                # Extract hashes (simplified)
                hashes = re.findall(r"\b[a-fA-F0-9]{32,64}\b", description)
                iocs.extend(hashes[:2])

                # Create news item
                news_item = {
                    "id": f"cve-news-{cve_id}",
                    "title": f"Critical CVE-{cve_id}: {vendor} {product}",
                    "summary": description[:200] + "..."
                    if len(description) > 200
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
                    "vendor": vendor,
                    "product": product,
                    "cwes": cwes,
                }

                news_items.append(news_item)
                count += 1

            self.news_items = news_items
            self._cache_items(news_items)
            self.last_fetch = datetime.utcnow()
            logger.info(f"Fetched {count} high-level CVEs")
            return count

        except Exception as e:
            logger.error(f"Failed to fetch high-level CVEs: {e}")
            # Try to load from cache
            cached = self._cached_items()
            if cached:
                self.news_items = cached
                logger.info(f"Loaded {len(cached)} CVEs from cache")
            return count

    def get_latest(self, limit: int = 10):
        """Get latest CVE news items"""
        cached = self._cached_items()
        if cached:
            self.news_items = cached
            return cached[:limit]

        if self.news_items:
            return self.news_items[:limit]

        # Return empty list if nothing cached
        return []

    def get_all_cves(self):
        """Get all CVE news items"""
        if not self.news_items:
            self._cached_items()
        return self.news_items


def get_cve_feed():
    """Get CVE news feed instance"""
    return CVENewsFeed()
