"""
CISA Known Exploited Vulnerabilities (KEV) Feed Integration
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import requests

from app.models.database import Indicator, Database
from app.core.config import settings

logger = logging.getLogger(__name__)


class CISAKevFeed:
    """CISA Known Exploited Vulnerabilities feed"""

    FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, db: Database):
        self.db = db
        self.enabled = False
        self.last_update: Optional[datetime] = None
        self.indicators_count = 0
        self.update_interval = 86400
        self.catalog_version = None

    def configure(self, enabled: bool = True, update_interval: int = 86400) -> bool:
        """Configure CISA KEV feed"""
        self.enabled = enabled
        self.update_interval = update_interval
        return True

    def is_enabled(self) -> bool:
        """Check if CISA KEV is enabled"""
        return self.enabled

    def fetch_vulnerabilities(self, limit: int = 10000) -> int:
        """Fetch vulnerabilities from CISA KEV"""
        if not self.enabled:
            logger.warning("CISA KEV feed not enabled")
            return 0

        count = 0
        try:
            headers = {"User-Agent": "CIG/1.0 - Cyber Intelligence Gateway"}

            response = requests.get(self.FEED_URL, headers=headers, timeout=60)
            response.raise_for_status()

            data = response.json()
            self.catalog_version = data.get("catalogVersion")
            count = self._parse_json(data)
            self.last_update = datetime.now()
            logger.info(
                f"CISA KEV feed updated: {count} vulnerabilities (version: {self.catalog_version})"
            )
            return count

        except Exception as e:
            logger.error(f"Failed to fetch CISA KEV feed: {e}")
            return 0

    def _parse_json(self, data: Dict) -> int:
        """Parse CISA KEV JSON"""
        count = 0
        vulnerabilities = data.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            try:
                cve_id = vuln.get("cveID", "")
                vendor = vuln.get("vendorProject", "")
                product = vuln.get("product", "")
                vuln_name = vuln.get("vulnerabilityName", "")
                date_added = vuln.get("dateAdded", "")
                short_desc = vuln.get("shortDescription", "")
                required_action = vuln.get("requiredAction", "")
                due_date = vuln.get("dueDate", "")
                known_ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")
                cwes = vuln.get("cwes", [])

                severity = "medium"
                if known_ransomware == "Known":
                    severity = "critical"
                elif (
                    "RCE" in short_desc or "remote code execution" in short_desc.lower()
                ):
                    severity = "high"

                indicator = Indicator(
                    id=f"cisa_kev_{hash(cve_id) % 1000000}",
                    value=cve_id,
                    type="cve",
                    source="cisa_kev",
                    feed_source="cisa_kev",
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                    confidence=95 if known_ransomware == "Known" else 80,
                    tags=["cisa_kev", severity, vendor, known_ransomware],
                    metadata={
                        "vendor": vendor,
                        "product": product,
                        "vulnerability_name": vuln_name,
                        "date_added": date_added,
                        "due_date": due_date,
                        "required_action": required_action,
                        "known_ransomware_use": known_ransomware,
                        "cwes": cwes,
                    },
                )
                self.db.add_indicator(indicator)
                count += 1

            except Exception as e:
                logger.debug(f"Failed to parse CISA KEV entry: {e}")

        return count

    def get_status(self) -> Dict[str, Any]:
        """Get CISA KEV feed status"""
        return {
            "enabled": self.enabled,
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "indicators_count": self.indicators_count,
            "update_interval": self.update_interval,
            "catalog_version": self.catalog_version,
        }


class CISAKevFeedManager:
    """Manager for CISA KEV feed"""

    def __init__(self, db: Database):
        self.db = db
        self.kev_feed = CISAKevFeed(db)
        self.enabled = False

    def configure(self, enabled: bool = True, update_interval: int = 86400) -> bool:
        """Configure CISA KEV feed"""
        self.enabled = enabled
        self.kev_feed.configure(enabled, update_interval)
        logger.info(f"CISA KEV feed configured: enabled={enabled}")
        return True

    def is_enabled(self) -> bool:
        """Check if CISA KEV is enabled"""
        return self.enabled

    def get_status(self) -> Dict[str, Any]:
        """Get status of CISA KEV feed"""
        return self.kev_feed.get_status()

    def update_all(self) -> Dict[str, int]:
        """Update CISA KEV feed"""
        results = {}
        if self.kev_feed.is_enabled():
            results["cisa_kev"] = self.kev_feed.fetch_vulnerabilities()
        return results
