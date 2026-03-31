"""
CVE Details Feed Integration
Fetches vulnerability data from cvedetails.com
https://www.cvedetails.com/vulnerability-list/
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import re
import requests
from bs4 import BeautifulSoup

from app.models.database import Indicator, Database
from app.core.config import settings

logger = logging.getLogger(__name__)


class CVEDetailsFeed:
    """CVE Details vulnerability feed"""

    BASE_URL = "https://www.cvedetails.com"
    FEED_URLS = {
        "top_vulnerabilities": "/vulnerability-list.php",
        "recent": "/vulnerabilities.php",
        "厂商_software": "/vulnerability-list.php?vendor_id=0&product_id=0&version_id=&search=&cwe_id=0&opec=0&opov=0&opnv=0&pub_order_by=pubDate",
    }

    def __init__(self, db: Database):
        self.db = db
        self.enabled = False
        self.last_update: Optional[datetime] = None
        self.indicators_count = 0
        self.update_interval = 3600

    def configure(self, enabled: bool = True, update_interval: int = 3600) -> bool:
        """Configure CVE Details feed"""
        self.enabled = enabled
        self.update_interval = update_interval
        return True

    def is_enabled(self) -> bool:
        """Check if CVE Details is enabled"""
        return self.enabled

    def fetch_vulnerabilities(
        self, vendor_id: int = 0, product_id: int = 0, limit: int = 100
    ) -> int:
        """Fetch vulnerabilities from CVE Details"""
        if not self.enabled:
            logger.warning("CVE Details feed not enabled")
            return 0

        count = 0
        try:
            url = f"{self.BASE_URL}/vulnerability-list.php?vendor_id={vendor_id}&product_id={product_id}&page={1}"
            headers = {"User-Agent": "CIG/1.0 - Cyber Intelligence Gateway"}

            response = requests.get(url, headers=headers, timeout=60)
            response.raise_for_status()

            count = self._parse_html(response.text)
            self.last_update = datetime.now()
            logger.info(f"CVE Details feed updated: {count} vulnerabilities")
            return count

        except Exception as e:
            logger.error(f"Failed to fetch CVE Details feed: {e}")
            return 0

    def _parse_html(self, content: str) -> int:
        """Parse CVE Details HTML page"""
        count = 0
        try:
            soup = BeautifulSoup(content, "html.parser")
            table = soup.find("table", {"class": "searchresult-table"})
            if not table:
                return 0

            rows = table.find_all("tr")
            for row in rows:
                cells = row.find_all("td")
                if len(cells) < 5:
                    continue

                try:
                    cve_link = cells[0].find("a")
                    if not cve_link:
                        continue

                    cve_id = cve_link.get_text().strip()
                    if not cve_id.startswith("CVE-"):
                        continue

                    vendor = cells[1].get_text().strip()
                    product = cells[2].get_text().strip()
                    version = cells[3].get_text().strip()
                    vuln_type = cells[4].get_text().strip()

                    score_cell = cells[5].get_text().strip()
                    severity = "medium"
                    try:
                        score = float(score_cell)
                        if score >= 9.0:
                            severity = "critical"
                        elif score >= 7.0:
                            severity = "high"
                        elif score >= 4.0:
                            severity = "medium"
                        else:
                            severity = "low"
                    except:
                        pass

                    indicator = Indicator(
                        id=f"cvedetails_{hash(cve_id) % 1000000}",
                        value=cve_id,
                        type="cve",
                        source="cvedetails",
                        feed_source="cvedetails",
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                        confidence=80,
                        tags=["vulnerability", severity, vendor],
                        metadata={
                            "vendor": vendor,
                            "product": product,
                            "version": version,
                            "vulnerability_type": vuln_type,
                            "score": score_cell,
                        },
                    )
                    self.db.add_indicator(indicator)
                    count += 1

                except Exception as e:
                    logger.debug(f"Failed to parse CVE row: {e}")

        except Exception as e:
            logger.error(f"Failed to parse CVE Details HTML: {e}")

        return count

    def get_status(self) -> Dict[str, Any]:
        """Get CVE Details feed status"""
        return {
            "enabled": self.enabled,
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "indicators_count": self.indicators_count,
            "update_interval": self.update_interval,
        }


class CVEDetailsFeedManager:
    """Manager for CVE Details feeds"""

    def __init__(self, db: Database):
        self.db = db
        self.cve_feed = CVEDetailsFeed(db)
        self.enabled = False

    def configure(self, enabled: bool = True, update_interval: int = 3600) -> bool:
        """Configure CVE Details feed"""
        self.enabled = enabled
        self.cve_feed.configure(enabled, update_interval)
        logger.info(f"CVE Details feed configured: enabled={enabled}")
        return True

    def is_enabled(self) -> bool:
        """Check if CVE Details is enabled"""
        return self.enabled

    def get_status(self) -> Dict[str, Any]:
        """Get status of CVE Details feed"""
        return self.cve_feed.get_status()

    def update_all(self) -> Dict[str, int]:
        """Update CVE Details feed"""
        results = {}
        if self.cve_feed.is_enabled():
            results["cvedetails"] = self.cve_feed.fetch_vulnerabilities()
        return results
