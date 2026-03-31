"""
Shadowserver Feed Integration
https://www.shadowserver.org/what-we-do/network-reporting/
Provides network vulnerability scanning reports
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import requests
import csv
import io

from app.models.database import Indicator, Database
from app.core.config import settings

logger = logging.getLogger(__name__)


class ShadowserverFeed:
    """Shadowserver Network Reporting Feed"""

    REPORTS = {
        "vulnerable_http": "https://dn-huangsdjfi92ff8t9.a03.x5hn.com/api/csv/reports/scan_vulnerable_http",
    }

    def __init__(self, db: Database):
        self.db = db
        self.enabled = False
        self.api_key = getattr(settings, "shadowserver_api_key", "")
        self.last_update: Optional[datetime] = None
        self.indicators_count = 0
        self.update_interval = 86400

    def configure(
        self, api_key: str, enabled: bool = True, update_interval: int = 86400
    ) -> bool:
        """Configure Shadowserver feed"""
        self.api_key = api_key
        self.enabled = enabled
        self.update_interval = update_interval
        return True

    def is_enabled(self) -> bool:
        """Check if Shadowserver is enabled"""
        return self.enabled and bool(self.api_key)

    def fetch_vulnerable_http(self, limit: int = 5000) -> int:
        """Fetch vulnerable HTTP report from Shadowserver"""
        if not self.is_enabled():
            logger.warning("Shadowserver not configured")
            return 0

        count = 0
        try:
            url = self.REPORTS.get("vulnerable_http")
            if not url:
                return 0

            headers = {
                "User-Agent": "CIG/1.0 - Cyber Intelligence Gateway",
                "Authorization": f"Bearer {self.api_key}",
            }

            response = requests.get(url, headers=headers, timeout=120)
            response.raise_for_status()

            count = self._parse_csv(response.text)
            self.last_update = datetime.now()
            logger.info(f"Shadowserver vulnerable-http updated: {count} indicators")
            return count

        except Exception as e:
            logger.error(f"Failed to fetch Shadowserver feed: {e}")
            return 0

    def _parse_csv(self, content: str) -> int:
        """Parse Shadowserver CSV response"""
        count = 0
        try:
            reader = csv.DictReader(io.StringIO(content))
            for row in reader:
                try:
                    tag = row.get("tag", "")
                    cve = row.get("cve", "")
                    ip_address = row.get("ip_address", "")
                    port = row.get("port", "")
                    protocol = row.get("protocol", "")
                    source = row.get("source", "")

                    if not tag:
                        continue

                    cve_id = cve if cve else tag

                    indicator = Indicator(
                        id=f"shadowserver_{hash(cve_id + ip_address + port) % 10000000}",
                        value=cve_id if cve_id != tag else f"{ip_address}:{port}",
                        type="vulnerability",
                        source="shadowserver",
                        feed_source="shadowserver_vulnerable_http",
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat(),
                        confidence=85,
                        tags=["shadowserver", tag, "vulnerable_http"],
                        metadata={
                            "ip_address": ip_address,
                            "port": port,
                            "protocol": protocol,
                            "tag": tag,
                            "source": source,
                        },
                    )
                    self.db.add_indicator(indicator)
                    count += 1

                except Exception as e:
                    logger.debug(f"Failed to parse Shadowserver row: {e}")

        except Exception as e:
            logger.error(f"Failed to parse Shadowserver CSV: {e}")

        return count

    def get_status(self) -> Dict[str, Any]:
        """Get Shadowserver feed status"""
        return {
            "enabled": self.enabled,
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "indicators_count": self.indicators_count,
            "update_interval": self.update_interval,
        }


class ShadowserverFeedManager:
    """Manager for Shadowserver feeds"""

    def __init__(self, db: Database):
        self.db = db
        self.vuln_http = ShadowserverFeed(db)
        self.enabled = False

    def configure(
        self, api_key: str, enabled: bool = True, update_interval: int = 86400
    ) -> bool:
        """Configure Shadowserver feed"""
        self.enabled = enabled
        self.vuln_http.configure(api_key, enabled, update_interval)
        logger.info(f"Shadowserver feed configured: enabled={enabled}")
        return True

    def is_enabled(self) -> bool:
        """Check if Shadowserver is enabled"""
        return self.enabled

    def get_status(self) -> Dict[str, Any]:
        """Get status of Shadowserver feed"""
        return {
            "enabled": self.enabled,
            "vulnerable_http": self.vuln_http.get_status(),
        }

    def update_all(self) -> Dict[str, int]:
        """Update Shadowserver feeds"""
        results = {}
        if self.vuln_http.is_enabled():
            results["vulnerable_http"] = self.vuln_http.fetch_vulnerable_http()
        return results
