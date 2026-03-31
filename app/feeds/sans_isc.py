"""
SANS Internet Storm Center Threat Feed Integration
https://isc.sans.edu/data/threatfeed.html
Provides IP-based threat intelligence from various sources
"""

import logging
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
import requests
import xml.etree.ElementTree as ET

from app.models.database import Indicator, Database
from app.core.config import settings

logger = logging.getLogger(__name__)


class SANSISCFeed:
    """SANS Internet Storm Center threat feed"""

    API_BASE = "https://isc.sans.edu/api"

    FEEDS = {
        "dshieldssh": {"category": "bots", "description": "DShield SSH Attackers"},
        "dshieldweb": {"category": "bots", "description": "DShield Webhoneypot"},
        "openbl_ssh": {
            "category": "port_scanners",
            "description": "OpenBL SSH Scanners",
        },
        "openbl_http": {
            "category": "port_scanners",
            "description": "OpenBL HTTP Scanners",
        },
        "openbl_smtp": {
            "category": "port_scanners",
            "description": "OpenBL SMTP Scanners",
        },
        "openbl_ftp": {
            "category": "port_scanners",
            "description": "OpenBL FTP Scanners",
        },
        "openbl_mail": {
            "category": "port_scanners",
            "description": "OpenBL MAIL Scanners",
        },
        "urlhaus": {"category": "bots", "description": "URLhaus Malware URLs"},
        "malwaredomainlist": {"category": "bots", "description": "MalwareDomainList"},
        "ciarmy": {"category": "others", "description": "CI Army List"},
        "emergingthreats": {"category": "others", "description": "Emerging Threats"},
        "forumspam": {"category": "others", "description": "Forum Spammers"},
        "malc0de": {"category": "others", "description": "Malc0de Blocklist"},
        "shodan": {"category": "research", "description": "Shodan Scanners"},
        "onyphe": {"category": "research", "description": "Onyphe Scanners"},
        "binaryedge": {"category": "research", "description": "Binary Edge Scanners"},
        "censys": {"category": "research", "description": "Censys Scanners"},
        "rapid7": {"category": "research", "description": "Rapid7 Sonar Scans"},
        "leakix": {"category": "research", "description": "LeakIX Scanners"},
        "net Systems Research": {
            "category": "research",
            "description": "Net Systems Research",
        },
    }

    def __init__(self, db: Database):
        self.db = db
        self.enabled = False
        self.last_update: Optional[datetime] = None
        self.indicators_count = 0
        self.update_interval = 3600
        self.api_key = getattr(settings, "sans_api_key", "")
        self.existing_ips: Set[str] = set()

    def configure(
        self, enabled: bool = True, update_interval: int = 3600, api_key: str = ""
    ) -> bool:
        """Configure SANS ISC feed"""
        self.enabled = enabled
        self.update_interval = update_interval
        self.api_key = api_key
        return True

    def is_enabled(self) -> bool:
        """Check if SANS ISC is enabled"""
        return self.enabled

    def fetch_threat_ips(self, limit: int = 5000) -> int:
        """Fetch threat IPs from SANS ISC feeds"""
        if not self.enabled:
            logger.warning("SANS ISC feed not enabled")
            return 0

        count = 0
        existing = self._get_existing_ips()
        self.existing_ips = existing

        headers = {"User-Agent": "CIG/1.0 - Cyber Intelligence Gateway"}

        feeds_to_fetch = [
            "dshieldssh",
            "dshieldweb",
            "openbl_ssh",
            "openbl_http",
            "openbl_smtp",
            "urlhaus",
            "malwaredomainlist",
            "ciarmy",
            "emergingthreats",
            "forumspam",
            "malc0de",
        ]

        for feed_name in feeds_to_fetch:
            try:
                url = f"{self.API_BASE}/threatlist/{feed_name}"
                response = requests.get(url, headers=headers, timeout=60)
                response.raise_for_status()

                parsed = (
                    response.json()
                    if response.headers.get("content-type", "").startswith(
                        "application/json"
                    )
                    else self._parse_xml(response.text, feed_name)
                )

                for item in parsed:
                    ip = item.get("ipv4", "")
                    if not ip or ip in self.existing_ips:
                        continue

                    first_seen = item.get("date", datetime.now().strftime("%Y-%m-%d"))
                    last_seen = item.get("lastseen", first_seen)

                    feed_info = self.FEEDS.get(feed_name, {})
                    category = feed_info.get("category", "others")
                    description = feed_info.get("description", feed_name)

                    indicator = Indicator(
                        id=f"sans_{hash(ip) % 10000000}",
                        value=ip,
                        type="ipv4",
                        source="sans_isc",
                        feed_source=f"sans_{feed_name}",
                        first_seen=first_seen,
                        last_seen=last_seen,
                        confidence=70 if category == "bots" else 50,
                        tags=["sans_isc", category, feed_name],
                        metadata={
                            "feed": feed_name,
                            "description": description,
                            "category": category,
                        },
                    )
                    self.db.add_indicator(indicator)
                    self.existing_ips.add(ip)
                    count += 1

                    if count >= limit:
                        break

            except Exception as e:
                logger.debug(f"Failed to fetch SANS ISC feed {feed_name}: {e}")

            if count >= limit:
                break

        self.last_update = datetime.now()
        self.indicators_count = count
        logger.info(f"SANS ISC feed updated: {count} indicators")
        return count

    def _parse_xml(self, content: str, feed_name: str) -> List[Dict]:
        """Parse XML response"""
        items = []
        try:
            root = ET.fromstring(content)
            for elem in root.findall(".//ipv4"):
                items.append(
                    {
                        "ipv4": elem.text,
                        "date": elem.get("date", ""),
                        "lastseen": elem.get("lastseen", ""),
                    }
                )
        except Exception as e:
            logger.debug(f"Failed to parse XML for {feed_name}: {e}")
        return items

    def _get_existing_ips(self) -> Set[str]:
        """Get existing IPs from database to avoid duplicates"""
        try:
            indicators = self.db.get_indicators(limit=100000)
            return {ind.value for ind in indicators if ind.source == "sans_isc"}
        except Exception:
            return set()

    def get_status(self) -> Dict[str, Any]:
        """Get SANS ISC feed status"""
        return {
            "enabled": self.enabled,
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "indicators_count": self.indicators_count,
            "update_interval": self.update_interval,
        }


class SANSISCFeedManager:
    """Manager for SANS ISC feeds"""

    def __init__(self, db: Database):
        self.db = db
        self.sans_feed = SANSISCFeed(db)
        self.enabled = False

    def configure(
        self, enabled: bool = True, update_interval: int = 3600, api_key: str = ""
    ) -> bool:
        """Configure SANS ISC feed"""
        self.enabled = enabled
        self.sans_feed.configure(enabled, update_interval, api_key)
        logger.info(f"SANS ISC feed configured: enabled={enabled}")
        return True

    def is_enabled(self) -> bool:
        """Check if SANS ISC is enabled"""
        return self.enabled

    def get_status(self) -> Dict[str, Any]:
        """Get status of SANS ISC feed"""
        return self.sans_feed.get_status()

    def update_all(self) -> Dict[str, int]:
        """Update SANS ISC feeds"""
        results = {}
        if self.sans_feed.is_enabled():
            results["sans_isc"] = self.sans_feed.fetch_threat_ips()
        return results
