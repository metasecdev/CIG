"""
Abuse.ch Feed Integration
Supports URLhaus (malware URLs) and ThreatFox (malware indicators)
https://github.com/abusech
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import re

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from app.models.database import Indicator, Database
from app.core.config import settings

logger = logging.getLogger(__name__)


class URLhausFeed:
    """URLhaus malware URL feed"""

    FEED_URLS = {
        "full": "https://urlhaus-api.abuse.ch/downloads/csv_full/",
        "short": "https://urlhaus-api.abuse.ch/downloads/csv_short/",
    }

    def __init__(self, db: Database):
        self.db = db
        self.api_key = getattr(settings, "abusech_api_key", "")
        self.enabled = False
        self.last_update: Optional[datetime] = None
        self.indicators_count = 0

    def configure(self, api_key: str, enabled: bool = True) -> bool:
        """Configure URLhaus feed"""
        self.api_key = api_key
        self.enabled = enabled
        return True

    def is_enabled(self) -> bool:
        """Check if URLhaus is enabled"""
        return self.enabled

    def fetch_urls(self, feed_type: str = "short") -> int:
        """Fetch malware URLs from URLhaus"""
        if not self.enabled:
            logger.warning("URLhaus feed not enabled")
            return 0

        url = self.FEED_URLS.get(feed_type, self.FEED_URLS["short"])

        try:
            headers = {"User-Agent": "CIG/1.0 - Cyber Intelligence Gateway"}
            if self.api_key:
                headers["Authorization"] = f"Token {self.api_key}"

            response = requests.get(url, headers=headers, timeout=60)
            response.raise_for_status()

            count = self._parse_csv(response.text)
            self.last_update = datetime.now()
            logger.info(f"URLhaus feed updated: {count} URLs")
            return count

        except Exception as e:
            logger.error(f"Failed to fetch URLhaus feed: {e}")
            return 0

    def _parse_csv(self, content: str) -> int:
        """Parse URLhaus CSV format"""
        count = 0
        lines = content.strip().split("\n")

        for line in lines:
            if not line or line.startswith("#") or line.startswith("id"):
                continue

            try:
                parts = line.split(",")
                if len(parts) >= 5:
                    url = parts[1].strip().strip('"')
                    url_status = parts[4].strip().strip('"')

                    if url and url_status in ["online", "offline"]:
                        indicator = Indicator(
                            id=f"urlhaus_{hash(url) % 1000000}",
                            value=url,
                            type="url",
                            source="urlhaus",
                            feed_source="urlhaus",
                            first_seen=datetime.now().isoformat(),
                            last_seen=datetime.now().isoformat(),
                            confidence=90 if url_status == "online" else 50,
                            tags=["malware", url_status],
                            metadata={},
                        )
                        self.db.add_indicator(indicator)
                        count += 1

            except Exception as e:
                logger.debug(f"Failed to parse URLhaus line: {e}")

        return count


class ThreatFoxFeed:
    """ThreatFox malware indicator feed"""

    FEED_URL = "https://threatfox-api.abuse.ch/api/v1/"

    def __init__(self, db: Database):
        self.db = db
        self.api_key = getattr(settings, "abusech_api_key", "")
        self.enabled = False
        self.last_update: Optional[datetime] = None
        self.indicators_count = 0

    def configure(self, api_key: str, enabled: bool = True) -> bool:
        """Configure ThreatFox feed"""
        self.api_key = api_key
        self.enabled = enabled
        return True

    def is_enabled(self) -> bool:
        """Check if ThreatFox is enabled"""
        return self.enabled

    def fetch_indicators(self, limit: int = 1000) -> int:
        """Fetch malware indicators from ThreatFox"""
        if not self.enabled:
            logger.warning("ThreatFox feed not enabled")
            return 0

        try:
            payload = {"query": "get_iocs", "limit": limit, "days": 7}

            headers = {
                "User-Agent": "CIG/1.0 - Cyber Intelligence Gateway",
                "Content-Type": "application/json",
            }
            if self.api_key:
                headers["API-KEY"] = self.api_key

            response = requests.post(
                self.FEED_URL, json=payload, headers=headers, timeout=60
            )

            if response.status_code == 200:
                data = response.json()
                count = self._parse_response(data)
                self.last_update = datetime.now()
                logger.info(f"ThreatFox feed updated: {count} indicators")
                return count
            else:
                logger.warning(f"ThreatFox API returned {response.status_code}")
                return 0

        except Exception as e:
            logger.error(f"Failed to fetch ThreatFox feed: {e}")
            return 0

    def _parse_response(self, data: Dict) -> int:
        """Parse ThreatFox response"""
        count = 0

        try:
            iocs = data.get("data", [])
            for ioc in iocs:
                ioc_type = ioc.get("ioc_type", "")
                ioc_value = ioc.get("ioc", "")
                malware = ioc.get("malware", {}).get("alias", "unknown")

                if not ioc_value:
                    continue

                indicator_type = "url"
                if ioc_type == "ip:port":
                    indicator_type = "ip"
                elif ioc_type == "domain":
                    indicator_type = "domain"
                elif ioc_type == "md5" or ioc_type == "sha1" or ioc_type == "sha256":
                    indicator_type = "hash"

                indicator = Indicator(
                    id=f"threatfox_{hash(ioc_value) % 1000000}",
                    value=ioc_value,
                    type=indicator_type,
                    source="threatfox",
                    feed_source="threatfox",
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat(),
                    confidence=80,
                    tags=["malware", malware],
                    metadata={"malware": malware},
                )
                self.db.add_indicator(indicator)
                count += 1

        except Exception as e:
            logger.error(f"Failed to parse ThreatFox response: {e}")

        return count


class AbuseChFeedManager:
    """Manager for all abuse.ch feeds"""

    def __init__(self, db: Database):
        self.db = db
        self.urlhaus = URLhausFeed(db)
        self.threatfox = ThreatFoxFeed(db)
        self.api_key = ""
        self.enabled = False

    def configure(
        self, api_key: str, enable_urlhaus: bool = True, enable_threatfox: bool = True
    ) -> bool:
        """Configure all abuse.ch feeds"""
        self.api_key = api_key
        self.enabled = True

        self.urlhaus.configure(api_key, enable_urlhaus)
        self.threatfox.configure(api_key, enable_threatfox)

        logger.info(
            f"Abuse.ch feeds configured: urlhaus={enable_urlhaus}, threatfox={enable_threatfox}"
        )
        return True

    def is_enabled(self) -> bool:
        """Check if any abuse.ch feed is enabled"""
        return self.enabled

    def get_status(self) -> Dict[str, Any]:
        """Get status of all abuse.ch feeds"""
        return {
            "enabled": self.enabled,
            "urlhaus": {
                "enabled": self.urlhaus.is_enabled(),
                "last_update": self.urlhaus.last_update.isoformat()
                if self.urlhaus.last_update
                else None,
                "indicators_count": self.urlhaus.indicators_count,
            },
            "threatfox": {
                "enabled": self.threatfox.is_enabled(),
                "last_update": self.threatfox.last_update.isoformat()
                if self.threatfox.last_update
                else None,
                "indicators_count": self.threatfox.indicators_count,
            },
        }

    def update_all(self) -> Dict[str, int]:
        """Update all enabled feeds"""
        results = {}

        if self.urlhaus.is_enabled():
            results["urlhaus"] = self.urlhaus.fetch_urls()

        if self.threatfox.is_enabled():
            results["threatfox"] = self.threatfox.fetch_indicators()

        return results
