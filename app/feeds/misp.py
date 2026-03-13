"""
MISP Feed Integration Module
Fetches threat indicators from MISP servers
"""

import asyncio
import logging
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
import ipaddress

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from app.models.database import Indicator, Database
from app.core.config import settings

logger = logging.getLogger(__name__)


class MISPClient:
    """Client for connecting to MISP servers"""

    def __init__(self, url: str, api_key: str, verify_ssl: bool = False):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = None

    def _get_session(self) -> Optional[requests.Session]:
        """Get or create requests session"""
        if not HAS_REQUESTS:
            logger.warning("requests library not available")
            return None

        if self.session is None:
            self.session = requests.Session()
            self.session.headers.update({
                "Authorization": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json"
            })
        return self.session

    def test_connection(self) -> bool:
        """Test connection to MISP server"""
        try:
            session = self._get_session()
            if session is None:
                return False
            response = session.get(
                f"{self.url}/events",
                params={"limit": 1},
                verify=self.verify_ssl,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"MISP connection test failed: {e}")
            return False

    def get_attribute_count(self) -> int:
        """Get total attribute count"""
        try:
            session = self._get_session()
            if session is None:
                return 0
            response = session.get(
                f"{self.url}/attributes/count",
                verify=self.verify_ssl,
                timeout=30
            )
            if response.status_code == 200:
                return response.json().get("count", 0)
        except Exception as e:
            logger.error(f"Failed to get MISP attribute count: {e}")
        return 0

    def fetch_attributes(self, type_filter: Optional[List[str]] = None,
                        limit: int = 1000) -> List[Dict[str, Any]]:
        """Fetch attributes from MISP"""
        try:
            session = self._get_session()
            if session is None:
                return []

            params = {"limit": limit, "type": type_filter} if type_filter else {"limit": limit}

            response = session.get(
                f"{self.url}/attributes",
                params=params,
                verify=self.verify_ssl,
                timeout=60
            )

            if response.status_code == 200:
                return response.json().get("response", []).get("Attribute", [])
        except Exception as e:
            logger.error(f"Failed to fetch MISP attributes: {e}")
        return []

    def fetch_events(self, last: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch events from MISP"""
        try:
            session = self._get_session()
            if session is None:
                return []

            params = {"limit": limit}
            if last:
                params["last"] = last

            response = session.get(
                f"{self.url}/events",
                params=params,
                verify=self.verify_ssl,
                timeout=60
            )

            if response.status_code == 200:
                return response.json().get("response", []).get("Event", [])
        except Exception as e:
            logger.error(f"Failed to fetch MISP events: {e}")
        return []


class MISPFeed:
    """MISP Feed manager"""

    def __init__(self, db: Database):
        self.db = db
        self.client: Optional[MISPClient] = None
        self.last_update: Optional[datetime] = None
        self.indicators_count = 0
        self.enabled = False

    def configure(self, url: str, api_key: str, verify_ssl: bool = False) -> bool:
        """Configure MISP connection"""
        if not url or not api_key:
            logger.warning("MISP URL or API key not configured")
            return False

        self.client = MISPClient(url, api_key, verify_ssl)
        self.enabled = True
        return True

    def is_enabled(self) -> bool:
        """Check if MISP is enabled"""
        return self.enabled and self.client is not None

    def test_connection(self) -> bool:
        """Test MISP connection"""
        if not self.client:
            return False
        return self.client.test_connection()

    def parse_indicator_type(self, attribute_type: str) -> str:
        """Map MISP attribute type to our indicator type"""
        type_mapping = {
            "ip-src": "ip",
            "ip-dst": "ip",
            "domain": "domain",
            "hostname": "domain",
            "md5": "hash",
            "sha1": "hash",
            "sha256": "hash",
            "url": "url",
            "link": "url",
            "uri": "url",
            "email": "email",
            "email-src": "email",
            "email-dst": "email",
        }
        return type_mapping.get(attribute_type.lower(), "")

    def is_valid_ip(self, value: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def fetch_and_process(self) -> int:
        """Fetch indicators from MISP and store in database"""
        if not self.client:
            logger.warning("MISP client not configured")
            return 0

        logger.info("Fetching attributes from MISP...")
        attributes = self.client.fetch_attributes(limit=5000)

        if not attributes:
            logger.warning("No attributes fetched from MISP")
            return 0

        indicators = []
        now = datetime.utcnow().isoformat()

        for attr in attributes:
            value = attr.get("value", "").strip()
            attr_type = attr.get("type", "")
            indicator_type = self.parse_indicator_type(attr_type)

            if not value or not indicator_type:
                continue

            # Validate IP addresses
            if indicator_type == "ip" and not self.is_valid_ip(value):
                continue

            indicator = Indicator(
                id=str(uuid.uuid4()),
                value=value,
                type=indicator_type,
                source="misp",
                feed_id=f"misp_{attr.get('event_id', 'unknown')}",
                first_seen=now,
                last_seen=now,
                tags=",".join(attr.get("tags", [])) if isinstance(attr.get("tags"), list) else str(attr.get("tags", ""))
            )
            indicators.append(indicator)

        if indicators:
            self.db.bulk_insert_indicators(indicators)
            self.indicators_count = len(indicators)
            logger.info(f"Stored {len(indicators)} MISP indicators")
            self.last_update = datetime.utcnow()

        return len(indicators)

    def get_status(self) -> Dict[str, Any]:
        """Get MISP feed status"""
        return {
            "enabled": self.is_enabled(),
            "connected": self.test_connection() if self.is_enabled() else False,
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "indicators_count": self.indicators_count,
            "url": self.client.url if self.client else None
        }
