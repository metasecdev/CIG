"""
AbuseIPDB Feed Integration
Fetches threat indicators from AbuseIPDB
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import uuid

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from app.models.database import Indicator, Database
from app.core.config import settings

logger = logging.getLogger(__name__)


class AbuseIPDBFeed:
    """AbuseIPDB Feed manager"""

    def __init__(self, db: Database):
        self.db = db
        self.api_key = getattr(settings, 'abuseipdb_api_key', '')
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.last_update: Optional[datetime] = None
        self.indicators_count = 0
        self.enabled = False

    def configure(self, api_key: str) -> bool:
        """Configure AbuseIPDB connection"""
        if not api_key:
            logger.warning("AbuseIPDB API key not configured")
            return False

        self.api_key = api_key
        self.enabled = True
        return True

    def is_enabled(self) -> bool:
        """Check if AbuseIPDB is enabled"""
        return self.enabled and bool(self.api_key)

    def test_connection(self) -> bool:
        """Test AbuseIPDB API connection"""
        if not self.api_key:
            return False

        try:
            headers = {
                'Accept': 'application/json',
                'Key': self.api_key
            }

            # Test with a known malicious IP check
            response = requests.get(
                f"{self.base_url}/check",
                headers=headers,
                params={'ipAddress': '127.0.0.1', 'maxAgeInDays': 90},
                timeout=10
            )

            return response.status_code == 200
        except Exception as e:
            logger.error(f"AbuseIPDB connection test failed: {e}")
            return False

    def fetch_blacklist(self, confidence_threshold: int = 80,
                       limit: int = 10000) -> int:
        """Fetch blacklist from AbuseIPDB"""
        if not self.is_enabled():
            logger.warning("AbuseIPDB not configured")
            return 0

        try:
            headers = {
                'Accept': 'application/json',
                'Key': self.api_key
            }

            params = {
                'confidenceMinimum': confidence_threshold,
                'limit': min(limit, 10000)  # API limit
            }

            response = requests.get(
                f"{self.base_url}/blacklist",
                headers=headers,
                params=params,
                timeout=60
            )

            if response.status_code != 200:
                logger.error(f"AbuseIPDB API error: {response.status_code}")
                return 0

            data = response.json()
            blacklist = data.get('data', [])

            indicators = []
            now = datetime.utcnow().isoformat()

            for entry in blacklist:
                ip_address = entry.get('ipAddress')
                if not ip_address:
                    continue

                # Create indicator
                indicator = Indicator(
                    id=str(uuid.uuid4()),
                    value=ip_address,
                    type="ip",
                    source="abuseipdb",
                    feed_id=f"abuseipdb_{entry.get('abuseConfidenceScore', 0)}",
                    first_seen=now,
                    last_seen=now,
                    tags=f"confidence:{entry.get('abuseConfidenceScore', 0)},category:{entry.get('category', '')}"
                )
                indicators.append(indicator)

            if indicators:
                self.db.bulk_insert_indicators(indicators)
                self.indicators_count = len(indicators)
                logger.info(f"Stored {len(indicators)} AbuseIPDB indicators")
                self.last_update = datetime.utcnow()

            return len(indicators)

        except Exception as e:
            logger.error(f"Failed to fetch AbuseIPDB blacklist: {e}")
            return 0

    def check_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Check an IP address against AbuseIPDB"""
        if not self.is_enabled():
            return None

        try:
            headers = {
                'Accept': 'application/json',
                'Key': self.api_key
            }

            response = requests.get(
                f"{self.base_url}/check",
                headers=headers,
                params={'ipAddress': ip_address, 'maxAgeInDays': 90},
                timeout=10
            )

            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'ip': ip_address,
                    'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                    'country_code': data.get('countryCode', ''),
                    'usage_type': data.get('usageType', ''),
                    'isp': data.get('isp', ''),
                    'domain': data.get('domain', ''),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'total_reports': data.get('totalReports', 0),
                    'last_reported_at': data.get('lastReportedAt', '')
                }

        except Exception as e:
            logger.error(f"Failed to check IP {ip_address}: {e}")

        return None

    def get_status(self) -> Dict[str, Any]:
        """Get AbuseIPDB feed status"""
        return {
            "enabled": self.is_enabled(),
            "connected": self.test_connection() if self.is_enabled() else False,
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "indicators_count": self.indicators_count,
            "api_configured": bool(self.api_key)
        }