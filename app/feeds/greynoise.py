"""
GrayNoise Intelligence Feed Integration
Fetches internet background noise and botnet data from GrayNoise API
Provides real-time threat intelligence on scanning and exploit activities
"""

import logging
import requests
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class GrayNoiseStats:
    """GrayNoise polling statistics"""

    total_ips_checked: int = 0
    malicious_ips: int = 0
    unknown_ips: int = 0
    benign_ips: int = 0
    last_query: Optional[str] = None
    last_error: Optional[str] = None
    consecutive_failures: int = 0
    poll_count: int = 0
    api_calls_remaining: int = 0


class GrayNoiseConnector:
    """
    GrayNoise threat intelligence feed connector
    Future enhancement for integrating GrayNoise API for IP reputation
    """

    API_BASE = "https://api.greynoise.io/v3"
    COMMUNITY_API_BASE = "https://api.greynoise.io/v2"

    def __init__(self, api_key: str = "", use_community: bool = False, database=None):
        """
        Initialize GrayNoise connector

        Args:
            api_key: GrayNoise API key
            use_community: Use community/free API instead of commercial
            database: Optional database instance for storing intelligence
        """
        self.api_key = api_key
        self.use_community = use_community
        self.database = database
        self.session = None
        self.stats = GrayNoiseStats()
        self.last_query_time: Optional[datetime] = None
        self.ip_cache: List[Dict[str, Any]] = []

    def _connect(self) -> requests.Session:
        """
        Establish connection to GrayNoise API

        Returns:
            Requests session with authentication headers
        """
        if self.session is not None:
            return self.session

        self.session = requests.Session()

        if not self.use_community:
            self.session.headers.update(
                {
                    "Authorization": f"Key {self.api_key}",
                    "User-Agent": "CIG/1.0 (Cyber Intelligence Gateway)",
                }
            )
        else:
            self.session.headers.update(
                {
                    "Authorization": f"Bearer {self.api_key}",
                    "User-Agent": "CIG/1.0 (Cyber Intelligence Gateway)",
                }
            )

        return self.session

    def check_ip(self, ip_address: str) -> Tuple[Dict[str, Any], bool]:
        """
        Check reputation of a single IP address

        Args:
            ip_address: IP to check

        Returns:
            (ip_data, success)
        """
        if not self.api_key:
            logger.warning("GrayNoise API key not configured")
            return {}, False

        try:
            session = self._connect()
            endpoint = (
                f"{self.API_BASE}/ips/{ip_address}"
                if not self.use_community
                else f"{self.COMMUNITY_API_BASE}/ips/{ip_address}"
            )

            response = session.get(endpoint, timeout=10)
            response.raise_for_status()

            data = response.json()

            # Track remaining API calls for rate limit management
            if "rate_limit_remaining" in response.headers:
                self.stats.api_calls_remaining = int(
                    response.headers.get("rate_limit_remaining", 0)
                )

            logger.debug(
                f"GrayNoise IP check for {ip_address}: {data.get('classification', 'unknown')}"
            )
            return data, True

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                # IP not found in GrayNoise
                return {"ip": ip_address, "classification": "unknown"}, True
            msg = f"GrayNoise API error: {e}"
            logger.error(msg)
            self.stats.last_error = msg
            self.stats.consecutive_failures += 1
            return {}, False
        except Exception as e:
            msg = f"GrayNoise IP check failed: {e}"
            logger.error(msg)
            self.stats.last_error = msg
            self.stats.consecutive_failures += 1
            return {}, False

    def query_ips(self, ips: List[str]) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Query multiple IP addresses for reputation

        Args:
            ips: List of IP addresses to check

        Returns:
            (list_of_ip_data, success)
        """
        results = []

        for ip in ips:
            data, success = self.check_ip(ip)
            if success:
                results.append(data)

            # Update statistics
            classification = data.get("classification", "unknown")
            self.stats.total_ips_checked += 1

            if classification == "malicious":
                self.stats.malicious_ips += 1
            elif classification == "benign":
                self.stats.benign_ips += 1
            else:
                self.stats.unknown_ips += 1

        self.last_query_time = datetime.now(timezone.utc)
        self.stats.last_query = self.last_query_time.isoformat()
        self.stats.consecutive_failures = 0
        self.stats.last_error = None
        self.stats.poll_count += 1

        # Ingest into database if available
        if self.database:
            self._ingest_ips(results)

        logger.info(f"GrayNoise query: {len(results)} IPs processed")
        return results, True

    def get_trending_ips(self, limit: int = 100) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Get trending malicious IPs from GrayNoise (if available in API)

        Args:
            limit: Maximum IPs to return

        Returns:
            (trending_ips, success)
        """
        if not self.api_key:
            logger.warning("GrayNoise API key not configured")
            return [], False

        try:
            session = self._connect()

            # This endpoint may vary based on GrayNoise API version
            endpoint = f"{self.API_BASE}/ips?limit={limit}&classification=malicious"

            response = session.get(endpoint, timeout=30)
            response.raise_for_status()

            data = response.json()
            ips = data.get("data", [])[:limit]

            logger.info(f"Retrieved {len(ips)} trending malicious IPs from GrayNoise")
            return ips, True

        except Exception as e:
            msg = f"Failed to get trending IPs: {e}"
            logger.error(msg)
            self.stats.last_error = msg
            self.stats.consecutive_failures += 1
            return [], False

    def _normalize_ips(self, ip_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Normalize GrayNoise IP data to standard indicator format

        Args:
            ip_data: Raw IP data from GrayNoise API

        Returns:
            Normalized IP indicators
        """
        normalized = []

        for item in ip_data:
            classification = item.get("classification", "unknown")

            # Only include malicious IPs or suspicious ones
            if classification not in ["malicious", "benign"]:
                continue

            severity_map = {
                "malicious": "high",
                "benign": "info",
                "unknown": "low",
            }

            normalized_item = {
                "value": item.get("ip", ""),
                "type": "ip",
                "source": "greynoise",
                "feed_source": "greynoise",
                "severity": severity_map.get(classification, "info"),
                "confidence": 90,  # GrayNoise is highly reliable
                "tags": [
                    "greynoise",
                    classification,
                    item.get("last_seen_classification", "unknown"),
                ],
                "first_seen": self.last_query_time.isoformat()
                if self.last_query_time
                else None,
                "last_seen": datetime.now(timezone.utc).isoformat(),
                "raw_data": item,
                "description": f"GrayNoise classification: {classification}",
            }
            normalized.append(normalized_item)

        return normalized

    def _ingest_ips(self, ip_data: List[Dict[str, Any]]):
        """Ingest normalized IP data into database"""
        if not self.database or not ip_data:
            return

        try:
            normalized = self._normalize_ips(ip_data)
            for ip in normalized:
                self.database.add_indicator(
                    value=ip["value"],
                    type=ip["type"],
                    source=ip["source"],
                    feed_source=ip["feed_source"],
                    tags=",".join(ip.get("tags", [])),
                    first_seen=ip.get("first_seen"),
                    last_seen=ip.get("last_seen"),
                )
            logger.debug(f"Ingested {len(normalized)} GrayNoise IPs into database")
        except Exception as e:
            logger.error(f"Failed to ingest GrayNoise data: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get polling statistics"""
        return asdict(self.stats)

    def reset_stats(self):
        """Reset statistics"""
        self.stats = GrayNoiseStats()

    async def query_ips_async(
        self, ips: List[str]
    ) -> Tuple[List[Dict[str, Any]], bool]:
        """Async wrapper for querying IPs"""
        try:
            return await asyncio.to_thread(self.query_ips, ips)
        except Exception as e:
            logger.error(f"Async query failed: {e}")
            return [], False

    async def get_trending_ips_async(
        self, limit: int = 100
    ) -> Tuple[List[Dict[str, Any]], bool]:
        """Async wrapper for getting trending IPs"""
        try:
            return await asyncio.to_thread(self.get_trending_ips, limit)
        except Exception as e:
            logger.error(f"Async trending IPs query failed: {e}")
            return [], False

    def query_ips_by_age(
        self, days: int = 2, limit: int = 100
    ) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Query IPs by last seen age (recent activity)

        Args:
            days: Number of days to look back (e.g., 2 = last 2 days)
            limit: Maximum IPs to return

        Returns:
            (list_of_ip_data, success)
        """
        if not self.api_key:
            logger.warning("GrayNoise API key not configured")
            return [], False

        try:
            session = self._connect()

            # Query endpoint for IPs seen in the last N days
            # Using the query/list endpoint with filters
            endpoint = f"{self.API_BASE}/query"

            # Query for malicious IPs seen recently
            payload = {
                "query": f"last_seen:{days}d classification:malicious",
                "limit": min(limit, 1000),
                "sort": ["-last_seen"],
            }

            response = session.post(endpoint, json=payload, timeout=30)
            response.raise_for_status()

            data = response.json()
            ips = data.get("data", [])[:limit]

            logger.info(f"Retrieved {len(ips)} malicious IPs seen in last {days} days")
            return ips, True

        except Exception as e:
            msg = f"Failed to query IPs by age: {e}"
            logger.error(msg)
            self.stats.last_error = msg
            self.stats.consecutive_failures += 1
            return [], False

    def get_recent_activity(
        self, days: int = 2, classification: str = "malicious"
    ) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Get recent activity from GrayNoise

        Args:
            days: Number of days to look back
            classification: Filter by classification (malicious, benign, unknown)

        Returns:
            (activity_data, success)
        """
        if not self.api_key:
            logger.warning("GrayNoise API key not configured")
            return [], False

        try:
            session = self._connect()

            # Use the community query endpoint for recent activity
            if self.use_community:
                endpoint = f"{self.COMMUNITY_API_BASE}/noise/recent"
            else:
                endpoint = f"{self.API_BASE}/query"
                payload = {
                    "query": f"last_seen:{days}d classification:{classification}",
                    "limit": 100,
                    "sort": ["-last_seen"],
                }
                response = session.post(endpoint, json=payload, timeout=30)

            if self.use_community:
                params = {"days": days}
                response = session.get(endpoint, params=params, timeout=30)

            response.raise_for_status()
            data = response.json()

            records = (
                data.get("data", []) if "data" in data else data.get("records", [])
            )

            logger.info(
                f"Retrieved {len(records)} {classification} IPs from last {days} days"
            )
            return records, True

        except Exception as e:
            msg = f"Failed to get recent activity: {e}"
            logger.error(msg)
            self.stats.last_error = msg
            return [], False

    def get_query_results(
        self, query: str = "last_seen:2d", limit: int = 100
    ) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Execute custom GrayNoise query

        Args:
            query: GrayNoise query string (e.g., "last_seen:2d", "classification:malicious")
            limit: Maximum results

        Returns:
            (query_results, success)
        """
        if not self.api_key:
            logger.warning("GrayNoise API key not configured")
            return [], False

        try:
            session = self._connect()

            # Use the query endpoint
            endpoint = f"{self.API_BASE}/query"
            payload = {"query": query, "limit": min(limit, 1000)}

            response = session.post(endpoint, json=payload, timeout=30)
            response.raise_for_status()

            data = response.json()
            results = data.get("data", [])[:limit]

            logger.info(f"Query '{query}' returned {len(results)} results")
            return results, True

        except Exception as e:
            msg = f"Query failed: {e}"
            logger.error(msg)
            self.stats.last_error = msg
            return [], False


# Global instance
_greynoise_connector: Optional[GrayNoiseConnector] = None


def get_greynoise_connector(
    api_key: str = "", use_community: bool = False, database=None
) -> GrayNoiseConnector:
    """Get or create GrayNoise connector instance"""
    global _greynoise_connector
    if _greynoise_connector is None:
        _greynoise_connector = GrayNoiseConnector(
            api_key=api_key, use_community=use_community, database=database
        )
    return _greynoise_connector


async def poll_greynoise_feed(
    api_key: str = "", use_community: bool = False, database=None
):
    """Async function to poll GrayNoise feed (for scheduler integration)"""
    connector = get_greynoise_connector(
        api_key=api_key, use_community=use_community, database=database
    )
    return await connector.get_trending_ips_async()
