"""
Nessus Vulnerability Feed Integration
Fetches vulnerability data from Nessus cloud API
Future enhancement for vulnerability management
"""

import logging
import requests
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class NessusStats:
    """Nessus polling statistics"""
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    last_scan: Optional[str] = None
    last_error: Optional[str] = None
    consecutive_failures: int = 0
    poll_count: int = 0


class NessusConnector:
    """
    Nessus vulnerability feed connector
    Future enhancement for integrating Nessus cloud/on-premise scans
    """

    API_BASE = "https://cloud.nessus.com/api/v2"  # Default Nessus cloud endpoint

    def __init__(self, api_key: str = "", api_secret: str = "", database=None):
        """
        Initialize Nessus connector
        
        Args:
            api_key: Nessus API access key
            api_secret: Nessus API secret key
            database: Optional database instance for storing vulnerabilities
        """
        self.api_key = api_key
        self.api_secret = api_secret
        self.database = database
        self.session = None
        self.stats = NessusStats()
        self.last_scan_time: Optional[datetime] = None
        self.vulnerability_cache: List[Dict[str, Any]] = []

    def _connect(self) -> requests.Session:
        """
        Establish connection to Nessus API
        
        Returns:
            Requests session with authentication headers
        """
        if self.session is not None:
            return self.session

        self.session = requests.Session()
        self.session.headers.update({
            "X-ApiKeys": f"accessKey={self.api_key}; secretKey={self.api_secret}",
            "Accept": "application/json",
        })
        return self.session

    def get_scans(self) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Get list of available scans
        
        Returns:
            (list_of_scans, success)
        """
        if not self.api_key or not self.api_secret:
            logger.warning("Nessus API credentials not configured")
            return [], False

        try:
            session = self._connect()
            response = session.get(f"{self.API_BASE}/scans", timeout=30)
            response.raise_for_status()
            
            scans = response.json().get("scans", [])
            logger.info(f"Retrieved {len(scans)} Nessus scans")
            return scans, True

        except Exception as e:
            msg = f"Failed to get Nessus scans: {e}"
            logger.error(msg)
            self.stats.last_error = msg
            self.stats.consecutive_failures += 1
            return [], False

    def get_scan_details(self, scan_id: int) -> Tuple[Dict[str, Any], bool]:
        """
        Get detailed vulnerability data from a specific scan
        
        Args:
            scan_id: Nessus scan ID
        
        Returns:
            (scan_details, success)
        """
        if not self.api_key or not self.api_secret:
            logger.warning("Nessus API credentials not configured")
            return {}, False

        try:
            session = self._connect()
            response = session.get(f"{self.API_BASE}/scans/{scan_id}", timeout=30)
            response.raise_for_status()
            
            details = response.json()
            logger.info(f"Retrieved details for scan {scan_id}")
            return details, True

        except Exception as e:
            msg = f"Failed to get Nessus scan details: {e}"
            logger.error(msg)
            self.stats.last_error = msg
            self.stats.consecutive_failures += 1
            return {}, False

    def fetch_vulnerabilities(self, limit: int = 1000) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Fetch latest vulnerabilities from latest scan
        
        Args:
            limit: Maximum vulnerabilities to fetch
        
        Returns:
            (vulnerabilities_list, success)
        """
        if not self.api_key or not self.api_secret:
            logger.warning("Nessus API credentials not configured")
            return [], False

        try:
            scans, success = self.get_scans()
            if not success or not scans:
                return [], False

            # Get the latest scan
            latest_scan = scans[0]
            scan_id = latest_scan.get("id")
            
            details, success = self.get_scan_details(scan_id)
            if not success:
                return [], False

            vulnerabilities = self._normalize_vulnerabilities(details, scan_id)
            
            self.vulnerability_cache = vulnerabilities[:limit]
            self.last_scan_time = datetime.now(timezone.utc)
            self.stats.last_scan = self.last_scan_time.isoformat()
            self.stats.total_vulnerabilities = len(vulnerabilities)
            self.stats.consecutive_failures = 0
            self.stats.last_error = None
            self.stats.poll_count += 1

            # Ingest into database if available
            if self.database:
                self._ingest_vulnerabilities(vulnerabilities)

            logger.info(f"Fetched {len(vulnerabilities)} vulnerabilities from Nessus")
            return vulnerabilities, True

        except Exception as e:
            msg = f"Failed to fetch Nessus vulnerabilities: {e}"
            logger.error(msg)
            self.stats.last_error = msg
            self.stats.consecutive_failures += 1
            return [], False

    def _normalize_vulnerabilities(
        self, scan_data: Dict[str, Any], scan_id: int
    ) -> List[Dict[str, Any]]:
        """
        Normalize Nessus vulnerability data to standard indicator format
        
        Args:
            scan_data: Raw scan data from Nessus API
            scan_id: Source scan ID
        
        Returns:
            Normalized vulnerability indicators
        """
        normalized = []
        
        # Extract vulnerabilities from scan info
        vulns = scan_data.get("vulnerabilities", [])
        
        for vuln in vulns:
            severity_map = {
                0: "info",
                1: "low",
                2: "medium",
                3: "high",
                4: "critical",
            }
            
            severity_level = severity_map.get(vuln.get("severity", 0), "info")
            
            normalized_item = {
                "value": vuln.get("plugin_id", ""),
                "type": "cve" if "cve" in str(vuln).lower() else "vulnerability",
                "source": "nessus",
                "feed_source": f"nessus-scan-{scan_id}",
                "severity": severity_level,
                "confidence": 95,  # Nessus is highly reliable
                "tags": [
                    "nessus",
                    severity_level,
                    vuln.get("plugin_family", "unknown").lower(),
                ],
                "first_seen": self.last_scan_time.isoformat() if self.last_scan_time else None,
                "last_seen": self.last_scan_time.isoformat() if self.last_scan_time else None,
                "raw_data": vuln,
                "description": vuln.get("plugin_output", ""),
            }
            
            # Track severity counts
            if severity_level == "critical":
                self.stats.critical_count += 1
            elif severity_level == "high":
                self.stats.high_count += 1
            elif severity_level == "medium":
                self.stats.medium_count += 1
            elif severity_level == "low":
                self.stats.low_count += 1
            
            normalized.append(normalized_item)
        
        return normalized

    def _ingest_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]):
        """Ingest normalized vulnerabilities into database"""
        if not self.database or not vulnerabilities:
            return

        try:
            for vuln in vulnerabilities:
                self.database.add_indicator(
                    value=vuln["value"],
                    type=vuln["type"],
                    source=vuln["source"],
                    feed_source=vuln["feed_source"],
                    tags=",".join(vuln.get("tags", [])),
                    first_seen=vuln.get("first_seen"),
                    last_seen=vuln.get("last_seen"),
                )
            logger.debug(f"Ingested {len(vulnerabilities)} Nessus vulnerabilities into database")
        except Exception as e:
            logger.error(f"Failed to ingest Nessus vulnerabilities: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get polling statistics"""
        return asdict(self.stats)

    def reset_stats(self):
        """Reset statistics"""
        self.stats = NessusStats()

    async def fetch_vulnerabilities_async(self) -> Tuple[List[Dict[str, Any]], bool]:
        """Async wrapper for fetching vulnerabilities"""
        try:
            return await asyncio.to_thread(self.fetch_vulnerabilities)
        except Exception as e:
            logger.error(f"Async fetch failed: {e}")
            return [], False


# Global instance
_nessus_connector: Optional[NessusConnector] = None


def get_nessus_connector(api_key: str = "", api_secret: str = "", database=None) -> NessusConnector:
    """Get or create Nessus connector instance"""
    global _nessus_connector
    if _nessus_connector is None:
        _nessus_connector = NessusConnector(api_key=api_key, api_secret=api_secret, database=database)
    return _nessus_connector


async def poll_nessus_feed(api_key: str = "", api_secret: str = "", database=None):
    """Async function to poll Nessus feed (for scheduler integration)"""
    connector = get_nessus_connector(api_key=api_key, api_secret=api_secret, database=database)
    return await connector.fetch_vulnerabilities_async()
