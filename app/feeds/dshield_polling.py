"""DShield Honeypot API Live Polling
Fetches real-time threat data from SANS DShield honeypot network
Provides continuous polling with database integration
"""

import logging
import requests
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta, timezone
import json
from dataclasses import dataclass, asdict
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class DShieldStats:
    """DShield polling statistics"""
    total_ssh_attacks: int = 0
    total_web_attacks: int = 0
    unique_attacker_ips: int = 0
    last_ssh_poll: Optional[str] = None
    last_web_poll: Optional[str] = None
    last_error: Optional[str] = None
    consecutive_failures: int = 0
    poll_count: int = 0


class DShieldPoller:
    """Live polling for SANS DShield honeypot data with database integration"""

    API_BASE = "https://isc.sans.edu/api"
    CRITICAL_SEVERITY = "critical"

    def __init__(self, database=None):
        self.database = database
        self.last_ssh_poll: Optional[datetime] = None
        self.last_web_poll: Optional[datetime] = None
        self.last_port_scan_poll: Optional[datetime] = None
        self.ssh_cache: List[Dict[str, Any]] = []
        self.web_cache: List[Dict[str, Any]] = []
        self.port_scan_cache: Dict[str, Any] = {}
        self.cache_ttl = 300  # 5 minutes
        self.stats = DShieldStats()
        self.poll_interval = 300  # 5 minutes default
        self._is_polling = False

    def poll_ssh_attackers(self, limit: int = 100) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Fetch latest SSH attacker IPs from DShield honeypot
        
        Returns:
            (attacks_list, success)
        """
        try:
            url = f"{self.API_BASE}/dshield/ssh/attacks"
            headers = {"User-Agent": "CIG/1.0 (Cyber Intelligence Gateway)"}
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            attacks = data.get("attacks", [])[:limit]
            
            # Normalize the data
            normalized_attacks = self._normalize_attacks(attacks, "ssh")
            
            self.ssh_cache = normalized_attacks
            self.last_ssh_poll = datetime.now(timezone.utc)
            self.stats.last_ssh_poll = self.last_ssh_poll.isoformat()
            self.stats.total_ssh_attacks = len(attacks)
            self.stats.consecutive_failures = 0
            self.stats.last_error = None
            self.stats.poll_count += 1
            
            # Ingest into database if available
            if self.database:
                self._ingest_indicators(normalized_attacks, "dshield-ssh")
            
            logger.info(f"DShield SSH poll: fetched {len(attacks)} active attackers")
            return normalized_attacks, True
            
        except requests.exceptions.Timeout:
            msg = "DShield SSH poll timeout"
            logger.error(msg)
            self.stats.last_error = msg
            self.stats.consecutive_failures += 1
            return self.ssh_cache, False
        except requests.exceptions.ConnectionError:
            msg = "DShield SSH poll connection error"
            logger.error(msg)
            self.stats.last_error = msg
            self.stats.consecutive_failures += 1
            return self.ssh_cache, False
        except Exception as e:
            msg = f"DShield SSH poll failed: {e}"
            logger.error(msg)
            self.stats.last_error = msg
            self.stats.consecutive_failures += 1
            return self.ssh_cache, False

    def poll_web_attackers(self, limit: int = 100) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Fetch latest Web vulnerability scanner IPs from DShield honeypot
        
        Returns:
            (attacks_list, success)
        """
        try:
            url = f"{self.API_BASE}/dshield/web/attacks"
            headers = {"User-Agent": "CIG/1.0 (Cyber Intelligence Gateway)"}
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            attacks = data.get("attacks", [])[:limit]
            
            # Normalize the data
            normalized_attacks = self._normalize_attacks(attacks, "web")
            
            self.web_cache = normalized_attacks
            self.last_web_poll = datetime.now(timezone.utc)
            self.stats.last_web_poll = self.last_web_poll.isoformat()
            self.stats.total_web_attacks = len(attacks)
            self.stats.consecutive_failures = 0
            self.stats.last_error = None
            self.stats.poll_count += 1
            
            # Ingest into database if available
            if self.database:
                self._ingest_indicators(normalized_attacks, "dshield-web")
            
            logger.info(f"DShield Web poll: fetched {len(attacks)} active scanners")
            return normalized_attacks, True
            
        except requests.exceptions.Timeout:
            msg = "DShield Web poll timeout"
            logger.error(msg)
            self.stats.last_error = msg
            self.stats.consecutive_failures += 1
            return self.web_cache, False
        except requests.exceptions.ConnectionError:
            msg = "DShield Web poll connection error"
            logger.error(msg)
            self.stats.last_error = msg
            self.stats.consecutive_failures += 1
            return self.web_cache, False
        except Exception as e:
            msg = f"DShield Web poll failed: {e}"
            logger.error(msg)
            self.stats.last_error = msg
            self.stats.consecutive_failures += 1
            return self.web_cache, False

    def poll_port_scan_trends(self, limit: int = 100) -> Tuple[Dict[str, Any], bool]:
        """
        Fetch trending port scan activity
        
        Returns:
            (port_scan_data, success)
        """
        try:
            url = f"{self.API_BASE}/dshield/portscans"
            headers = {"User-Agent": "CIG/1.0 (Cyber Intelligence Gateway)"}
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            ports = data.get("ports", [])[:limit]
            
            self.port_scan_cache = data
            self.last_port_scan_poll = datetime.now(timezone.utc)
            logger.info(f"DShield port scan trends: {len(ports)} trending ports")
            return data, True
            
        except Exception as e:
            logger.error(f"DShield port scan poll failed: {e}")
            return self.port_scan_cache, False

    def _normalize_attacks(self, attacks: List[Dict[str, Any]], attack_type: str) -> List[Dict[str, Any]]:
        """
        Normalize DShield attack data to standard indicator format
        
        Args:
            attacks: Raw attack data from DShield API
            attack_type: "ssh" or "web"
        
        Returns:
            Normalized indicators
        """
        normalized = []
        for attack in attacks:
            if not attack.get("ip"):
                continue
            
            normalized_item = {
                "value": attack.get("ip"),
                "type": "ip",
                "source": "dshield",
                "feed_source": f"dshield-{attack_type}",
                "severity": self.CRITICAL_SEVERITY,  # DShield is critical
                "confidence": 95,  # DShield honeypot data is highly reliable
                "tags": [
                    f"dshield-{attack_type}",
                    attack.get("country", "unknown"),
                    attack.get("asn", "unknown"),
                ],
                "first_seen": attack.get("first_seen", datetime.now(timezone.utc).isoformat()),
                "last_seen": attack.get("last_seen", datetime.now(timezone.utc).isoformat()),
                "raw_data": attack,
            }
            normalized.append(normalized_item)
        
        return normalized

    def _ingest_indicators(self, indicators: List[Dict[str, Any]], feed_source: str):
        """Ingest normalized indicators into database"""
        if not self.database or not indicators:
            return
        
        try:
            for indicator in indicators:
                self.database.add_indicator(
                    value=indicator["value"],
                    type=indicator["type"],
                    source=indicator["source"],
                    feed_source=feed_source,
                    tags=",".join(indicator.get("tags", [])),
                    first_seen=indicator.get("first_seen"),
                    last_seen=indicator.get("last_seen"),
                )
            logger.debug(f"Ingested {len(indicators)} DShield indicators into database")
        except Exception as e:
            logger.error(f"Failed to ingest DShield indicators: {e}")

    def get_cached_ssh_attackers(self) -> List[Dict[str, Any]]:
        """Get cached SSH attacker data (poll if cache expired)"""
        if not self.ssh_cache:
            self.poll_ssh_attackers()
            return self.ssh_cache
        
        # Check if cache is fresh
        if self.last_ssh_poll and (datetime.now(timezone.utc) - self.last_ssh_poll).total_seconds() < self.cache_ttl:
            return self.ssh_cache
        
        # Cache expired, poll fresh data
        attacks, _ = self.poll_ssh_attackers()
        return attacks

    def get_cached_web_attackers(self) -> List[Dict[str, Any]]:
        """Get cached Web attacker data (poll if cache expired)"""
        if not self.web_cache:
            self.poll_web_attackers()
            return self.web_cache
        
        # Check if cache is fresh
        if self.last_web_poll and (datetime.now(timezone.utc) - self.last_web_poll).total_seconds() < self.cache_ttl:
            return self.web_cache
        
        # Cache expired, poll fresh data
        attacks, _ = self.poll_web_attackers()
        return attacks

    async def poll_all_async(self) -> Dict[str, Tuple[List[Dict[str, Any]], bool]]:
        """Poll all DShield data sources asynchronously"""
        results = {}
        tasks = [
            (
                "ssh",
                lambda: self.poll_ssh_attackers(),
            ),
            (
                "web",
                lambda: self.poll_web_attackers(),
            ),
            (
                "port_scans",
                lambda: self.poll_port_scan_trends(),
            ),
        ]
        
        for name, task_func in tasks:
            try:
                result = task_func()
                results[name] = result
            except Exception as e:
                logger.error(f"Async poll {name} failed: {e}")
                results[name] = ([], False)
        
        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get polling statistics"""
        return asdict(self.stats)

    def reset_stats(self):
        """Reset statistics"""
        self.stats = DShieldStats()

    def summarize_threats(self) -> Dict[str, Any]:
        """Get summary of current threat landscape from DShield"""
        ssh_data = self.get_cached_ssh_attackers()
        web_data = self.get_cached_web_attackers()
        
        # Extract IPs and count unique
        ssh_ips = set([item.get("value") for item in ssh_data if "value" in item])
        web_ips = set([item.get("value") for item in web_data if "value" in item])
        all_ips = ssh_ips.union(web_ips)
        
        # Update stats
        self.stats.unique_attacker_ips = len(all_ips)
        
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ssh_attacks": {
                "count": len(ssh_data),
                "unique_ips": len(ssh_ips),
                "top_countries": self._extract_top_countries(ssh_data),
                "top_ports": self._extract_top_ports(ssh_data),
            },
            "web_attacks": {
                "count": len(web_data),
                "unique_ips": len(web_ips),
                "top_countries": self._extract_top_countries(web_data),
                "top_ports": self._extract_top_ports(web_data),
            },
            "global_unique_ips": len(all_ips),
        }

    def _extract_top_countries(self, data: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
        """Extract top countries from attack data"""
        countries = {}
        for item in data:
            tags = item.get("tags", [])
            if tags:
                country = tags[0]  # First tag is country in normalized format
                countries[country] = countries.get(country, 0) + 1
        
        sorted_countries = sorted(countries.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [{"country": c[0], "attacks": c[1]} for c in sorted_countries]

    def _extract_top_ports(self, data: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
        """Extract top ports from attack data"""
        ports = {}
        for item in data:
            raw_data = item.get("raw_data", {})
            port = raw_data.get("port", "unknown")
            ports[port] = ports.get(port, 0) + 1
        
        sorted_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [{"port": str(p[0]), "attempts": p[1]} for p in sorted_ports]


# Global instance
_dshield_poller: Optional[DShieldPoller] = None


def get_dshield_poller(database=None) -> DShieldPoller:
    """Get or create DShield poller instance"""
    global _dshield_poller
    if _dshield_poller is None:
        _dshield_poller = DShieldPoller(database=database)
    return _dshield_poller


async def poll_dshield_feed(database=None):
    """Async function to poll DShield feed (for scheduler integration)"""
    poller = get_dshield_poller(database=database)
    results = await poller.poll_all_async()
    return results

