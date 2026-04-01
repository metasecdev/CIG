"""DShield Honeypot API Live Polling
Fetches real-time threat data from SANS DShield honeypot network
"""

import logging
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)


class DShieldPoller:
    """Live polling for SANS DShield honeypot data"""

    API_BASE = "https://isc.sans.edu/api"

    def __init__(self):
        self.last_ssh_poll: Optional[datetime] = None
        self.last_web_poll: Optional[datetime] = None
        self.ssh_cache: List[Dict[str, Any]] = []
        self.web_cache: List[Dict[str, Any]] = []
        self.cache_ttl = 300  # 5 minutes

    def poll_ssh_attackers(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch latest SSH attacker IPs from DShield honeypot"""
        try:
            url = f"{self.API_BASE}/dshield/ssh/attacks"
            headers = {"User-Agent": "CIG/1.0"}
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            attacks = data.get("attacks", [])[:limit]
            
            self.ssh_cache = attacks
            self.last_ssh_poll = datetime.utcnow()
            
            logger.info(f"DShield SSH poll: fetched {len(attacks)} active attackers")
            return attacks
        except Exception as e:
            logger.error(f"DShield SSH poll failed: {e}")
            return self.ssh_cache

    def poll_web_attackers(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch latest Web vulnerability scanner IPs from DShield honeypot"""
        try:
            url = f"{self.API_BASE}/dshield/web/attacks"
            headers = {"User-Agent": "CIG/1.0"}
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            attacks = data.get("attacks", [])[:limit]
            
            self.web_cache = attacks
            self.last_web_poll = datetime.utcnow()
            
            logger.info(f"DShield Web poll: fetched {len(attacks)} active scanners")
            return attacks
        except Exception as e:
            logger.error(f"DShield Web poll failed: {e}")
            return self.web_cache

    def poll_port_scan_trends(self) -> Dict[str, Any]:
        """Fetch trending port scan activity"""
        try:
            url = f"{self.API_BASE}/dshield/portscans"
            headers = {"User-Agent": "CIG/1.0"}
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            logger.info(f"DShield port scan trends: {len(data.get('ports', []))} trending ports")
            return data
        except Exception as e:
            logger.error(f"DShield port scan poll failed: {e}")
            return {"ports": []}

    def get_cached_ssh_attackers(self) -> List[Dict[str, Any]]:
        """Get cached SSH attacker data"""
        if not self.ssh_cache:
            return []
        
        # Check if cache is fresh
        if self.last_ssh_poll and (datetime.utcnow() - self.last_ssh_poll).total_seconds() < self.cache_ttl:
            return self.ssh_cache
        
        # Cache expired, poll fresh data
        return self.poll_ssh_attackers()

    def get_cached_web_attackers(self) -> List[Dict[str, Any]]:
        """Get cached Web attacker data"""
        if not self.web_cache:
            return []
        
        # Check if cache is fresh
        if self.last_web_poll and (datetime.utcnow() - self.last_web_poll).total_seconds() < self.cache_ttl:
            return self.web_cache
        
        # Cache expired, poll fresh data
        return self.poll_web_attackers()

    def summarize_threats(self) -> Dict[str, Any]:
        """Get summary of current threat landscape from DShield"""
        ssh_data = self.get_cached_ssh_attackers()
        web_data = self.get_cached_web_attackers()
        
        # Extract IPs and count unique
        ssh_ips = set([item.get("ip") for item in ssh_data if "ip" in item])
        web_ips = set([item.get("ip") for item in web_data if "ip" in item])
        all_ips = ssh_ips.union(web_ips)
        
        return {
            "last_updated": datetime.utcnow().isoformat(),
            "ssh_attacks": {
                "count": len(ssh_data),
                "unique_ips": len(ssh_ips),
                "top_countries": self._extract_top_countries(ssh_data),
            },
            "web_attacks": {
                "count": len(web_data),
                "unique_ips": len(web_ips),
                "top_countries": self._extract_top_countries(web_data),
            },
            "global_unique_ips": len(all_ips),
        }

    def _extract_top_countries(self, data: List[Dict[str, Any]], limit: int = 5) -> List[Dict[str, Any]]:
        """Extract top countries from attack data"""
        countries = {}
        for item in data:
            country = item.get("country", "Unknown")
            countries[country] = countries.get(country, 0) + 1
        
        sorted_countries = sorted(countries.items(), key=lambda x: x[1], reverse=True)[:limit]
        return [{"country": c[0], "attacks": c[1]} for c in sorted_countries]


# Global instance
_dshield_poller: Optional[DShieldPoller] = None


def get_dshield_poller() -> DShieldPoller:
    """Get or create DShield poller instance"""
    global _dshield_poller
    if _dshield_poller is None:
        _dshield_poller = DShieldPoller()
    return _dshield_poller
