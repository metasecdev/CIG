"""
VirusTotal Connector Module
Provides integration with VirusTotal API v3 for threat intelligence
"""

import logging
import requests
from typing import Dict, Any, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)


class VirusTotalConnector:
    """VirusTotal API v3 integration"""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.headers = (
            {
                "x-apikey": api_key,
                "Accept": "application/json",
            }
            if api_key
            else {}
        )

    def search(
        self,
        query: str,
        limit: int = 10,
        type_filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Search for files, URLs, domains, IPs"""
        if not self.api_key:
            return {"status": "error", "message": "API key not configured"}

        params = {"query": query, "limit": limit}
        if type_filter:
            params["type"] = type_filter

        try:
            response = requests.get(
                f"{self.BASE_URL}/search",
                headers=self.headers,
                params=params,
                timeout=30,
            )
            if response.status_code == 200:
                return {"status": "success", "data": response.json()}
            return {"status": "error", "message": f"HTTP {response.status_code}"}
        except Exception as e:
            logger.error(f"VirusTotal search failed: {e}")
            return {"status": "error", "message": str(e)}

    def search_files(self, query: str, limit: int = 10) -> Dict[str, Any]:
        """Search for file hashes"""
        return self.search(query, limit, "file")

    def search_urls(self, query: str, limit: int = 10) -> Dict[str, Any]:
        """Search for URLs"""
        return self.search(query, limit, "url")

    def search_domains(self, query: str, limit: int = 10) -> Dict[str, Any]:
        """Search for domains"""
        return self.search(query, limit, "domain")

    def search_ips(self, query: str, limit: int = 10) -> Dict[str, Any]:
        """Search for IP addresses"""
        return self.search(query, limit, "ip_address")

    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """Get file analysis report"""
        if not self.api_key:
            return {"status": "error", "message": "API key not configured"}

        try:
            response = requests.get(
                f"{self.BASE_URL}/files/{file_hash}",
                headers=self.headers,
                timeout=30,
            )
            if response.status_code == 200:
                return {"status": "success", "data": response.json()}
            return {"status": "error", "message": f"HTTP {response.status_code}"}
        except Exception as e:
            logger.error(f"VirusTotal file report failed: {e}")
            return {"status": "error", "message": str(e)}

    def get_url_report(self, url: str) -> Dict[str, Any]:
        """Get URL analysis report"""
        if not self.api_key:
            return {"status": "error", "message": "API key not configured"}

        try:
            response = requests.get(
                f"{self.BASE_URL}/urls",
                headers=self.headers,
                params={"url": url},
                timeout=30,
            )
            if response.status_code == 200:
                return {"status": "success", "data": response.json()}
            return {"status": "error", "message": f"HTTP {response.status_code}"}
        except Exception as e:
            logger.error(f"VirusTotal URL report failed: {e}")
            return {"status": "error", "message": str(e)}

    def get_ip_report(self, ip: str) -> Dict[str, Any]:
        """Get IP analysis report"""
        if not self.api_key:
            return {"status": "error", "message": "API key not configured"}

        try:
            response = requests.get(
                f"{self.BASE_URL}/ip_addresses/{ip}",
                headers=self.headers,
                timeout=30,
            )
            if response.status_code == 200:
                return {"status": "success", "data": response.json()}
            return {"status": "error", "message": f"HTTP {response.status_code}"}
        except Exception as e:
            logger.error(f"VirusTotal IP report failed: {e}")
            return {"status": "error", "message": str(e)}

    def get_domain_report(self, domain: str) -> Dict[str, Any]:
        """Get domain analysis report"""
        if not self.api_key:
            return {"status": "error", "message": "API key not configured"}

        try:
            response = requests.get(
                f"{self.BASE_URL}/domains/{domain}",
                headers=self.headers,
                timeout=30,
            )
            if response.status_code == 200:
                return {"status": "success", "data": response.json()}
            return {"status": "error", "message": f"HTTP {response.status_code}"}
        except Exception as e:
            logger.error(f"VirusTotal domain report failed: {e}")
            return {"status": "error", "message": str(e)}

    def test_connection(self) -> Dict[str, Any]:
        """Test API connection"""
        if not self.api_key:
            return {"status": "error", "message": "API key not configured"}

        try:
            response = self.search("test", limit=1)
            if response.get("status") == "success":
                return {"status": "success", "message": "API connection OK"}
            return response
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def get_malware_info(self, malware_name: str) -> Dict[str, Any]:
        """Search for malware by name"""
        return self.search(malware_name)

    def get_malware_by_tag(self, tag: str) -> Dict[str, Any]:
        """Search for malware by tag (e.g., tag:winnti)"""
        return self.search(f"tag:{tag}")


_virustotal_connector: Optional[VirusTotalConnector] = None


def get_virustotal_connector(api_key: Optional[str] = None) -> VirusTotalConnector:
    """Get or create VirusTotal connector"""
    global _virustotal_connector
    if _virustotal_connector is None:
        _virustotal_connector = VirusTotalConnector(api_key=api_key)
    return _virustotal_connector


def init_virustotal_connector() -> Optional[VirusTotalConnector]:
    """Initialize from credentials"""
    from app.config.feed_credentials import FeedCredentialManager

    cred_manager = FeedCredentialManager()
    vt_creds = cred_manager.get_virustotal_credentials()

    if vt_creds and vt_creds.api_key:
        return VirusTotalConnector(api_key=vt_creds.api_key)
    return None
