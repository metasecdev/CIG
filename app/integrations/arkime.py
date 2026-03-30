"""
Arkime Integration for CIG
Connects CIG alerts and PCAP data with Arkime packet capture system
"""

import logging
import json
import os
from typing import Dict, Any, Optional, List
from datetime import datetime
import hashlib

logger = logging.getLogger(__name__)


class ArkimeConnector:
    """Connector for Arkime packet capture system"""

    def __init__(
        self,
        arkime_url: str = "http://localhost:8005",
        arkime_secret: str = "secret",
        arkime_nodes: Optional[List[str]] = None,
    ):
        self.arkime_url = arkime_url.rstrip("/")
        self.arkime_secret = arkime_secret
        self.arkime_nodes = arkime_nodes or ["node0"]
        self.api_base = f"{self.arkime_url}/api"

    def _get_headers(self) -> Dict[str, str]:
        """Get headers for Arkime API requests"""
        return {
            "Content-Type": "application/json",
            "Cookie": f"arkime={self.arkime_secret}",
        }

    def test_connection(self) -> bool:
        """Test connection to Arkime"""
        try:
            import requests

            response = requests.get(
                f"{self.api_base}/health", headers=self._get_headers(), timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Arkime connection test failed: {e}")
            return False

    def upload_pcap(self, pcap_path: str, node: Optional[str] = None) -> bool:
        """Upload PCAP file to Arkime"""
        if not os.path.exists(pcap_path):
            logger.error(f"PCAP file not found: {pcap_path}")
            return False

        node = node or self.arkime_nodes[0]

        try:
            import requests

            with open(pcap_path, "rb") as f:
                files = {
                    "file": (os.path.basename(pcap_path), f, "application/octet-stream")
                }
                response = requests.post(
                    f"{self.api_base}/pcap/{node}",
                    files=files,
                    headers={"Cookie": f"arkime={self.arkime_secret}"},
                    timeout=300,
                )

            if response.status_code == 200:
                logger.info(f"Uploaded PCAP to Arkime: {pcap_path}")
                return True
            else:
                logger.error(
                    f"Failed to upload PCAP: {response.status_code} - {response.text}"
                )
                return False
        except Exception as e:
            logger.error(f"Error uploading PCAP to Arkime: {e}")
            return False

    def search_sessions(
        self,
        query: str,
        start_time: Optional[int] = None,
        stop_time: Optional[int] = None,
        limit: int = 100,
    ) -> Optional[List[Dict[str, Any]]]:
        """Search Arkime sessions"""
        try:
            import requests

            params = {"query": query, "limit": limit, "date": "all"}
            if start_time:
                params["startTime"] = start_time
            if stop_time:
                params["stopTime"] = stop_time

            response = requests.get(
                f"{self.api_base}/sessions",
                params=params,
                headers=self._get_headers(),
                timeout=30,
            )

            if response.status_code == 200:
                data = response.json()
                return data.get("sessions", [])
            else:
                logger.error(f"Arkime search failed: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error searching Arkime: {e}")
            return None

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session details by ID"""
        try:
            import requests

            response = requests.get(
                f"{self.api_base}/session/{session_id}",
                headers=self._get_headers(),
                timeout=30,
            )

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get session: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error getting Arkime session: {e}")
            return None

    def download_pcap(self, session_id: str, output_path: str) -> bool:
        """Download PCAP for a session"""
        try:
            import requests

            response = requests.get(
                f"{self.api_base}/pcap/{session_id}",
                headers=self._get_headers(),
                timeout=60,
            )

            if response.status_code == 200:
                with open(output_path, "wb") as f:
                    f.write(response.content)
                logger.info(f"Downloaded PCAP to: {output_path}")
                return True
            else:
                logger.error(f"Failed to download PCAP: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error downloading PCAP: {e}")
            return False

    def add_tag(self, session_id: str, tag: str) -> bool:
        """Add tag to a session"""
        try:
            import requests

            response = requests.post(
                f"{self.api_base}/session/{session_id}/tags",
                json={"tag": tag},
                headers=self._get_headers(),
                timeout=10,
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error adding tag: {e}")
            return False

    def create_hunt(
        self, query: str, name: str, description: str = "", size: int = 100
    ) -> Optional[str]:
        """Create a hunt for sessions matching query"""
        try:
            import requests

            response = requests.post(
                f"{self.api_base}/hunt",
                json={
                    "name": name,
                    "query": query,
                    "size": size,
                    "description": description,
                },
                headers=self._get_headers(),
                timeout=30,
            )

            if response.status_code == 200:
                data = response.json()
                return data.get("id")
            else:
                logger.error(f"Failed to create hunt: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error creating hunt: {e}")
            return None

    def get_stats(self) -> Optional[Dict[str, Any]]:
        """Get Arkime statistics"""
        try:
            import requests

            response = requests.get(
                f"{self.api_base}/stats", headers=self._get_headers(), timeout=30
            )

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Failed to get stats: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error getting Arkime stats: {e}")
            return None


class CIGArkimeBridge:
    """Bridge between CIG alerts and Arkime"""

    def __init__(self, connector: ArkimeConnector):
        self.connector = connector

    def create_arkime_spi_from_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Create Arkime SPI (Security Privacy Intelligence) data from CIG alert"""
        return {
            "srcIp": alert.get("source_ip", ""),
            "dstIp": alert.get("destination_ip", ""),
            "indicator": alert.get("indicator", ""),
            "indicatorType": alert.get("indicator_type", ""),
            "feedSource": alert.get("feed_source", ""),
            "ruleId": alert.get("rule_id", ""),
            "severity": alert.get("severity", "info"),
            "alertId": alert.get("id", ""),
            "timestamp": alert.get("timestamp", ""),
        }

    def correlate_alert_with_sessions(
        self, alert: Dict[str, Any], time_window_minutes: int = 60
    ) -> List[Dict[str, Any]]:
        """Find Arkime sessions related to an alert"""
        source_ip = alert.get("source_ip", "")
        dest_ip = alert.get("destination_ip", "")
        indicator = alert.get("indicator", "")

        sessions = []

        if source_ip:
            src_sessions = self.connector.search_sessions(
                query=f"ip.src == {source_ip}", limit=50
            )
            if src_sessions:
                sessions.extend(src_sessions)

        if dest_ip and dest_ip != source_ip:
            dst_sessions = self.connector.search_sessions(
                query=f"ip.dst == {dest_ip}", limit=50
            )
            if dst_sessions:
                sessions.extend(dst_sessions)

        if indicator and "." in indicator:
            domain_sessions = self.connector.search_sessions(
                query=f"dns.qry.name == {indicator}", limit=50
            )
            if domain_sessions:
                sessions.extend(domain_sessions)

        return sessions

    def create_alert_hunt(self, alert: Dict[str, Any]) -> Optional[str]:
        """Create an Arkime hunt for sessions related to alert"""
        source_ip = alert.get("source_ip", "")
        dest_ip = alert.get("destination_ip", "")

        queries = []
        if source_ip:
            queries.append(f"ip.src == {source_ip}")
        if dest_ip:
            queries.append(f"ip.dst == {dest_ip}")

        if not queries:
            return None

        query = " OR ".join(queries)
        hunt_name = f"CIG-Alert-{alert.get('id', 'unknown')}"
        description = f"Alert: {alert.get('indicator')} ({alert.get('severity')}) from {alert.get('feed_source')}"

        return self.connector.create_hunt(query, hunt_name, description)

    def tag_sessions_with_alert(
        self, sessions: List[Dict[str, Any]], alert: Dict[str, Any]
    ) -> int:
        """Tag Arkime sessions with alert information"""
        tag = f"cig:alert:{alert.get('severity', 'info')}"
        tag = tag.lower()

        tagged = 0
        for session in sessions:
            session_id = session.get("id")
            if session_id:
                if self.connector.add_tag(session_id, tag):
                    tagged += 1

        return tagged

    def upload_pcap_for_alert(self, pcap_path: str, alert: Dict[str, Any]) -> bool:
        """Upload PCAP and tag with alert information"""
        if not os.path.exists(pcap_path):
            return False

        success = self.connector.upload_pcap(pcap_path)

        if success:
            tag = f"cig:alert:{alert.get('severity', 'info')}:{alert.get('id', '')}"
            self.connector.add_tag(os.path.basename(pcap_path), tag)

        return success


def create_arkime_connector(config: Dict[str, Any]) -> ArkimeConnector:
    """Factory function to create Arkime connector from config"""
    return ArkimeConnector(
        arkime_url=config.get("arkime_url", "http://localhost:8005"),
        arkime_secret=config.get("arkime_secret", "secret"),
        arkime_nodes=config.get("arkime_nodes"),
    )
