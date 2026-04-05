"""
OpenCTI Connector Module
Provides integration with OpenCTI (Open Cyber Threat Intelligence) platform
for threat actors, cyber activity, and reporting
"""

import logging
import requests
from typing import Dict, Any, Optional, List
from datetime import datetime

logger = logging.getLogger(__name__)


class OpenCTIConnector:
    """OpenCTI integration connector"""

    def __init__(
        self,
        url: str = "http://localhost:4000",
        api_key: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.headers = {
            "Content-Type": "application/json",
        }
        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"

    def test_connection(self) -> Dict[str, Any]:
        """Test connection to OpenCTI"""
        try:
            response = requests.get(
                f"{self.url}/api/system/version",
                headers=self.headers,
                verify=self.verify_ssl,
                timeout=10,
            )
            if response.status_code == 200:
                return {
                    "status": "success",
                    "version": response.json().get("version", "unknown"),
                }
            return {
                "status": "error",
                "message": f"HTTP {response.status_code}: {response.text[:200]}",
            }
        except requests.exceptions.ConnectionError:
            return {
                "status": "error",
                "message": "Connection refused - is OpenCTI running?",
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def create_threat_actor(self, actor_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create or update a threat actor in OpenCTI"""
        if not self.api_key:
            return {"status": "error", "message": "API key not configured"}

        try:
            # Map actor data to OpenCTI format
            stix_data = self._map_actor_to_stix(actor_data)
            response = requests.post(
                f"{self.url}/api/v1/attack_patterns",
                headers=self.headers,
                json=stix_data,
                verify=self.verify_ssl,
                timeout=30,
            )
            if response.status_code in [200, 201]:
                return {
                    "status": "success",
                    "id": response.json().get("id"),
                }
            return {
                "status": "error",
                "message": f"HTTP {response.status_code}: {response.text[:200]}",
            }
        except Exception as e:
            logger.error(f"Failed to create threat actor: {e}")
            return {"status": "error", "message": str(e)}

    def _map_actor_to_stix(self, actor_data: Dict[str, Any]) -> Dict[str, Any]:
        """Map internal actor format to STIX 2.1 format"""
        return {
            "type": "intrusion-set",
            "spec_version": "2.1",
            "name": actor_data.get("name", ""),
            "aliases": [
                a.strip() for a in actor_data.get("alias", "").split(",") if a.strip()
            ],
            "description": actor_data.get("description", ""),
            "labels": [
                actor_data.get("actor_type", "").lower(),
                actor_data.get("motivation", "").lower(),
            ],
            "external_references": [
                {
                    "source_name": "MITRE ATT&CK",
                    "external_id": actor_data.get("mitre_id", ""),
                    "url": f"https://attack.mitre.org/groups/{actor_data.get('mitre_id', '').lower().replace('G', 'G')}",
                }
            ]
            if actor_data.get("mitre_id")
            else [],
            "granular_marking": [],
        }

    def report_cyber_activity(
        self,
        actor_name: str,
        activity: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Report cyber activity to OpenCTI"""
        if not self.api_key:
            return {"status": "error", "message": "API key not configured"}

        try:
            stix_activity = {
                "type": "x-opencti-relationship",
                "relationship_type": "perpetrates",
                "source_ref": actor_name,
                "target_ref": activity.get("target", ""),
                "description": activity.get("description", ""),
                "external_references": [
                    {
                        "source_name": activity.get("source", ""),
                        "url": activity.get("source_url", ""),
                    }
                ]
                if activity.get("source_url")
                else [],
            }
            response = requests.post(
                f"{self.url}/api/v1/relationships",
                headers=self.headers,
                json=stix_activity,
                verify=self.verify_ssl,
                timeout=30,
            )
            if response.status_code in [200, 201]:
                return {"status": "success", "id": response.json().get("id")}
            return {
                "status": "error",
                "message": f"HTTP {response.status_code}: {response.text[:200]}",
            }
        except Exception as e:
            logger.error(f"Failed to report activity: {e}")
            return {"status": "error", "message": str(e)}

    def create_indicator(self, indicator_data: Dict[str, Any]) -> Dict[str, Any]:
        """Createindicator in OpenCTI"""
        if not self.api_key:
            return {"status": "error", "message": "API key not configured"}

        try:
            indicator_type = indicator_data.get("type", "unknown")
            pattern = self._build_indicator_pattern(
                indicator_type, indicator_data.get("value", "")
            )

            stix_indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": datetime.utcnow().isoformat() + "Z",
                "labels": [indicator_data.get("source", "unknown")],
                "name": f"Indicator for {indicator_data.get('value', 'unknown')}",
                "description": f"Threat indicator from {indicator_data.get('source', 'unknown')}",
            }

            response = requests.post(
                f"{self.url}/api/v1/indicators",
                headers=self.headers,
                json=stix_indicator,
                verify=self.verify_ssl,
                timeout=30,
            )
            if response.status_code in [200, 201]:
                return {"status": "success", "id": response.json().get("id")}
            return {
                "status": "error",
                "message": f"HTTP {response.status_code}: {response.text[:200]}",
            }
        except Exception as e:
            logger.error(f"Failed to create indicator: {e}")
            return {"status": "error", "message": str(e)}

    def _build_indicator_pattern(self, indicator_type: str, value: str) -> str:
        """Build STIX pattern from indicator type and value"""
        patterns = {
            "IPv4": f"[ipv4-addr:value = '{value}']",
            "IPv6": f"[ipv6-addr:value = '{value}']",
            "domain": f"[domain-name:value = '{value}']",
            "url": f"[url:value = '{value}']",
            "email": f"[email-addr:value = '{value}']",
            "file_hash": f"[file:hashes.MD5 = '{value}']",
            "file_name": f"[file:name = '{value}']",
        }
        return patterns.get(indicator_type, f"[file:name = '{value}']")

    def get_actor_report(self, actor_name: str) -> Dict[str, Any]:
        """Get full report for a threat actor"""
        if not self.api_key:
            return {"status": "error", "message": "API key not configured"}

        try:
            response = requests.get(
                f"{self.url}/api/v1/intrusion_sets?search={actor_name}",
                headers=self.headers,
                verify=self.verify_ssl,
                timeout=30,
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    "status": "success",
                    "actors": data.get("entities", []),
                    "count": data.get("pagination", {}).get("nbEntities", 0),
                }
            return {"status": "error", "message": f"HTTP {response.status_code}"}
        except Exception as e:
            logger.error(f"Failed to get actor report: {e}")
            return {"status": "error", "message": str(e)}

    def sync_actor_to_opencti(self, actor_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sync a threat actor with all associated data to OpenCTI"""
        result = {
            "actor": actor_data.get("name", "unknown"),
            "operations": [],
            "status": "success",
        }

        # Create the actor
        op = self.create_threat_actor(actor_data)
        result["operations"].append({"action": "create_actor", **op})

        # Add associated malware
        malware_list = actor_data.get("associated_malware", "").split(",")
        for malware in malware_list:
            malware = malware.strip()
            if malware:
                op = self._add_malware_to_opencti(actor_data.get("name"), malware)
                result["operations"].append({"action": f"add_malware_{malware}", **op})

        # Add associated tools
        tools_list = actor_data.get("associated_tools", "").split(",")
        for tool in tools_list:
            tool = tool.strip()
            if tool:
                op = self._add_tool_to_opencti(actor_data.get("name"), tool)
                result["operations"].append({"action": f"add_tool_{tool}", **op})

        return result

    def _add_malware_to_opencti(self, actor_name: str, malware: str) -> Dict[str, Any]:
        """Add malware associated with actor"""
        if not self.api_key:
            return {"status": "error", "message": "API key not configured"}

        try:
            stix_malware = {
                "type": "malware",
                "spec_version": "2.1",
                "name": malware,
                "is_family": False,
                "labels": ["malware"],
            }
            response = requests.post(
                f"{self.url}/api/v1/malware",
                headers=self.headers,
                json=stix_malware,
                verify=self.verify_ssl,
                timeout=30,
            )
            if response.status_code in [200, 201]:
                return {"status": "success", "id": response.json().get("id")}
            return {"status": "error", "message": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _add_tool_to_opencti(self, actor_name: str, tool: str) -> Dict[str, Any]:
        """Add tool associated with actor"""
        if not self.api_key:
            return {"status": "error", "message": "API key not configured"}

        try:
            stix_tool = {
                "type": "tool",
                "spec_version": "2.1",
                "name": tool,
                "labels": ["tool"],
            }
            response = requests.post(
                f"{self.url}/api/v1/tools",
                headers=self.headers,
                json=stix_tool,
                verify=self.verify_ssl,
                timeout=30,
            )
            if response.status_code in [200, 201]:
                return {"status": "success", "id": response.json().get("id")}
            return {"status": "error", "message": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}


_opencti_connector: Optional[OpenCTIConnector] = None


def get_opencti_connector(
    url: str = "http://localhost:4000",
    api_key: Optional[str] = None,
) -> OpenCTIConnector:
    """Get or create OpenCTI connector instance"""
    global _opencti_connector
    if _opencti_connector is None:
        _opencti_connector = OpenCTIConnector(url=url, api_key=api_key)
    return _opencti_connector
