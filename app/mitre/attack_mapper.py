"""
MITRE ATT&CK Framework Integration
Maps network events to MITRE ATT&CK TTPs
"""

import logging
import json
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
import re
import warnings

# Suppress typing.io compatibility warnings from mitreattack library
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", message=".*typing.io.*")

try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from mitreattack.attackToExcel import attackToExcel
        from mitreattack.navlayers import Layer

    HAS_MITRE = True
except ImportError:
    HAS_MITRE = False
except Exception:
    HAS_MITRE = False

from app.models.database import Database, Alert
from app.core.config import settings

logger = logging.getLogger(__name__)


class MITREAttackMapper:
    """Maps network events to MITRE ATT&CK TTPs"""

    def __init__(self, db: Database):
        self.db = db
        self.ttp_mappings = {}
        self.technique_mappings = {}
        self.tactic_mappings = {}

        try:
            self._load_attack_data()
        except Exception as e:
            logger.warning(f"Could not load MITRE library data: {e}")
            logger.info("Loading simplified TTP mappings as fallback")
            self._load_simplified_mappings()

    def _load_attack_data(self):
        """Load MITRE ATT&CK framework data"""
        try:
            # Load enterprise techniques
            from mitreattack.attackToExcel.attackToExcel import attackToExcel
            from mitreattack.attackToExcel.stixToDf import stixToDf

            # This would normally load from STIX data
            # For now, we'll use a simplified mapping
            self._load_simplified_mappings()

            logger.info("Loaded MITRE ATT&CK framework data")
        except Exception as e:
            if "typing.io" in str(e):
                logger.warning("MITRE ATT&CK dependency mismatch (typing.io); using fallback mappings")
            else:
                logger.error(f"Failed to load MITRE ATT&CK data: {e}")
            self._load_simplified_mappings()

    def _load_simplified_mappings(self):
        """Load simplified TTP mappings for common techniques"""
        # Common MITRE ATT&CK techniques and their indicators
        self.technique_mappings = {
            # Reconnaissance
            "T1595": {  # Active Scanning
                "indicators": ["port_scan", "network_scan", "vulnerability_scan"],
                "tactic": "TA0043",
                "name": "Active Scanning",
            },
            "T1046": {  # Network Service Discovery
                "indicators": ["service_enumeration", "banner_grabbing"],
                "tactic": "TA0043",
                "name": "Network Service Discovery",
            },
            "T1592": {  # Gather Victim Host Information
                "indicators": ["host_discovery", "system_info"],
                "tactic": "TA0043",
                "name": "Gather Victim Host Information",
            },
            # Initial Access
            "T1190": {  # Exploit Public-Facing Application
                "indicators": ["web_exploit", "sql_injection", "xss"],
                "tactic": "TA0001",
                "name": "Exploit Public-Facing Application",
            },
            "T1078": {  # Valid Accounts
                "indicators": ["brute_force", "credential_stuffing"],
                "tactic": "TA0001",
                "name": "Valid Accounts",
            },
            "T1566": {  # Phishing
                "indicators": [
                    "phishing",
                    "malicious_attachment",
                    "spear_phishing",
                    "email",
                ],
                "tactic": "TA0001",
                "name": "Phishing",
            },
            "T1133": {  # External Remote Services
                "indicators": ["vpn", "remote_access", "ssh"],
                "tactic": "TA0001",
                "name": "External Remote Services",
            },
            "T1046": {  # Network Service Discovery
                "indicators": ["service_enumeration", "banner_grabbing"],
                "tactic": "TA0043",
                "name": "Network Service Discovery",
            },
            # Initial Access
            "T1190": {  # Exploit Public-Facing Application
                "indicators": ["web_exploit", "sql_injection", "xss"],
                "tactic": "TA0001",
                "name": "Exploit Public-Facing Application",
            },
            "T1078": {  # Valid Accounts
                "indicators": ["brute_force", "credential_stuffing"],
                "tactic": "TA0001",
                "name": "Valid Accounts",
            },
            # Execution
            "T1059": {  # Command and Scripting Interpreter
                "indicators": ["powershell", "cmd_execution", "script_execution"],
                "tactic": "TA0002",
                "name": "Command and Scripting Interpreter",
            },
            "T1204": {  # User Execution
                "indicators": ["malicious_attachment", "drive_by_download"],
                "tactic": "TA0002",
                "name": "User Execution",
            },
            # Persistence
            "T1098": {  # Account Manipulation
                "indicators": ["account_modification", "privilege_escalation"],
                "tactic": "TA0003",
                "name": "Account Manipulation",
            },
            # Privilege Escalation
            "T1068": {  # Exploitation for Privilege Escalation
                "indicators": ["local_exploit", "kernel_exploit"],
                "tactic": "TA0004",
                "name": "Exploitation for Privilege Escalation",
            },
            # Defense Evasion
            "T1070": {  # Indicator Removal
                "indicators": ["log_deletion", "evidence_removal"],
                "tactic": "TA0005",
                "name": "Indicator Removal",
            },
            "T1027": {  # Obfuscated Files or Information
                "indicators": ["encoded_payload", "encrypted_traffic"],
                "tactic": "TA0005",
                "name": "Obfuscated Files or Information",
            },
            # Credential Access
            "T1003": {  # OS Credential Dumping
                "indicators": ["credential_dump", "mimikatz"],
                "tactic": "TA0006",
                "name": "OS Credential Dumping",
            },
            # Discovery
            "T1082": {  # System Information Discovery
                "indicators": ["system_enumeration", "recon_commands"],
                "tactic": "TA0007",
                "name": "System Information Discovery",
            },
            "T1016": {  # System Network Configuration Discovery
                "indicators": ["network_config", "ipconfig", "ifconfig"],
                "tactic": "TA0007",
                "name": "System Network Configuration Discovery",
            },
            # Lateral Movement
            "T1021": {  # Remote Services
                "indicators": ["rdp_connection", "ssh_brute_force", "lateral_movement"],
                "tactic": "TA0008",
                "name": "Remote Services",
            },
            # Collection
            "T1115": {  # Clipboard Data
                "indicators": ["clipboard_access"],
                "tactic": "TA0009",
                "name": "Clipboard Data",
            },
            # Command and Control
            "T1071": {  # Application Layer Protocol
                "indicators": ["c2_traffic", "beaconing"],
                "tactic": "TA0011",
                "name": "Application Layer Protocol",
            },
            "T1573": {  # Encrypted Channel
                "indicators": ["encrypted_c2", "dns_tunneling"],
                "tactic": "TA0011",
                "name": "Encrypted Channel",
            },
            # Exfiltration
            "T1041": {  # Exfiltration Over C2 Channel
                "indicators": ["data_exfil", "c2_exfil"],
                "tactic": "TA0010",
                "name": "Exfiltration Over C2 Channel",
            },
            # Impact
            "T1486": {  # Data Encrypted for Impact
                "indicators": ["ransomware", "data_encryption"],
                "tactic": "TA0040",
                "name": "Data Encrypted for Impact",
            },
        }

        # Tactic mappings
        self.tactic_mappings = {
            "TA0043": {"name": "Reconnaissance", "short": "recon"},
            "TA0001": {"name": "Initial Access", "short": "initial-access"},
            "TA0002": {"name": "Execution", "short": "execution"},
            "TA0003": {"name": "Persistence", "short": "persistence"},
            "TA0004": {"name": "Privilege Escalation", "short": "privilege-escalation"},
            "TA0005": {"name": "Defense Evasion", "short": "defense-evasion"},
            "TA0006": {"name": "Credential Access", "short": "credential-access"},
            "TA0007": {"name": "Discovery", "short": "discovery"},
            "TA0008": {"name": "Lateral Movement", "short": "lateral-movement"},
            "TA0009": {"name": "Collection", "short": "collection"},
            "TA0010": {"name": "Exfiltration", "short": "exfiltration"},
            "TA0011": {"name": "Command and Control", "short": "command-and-control"},
            "TA0040": {"name": "Impact", "short": "impact"},
        }

    def map_event_to_ttp(self, event_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Map a network event to potential MITRE ATT&CK TTPs"""
        ttps = []

        # Extract event characteristics
        event_type = event_data.get("type", "")
        source_ip = event_data.get("source_ip", "")
        destination_ip = event_data.get("destination_ip", "")
        protocol = event_data.get("protocol", "")
        indicator = event_data.get("indicator", "")
        message = event_data.get("message", "").lower()

        # Check each technique for matches
        for technique_id, technique_data in self.technique_mappings.items():
            confidence = 0
            matched_indicators = []

            # Check indicator patterns
            for indicator_pattern in technique_data["indicators"]:
                if (
                    indicator_pattern.lower() in message
                    or indicator_pattern.lower() in indicator.lower()
                ):
                    confidence += 30
                    matched_indicators.append(indicator_pattern)

            # Network-specific checks
            if technique_id == "T1595":  # Active Scanning
                if protocol in ["tcp", "udp"] and self._is_scan_pattern(
                    source_ip, destination_ip
                ):
                    confidence += 40
                    matched_indicators.append("network_scan")

            elif technique_id == "T1046":  # Network Service Discovery
                if protocol in ["tcp", "udp"] and self._is_service_scan(message):
                    confidence += 35
                    matched_indicators.append("service_discovery")

            elif technique_id == "T1071":  # C2 Traffic
                if self._is_c2_pattern(event_data):
                    confidence += 45
                    matched_indicators.append("c2_traffic")

            elif technique_id == "T1573":  # Encrypted Channel
                if self._is_encrypted_traffic(event_data):
                    confidence += 40
                    matched_indicators.append("encrypted_channel")

            elif technique_id == "T1041":  # Exfiltration
                if self._is_exfil_pattern(event_data):
                    confidence += 50
                    matched_indicators.append("data_exfiltration")

            # Only include high-confidence matches
            if confidence >= 30:
                tactic_id = technique_data["tactic"]
                tactic_info = self.tactic_mappings.get(tactic_id, {})

                ttps.append(
                    {
                        "technique_id": technique_id,
                        "technique_name": technique_data["name"],
                        "tactic_id": tactic_id,
                        "tactic_name": tactic_info.get("name", ""),
                        "confidence": min(confidence, 100),
                        "matched_indicators": matched_indicators,
                        "event_data": event_data,
                    }
                )

        return ttps

    def _is_scan_pattern(self, src_ip: str, dst_ip: str) -> bool:
        """Check if traffic pattern indicates scanning"""
        # This would use more sophisticated analysis
        # For now, simple heuristics
        return True  # Placeholder

    def _is_service_scan(self, message: str) -> bool:
        """Check if message indicates service scanning"""
        scan_keywords = ["scan", "enumeration", "banner", "version"]
        return any(keyword in message for keyword in scan_keywords)

    def _is_c2_pattern(self, event_data: Dict[str, Any]) -> bool:
        """Check if traffic pattern indicates C2 communication"""
        # Look for beaconing patterns, unusual ports, etc.
        destination_port = event_data.get("destination_port", 0)
        protocol = event_data.get("protocol", "")

        # Common C2 ports
        suspicious_ports = [4444, 8080, 8443, 53, 80, 443]  # Add more as needed

        if destination_port in suspicious_ports:
            return True

        # Check for DNS tunneling indicators
        if protocol == "udp" and destination_port == 53:
            domain = event_data.get("indicator", "")
            if len(domain) > 50 or "." not in domain:  # Suspicious domain patterns
                return True

        return False

    def _is_encrypted_traffic(self, event_data: Dict[str, Any]) -> bool:
        """Check if traffic appears to be encrypted"""
        # This would analyze packet payloads for encryption indicators
        # For now, check for HTTPS or known encrypted protocols
        destination_port = event_data.get("destination_port", 0)
        protocol = event_data.get("protocol", "")

        encrypted_ports = [443, 993, 995, 8443]  # HTTPS, IMAPS, POP3S, etc.
        return destination_port in encrypted_ports

    def _is_exfil_pattern(self, event_data: Dict[str, Any]) -> bool:
        """Check if traffic pattern indicates data exfiltration"""
        # Look for large data transfers to unusual destinations
        # This would need more sophisticated analysis
        return False  # Placeholder

    def get_technique_info(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific technique"""
        return self.technique_mappings.get(technique_id)

    def get_tactic_info(self, tactic_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific tactic"""
        return self.tactic_mappings.get(tactic_id)

    def get_all_techniques(self) -> Dict[str, Dict[str, Any]]:
        """Get all loaded techniques"""
        return self.technique_mappings

    def get_all_tactics(self) -> Dict[str, Dict[str, Any]]:
        """Get all loaded tactics"""
        return self.tactic_mappings
