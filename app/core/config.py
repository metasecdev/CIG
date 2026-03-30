"""
Configuration management for Cyber Intelligence Gateway
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path

# Use repository root as base for relative paths (avoids relying on working directory)
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_DIR = REPO_ROOT / "data"


@dataclass
class Settings:
    """Application settings loaded from environment variables"""

    # Application
    app_name: str = "Cyber Intelligence Gateway"
    debug: bool = False
    log_level: str = "INFO"

    # API Server
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Database
    database_path: str = str(DEFAULT_DATA_DIR / "cig.db")

    # PCAP Configuration
    pcap_dir: str = str(DEFAULT_DATA_DIR / "pcaps")
    pcap_rotation_size: str = "100M"
    pcap_max_files: int = 100
    lan_interface: str = "eth0"
    wan_interface: str = "eth1"

    # MISP Configuration
    misp_url: str = ""
    misp_api_key: str = ""
    misp_verify_ssl: bool = False
    misp_update_interval: int = 300  # seconds

    # pfBlocker Configuration
    pfblocker_feeds: List[str] = field(
        default_factory=lambda: [
            # ph00lt0/blocklist - ads, analytics, trackers, malware, phishing
            "https://raw.githubusercontent.com/ph00lt0/blocklist/master/blocklist.txt",
        ]
    )
    pfblocker_update_interval: int = 3600  # seconds
    pfblocker_local_blocklist: str = "config/pfblocker_local.txt"

    # AbuseIPDB Configuration
    abuseipdb_api_key: str = "15b61bb636b0a9f080cb9cecc7774b6eab1368f07edc73895a8367ab4e963d5cd84dff7b56e03a60"
    abuseipdb_update_interval: int = 3600  # seconds
    abuseipdb_confidence_threshold: int = 75  # minimum confidence score

    # Abuse.ch Configuration (URLhaus + ThreatFox)
    abusech_api_key: str = "d39bf4b6b6deaf1c4adac4fc7c5b27c88f3771583fe8534a"
    abusech_enabled: bool = True
    abusech_update_interval: int = 3600  # seconds

    # Feed enable/disable flags
    enable_misp: bool = True
    enable_pfblocker: bool = True
    enable_abuseipdb: bool = True
    enable_urlhaus: bool = True
    enable_threatfox: bool = True

    # Feed Update Configuration
    skip_feed_updates: bool = False  # Skip all feed updates for testing

    # DNS Log Configuration
    dns_log_path: str = str(DEFAULT_DATA_DIR / "logs" / "dns.log")
    dns_query_log_enabled: bool = True
    skip_dns_monitoring: bool = False  # Skip DNS monitoring for testing

    # Threat Matching
    match_dns_queries: bool = True
    match_pcap_traffic: bool = True
    alert_retention_days: int = 30

    # Notification
    webhook_url: Optional[str] = None

    def __post_init__(self):
        """Ensure directories exist"""
        try:
            Path(self.pcap_dir).mkdir(parents=True, exist_ok=True)
            Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
            Path(self.dns_log_path).parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            # Log warning but don't fail - directories might be created later
            print(f"Warning: Could not create directories: {e}")

    @classmethod
    def from_env(cls) -> "Settings":
        """Load settings from environment variables"""
        return cls(
            # Application
            app_name=os.getenv("APP_NAME", "Cyber Intelligence Gateway"),
            debug=os.getenv("DEBUG", "false").lower() == "true",
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            # API
            api_host=os.getenv("API_HOST", "0.0.0.0"),
            api_port=int(os.getenv("API_PORT", "8000")),
            # Database
            database_path=os.getenv("DATABASE_PATH", "data/cig.db"),
            # PCAP
            pcap_dir=os.getenv("PCAP_DIR", "data/pcaps"),
            pcap_rotation_size=os.getenv("PCAP_ROTATION_SIZE", "100M"),
            pcap_max_files=int(os.getenv("PCAP_MAX_FILES", "100")),
            lan_interface=os.getenv("LAN_INTERFACE", "eth0"),
            wan_interface=os.getenv("WAN_INTERFACE", "eth1"),
            # MISP
            misp_url=os.getenv("MISP_URL", ""),
            misp_api_key=os.getenv("MISP_API_KEY", ""),
            misp_verify_ssl=os.getenv("MISP_VERIFY_SSL", "false").lower() == "true",
            misp_update_interval=int(os.getenv("MISP_UPDATE_INTERVAL", "300")),
            # pfBlocker
            pfblocker_feeds=os.getenv("PFBLOCKER_FEEDS", "").split(",")
            if os.getenv("PFBLOCKER_FEEDS")
            else [
                # ph00lt0/blocklist - ads, analytics, trackers, malware, phishing
                "https://raw.githubusercontent.com/ph00lt0/blocklist/master/blocklist.txt",
            ],
            pfblocker_update_interval=int(
                os.getenv("PFBLOCKER_UPDATE_INTERVAL", "3600")
            ),
            pfblocker_local_blocklist=os.getenv(
                "PFBLOCKER_LOCAL_BLOCKLIST", "/config/pfblocker_local.txt"
            ),
            # AbuseIPDB
            abuseipdb_api_key=os.getenv(
                "ABUSEIPDB_API_KEY",
                "15b61bb636b0a9f080cb9cecc7774b6eab1368f07edc73895a8367ab4e963d5cd84dff7b56e03a60",
            ),
            abuseipdb_update_interval=int(
                os.getenv("ABUSEIPDB_UPDATE_INTERVAL", "3600")
            ),
            abuseipdb_confidence_threshold=int(
                os.getenv("ABUSEIPDB_CONFIDENCE_THRESHOLD", "75")
            ),
            # Feed Updates
            skip_feed_updates=os.getenv("SKIP_FEED_UPDATES", "false").lower() == "true",
            # DNS
            dns_log_path=os.getenv("DNS_LOG_PATH", "data/logs/dns.log"),
            dns_query_log_enabled=os.getenv("DNS_QUERY_LOG_ENABLED", "true").lower()
            == "true",
            skip_dns_monitoring=os.getenv("SKIP_DNS_MONITORING", "false").lower()
            == "true",
            # Matching
            match_dns_queries=os.getenv("MATCH_DNS_QUERIES", "true").lower() == "true",
            match_pcap_traffic=os.getenv("MATCH_PCAP_TRAFFIC", "true").lower()
            == "true",
            alert_retention_days=int(os.getenv("ALERT_RETENTION_DAYS", "30")),
            # Notification
            webhook_url=os.getenv("WEBHOOK_URL"),
        )


# Global settings instance
settings = Settings.from_env()
