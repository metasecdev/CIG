"""
Feed Credentials and Configuration Management
Centralized management of API credentials for external threat feeds
"""

import json
import logging
from pathlib import Path
from typing import Dict, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class FeedCredentialType(str, Enum):
    """Types of credential storage"""
    NESSUS = "nessus"
    GRAYNOISE = "graynoise"
    CUSTOM_API = "custom_api"
    REPORT_INGESTION = "report_ingestion"


@dataclass
class NessusCredentials:
    """Nessus API credentials"""
    api_key: str
    api_secret: str
    host: str = "https://cloud.nessus.com"
    enabled: bool = False


@dataclass
class GrayNoiseCredentials:
    """GrayNoise API credentials"""
    api_key: str
    api_type: str = "enterprise"  # 'community' or 'enterprise'
    enabled: bool = False


@dataclass
class CustomAPIFeedConfig:
    """Custom API feed configuration"""
    feed_id: str
    feed_name: str
    api_url: str
    auth_type: str  # 'api_key', 'bearer', 'basic', 'custom', 'oauth2'
    auth_value: str
    custom_headers: Optional[Dict[str, str]] = None
    polling_interval_hours: int = 24
    enabled: bool = False


@dataclass
class FilterConfiguration:
    """Feed filter configuration"""
    filter_id: str
    filter_name: str
    indicator_types: list = None  # e.g., ['IP', 'DOMAIN', 'URL']
    min_severity: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    max_age_days: int = 30
    exclude_feeds: list = None  # List of feed IDs to exclude
    regex_patterns: list = None  # Custom regex patterns
    enabled: bool = False

    def __post_init__(self):
        if self.indicator_types is None:
            self.indicator_types = []
        if self.exclude_feeds is None:
            self.exclude_feeds = []
        if self.regex_patterns is None:
            self.regex_patterns = []


class FeedCredentialManager:
    """Manages feed credentials and configurations"""

    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or Path("/Users/wo/code/config")
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.credentials_file = self.config_dir / "feed_credentials.json"
        self.filters_file = self.config_dir / "feed_filters.json"
        self.credentials = self._load_credentials()
        self.filters = self._load_filters()

    def _load_credentials(self) -> Dict[str, Any]:
        """Load credentials from file"""
        if self.credentials_file.exists():
            try:
                with open(self.credentials_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load credentials: {e}")
                return self._get_default_credentials()
        return self._get_default_credentials()

    def _get_default_credentials(self) -> Dict[str, Any]:
        """Get default empty credentials structure"""
        return {
            "nessus": {"api_key": "", "api_secret": "", "host": "https://cloud.nessus.com", "enabled": False},
            "graynoise": {"api_key": "", "api_type": "enterprise", "enabled": False},
            "custom_apis": {},
            "filters": {}
        }

    def _load_filters(self) -> Dict[str, Any]:
        """Load filter configurations from file"""
        if self.filters_file.exists():
            try:
                with open(self.filters_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load filters: {e}")
                return {}
        return {}

    def _save_credentials(self):
        """Save credentials to file"""
        try:
            # Ensure sensitive data isn't logged
            safe_creds = {k: v for k, v in self.credentials.items()}
            if "nessus" in safe_creds:
                safe_creds["nessus"] = {**safe_creds["nessus"], "api_key": "***", "api_secret": "***"}
            if "graynoise" in safe_creds:
                safe_creds["graynoise"] = {**safe_creds["graynoise"], "api_key": "***"}

            with open(self.credentials_file, 'w') as f:
                json.dump(self.credentials, f, indent=2)
            logger.info("Credentials saved successfully")
        except Exception as e:
            logger.error(f"Failed to save credentials: {e}")

    def _save_filters(self):
        """Save filters to file"""
        try:
            with open(self.filters_file, 'w') as f:
                json.dump(self.filters, f, indent=2)
            logger.info("Filters saved successfully")
        except Exception as e:
            logger.error(f"Failed to save filters: {e}")

    def set_nessus_credentials(self, api_key: str, api_secret: str, host: str = "https://cloud.nessus.com", enabled: bool = False) -> bool:
        """Set Nessus API credentials"""
        try:
            self.credentials["nessus"] = {
                "api_key": api_key,
                "api_secret": api_secret,
                "host": host,
                "enabled": enabled
            }
            self._save_credentials()
            logger.info(f"Nessus credentials updated (enabled={enabled})")
            return True
        except Exception as e:
            logger.error(f"Failed to set Nessus credentials: {e}")
            return False

    def set_graynoise_credentials(self, api_key: str, api_type: str = "enterprise", enabled: bool = False) -> bool:
        """Set GrayNoise API credentials"""
        try:
            self.credentials["graynoise"] = {
                "api_key": api_key,
                "api_type": api_type,
                "enabled": enabled
            }
            self._save_credentials()
            logger.info(f"GrayNoise credentials updated (enabled={enabled}, type={api_type})")
            return True
        except Exception as e:
            logger.error(f"Failed to set GrayNoise credentials: {e}")
            return False

    def get_nessus_credentials(self) -> Optional[NessusCredentials]:
        """Get Nessus credentials"""
        try:
            nessus_data = self.credentials.get("nessus", {})
            if nessus_data.get("api_key"):
                return NessusCredentials(**nessus_data)
        except Exception as e:
            logger.error(f"Failed to retrieve Nessus credentials: {e}")
        return None

    def get_graynoise_credentials(self) -> Optional[GrayNoiseCredentials]:
        """Get GrayNoise credentials"""
        try:
            gn_data = self.credentials.get("graynoise", {})
            if gn_data.get("api_key"):
                return GrayNoiseCredentials(**gn_data)
        except Exception as e:
            logger.error(f"Failed to retrieve GrayNoise credentials: {e}")
        return None

    def is_nessus_enabled(self) -> bool:
        """Check if Nessus is enabled"""
        return self.credentials.get("nessus", {}).get("enabled", False)

    def is_graynoise_enabled(self) -> bool:
        """Check if GrayNoise is enabled"""
        return self.credentials.get("graynoise", {}).get("enabled", False)

    def add_custom_api_feed(self, feed_id: str, feed_name: str, api_url: str, 
                           auth_type: str, auth_value: str, 
                           custom_headers: Optional[Dict] = None, 
                           polling_interval_hours: int = 24,
                           enabled: bool = False) -> bool:
        """Add or update a custom API feed configuration"""
        try:
            if "custom_apis" not in self.credentials:
                self.credentials["custom_apis"] = {}

            self.credentials["custom_apis"][feed_id] = {
                "feed_id": feed_id,
                "feed_name": feed_name,
                "api_url": api_url,
                "auth_type": auth_type,
                "auth_value": auth_value,
                "custom_headers": custom_headers or {},
                "polling_interval_hours": polling_interval_hours,
                "enabled": enabled
            }
            self._save_credentials()
            logger.info(f"Custom API feed '{feed_id}' added/updated (enabled={enabled})")
            return True
        except Exception as e:
            logger.error(f"Failed to add custom API feed: {e}")
            return False

    def get_custom_api_feed(self, feed_id: str) -> Optional[Dict]:
        """Get custom API feed configuration"""
        return self.credentials.get("custom_apis", {}).get(feed_id)

    def list_custom_api_feeds(self) -> Dict[str, Dict]:
        """List all custom API feeds"""
        return self.credentials.get("custom_apis", {})

    def remove_custom_api_feed(self, feed_id: str) -> bool:
        """Remove a custom API feed"""
        try:
            if feed_id in self.credentials.get("custom_apis", {}):
                del self.credentials["custom_apis"][feed_id]
                self._save_credentials()
                logger.info(f"Custom API feed '{feed_id}' removed")
                return True
        except Exception as e:
            logger.error(f"Failed to remove custom API feed: {e}")
        return False

    def save_filter_config(self, filter_id: str, filter_config: Dict[str, Any]) -> bool:
        """Save filter configuration"""
        try:
            self.filters[filter_id] = filter_config
            self._save_filters()
            logger.info(f"Filter configuration '{filter_id}' saved")
            return True
        except Exception as e:
            logger.error(f"Failed to save filter config: {e}")
            return False

    def get_filter_config(self, filter_id: str) -> Optional[Dict]:
        """Get filter configuration"""
        return self.filters.get(filter_id)

    def list_filter_configs(self) -> Dict[str, Dict]:
        """List all filter configurations"""
        return self.filters

    def remove_filter_config(self, filter_id: str) -> bool:
        """Remove filter configuration"""
        try:
            if filter_id in self.filters:
                del self.filters[filter_id]
                self._save_filters()
                logger.info(f"Filter configuration '{filter_id}' removed")
                return True
        except Exception as e:
            logger.error(f"Failed to remove filter config: {e}")
        return False

    def get_status(self) -> Dict[str, Any]:
        """Get overall configuration status"""
        return {
            "nessus_enabled": self.is_nessus_enabled(),
            "nessus_configured": bool(self.credentials.get("nessus", {}).get("api_key")),
            "graynoise_enabled": self.is_graynoise_enabled(),
            "graynoise_configured": bool(self.credentials.get("graynoise", {}).get("api_key")),
            "custom_api_feeds": len(self.credentials.get("custom_apis", {})),
            "filter_configs": len(self.filters),
            "credentials_file": str(self.credentials_file),
            "filters_file": str(self.filters_file)
        }
