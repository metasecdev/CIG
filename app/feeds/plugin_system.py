"""
Custom threat feed plugin system
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class IndicatorType(Enum):
    """Supported indicator types"""
    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    FILE_HASH = "hash"
    URL = "url"
    EMAIL = "email"
    REGISTRY = "registry"
    ASN = "asn"
    FILENAME = "filename"


@dataclass
class FeedIndicator:
    """Indicator from a threat feed"""
    value: str
    indicator_type: IndicatorType
    source: str
    confidence: int = 100  # 0-100 confidence level
    tags: List[str] = None
    context: Dict[str, Any] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.context is None:
            self.context = {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "type": self.indicator_type.value,
            "source": self.source,
            "confidence": self.confidence,
            "tags": self.tags,
            "context": self.context,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class ThreatFeed(ABC):
    """Abstract base class for threat feeds"""

    def __init__(self, name: str, enabled: bool = True):
        """
        Initialize threat feed.
        
        Args:
            name: Feed name
            enabled: Whether feed is enabled
        """
        self.name = name
        self.enabled = enabled
        self.last_update = None
        self.indicator_count = 0

    @abstractmethod
    def fetch_indicators(self) -> List[FeedIndicator]:
        """
        Fetch indicators from feed.
        
        Returns:
            List of FeedIndicator objects
        """
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """
        Verify feed is accessible and responding.
        
        Returns:
            True if feed is healthy, False otherwise
        """
        pass

    def validate_indicator(self, indicator: FeedIndicator) -> bool:
        """
        Validate indicator format.
        
        Args:
            indicator: FeedIndicator to validate
        
        Returns:
            True if valid
        """
        if not indicator.value:
            return False
        if not 0 <= indicator.confidence <= 100:
            return False
        return True


class HTTPFeed(ThreatFeed):
    """Base class for HTTP-based threat feeds"""

    def __init__(self, name: str, url: str, enabled: bool = True,
                 auth_token: Optional[str] = None):
        """
        Initialize HTTP feed.
        
        Args:
            name: Feed name
            url: Feed URL
            enabled: Whether feed is enabled
            auth_token: Optional authentication token
        """
        super().__init__(name, enabled)
        self.url = url
        self.auth_token = auth_token

    def health_check(self) -> bool:
        """Check feed connectivity"""
        try:
            import requests
            response = requests.head(
                self.url,
                headers=self._get_headers(),
                timeout=5
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Health check failed for {self.name}: {e}")
            return False

    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers for requests"""
        headers = {"User-Agent": "CIG/1.0"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers

    def _fetch_json(self, url: Optional[str] = None) -> Dict[str, Any]:
        """Fetch JSON from URL"""
        import requests
        response = requests.get(
            url or self.url,
            headers=self._get_headers(),
            timeout=10
        )
        response.raise_for_status()
        return response.json()


class FileFeed(ThreatFeed):
    """Base class for file-based threat feeds"""

    def __init__(self, name: str, file_path: str, enabled: bool = True):
        """
        Initialize file feed.
        
        Args:
            name: Feed name
            file_path: Path to feed file
            enabled: Whether feed is enabled
        """
        super().__init__(name, enabled)
        self.file_path = file_path

    def health_check(self) -> bool:
        """Check if feed file exists"""
        from pathlib import Path
        return Path(self.file_path).exists()


class CustomFeedRegistry:
    """Registry for custom threat feeds"""

    def __init__(self):
        """Initialize feed registry"""
        self.feeds: Dict[str, ThreatFeed] = {}

    def register(self, feed: ThreatFeed) -> None:
        """
        Register a threat feed.
        
        Args:
            feed: ThreatFeed instance
        """
        self.feeds[feed.name] = feed
        logger.info(f"Feed registered: {feed.name}")

    def unregister(self, name: str) -> None:
        """Unregister a threat feed"""
        if name in self.feeds:
            del self.feeds[name]
            logger.info(f"Feed unregistered: {name}")

    def get_feed(self, name: str) -> Optional[ThreatFeed]:
        """Get feed by name"""
        return self.feeds.get(name)

    def get_all_feeds(self) -> List[ThreatFeed]:
        """Get all registered feeds"""
        return list(self.feeds.values())

    def get_enabled_feeds(self) -> List[ThreatFeed]:
        """Get all enabled feeds"""
        return [f for f in self.feeds.values() if f.enabled]

    def fetch_from_all(self) -> Dict[str, List[FeedIndicator]]:
        """
        Fetch from all enabled feeds.
        
        Returns:
            Dict mapping feed names to indicator lists
        """
        results = {}
        for feed in self.get_enabled_feeds():
            try:
                results[feed.name] = feed.fetch_indicators()
                feed.indicator_count = len(results[feed.name])
                logger.info(f"Fetched {feed.indicator_count} indicators from {feed.name}")
            except Exception as e:
                logger.error(f"Failed to fetch from {feed.name}: {e}")
                results[feed.name] = []
        return results

    def health_check_all(self) -> Dict[str, bool]:
        """
        Check health of all feeds.
        
        Returns:
            Dict mapping feed names to health status
        """
        results = {}
        for feed in self.feeds.values():
            try:
                results[feed.name] = feed.health_check()
            except Exception as e:
                logger.error(f"Health check error for {feed.name}: {e}")
                results[feed.name] = False
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get feed statistics"""
        return {
            "total_feeds": len(self.feeds),
            "enabled_feeds": len(self.get_enabled_feeds()),
            "feeds": {
                name: {
                    "enabled": feed.enabled,
                    "indicators": feed.indicator_count,
                    "last_update": feed.last_update,
                }
                for name, feed in self.feeds.items()
            }
        }


# Example custom feed implementation
class ExampleCustomFeed(HTTPFeed):
    """Example custom threat feed"""

    def __init__(self, api_key: str = ""):
        super().__init__(
            name="ExampleFeed",
            url="https://api.example.com/indicators",
            enabled=True,
            auth_token=api_key
        )

    def fetch_indicators(self) -> List[FeedIndicator]:
        """Fetch indicators from example API"""
        try:
            data = self._fetch_json()
            indicators = []

            for item in data.get("indicators", []):
                indicator = FeedIndicator(
                    value=item["value"],
                    indicator_type=IndicatorType(item["type"]),
                    source=self.name,
                    confidence=item.get("confidence", 100),
                    tags=item.get("tags", []),
                    context={
                        "source_url": self.url,
                        "api_data": item.get("extra", {})
                    }
                )

                if self.validate_indicator(indicator):
                    indicators.append(indicator)

            return indicators
        except Exception as e:
            logger.error(f"Error fetching from {self.name}: {e}")
            return []
