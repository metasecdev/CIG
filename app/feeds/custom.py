"""
Custom Feed Source Support
Allows adding custom threat intelligence feed sources
"""

import logging
from typing import List, Dict, Any, Optional, Callable
from abc import ABC, abstractmethod
from datetime import datetime
import hashlib
import re

logger = logging.getLogger(__name__)


class FeedParser(ABC):
    """Abstract base class for feed parsers"""

    @abstractmethod
    def parse(self, content: str) -> List[Dict[str, Any]]:
        """Parse feed content and return list of indicators"""
        pass

    @abstractmethod
    def get_indicator_type(self) -> str:
        """Return the indicator type this parser handles"""
        pass


class PlainTextParser(FeedParser):
    """Parser for plain text feeds (one indicator per line)"""

    def __init__(self, indicator_type: str = "ip"):
        self.indicator_type = indicator_type

    def parse(self, content: str) -> List[Dict[str, Any]]:
        """Parse plain text content"""
        indicators = []
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            value = line.split()[0]
            if self._validate_indicator(value):
                indicators.append(
                    {
                        "value": value,
                        "type": self.indicator_type,
                        "source": "custom_feed",
                    }
                )
        return indicators

    def get_indicator_type(self) -> str:
        return self.indicator_type

    def _validate_indicator(self, value: str) -> bool:
        if self.indicator_type == "ip":
            return self._is_valid_ip(value)
        elif self.indicator_type == "domain":
            return self._is_valid_domain(value)
        elif self.indicator_type == "url":
            return self._is_valid_url(value)
        elif self.indicator_type == "hash":
            return self._is_valid_hash(value)
        return True

    def _is_valid_ip(self, value: str) -> bool:
        import ipaddress

        try:
            ipaddress.ip_address(value)
            return True
        except:
            return False

    def _is_valid_domain(self, value: str) -> bool:
        pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
        return bool(re.match(pattern, value))

    def _is_valid_url(self, value: str) -> bool:
        return value.startswith(("http://", "https://"))

    def _is_valid_hash(self, value: str) -> bool:
        lengths = {"md5": 32, "sha1": 40, "sha256": 64}
        for hash_type, length in lengths.items():
            if len(value) == length and re.match(r"^[a-fA-F0-9]+$", value):
                return True
        return False


class JSONFeedParser(FeedParser):
    """Parser for JSON format feeds"""

    def __init__(self, value_field: str = "indicator", type_field: str = "type"):
        self.value_field = value_field
        self.type_field = type_field

    def parse(self, content: str) -> List[Dict[str, Any]]:
        """Parse JSON content"""
        import json

        indicators = []

        try:
            data = json.loads(content)
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                items = data.get("indicators", [data])
            else:
                return []

            for item in items:
                value = item.get(self.value_field)
                if value:
                    indicators.append(
                        {
                            "value": value,
                            "type": item.get(self.type_field, "unknown"),
                            "source": "custom_feed",
                            "metadata": item,
                        }
                    )
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON feed: {e}")

        return indicators

    def get_indicator_type(self) -> str:
        return "mixed"


class CSVFeedParser(FeedParser):
    """Parser for CSV format feeds"""

    def __init__(self, value_column: int = 0, type_column: Optional[int] = None):
        self.value_column = value_column
        self.type_column = type_column

    def parse(self, content: str) -> List[Dict[str, Any]]:
        """Parse CSV content"""
        indicators = []

        lines = content.strip().split("\n")
        for line in lines:
            if not line or line.startswith("#"):
                continue

            parts = line.split(",")
            if len(parts) > self.value_column:
                value = parts[self.value_column].strip().strip('"')
                indicator_type = "unknown"

                if self.type_column is not None and len(parts) > self.type_column:
                    indicator_type = parts[self.type_column].strip().strip('"')

                if value:
                    indicators.append(
                        {
                            "value": value,
                            "type": indicator_type,
                            "source": "custom_feed",
                        }
                    )

        return indicators

    def get_indicator_type(self) -> str:
        return "mixed"


class CustomFeedSource:
    """Custom threat intelligence feed source"""

    def __init__(
        self,
        name: str,
        url: str,
        parser: FeedParser,
        update_interval: int = 3600,
        enabled: bool = True,
        auth_token: Optional[str] = None,
    ):
        self.name = name
        self.url = url
        self.parser = parser
        self.update_interval = update_interval
        self.enabled = enabled
        self.auth_token = auth_token
        self.last_update: Optional[datetime] = None
        self.last_indicator_count = 0

    def fetch_and_parse(self, session) -> List[Dict[str, Any]]:
        """Fetch feed and parse indicators"""
        headers = {"User-Agent": "CIG/1.0 Custom Feed"}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"

        response = session.get(self.url, headers=headers, timeout=30)
        response.raise_for_status()

        indicators = self.parser.parse(response.text)
        self.last_update = datetime.now()
        self.last_indicator_count = len(indicators)

        logger.info(
            f"Custom feed '{self.name}' updated with {len(indicators)} indicators"
        )
        return indicators


class CustomFeedManager:
    """Manager for custom feed sources"""

    def __init__(self, db=None):
        self.db = db
        self.feeds: Dict[str, CustomFeedSource] = {}
        self._parsers = {
            "plain_text": PlainTextParser,
            "json": JSONFeedParser,
            "csv": CSVFeedParser,
        }

    def register_feed(
        self,
        name: str,
        url: str,
        feed_type: str = "plain_text",
        indicator_type: str = "ip",
        update_interval: int = 3600,
        auth_token: Optional[str] = None,
    ) -> bool:
        """Register a new custom feed source"""
        try:
            parser = self._create_parser(feed_type, indicator_type)
            feed = CustomFeedSource(
                name=name,
                url=url,
                parser=parser,
                update_interval=update_interval,
                auth_token=auth_token,
            )
            self.feeds[name] = feed
            logger.info(f"Registered custom feed: {name} ({feed_type})")
            return True
        except Exception as e:
            logger.error(f"Failed to register custom feed '{name}': {e}")
            return False

    def _create_parser(self, feed_type: str, indicator_type: str) -> FeedParser:
        """Create appropriate parser"""
        if feed_type == "plain_text":
            return PlainTextParser(indicator_type)
        elif feed_type == "json":
            return JSONFeedParser()
        elif feed_type == "csv":
            return CSVFeedParser()
        else:
            raise ValueError(f"Unknown feed type: {feed_type}")

    def update_feed(self, name: str, session) -> Optional[List[Dict[str, Any]]]:
        """Update a specific feed"""
        if name not in self.feeds:
            return None

        feed = self.feeds[name]
        if not feed.enabled:
            return None

        return feed.fetch_and_parse(session)

    def update_all(self, session) -> Dict[str, int]:
        """Update all enabled feeds"""
        results = {}
        for name, feed in self.feeds.items():
            if feed.enabled:
                try:
                    indicators = feed.fetch_and_parse(session)
                    results[name] = len(indicators)
                except Exception as e:
                    logger.error(f"Failed to update feed '{name}': {e}")
                    results[name] = -1
        return results

    def get_feed_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all feeds"""
        status = {}
        for name, feed in self.feeds.items():
            status[name] = {
                "url": feed.url,
                "enabled": feed.enabled,
                "last_update": feed.last_update.isoformat()
                if feed.last_update
                else None,
                "indicator_count": feed.last_indicator_count,
                "update_interval": feed.update_interval,
            }
        return status

    def remove_feed(self, name: str) -> bool:
        """Remove a custom feed"""
        if name in self.feeds:
            del self.feeds[name]
            return True
        return False

    def enable_feed(self, name: str) -> bool:
        """Enable a feed"""
        if name in self.feeds:
            self.feeds[name].enabled = True
            return True
        return False

    def disable_feed(self, name: str) -> bool:
        """Disable a feed"""
        if name in self.feeds:
            self.feeds[name].enabled = False
            return True
        return False
