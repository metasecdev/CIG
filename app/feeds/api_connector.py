"""
Generic API Feed Connector Framework
Provides base classes and utilities for integrating any API-based threat intelligence feed
Supports various authentication methods and data formats
"""

import logging
import requests
import asyncio
import json
from typing import List, Dict, Any, Optional, Tuple, Callable, Protocol
from datetime import datetime, timezone
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger(__name__)


class AuthMethod(Enum):
    """Supported authentication methods"""
    NONE = "none"
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    BASIC_AUTH = "basic_auth"
    CUSTOM_HEADERS = "custom_headers"
    OAUTH2 = "oauth2"


class FeedDataFormat(Enum):
    """Supported data formats"""
    JSON = "json"
    CSV = "csv"
    XML = "xml"
    STIX = "stix"
    CUSTOM = "custom"


@dataclass
class APIFeedConfig:
    """Configuration for API-based feed"""
    feed_id: str
    feed_name: str
    api_endpoint: str
    auth_method: AuthMethod = AuthMethod.NONE
    auth_credentials: Dict[str, str] = field(default_factory=dict)
    data_format: FeedDataFormat = FeedDataFormat.JSON
    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, str] = field(default_factory=dict)
    request_timeout: int = 30
    rate_limit_delay: int = 0  # Seconds between requests
    enabled: bool = True


@dataclass
class APIFeedStats:
    """Statistics for API feed polling"""
    total_records: int = 0
    successfully_processed: int = 0
    failed_records: int = 0
    last_fetch: Optional[str] = None
    last_error: Optional[str] = None
    consecutive_failures: int = 0
    total_fetches: int = 0
    average_response_time: float = 0.0


class DataTransformer(ABC):
    """
    Base class for transforming API response data to standard indicator format
    Implement for each feed type
    """

    @abstractmethod
    def transform(self, api_response: Any) -> List[Dict[str, Any]]:
        """
        Transform raw API response to list of indicators
        
        Args:
            api_response: Raw response from API
        
        Returns:
            List of standardized indicators
        """
        pass

    @abstractmethod
    def get_indicator_type(self, record: Dict[str, Any]) -> str:
        """Get indicator type from record"""
        pass

    @abstractmethod
    def get_severity(self, record: Dict[str, Any]) -> str:
        """Get severity from record"""
        pass


class GenericAPIFeedConnector:
    """
    Generic connector for API-based threat intelligence feeds
    Supports multiple authentication methods, formats, and transformations
    """

    def __init__(
        self,
        config: APIFeedConfig,
        transformer: Optional[DataTransformer] = None,
        database=None,
    ):
        """
        Initialize API feed connector
        
        Args:
            config: Feed configuration
            transformer: Data transformer for this feed
            database: Optional database for storing indicators
        """
        self.config = config
        self.transformer = transformer
        self.database = database
        self.session: Optional[requests.Session] = None
        self.stats = APIFeedStats()
        self.last_fetch_time: Optional[datetime] = None
        self.record_cache: List[Dict[str, Any]] = []

    def _create_session(self) -> requests.Session:
        """Create authenticated requests session"""
        if self.session is not None:
            return self.session

        session = requests.Session()

        # Add custom headers
        if self.config.headers:
            session.headers.update(self.config.headers)

        # Setup authentication
        if self.config.auth_method == AuthMethod.API_KEY:
            api_key = self.config.auth_credentials.get("api_key")
            header_name = self.config.auth_credentials.get("header_name", "X-API-Key")
            session.headers[header_name] = api_key

        elif self.config.auth_method == AuthMethod.BEARER_TOKEN:
            token = self.config.auth_credentials.get("token")
            session.headers["Authorization"] = f"Bearer {token}"

        elif self.config.auth_method == AuthMethod.BASIC_AUTH:
            username = self.config.auth_credentials.get("username")
            password = self.config.auth_credentials.get("password")
            session.auth = (username, password)

        elif self.config.auth_method == AuthMethod.CUSTOM_HEADERS:
            for key, value in self.config.auth_credentials.items():
                if key.startswith("header_"):
                    header_name = key.replace("header_", "")
                    session.headers[header_name] = value

        session.headers["User-Agent"] = "CIG/1.0 (Cyber Intelligence Gateway)"
        self.session = session
        return session

    def fetch_data(self) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Fetch data from API endpoint
        
        Returns:
            (indicators, success)
        """
        try:
            session = self._create_session()
            start_time = datetime.now(timezone.utc)

            response = session.get(
                self.config.api_endpoint,
                params=self.config.query_params,
                timeout=self.config.request_timeout,
            )
            response.raise_for_status()

            # Parse response based on format
            if self.config.data_format == FeedDataFormat.JSON:
                data = response.json()
            elif self.config.data_format == FeedDataFormat.XML:
                import xml.etree.ElementTree as ET
                data = ET.fromstring(response.text)
            else:
                data = response.text

            # Transform data using transformer if available
            if self.transformer:
                records = self.transformer.transform(data)
            else:
                # Default behavior: assume data is list of records
                records = data if isinstance(data, list) else []

            # Calculate response time
            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
            self.stats.average_response_time = (
                (self.stats.average_response_time * self.stats.total_fetches + elapsed) /
                (self.stats.total_fetches + 1)
            )

            # Update statistics
            self.stats.total_records = len(records)
            self.stats.successfully_processed = len(records)
            self.stats.last_fetch = datetime.now(timezone.utc).isoformat()
            self.stats.consecutive_failures = 0
            self.stats.last_error = None
            self.stats.total_fetches += 1

            # Cache records
            self.record_cache = records

            # Ingest into database if available
            if self.database and records:
                self._ingest_records(records)

            logger.info(
                f"Fetched {len(records)} records from {self.config.feed_name} "
                f"(took {elapsed:.2f}s)"
            )
            return records, True

        except requests.exceptions.Timeout:
            msg = f"{self.config.feed_name}: Request timeout"
            logger.error(msg)
            self.stats.last_error = msg
            self.stats.consecutive_failures += 1
            return [], False

        except requests.exceptions.ConnectionError:
            msg = f"{self.config.feed_name}: Connection error"
            logger.error(msg)
            self.stats.last_error = msg
            self.stats.consecutive_failures += 1
            return [], False

        except requests.exceptions.HTTPError as e:
            msg = f"{self.config.feed_name}: HTTP {e.response.status_code}"
            logger.error(msg)
            self.stats.last_error = msg
            self.stats.consecutive_failures += 1
            return [], False

        except Exception as e:
            msg = f"{self.config.feed_name}: {str(e)}"
            logger.error(msg)
            self.stats.last_error = msg
            self.stats.consecutive_failures += 1
            return [], False

    def _normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a single record to standard indicator format
        Uses transformer if available, otherwise basic normalization
        """
        if self.transformer:
            indicator_type = self.transformer.get_indicator_type(record)
            severity = self.transformer.get_severity(record)
        else:
            indicator_type = record.get("type", "custom")
            severity = record.get("severity", "medium")

        return {
            "value": record.get("value", record.get("id", "")),
            "type": indicator_type,
            "source": self.config.feed_id,
            "feed_source": self.config.feed_name,
            "severity": severity,
            "confidence": record.get("confidence", 75),
            "tags": record.get("tags", []),
            "first_seen": record.get("first_seen", datetime.now(timezone.utc).isoformat()),
            "last_seen": record.get("last_seen", datetime.now(timezone.utc).isoformat()),
            "raw_data": record,
        }

    def _ingest_records(self, records: List[Dict[str, Any]]):
        """Ingest records into database"""
        if not self.database or not records:
            return

        try:
            for record in records:
                normalized = self._normalize_record(record)
                self.database.add_indicator(
                    value=normalized["value"],
                    type=normalized["type"],
                    source=normalized["source"],
                    feed_source=normalized["feed_source"],
                    tags=",".join(normalized.get("tags", [])),
                    first_seen=normalized.get("first_seen"),
                    last_seen=normalized.get("last_seen"),
                )
            logger.debug(f"Ingested {len(records)} records into database")
        except Exception as e:
            logger.error(f"Failed to ingest records: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get feed statistics"""
        return asdict(self.stats)

    def reset_stats(self):
        """Reset statistics"""
        self.stats = APIFeedStats()

    def enable(self):
        """Enable the feed"""
        self.config.enabled = True
        logger.info(f"Enabled feed: {self.config.feed_name}")

    def disable(self):
        """Disable the feed"""
        self.config.enabled = False
        logger.info(f"Disabled feed: {self.config.feed_name}")

    async def fetch_data_async(self) -> Tuple[List[Dict[str, Any]], bool]:
        """Async wrapper for fetching data"""
        try:
            return await asyncio.to_thread(self.fetch_data)
        except Exception as e:
            logger.error(f"Async fetch failed: {e}")
            return [], False


class APIFeedConnectorFactory:
    """Factory for creating and managing API feed connectors"""

    def __init__(self):
        self.connectors: Dict[str, GenericAPIFeedConnector] = {}
        self.transformers: Dict[str, DataTransformer] = {}

    def register_transformer(self, feed_id: str, transformer: DataTransformer):
        """Register a data transformer for a feed"""
        self.transformers[feed_id] = transformer
        logger.info(f"Registered transformer for feed: {feed_id}")

    def create_connector(
        self,
        config: APIFeedConfig,
        database=None,
    ) -> GenericAPIFeedConnector:
        """Create a new API feed connector"""
        transformer = self.transformers.get(config.feed_id)
        connector = GenericAPIFeedConnector(config, transformer=transformer, database=database)
        self.connectors[config.feed_id] = connector
        logger.info(f"Created connector for feed: {config.feed_name}")
        return connector

    def get_connector(self, feed_id: str) -> Optional[GenericAPIFeedConnector]:
        """Get an existing connector"""
        return self.connectors.get(feed_id)

    def get_all_connectors(self) -> Dict[str, GenericAPIFeedConnector]:
        """Get all connectors"""
        return self.connectors.copy()

    async def fetch_all_async(self) -> Dict[str, Tuple[List[Dict[str, Any]], bool]]:
        """Fetch from all enabled connectors asynchronously"""
        results = {}
        tasks = []

        for feed_id, connector in self.connectors.items():
            if connector.config.enabled:
                tasks.append((feed_id, connector.fetch_data_async()))

        for feed_id, task in tasks:
            try:
                result = await task
                results[feed_id] = result
            except Exception as e:
                logger.error(f"Fetch from {feed_id} failed: {e}")
                results[feed_id] = ([], False)

        return results
