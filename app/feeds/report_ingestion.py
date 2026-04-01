"""
Report Ingestion Connector Framework
Provides utilities for ingesting and parsing security reports
Supports multiple formats: JSON, CSV, STIX, pdf metadata, raw text
Extracts indicators and intelligence from security reports
"""

import logging
import json
import csv
from typing import List, Dict, Any, Optional, Tuple, BinaryIO
from pathlib import Path
from datetime import datetime, timezone
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from enum import Enum
import re

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Supported report formats"""
    JSON = "json"
    CSV = "csv"
    STIX = "stix"
    PDF = "pdf"
    TEXT = "text"
    XML = "xml"


class ReportType(Enum):
    """Types of security reports"""
    INCIDENT = "incident"
    THREAT_ANALYSIS = "threat_analysis"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    APT_REPORT = "apt_report"
    MALWARE_ANALYSIS = "malware_analysis"
    IOC_FEED = "ioc_feed"
    COMPLIANCE = "compliance"
    CUSTOM = "custom"


@dataclass
class ReportMetadata:
    """Metadata about an ingested report"""
    report_id: str
    report_title: str
    report_type: ReportType
    report_format: ReportFormat
    source: str
    ingestion_date: str
    publication_date: Optional[str] = None
    author: Optional[str] = None
    description: Optional[str] = None
    indicators_count: int = 0
    severity_distribution: Dict[str, int] = None

    def __post_init__(self):
        if self.severity_distribution is None:
            self.severity_distribution = {}


@dataclass
class ExtractedIndicator:
    """Indicator extracted from a report"""
    value: str
    type: str  # ip, domain, hash, url, email, etc.
    confidence: int
    severity: str
    source_report: str
    context: str = ""  # Additional context from the report
    references: List[str] = None

    def __post_init__(self):
        if self.references is None:
            self.references = []


class ReportParser(ABC):
    """Base class for parsing different report formats"""

    @abstractmethod
    def parse(self, content: Any) -> Tuple[List[Dict[str, Any]], bool]:
        """
        Parse report content
        
        Args:
            content: File content or path
        
        Returns:
            (parsed_data, success)
        """
        pass

    @abstractmethod
    def extract_indicators(self, parsed_data: Dict[str, Any]) -> List[ExtractedIndicator]:
        """Extract indicators from parsed data"""
        pass


class JSONReportParser(ReportParser):
    """Parser for JSON reports"""

    def parse(self, content: Any) -> Tuple[List[Dict[str, Any]], bool]:
        """Parse JSON report"""
        try:
            if isinstance(content, str):
                # Content is a file path
                with open(content, "r") as f:
                    data = json.load(f)
            else:
                # Content is already parsed or raw JSON
                data = json.loads(content) if isinstance(content, str) else content

            logger.debug(f"Parsed JSON report with {len(str(data))} bytes")
            return [data], True

        except Exception as e:
            logger.error(f"Failed to parse JSON report: {e}")
            return [], False

    def extract_indicators(self, parsed_data: Dict[str, Any]) -> List[ExtractedIndicator]:
        """Extract indicators from JSON data"""
        indicators = []

        # Look for common indicator fields
        indicator_patterns = {
            "ip_indicator": ["ip", "ips", "source_ip", "destination_ip", "attacker_ip"],
            "domain_indicator": ["domain", "domains", "hostname", "hostnames"],
            "hash_indicator": ["hash", "hashes", "md5", "sha1", "sha256"],
            "url_indicator": ["url", "urls"],
            "email_indicator": ["email", "emails"],
        }

        for field_name, possible_keys in indicator_patterns.items():
            for data_field in possible_keys:
                if data_field in parsed_data:
                    value = parsed_data[data_field]
                    if isinstance(value, list):
                        for item in value:
                            indicators.append(
                                ExtractedIndicator(
                                    value=str(item),
                                    type=field_name.replace("_indicator", ""),
                                    confidence=80,
                                    severity=parsed_data.get("severity", "medium"),
                                    source_report=parsed_data.get("id", "unknown"),
                                )
                            )

        return indicators


class CSVReportParser(ReportParser):
    """Parser for CSV reports"""

    def parse(self, content: Any) -> Tuple[List[Dict[str, Any]], bool]:
        """Parse CSV report"""
        try:
            records = []

            if isinstance(content, str) and Path(content).exists():
                # Content is a file path
                with open(content, "r") as f:
                    reader = csv.DictReader(f)
                    records = list(reader)
            elif isinstance(content, str):
                # Content is raw CSV text
                lines = content.strip().split("\n")
                reader = csv.DictReader(lines)
                records = list(reader)
            else:
                records = content

            logger.debug(f"Parsed CSV report with {len(records)} rows")
            return records, True

        except Exception as e:
            logger.error(f"Failed to parse CSV report: {e}")
            return [], False

    def extract_indicators(self, records: List[Dict[str, Any]]) -> List[ExtractedIndicator]:
        """Extract indicators from CSV records"""
        indicators = []

        for record in records:
            # Check for common indicator columns
            for key, value in record.items():
                if not value:
                    continue

                # Try to classify the value
                indicator_type = self._classify_indicator(key, value)
                if indicator_type:
                    indicators.append(
                        ExtractedIndicator(
                            value=value,
                            type=indicator_type,
                            confidence=75,
                            severity=record.get("severity", "medium"),
                            source_report=record.get("report_id", "unknown"),
                            context=f"Column: {key}",
                        )
                    )

        return indicators

    def _classify_indicator(self, field_name: str, value: str) -> Optional[str]:
        """Classify an indicator type based on field name and value"""
        field_lower = field_name.lower()

        # Field name based classification
        if any(x in field_lower for x in ["ip", "ipv4", "ipv6"]):
            if self._is_ip(value):
                return "ip"
        elif any(x in field_lower for x in ["domain", "hostname"]):
            if self._is_domain(value):
                return "domain"
        elif any(x in field_lower for x in ["hash", "md5", "sha1", "sha256"]):
            return "hash"
        elif any(x in field_lower for x in ["url", "uri"]):
            if self._is_url(value):
                return "url"
        elif any(x in field_lower for x in ["email"]):
            if self._is_email(value):
                return "email"

        return None

    @staticmethod
    def _is_ip(value: str) -> bool:
        """Check if value is an IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_domain(value: str) -> bool:
        """Check if value is a domain"""
        pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
        return bool(re.match(pattern, value))

    @staticmethod
    def _is_url(value: str) -> bool:
        """Check if value is a URL"""
        pattern = r"^https?://"
        return bool(re.match(pattern, value))

    @staticmethod
    def _is_email(value: str) -> bool:
        """Check if value is an email"""
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, value))


class TextReportParser(ReportParser):
    """Parser for plain text reports"""

    def parse(self, content: Any) -> Tuple[List[Dict[str, Any]], bool]:
        """Parse text report"""
        try:
            if isinstance(content, str) and Path(content).exists():
                with open(content, "r") as f:
                    text = f.read()
            else:
                text = content

            logger.debug(f"Parsed text report with {len(text)} characters")
            return [{"content": text}], True

        except Exception as e:
            logger.error(f"Failed to parse text report: {e}")
            return [], False

    def extract_indicators(self, parsed_data: Dict[str, Any]) -> List[ExtractedIndicator]:
        """Extract indicators from text using regex patterns"""
        indicators = []
        text = parsed_data.get("content", "")

        # IP addresses
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        for match in re.finditer(ip_pattern, text):
            value = match.group()
            if self._is_valid_ip(value):
                indicators.append(
                    ExtractedIndicator(
                        value=value,
                        type="ip",
                        confidence=70,
                        severity="medium",
                        source_report=parsed_data.get("id", "text_report"),
                    )
                )

        # URLs
        url_pattern = r"https?://[^\s]+"
        for match in re.finditer(url_pattern, text):
            indicators.append(
                ExtractedIndicator(
                    value=match.group(),
                    type="url",
                    confidence=70,
                    severity="medium",
                    source_report=parsed_data.get("id", "text_report"),
                )
            )

        # Email addresses
        email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        for match in re.finditer(email_pattern, text):
            indicators.append(
                ExtractedIndicator(
                    value=match.group(),
                    type="email",
                    confidence=65,
                    severity="low",
                    source_report=parsed_data.get("id", "text_report"),
                )
            )

        return indicators

    @staticmethod
    def _is_valid_ip(value: str) -> bool:
        """Validate IP address"""
        try:
            import ipaddress
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False


class ReportIngestionConnector:
    """Connector for ingesting and processing security reports"""

    def __init__(self, database=None):
        self.database = database
        self.parsers: Dict[ReportFormat, ReportParser] = {
            ReportFormat.JSON: JSONReportParser(),
            ReportFormat.CSV: CSVReportParser(),
            ReportFormat.TEXT: TextReportParser(),
        }
        self.ingested_reports: Dict[str, ReportMetadata] = {}

    def register_parser(self, format: ReportFormat, parser: ReportParser):
        """Register a custom parser for a report format"""
        self.parsers[format] = parser
        logger.info(f"Registered parser for format: {format.value}")

    def ingest_report(
        self,
        report_path: str,
        report_format: ReportFormat,
        report_type: ReportType = ReportType.CUSTOM,
        source: str = "manual",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[ExtractedIndicator], bool]:
        """
        Ingest a security report
        
        Args:
            report_path: Path to report file
            report_format: Format of the report
            report_type: Type of security report
            source: Source of the report
            metadata: Additional metadata
        
        Returns:
            (extracted_indicators, success)
        """
        try:
            # Get appropriate parser
            parser = self.parsers.get(report_format)
            if not parser:
                logger.error(f"No parser available for format: {report_format.value}")
                return [], False

            # Parse report
            parsed_data, success = parser.parse(report_path)
            if not success or not parsed_data:
                return [], False

            # Extract indicators from each parsed section
            all_indicators = []
            severity_dist = {}

            for data_item in parsed_data:
                indicators = parser.extract_indicators(data_item)
                all_indicators.extend(indicators)

                # Track severity distribution
                for indicator in indicators:
                    severity_dist[indicator.severity] = severity_dist.get(indicator.severity, 0) + 1

            # Create report metadata
            report_id = f"{source}_{datetime.now(timezone.utc).timestamp()}"
            report_title = Path(report_path).name if isinstance(report_path, str) else metadata.get("title", "Unknown")

            report_meta = ReportMetadata(
                report_id=report_id,
                report_title=report_title,
                report_type=report_type,
                report_format=report_format,
                source=source,
                ingestion_date=datetime.now(timezone.utc).isoformat(),
                indicators_count=len(all_indicators),
                severity_distribution=severity_dist,
                **metadata or {},
            )

            self.ingested_reports[report_id] = report_meta

            # Ingest indicators into database
            if self.database and all_indicators:
                self._ingest_indicators(all_indicators)

            logger.info(
                f"Ingested report: {report_title} "
                f"({len(all_indicators)} indicators extracted)"
            )
            return all_indicators, True

        except Exception as e:
            logger.error(f"Failed to ingest report: {e}")
            return [], False

    def _ingest_indicators(self, indicators: List[ExtractedIndicator]):
        """Ingest extracted indicators into database"""
        if not self.database:
            return

        try:
            for indicator in indicators:
                self.database.add_indicator(
                    value=indicator.value,
                    type=indicator.type,
                    source="report_ingestion",
                    feed_source=indicator.source_report,
                    tags=",".join([str(ind) for ind in indicator.references]) if indicator.references else "",
                    first_seen=datetime.now(timezone.utc).isoformat(),
                )
            logger.debug(f"Ingested {len(indicators)} indicators from reports into database")
        except Exception as e:
            logger.error(f"Failed to ingest indicators: {e}")

    def get_report_metadata(self, report_id: Optional[str] = None) -> Dict[str, Any]:
        """Get metadata for one or all ingested reports"""
        if report_id:
            if report_id in self.ingested_reports:
                meta = self.ingested_reports[report_id]
                return asdict(meta)
            return {}

        return {
            rid: asdict(meta)
            for rid, meta in self.ingested_reports.items()
        }

    def list_reports(self) -> List[Dict[str, Any]]:
        """List all ingested reports"""
        return [
            asdict(meta)
            for meta in self.ingested_reports.values()
        ]

    def get_report_statistics(self) -> Dict[str, Any]:
        """Get statistics about ingested reports"""
        total_reports = len(self.ingested_reports)
        total_indicators = sum(m.indicators_count for m in self.ingested_reports.values())
        
        report_types = {}
        for meta in self.ingested_reports.values():
            rt = meta.report_type.value
            report_types[rt] = report_types.get(rt, 0) + 1

        return {
            "total_reports": total_reports,
            "total_indicators": total_indicators,
            "report_types": report_types,
            "average_indicators_per_report": total_indicators / total_reports if total_reports > 0 else 0,
        }
