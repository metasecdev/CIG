"""
Fine-Grained Feed Filtering System
Provides advanced filtering capabilities for threat intelligence feeds
Supports filtering by type, severity, tags, confidence, and custom expressions
"""

import logging
import json
import re
from typing import List, Dict, Any, Optional, Callable, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


class IndicatorType(Enum):
    """Threat indicator types"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    CERTIFICATE = "certificate"
    ASN = "asn"
    ASNAME = "asname"
    CIDR = "cidr"
    FILE = "file"
    HOSTNAME = "hostname"
    REGISTRY = "registry"
    USER_AGENT = "user_agent"
    PHONE = "phone"
    CUSTOM = "custom"


class SeverityLevel(Enum):
    """Severity levels for indicators"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class FilterRule:
    """Individual filter rule"""
    id: str
    name: str
    description: str = ""
    enabled: bool = True
    
    # Type filters
    indicator_types: List[IndicatorType] = field(default_factory=list)  # Empty = all types
    
    # Severity filters
    min_severity: Optional[SeverityLevel] = None
    max_severity: Optional[SeverityLevel] = None
    
    # Tag-based filters
    include_tags: List[str] = field(default_factory=list)  # Must have at least one
    exclude_tags: List[str] = field(default_factory=list)  # Must not have any
    
    # Confidence/Score filters
    min_confidence: int = 0  # 0-100
    min_reputation_score: int = 0  # Feed-specific
    
    # Time-based filters
    age_days: Optional[int] = None  # Only indicators from last N days
    
    # Feed source filters
    allowed_feeds: List[str] = field(default_factory=list)  # Empty = all feeds
    excluded_feeds: List[str] = field(default_factory=list)
    
    # Pattern matching
    value_patterns: List[str] = field(default_factory=list)  # Regex patterns to match
    exclude_patterns: List[str] = field(default_factory=list)  # Patterns to exclude
    
    # Custom condition function (for complex logic)
    custom_condition: Optional[Callable] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "indicator_types": [t.value for t in self.indicator_types],
            "min_severity": self.min_severity.name if self.min_severity else None,
            "max_severity": self.max_severity.name if self.max_severity else None,
            "include_tags": self.include_tags,
            "exclude_tags": self.exclude_tags,
            "min_confidence": self.min_confidence,
            "min_reputation_score": self.min_reputation_score,
            "age_days": self.age_days,
            "allowed_feeds": self.allowed_feeds,
            "excluded_feeds": self.excluded_feeds,
            "value_patterns": self.value_patterns,
            "exclude_patterns": self.exclude_patterns,
        }


@dataclass
class FeedFilter:
    """Feed filtering configuration"""
    filter_id: str
    feed_id: str
    name: str
    description: str = ""
    enabled: bool = True
    
    # Composition of rules (AND/OR logic)
    rules: List[FilterRule] = field(default_factory=list)
    combine_with: str = "AND"  # AND or OR
    
    # Action when filter matches
    action: str = "include"  # "include" or "exclude"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "filter_id": self.filter_id,
            "feed_id": self.feed_id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "rules": [r.to_dict() for r in self.rules],
            "combine_with": self.combine_with,
            "action": self.action,
        }


class FeedFilterEngine:
    """
    Advanced filtering engine for threat feeds
    Evaluates indicators against multiple filter rules
    """

    def __init__(self, config_file: Optional[str] = None):
        self.filters: Dict[str, FeedFilter] = {}
        self.rules: Dict[str, FilterRule] = {}
        self.config_file = config_file or "config/feed_filters.json"
        self._load_config()

    def register_rule(self, rule: FilterRule) -> FilterRule:
        """Register a filter rule"""
        self.rules[rule.id] = rule
        logger.info(f"Registered filter rule: {rule.name}")
        return rule

    def register_filter(self, feed_filter: FeedFilter) -> FeedFilter:
        """Register a feed filter"""
        self.filters[feed_filter.filter_id] = feed_filter
        logger.info(f"Registered feed filter: {feed_filter.name}")
        return feed_filter

    def create_rule(
        self,
        rule_id: str,
        name: str,
        indicator_types: Optional[List[IndicatorType]] = None,
        min_severity: Optional[SeverityLevel] = None,
        include_tags: Optional[List[str]] = None,
        exclude_tags: Optional[List[str]] = None,
        min_confidence: int = 0,
        allowed_feeds: Optional[List[str]] = None,
        **kwargs
    ) -> FilterRule:
        """Create and register a new filter rule"""
        rule = FilterRule(
            id=rule_id,
            name=name,
            indicator_types=indicator_types or [],
            min_severity=min_severity,
            include_tags=include_tags or [],
            exclude_tags=exclude_tags or [],
            min_confidence=min_confidence,
            allowed_feeds=allowed_feeds or [],
            **kwargs
        )
        return self.register_rule(rule)

    def create_filter(
        self,
        filter_id: str,
        feed_id: str,
        name: str,
        rules: List[FilterRule],
        action: str = "include",
        combine_with: str = "AND",
        **kwargs
    ) -> FeedFilter:
        """Create and register a new filter"""
        feed_filter = FeedFilter(
            filter_id=filter_id,
            feed_id=feed_id,
            name=name,
            rules=rules,
            action=action,
            combine_with=combine_with,
            **kwargs
        )
        return self.register_filter(feed_filter)

    def evaluate_rule(self, rule: FilterRule, indicator: Dict[str, Any]) -> bool:
        """
        Evaluate if an indicator passes a single filter rule
        
        Returns:
            True if indicator passes the rule, False otherwise
        """
        if not rule.enabled:
            return True

        # Type check
        if rule.indicator_types:
            ind_type = indicator.get("type", "")
            if not any(t.value == ind_type for t in rule.indicator_types):
                return False

        # Severity check
        severity = indicator.get("severity")
        if severity and rule.min_severity:
            try:
                sev_level = SeverityLevel[severity.upper()]
                if sev_level.value < rule.min_severity.value:
                    return False
            except (KeyError, AttributeError):
                pass

        if severity and rule.max_severity:
            try:
                sev_level = SeverityLevel[severity.upper()]
                if sev_level.value > rule.max_severity.value:
                    return False
            except (KeyError, AttributeError):
                pass

        # Tag filtering
        tags = set(indicator.get("tags", []))
        if rule.include_tags and not tags.intersection(rule.include_tags):
            return False
        if rule.exclude_tags and tags.intersection(rule.exclude_tags):
            return False

        # Confidence check
        confidence = indicator.get("confidence", 0)
        if confidence < rule.min_confidence:
            return False

        # Feed source check
        feed_source = indicator.get("feed_source", "")
        if rule.allowed_feeds and feed_source not in rule.allowed_feeds:
            return False
        if rule.excluded_feeds and feed_source in rule.excluded_feeds:
            return False

        # Pattern matching
        value = indicator.get("value", "")
        if rule.value_patterns:
            if not any(re.match(pattern, value) for pattern in rule.value_patterns):
                return False
        if rule.exclude_patterns:
            if any(re.match(pattern, value) for pattern in rule.exclude_patterns):
                return False

        # Age check
        if rule.age_days:
            first_seen = indicator.get("first_seen")
            if first_seen:
                try:
                    first_seen_dt = datetime.fromisoformat(first_seen)
                    if datetime.utcnow() - first_seen_dt > timedelta(days=rule.age_days):
                        return False
                except ValueError:
                    pass

        # Custom condition check
        if rule.custom_condition:
            try:
                if not rule.custom_condition(indicator):
                    return False
            except Exception as e:
                logger.warning(f"Custom condition error: {e}")
                return False

        return True

    def evaluate_filter(self, feed_filter: FeedFilter, indicator: Dict[str, Any]) -> bool:
        """
        Evaluate if an indicator passes a feed filter
        Combines multiple rules with AND/OR logic
        
        Returns:
            True if indicator should be included (considering action), False otherwise
        """
        if not feed_filter.enabled:
            return True

        # Evaluate all rules
        rule_results = [
            self.evaluate_rule(rule, indicator)
            for rule in feed_filter.rules
        ]

        if not rule_results:
            return True

        # Combine results
        if feed_filter.combine_with == "AND":
            passes_filter = all(rule_results)
        else:  # OR
            passes_filter = any(rule_results)

        # Apply action
        if feed_filter.action == "include":
            return passes_filter
        else:  # exclude
            return not passes_filter

    def filter_indicators(
        self,
        indicators: List[Dict[str, Any]],
        feed_id: Optional[str] = None,
        filter_ids: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Apply filters to a list of indicators
        
        Args:
            indicators: List of indicator dictionaries
            feed_id: Filter by specific feed (if None, apply all filters)
            filter_ids: Specific filter IDs to apply (if None, apply all)
        
        Returns:
            Filtered list of indicators
        """
        if not indicators:
            return []

        # Determine which filters to apply
        filters_to_apply = []
        for fid, feed_filter in self.filters.items():
            if not feed_filter.enabled:
                continue
            if filter_ids and fid not in filter_ids:
                continue
            if feed_id and feed_filter.feed_id != feed_id:
                continue
            filters_to_apply.append(feed_filter)

        if not filters_to_apply:
            return indicators

        # Apply filters to each indicator
        filtered = []
        for indicator in indicators:
            # Check if indicator passes all applicable filters
            if all(self.evaluate_filter(f, indicator) for f in filters_to_apply):
                filtered.append(indicator)

        logger.debug(
            f"Filtered {len(indicators)} indicators -> {len(filtered)} "
            f"(applied {len(filters_to_apply)} filters)"
        )
        return filtered

    def get_filter_status(self, filter_id: Optional[str] = None) -> Dict[str, Any]:
        """Get status of one or all filters"""
        if filter_id:
            if filter_id not in self.filters:
                return {}
            return self.filters[filter_id].to_dict()
        
        return {fid: f.to_dict() for fid, f in self.filters.items()}

    def get_rule_status(self, rule_id: Optional[str] = None) -> Dict[str, Any]:
        """Get status of one or all rules"""
        if rule_id:
            if rule_id not in self.rules:
                return {}
            return self.rules[rule_id].to_dict()
        
        return {rid: r.to_dict() for rid, r in self.rules.items()}

    def enable_filter(self, filter_id: str) -> bool:
        """Enable a filter"""
        if filter_id in self.filters:
            self.filters[filter_id].enabled = True
            logger.info(f"Enabled filter: {filter_id}")
            self._save_config()
            return True
        return False

    def disable_filter(self, filter_id: str) -> bool:
        """Disable a filter"""
        if filter_id in self.filters:
            self.filters[filter_id].enabled = False
            logger.info(f"Disabled filter: {filter_id}")
            self._save_config()
            return True
        return False

    def _save_config(self):
        """Persist filter configuration"""
        try:
            Path(self.config_file).parent.mkdir(parents=True, exist_ok=True)
            config = {
                "timestamp": datetime.now().isoformat(),
                "filters": {fid: f.to_dict() for fid, f in self.filters.items()},
                "rules": {rid: r.to_dict() for rid, r in self.rules.items()},
            }
            with open(self.config_file, "w") as f:
                json.dump(config, f, indent=2)
            logger.debug("Filter configuration saved")
        except Exception as e:
            logger.error(f"Failed to save filter configuration: {e}")

    def _load_config(self):
        """Load filter configuration from file"""
        try:
            if not Path(self.config_file).exists():
                logger.debug("No filter configuration file found")
                return
            
            with open(self.config_file, "r") as f:
                config = json.load(f)
            
            logger.info(f"Filter configuration loaded from {self.config_file}")
        except Exception as e:
            logger.warning(f"Failed to load filter configuration: {e}")
