"""
Prometheus metrics for CIG monitoring
"""

from typing import Optional, Dict, Any
import time


class MetricsCollector:
    """Collect and track application metrics"""

    def __init__(self):
        """Initialize metrics collector"""
        self.metrics: Dict[str, Any] = {
            # Counters
            "alerts_created": 0,
            "alerts_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "alerts_by_feed": {"misp": 0, "pfblocker": 0, "abuseipdb": 0},
            "indicators_added": 0,
            "indicators_by_type": {"ip": 0, "domain": 0, "hash": 0, "url": 0, "email": 0},
            "feed_updates": {"misp": 0, "pfblocker": 0, "abuseipdb": 0},
            "feed_errors": {"misp": 0, "pfblocker": 0, "abuseipdb": 0},
            "cache_hits": 0,
            "cache_misses": 0,
            "api_requests": 0,
            "api_errors": {"4xx": 0, "5xx": 0},
            
            # Gauges
            "api_request_duration_ms": [],
            "indicator_lookup_duration_ms": [],
            "feed_update_duration_ms": [],
            
            # Timestamps
            "last_misp_update": None,
            "last_pfblocker_update": None,
            "last_abuseipdb_update": None,
        }

    def increment_alert(self, severity: str = "info", feed_source: str = "unknown") -> None:
        """Increment alert counter"""
        self.metrics["alerts_created"] += 1
        if severity in self.metrics["alerts_by_severity"]:
            self.metrics["alerts_by_severity"][severity] += 1
        if feed_source in self.metrics["alerts_by_feed"]:
            self.metrics["alerts_by_feed"][feed_source] += 1

    def increment_indicator(self, indicator_type: str = "ip") -> None:
        """Increment indicator counter"""
        self.metrics["indicators_added"] += 1
        if indicator_type in self.metrics["indicators_by_type"]:
            self.metrics["indicators_by_type"][indicator_type] += 1

    def record_feed_update(self, feed_name: str, duration_ms: float,
                          success: bool = True) -> None:
        """Record feed update metric"""
        if feed_name in self.metrics["feed_updates"]:
            self.metrics["feed_updates"][feed_name] += 1
            self.metrics[f"last_{feed_name}_update"] = time.time()

        if not success and feed_name in self.metrics["feed_errors"]:
            self.metrics["feed_errors"][feed_name] += 1

        if feed_name not in self.metrics["feed_update_duration_ms"]:
            self.metrics["feed_update_duration_ms"] = []
        self.metrics.setdefault("feed_update_duration_ms", []).append(duration_ms)

    def record_cache_hit(self) -> None:
        """Record cache hit"""
        self.metrics["cache_hits"] += 1

    def record_cache_miss(self) -> None:
        """Record cache miss"""
        self.metrics["cache_misses"] += 1

    def get_cache_hit_rate(self) -> float:
        """Get cache hit rate"""
        total = self.metrics["cache_hits"] + self.metrics["cache_misses"]
        if total == 0:
            return 0.0
        return (self.metrics["cache_hits"] / total) * 100

    def record_api_request(self, duration_ms: float, status_code: int) -> None:
        """Record API request"""
        self.metrics["api_requests"] += 1
        self.metrics["api_request_duration_ms"].append(duration_ms)

        if status_code >= 400:
            if status_code >= 500:
                self.metrics["api_errors"]["5xx"] += 1
            else:
                self.metrics["api_errors"]["4xx"] += 1

    def record_indicator_lookup(self, duration_ms: float, found: bool) -> None:
        """Record indicator lookup"""
        self.metrics["indicator_lookup_duration_ms"].append(duration_ms)
        if found:
            self.record_cache_hit()
        else:
            self.record_cache_miss()

    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary"""
        return {
            "alerts_total": self.metrics["alerts_created"],
            "alerts_by_severity": self.metrics["alerts_by_severity"],
            "alerts_by_feed": self.metrics["alerts_by_feed"],
            "indicators_total": self.metrics["indicators_added"],
            "indicators_by_type": self.metrics["indicators_by_type"],
            "feed_updates": self.metrics["feed_updates"],
            "feed_errors": self.metrics["feed_errors"],
            "cache_hit_rate": f"{self.get_cache_hit_rate():.2f}%",
            "api_requests_total": self.metrics["api_requests"],
            "api_errors": self.metrics["api_errors"],
            "avg_api_request_ms": self._get_average(
                self.metrics["api_request_duration_ms"]
            ),
            "avg_indicator_lookup_ms": self._get_average(
                self.metrics["indicator_lookup_duration_ms"]
            ),
            "avg_feed_update_ms": self._get_average(
                self.metrics["feed_update_duration_ms"]
            ),
        }

    def _get_average(self, values: list) -> float:
        """Calculate average from list of values"""
        if not values:
            return 0.0
        return sum(values) / len(values)

    def reset(self) -> None:
        """Reset all metrics"""
        for key in self.metrics:
            if isinstance(self.metrics[key], int):
                self.metrics[key] = 0
            elif isinstance(self.metrics[key], dict):
                for subkey in self.metrics[key]:
                    if isinstance(self.metrics[key][subkey], int):
                        self.metrics[key][subkey] = 0
            elif isinstance(self.metrics[key], list):
                self.metrics[key] = []


class PrometheusMetrics:
    """Prometheus-compatible metrics export"""

    def __init__(self, collector: Optional[MetricsCollector] = None):
        """
        Initialize Prometheus metrics.
        
        Args:
            collector: MetricsCollector instance
        """
        self.collector = collector or MetricsCollector()
        try:
            from prometheus_client import Counter, Histogram, Gauge
            self.prometheus_available = True
            
            self.alerts_total = Counter(
                'cig_alerts_total',
                'Total alerts created',
                ['severity', 'feed']
            )
            self.indicators_total = Counter(
                'cig_indicators_total',
                'Total indicators added',
                ['type', 'source']
            )
            self.indicator_lookup_duration = Histogram(
                'cig_indicator_lookup_seconds',
                'Indicator lookup duration',
                buckets=(0.001, 0.01, 0.05, 0.1, 0.5, 1.0)
            )
            self.feed_update_duration = Histogram(
                'cig_feed_update_seconds',
                'Feed update duration',
                ['feed']
            )
            self.cache_hits_total = Counter(
                'cig_cache_hits_total',
                'Total cache hits'
            )
            self.cache_misses_total = Counter(
                'cig_cache_misses_total',
                'Total cache misses'
            )
            self.api_requests_total = Counter(
                'cig_api_requests_total',
                'Total API requests',
                ['method', 'endpoint', 'status']
            )
        except ImportError:
            self.prometheus_available = False

    def record_alert(self, severity: str = "info", feed_source: str = "unknown") -> None:
        """Record alert metric"""
        self.collector.increment_alert(severity, feed_source)
        
        if self.prometheus_available:
            self.alerts_total.labels(severity=severity, feed=feed_source).inc()

    def record_indicator(self, indicator_type: str = "ip", source: str = "unknown") -> None:
        """Record indicator metric"""
        self.collector.increment_indicator(indicator_type)
        
        if self.prometheus_available:
            self.indicators_total.labels(type=indicator_type, source=source).inc()

    def record_feed_update(self, feed_name: str, duration_ms: float,
                          success: bool = True) -> None:
        """Record feed update"""
        self.collector.record_feed_update(feed_name, duration_ms, success)
        
        if self.prometheus_available:
            self.feed_update_duration.labels(feed=feed_name).observe(duration_ms / 1000)

    def record_cache_hit(self) -> None:
        """Record cache hit"""
        self.collector.record_cache_hit()
        if self.prometheus_available:
            self.cache_hits_total.inc()

    def record_cache_miss(self) -> None:
        """Record cache miss"""
        self.collector.record_cache_miss()
        if self.prometheus_available:
            self.cache_misses_total.inc()

    def record_api_request(self, method: str, endpoint: str, status_code: int,
                          duration_ms: float) -> None:
        """Record API request"""
        self.collector.record_api_request(duration_ms, status_code)
        
        if self.prometheus_available:
            self.api_requests_total.labels(
                method=method,
                endpoint=endpoint,
                status=status_code
            ).inc()

    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary"""
        return self.collector.get_summary()
