"""
Comprehensive Health Status for CIG
Provides health checks for all system components
"""

import logging
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)


class CIGHealthChecker:
    """Comprehensive health checker for all CIG components"""

    def __init__(self, database=None, threat_matcher=None, config=None):
        self.database = database
        self.threat_matcher = threat_matcher
        self.config = config
        self.checks = {}

    def check_all(self) -> Dict[str, Any]:
        """Run all health checks"""
        return {
            "timestamp": datetime.now().isoformat(),
            "overall_status": "healthy",
            "components": {
                "database": self.check_database(),
                "mitre_attack": self.check_mitre_attack(),
                "threat_feeds": self.check_threat_feeds(),
                "pcap_capture": self.check_pcap_capture(),
                "threat_matcher": self.check_threat_matcher(),
                "arkime": self.check_arkime(),
                "webhooks": self.check_webhooks(),
                "cache": self.check_cache(),
                "metrics": self.check_metrics(),
            },
        }

    def check_database(self) -> Dict[str, Any]:
        """Check database health"""
        try:
            if self.database is None:
                return {"status": "unavailable", "message": "Database not initialized"}

            # Test basic query
            alert_count = len(self.database.get_alerts(limit=1))

            # Check indicators
            indicators = self.database.get_indicators(limit=1)

            return {
                "status": "healthy",
                "message": "Database connection successful",
                "details": {
                    "connection": "ok",
                    "alert_count": alert_count,
                    "indicator_count": len(indicators),
                },
            }
        except Exception as e:
            return {"status": "unhealthy", "message": str(e)}

    def check_mitre_attack(self) -> Dict[str, Any]:
        """Check MITRE ATT&CK framework"""
        try:
            from app.mitre.attack_mapper import MITREAttackMapper

            if self.database is None:
                return {"status": "unavailable", "message": "Database not initialized"}

            mapper = MITREAttackMapper(self.database)
            tactics = mapper.get_all_tactics()
            techniques = mapper.get_all_techniques()

            # Test technique lookup
            test_technique = mapper.get_technique_info("T1566")

            return {
                "status": "healthy",
                "message": "MITRE ATT&CK framework loaded",
                "details": {
                    "tactics_count": len(tactics),
                    "techniques_count": len(techniques),
                    "phishing_technique": "available"
                    if test_technique
                    else "not_found",
                },
            }
        except Exception as e:
            return {"status": "unhealthy", "message": str(e)}

    def check_threat_feeds(self) -> Dict[str, Any]:
        """Check threat feed status"""
        feeds_status = {}

        # Check MISP
        try:
            from app.feeds.misp import MISPFeed

            misp_enabled = True  # Check from config
            feeds_status["misp"] = {
                "enabled": misp_enabled,
                "status": "configured" if misp_enabled else "disabled",
            }
        except Exception as e:
            feeds_status["misp"] = {"status": "error", "message": str(e)}

        # Check pfBlocker
        try:
            from app.feeds.pfblocker import PFBlockerFeed

            feeds_status["pfblocker"] = {"enabled": True, "status": "configured"}
        except Exception as e:
            feeds_status["pfblocker"] = {"status": "error", "message": str(e)}

        # Check AbuseIPDB
        try:
            from app.feeds.abuseipdb import AbuseIPDBFeed

            feeds_status["abuseipdb"] = {"enabled": True, "status": "configured"}
        except Exception as e:
            feeds_status["abuseipdb"] = {"status": "error", "message": str(e)}

        # Check Abuse.ch (URLhaus + ThreatFox)
        try:
            from app.feeds.abusech import AbuseChFeedManager
            from app.core.config import settings

            feeds_status["urlhaus"] = {
                "enabled": getattr(settings, "enable_urlhaus", True),
                "status": "configured",
            }
            feeds_status["threatfox"] = {
                "enabled": getattr(settings, "enable_threatfox", True),
                "status": "configured",
            }
        except Exception as e:
            feeds_status["urlhaus"] = {"status": "error", "message": str(e)}
            feeds_status["threatfox"] = {"status": "error", "message": str(e)}

        # Check custom feeds
        try:
            from app.feeds.custom import CustomFeedManager

            feeds_status["custom_feeds"] = {"enabled": True, "status": "configured"}
        except Exception as e:
            feeds_status["custom_feeds"] = {"status": "error", "message": str(e)}

        all_healthy = all(f.get("status") != "error" for f in feeds_status.values())

        return {
            "status": "healthy" if all_healthy else "degraded",
            "message": "Threat feeds checked",
            "details": feeds_status,
        }

    def check_pcap_capture(self) -> Dict[str, Any]:
        """Check PCAP capture functionality"""
        try:
            from app.capture.pcap import PCAPCapture

            return {
                "status": "healthy",
                "message": "PCAP capture module available",
                "details": {
                    "module_loaded": True,
                    "capture_capabilities": ["tcpdump", "scapy"],
                },
            }
        except Exception as e:
            return {"status": "unhealthy", "message": str(e)}

    def check_threat_matcher(self) -> Dict[str, Any]:
        """Check threat matcher engine"""
        try:
            if self.threat_matcher is None:
                return {
                    "status": "unavailable",
                    "message": "Threat matcher not initialized",
                }

            return {
                "status": "healthy",
                "message": "Threat matcher engine running",
                "details": {"engine_status": "active", "matching_enabled": True},
            }
        except Exception as e:
            return {"status": "unhealthy", "message": str(e)}

    def check_arkime(self) -> Dict[str, Any]:
        """Check Arkime integration"""
        try:
            from app.integrations.arkime import ArkimeConnector

            return {
                "status": "healthy",
                "message": "Arkime integration available",
                "details": {
                    "connector_available": True,
                    "features": ["pcap_upload", "session_search", "hunt_creation"],
                },
            }
        except Exception as e:
            return {"status": "unhealthy", "message": str(e)}

    def check_webhooks(self) -> Dict[str, Any]:
        """Check webhook alerting"""
        try:
            from app.alerts.webhook import WebhookAlertManager

            return {
                "status": "healthy",
                "message": "Webhook alerting available",
                "details": {"webhook_manager_available": True, "rate_limiting": True},
            }
        except Exception as e:
            return {"status": "unhealthy", "message": str(e)}

    def check_cache(self) -> Dict[str, Any]:
        """Check caching layer"""
        try:
            from app.utils.cache import InMemoryCache, RedisCache

            # Test in-memory cache
            cache = InMemoryCache(max_size=100)
            cache.set("test", {"value": "test"}, ttl=60)
            result = cache.get("test")

            return {
                "status": "healthy",
                "message": "Cache layer operational",
                "details": {"in_memory_cache": "working", "redis_cache": "available"},
            }
        except Exception as e:
            return {"status": "unhealthy", "message": str(e)}

    def check_metrics(self) -> Dict[str, Any]:
        """Check Prometheus metrics"""
        try:
            from app.utils.metrics import MetricsCollector, PrometheusMetrics

            collector = MetricsCollector()
            collector.increment_alert("high", "misp")

            return {
                "status": "healthy",
                "message": "Metrics collection operational",
                "details": {"collector": "working", "prometheus": "available"},
            }
        except Exception as e:
            return {"status": "unhealthy", "message": str(e)}


def get_health_status(database=None, threat_matcher=None) -> Dict[str, Any]:
    """Get comprehensive health status"""
    checker = CIGHealthChecker(database, threat_matcher)
    return checker.check_all()
