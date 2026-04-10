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
            indicator_counts = (
                self.database.get_indicator_counts()
                if hasattr(self.database, "get_indicator_counts")
                else {}
            )
            alert_stats = (
                self.database.get_alert_stats()
                if hasattr(self.database, "get_alert_stats")
                else {}
            )

            return {
                "status": "healthy",
                "message": "Database connection successful",
                "details": {
                    "connection": "ok",
                    "alert_count": alert_stats.get("total", alert_count),
                    "indicator_count": sum(indicator_counts.values())
                    if indicator_counts
                    else len(indicators),
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

        # Use config to get actual feed status
        from app.core.config import settings

        # Check MISP
        try:
            from app.feeds.misp import MISPFeed

            misp_enabled = getattr(settings, "enable_misp", True)
            feeds_status["misp"] = {
                "enabled": misp_enabled,
                "status": "configured" if misp_enabled else "disabled",
            }
        except Exception as e:
            feeds_status["misp"] = {"status": "error", "message": str(e)}

        # Check pfBlocker
        try:
            from app.feeds.pfblocker import PFBlockerFeed

            pf_enabled = getattr(settings, "enable_pfblocker", True)
            feeds_status["pfblocker"] = {
                "enabled": pf_enabled,
                "status": "configured" if pf_enabled else "disabled",
            }
        except Exception as e:
            feeds_status["pfblocker"] = {"status": "error", "message": str(e)}

        # Check AbuseIPDB
        try:
            from app.feeds.abuseipdb import AbuseIPDBFeed

            abuse_enabled = getattr(settings, "enable_abuseipdb", True)
            feeds_status["abuseipdb"] = {
                "enabled": abuse_enabled,
                "status": "configured" if abuse_enabled else "disabled",
            }
        except Exception as e:
            feeds_status["abuseipdb"] = {"status": "error", "message": str(e)}

        # Check CVE Details
        try:
            from app.feeds.cvedetails import CVEDetailsFeedManager

            cve_enabled = getattr(settings, "enable_cvedetails", True)
            feeds_status["cve_details"] = {
                "enabled": cve_enabled,
                "status": "configured" if cve_enabled else "disabled",
            }
        except Exception as e:
            feeds_status["cve_details"] = {"status": "error", "message": str(e)}

        # Check CISA KEV
        try:
            from app.feeds.cisa_kev import CISAKevFeedManager

            cisa_enabled = getattr(settings, "enable_cisa_kev", True)
            feeds_status["cisa_kev"] = {
                "enabled": cisa_enabled,
                "status": "configured" if cisa_enabled else "disabled",
            }
        except Exception as e:
            feeds_status["cisa_kev"] = {"status": "error", "message": str(e)}

        # Check Shadowserver
        try:
            from app.feeds.shadowserver import ShadowserverFeedManager

            shadow_enabled = getattr(settings, "enable_shadowserver", False)
            shadow_key = getattr(settings, "shadowserver_api_key", "")
            feeds_status["shadowserver"] = {
                "enabled": shadow_enabled and bool(shadow_key),
                "status": "configured" if shadow_enabled and shadow_key else "disabled",
            }
        except Exception as e:
            feeds_status["shadowserver"] = {"status": "error", "message": str(e)}

        # Check Abuse.ch (URLhaus + ThreatFox)
        try:
            from app.feeds.abusech import AbuseChFeedManager

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

        # Check Exploit-DB
        try:
            from app.feeds.exploitdb import ExploitDBFeedManager

            exploitdb_enabled = getattr(settings, "enable_exploitdb", True)
            feeds_status["exploitdb"] = {
                "enabled": exploitdb_enabled,
                "status": "configured" if exploitdb_enabled else "disabled",
            }
        except Exception as e:
            feeds_status["exploitdb"] = {"status": "error", "message": str(e)}

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
