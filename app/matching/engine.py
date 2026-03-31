"""
Threat Matching Engine
Matches network events against threat intelligence feeds
"""

import logging
import threading
import time
from typing import Optional, Dict, Any, List
from datetime import datetime

from app.models.database import Database, Alert
from app.feeds.misp import MISPFeed
from app.feeds.pfblocker import PFBlockerFeed
from app.feeds.abuseipdb import AbuseIPDBFeed
from app.feeds.abusech import AbuseChFeedManager
from app.feeds.cvedetails import CVEDetailsFeedManager
from app.feeds.cisa_kev import CISAKevFeedManager
from app.feeds.shadowserver import ShadowserverFeedManager
from app.feeds.cve_news import CVENewsFeed
from app.feeds.sans_isc import SANSISCFeedManager
from app.capture.pcap import PCAPCapture, DNSQueryMonitor, PacketAnalyzer
from app.mitre.attack_mapper import MITREAttackMapper
from app.reporting.security_report import SecurityReporter
from app.core.config import settings
import uuid

logger = logging.getLogger(__name__)


class ThreatMatcher:
    """Main threat matching engine"""

    def __init__(self, db: Database):
        self.db = db
        self.misp_feed = MISPFeed(db)
        self.pfblocker_feed = PFBlockerFeed(db)
        self.abuseipdb_feed = AbuseIPDBFeed(db)
        self.abusech_feeds = AbuseChFeedManager(db)
        self.cvedetails_feed = CVEDetailsFeedManager(db)
        self.cisa_kev_feed = CISAKevFeedManager(db)
        self.shadowserver_feed = ShadowserverFeedManager(db)
        self.cve_news_feed = CVENewsFeed(db)
        self.sans_isc_feed = SANSISCFeedManager(db)
        self.pcap_capture = PCAPCapture(db)
        self.dns_monitor = DNSQueryMonitor(db)
        self.packet_analyzer = PacketAnalyzer(db)
        self.mitre_mapper = MITREAttackMapper(db)
        self.reporter = SecurityReporter(db)

        self.running = False
        self.update_thread: Optional[threading.Thread] = None

        # Statistics
        self.stats = {
            "misp_indicators": 0,
            "pfblocker_indicators": 0,
            "abuseipdb_indicators": 0,
            "urlhaus_indicators": 0,
            "threatfox_indicators": 0,
            "cvedetails_indicators": 0,
            "cisa_kev_indicators": 0,
            "shadowserver_indicators": 0,
            "cve_news_count": 0,
            "sans_isc_indicators": 0,
            "total_alerts": 0,
            "last_misp_update": None,
            "last_pfblocker_update": None,
            "last_abuseipdb_update": None,
            "last_urlhaus_update": None,
            "last_threatfox_update": None,
            "last_cvedetails_update": None,
            "last_cisa_kev_update": None,
            "last_shadowserver_update": None,
            "last_cve_news_update": None,
            "last_sans_isc_update": None,
        }

    def configure(self) -> None:
        """Configure all feed integrations"""
        # Configure MISP
        if settings.misp_url and settings.misp_api_key:
            self.misp_feed.configure(
                settings.misp_url, settings.misp_api_key, settings.misp_verify_ssl
            )
            logger.info(f"Configured MISP: {settings.misp_url}")

        # Configure pfBlocker
        if settings.pfblocker_feeds:
            self.pfblocker_feed.enabled = True
            logger.info(
                f"Configured pfBlocker with {len(settings.pfblocker_feeds)} feeds"
            )

        # Configure AbuseIPDB
        abuseipdb_key = getattr(settings, "abuseipdb_api_key", "")
        if abuseipdb_key:
            self.abuseipdb_feed.configure(abuseipdb_key)
            logger.info("Configured AbuseIPDB feed")

        # Configure Abuse.ch feeds (URLhaus + ThreatFox)
        abusech_key = getattr(settings, "abusech_api_key", "")
        if abusech_key and getattr(settings, "abusech_enabled", False):
            self.abusech_feeds.configure(
                api_key=abusech_key,
                enable_urlhaus=getattr(settings, "enable_urlhaus", True),
                enable_threatfox=getattr(settings, "enable_threatfox", True),
            )
            logger.info("Configured Abuse.ch feeds (URLhaus + ThreatFox)")

        # Configure CVE Details
        self.cvedetails_feed.configure(
            enabled=getattr(settings, "enable_cvedetails", True),
            update_interval=getattr(settings, "cvedetails_update_interval", 3600),
        )
        logger.info("Configured CVE Details feed")

        # Configure CISA KEV
        self.cisa_kev_feed.configure(
            enabled=getattr(settings, "enable_cisa_kev", True),
            update_interval=getattr(settings, "cisa_kev_update_interval", 86400),
        )
        logger.info("Configured CISA KEV feed")

        # Configure Shadowserver
        shadowserver_key = getattr(settings, "shadowserver_api_key", "")
        if shadowserver_key and getattr(settings, "enable_shadowserver", False):
            self.shadowserver_feed.configure(
                api_key=shadowserver_key,
                enabled=True,
                update_interval=getattr(
                    settings, "shadowserver_update_interval", 86400
                ),
            )
            logger.info("Configured Shadowserver feed")

        # Configure CVE News
        self.cve_news_feed = CVENewsFeed(self.db)
        logger.info("Configured CVE News feed (10-minute updates)")

        # Configure SANS ISC
        self.sans_isc_feed.configure(
            enabled=getattr(settings, "enable_sans_isc", True),
            update_interval=getattr(settings, "sans_isc_update_interval", 3600),
            api_key=getattr(settings, "sans_api_key", ""),
        )
        logger.info("Configured SANS ISC feed")

    def start(self) -> None:
        """Start the threat matching engine"""
        if self.running:
            logger.warning("Threat matcher already running")
            return

        self.running = True
        self.configure()

        # Start initial feed updates in background thread
        update_thread = threading.Thread(target=self._update_feeds, daemon=True)
        update_thread.start()

        # Start background feed update thread
        self.update_thread = threading.Thread(
            target=self._feed_update_loop, daemon=True
        )
        self.update_thread.start()

        # Start DNS monitoring
        if settings.match_dns_queries and not settings.skip_dns_monitoring:
            self.dns_monitor.start_monitoring()

        logger.info("Threat matching engine started")

    def stop(self) -> None:
        """Stop the threat matching engine"""
        self.running = False
        self.dns_monitor.stop_monitoring()
        self.pcap_capture.stop_all_captures()
        logger.info("Threat matching engine stopped")

    def _feed_update_loop(self) -> None:
        """Background loop for periodic feed updates"""
        while self.running:
            try:
                time.sleep(60)  # Check every minute
                if not self.running:
                    break

                # Update MISP if interval passed
                if self.misp_feed.is_enabled():
                    last = self.misp_feed.last_update
                    if (
                        not last
                        or (datetime.utcnow() - last).total_seconds()
                        > settings.misp_update_interval
                    ):
                        self._update_misp()

                # Update pfBlocker if interval passed
                if self.pfblocker_feed.is_enabled():
                    last = self.pfblocker_feed.last_update
                    if (
                        not last
                        or (datetime.utcnow() - last).total_seconds()
                        > settings.pfblocker_update_interval
                    ):
                        self._update_pfblocker()

                # Update AbuseIPDB if interval passed (daily)
                if self.abuseipdb_feed.is_enabled():
                    last = self.abuseipdb_feed.last_update
                    if (
                        not last or (datetime.utcnow() - last).total_seconds() > 86400
                    ):  # 24 hours
                        self._update_abuseipdb()

            except Exception as e:
                logger.error(f"Error in feed update loop: {e}")

    def _update_feeds(self) -> None:
        """Update all feeds"""
        if settings.skip_feed_updates:
            logger.info("Skipping feed updates (SKIP_FEED_UPDATES=true)")
            return

        self._update_misp()
        self._update_pfblocker()
        self._update_abuseipdb()
        self._update_cvedetails()
        self._update_cisa_kev()
        self._update_shadowserver()
        self._update_cve_news()
        self._update_sans_isc()
        self._load_local_blocklist()
        self._cleanup_old_alerts()

    def _update_misp(self) -> int:
        """Update MISP indicators"""
        if not self.misp_feed.is_enabled():
            return 0

        try:
            count = self.misp_feed.fetch_and_process()
            self.stats["misp_indicators"] = count
            self.stats["last_misp_update"] = datetime.utcnow().isoformat()
            logger.info(f"Updated MISP: {count} indicators")
            return count
        except Exception as e:
            logger.error(f"Failed to update MISP: {e}")
            return 0

    def _update_pfblocker(self) -> int:
        """Update pfBlocker indicators"""
        if not self.pfblocker_feed.is_enabled():
            return 0

        try:
            count = self.pfblocker_feed.fetch_from_feeds(settings.pfblocker_feeds)
            self.stats["pfblocker_indicators"] = count
            self.stats["last_pfblocker_update"] = datetime.utcnow().isoformat()
            logger.info(f"Updated pfBlocker: {count} indicators")
            return count
        except Exception as e:
            logger.error(f"Failed to update pfBlocker: {e}")
            return 0

    def _update_abuseipdb(self) -> int:
        """Update AbuseIPDB indicators"""
        if not self.abuseipdb_feed.is_enabled():
            return 0

        try:
            count = self.abuseipdb_feed.fetch_blacklist(confidence_threshold=80)
            self.stats["abuseipdb_indicators"] = count
            self.stats["last_abuseipdb_update"] = datetime.utcnow().isoformat()
            logger.info(f"Updated AbuseIPDB: {count} indicators")
            return count
        except Exception as e:
            logger.error(f"Failed to update AbuseIPDB: {e}")
            return 0

    def _update_cvedetails(self) -> int:
        """Update CVE Details indicators"""
        if not self.cvedetails_feed.is_enabled():
            return 0

        try:
            results = self.cvedetails_feed.update_all()
            count = results.get("cvedetails", 0)
            self.stats["cvedetails_indicators"] = count
            self.stats["last_cvedetails_update"] = datetime.utcnow().isoformat()
            logger.info(f"Updated CVE Details: {count} vulnerabilities")
            return count
        except Exception as e:
            logger.error(f"Failed to update CVE Details: {e}")
            return 0

    def _update_cisa_kev(self) -> int:
        """Update CISA KEV indicators"""
        if not self.cisa_kev_feed.is_enabled():
            return 0

        try:
            results = self.cisa_kev_feed.update_all()
            count = results.get("cisa_kev", 0)
            self.stats["cisa_kev_indicators"] = count
            self.stats["last_cisa_kev_update"] = datetime.utcnow().isoformat()
            logger.info(f"Updated CISA KEV: {count} vulnerabilities")
            return count
        except Exception as e:
            logger.error(f"Failed to update CISA KEV: {e}")
            return 0

    def _update_shadowserver(self) -> int:
        """Update Shadowserver indicators"""
        if not self.shadowserver_feed.is_enabled():
            return 0

        try:
            results = self.shadowserver_feed.update_all()
            count = sum(results.values())
            self.stats["shadowserver_indicators"] = count
            self.stats["last_shadowserver_update"] = datetime.utcnow().isoformat()
            logger.info(f"Updated Shadowserver: {count} indicators")
            return count
        except Exception as e:
            logger.error(f"Failed to update Shadowserver: {e}")
            return 0

    def _update_cve_news(self) -> int:
        """Update CVE News feed"""
        try:
            count = self.cve_news_feed.fetch_high_level_cves(days=7, limit=50)
            self.stats["cve_news_count"] = count
            self.stats["last_cve_news_update"] = datetime.utcnow().isoformat()
            logger.info(f"Updated CVE News: {count} high-level CVEs")
            return count
        except Exception as e:
            logger.error(f"Failed to update CVE News: {e}")
            return 0

    def _update_sans_isc(self) -> int:
        """Update SANS ISC indicators"""
        if not self.sans_isc_feed.is_enabled():
            return 0

        try:
            results = self.sans_isc_feed.update_all()
            count = results.get("sans_isc", 0)
            self.stats["sans_isc_indicators"] = count
            self.stats["last_sans_isc_update"] = datetime.utcnow().isoformat()
            logger.info(f"Updated SANS ISC: {count} indicators")
            return count
        except Exception as e:
            logger.error(f"Failed to update SANS ISC: {e}")
            return 0

    def _load_local_blocklist(self) -> int:
        """Load local blocklist"""
        try:
            return self.pfblocker_feed.load_local_blocklist(
                settings.pfblocker_local_blocklist
            )
        except Exception as e:
            logger.error(f"Failed to load local blocklist: {e}")
            return 0

    def _cleanup_old_alerts(self) -> None:
        """Clean up old alerts based on retention policy"""
        try:
            deleted = self.db.delete_old_alerts(settings.alert_retention_days)
            if deleted > 0:
                logger.info(f"Cleaned up {deleted} old alerts")
        except Exception as e:
            logger.error(f"Failed to cleanup old alerts: {e}")

    def start_lan_capture(self) -> Optional[str]:
        """Start PCAP capture on LAN interface"""
        if not settings.match_pcap_traffic:
            return None
        return self.pcap_capture.start_capture(settings.lan_interface)

    def start_wan_capture(self) -> Optional[str]:
        """Start PCAP capture on WAN interface"""
        if not settings.match_pcap_traffic:
            return None
        return self.pcap_capture.start_capture(settings.wan_interface)

    def pause(self) -> None:
        """Pause the engine and capture activity"""
        if not self.running:
            logger.warning("Threat matcher already paused or stopped")
            return

        self.running = False
        self.dns_monitor.stop_monitoring()
        self.pcap_capture.pause_all_captures()
        logger.info("Threat matcher paused")

    def resume(self) -> None:
        """Resume the engine from pause"""
        if self.running:
            logger.warning("Threat matcher already running")
            return

        self.running = True
        self.dns_monitor.start_monitoring()
        self.pcap_capture.resume_all_captures()
        # restart feed loop thread if not alive
        if not self.update_thread or not self.update_thread.is_alive():
            self.update_thread = threading.Thread(
                target=self._feed_update_loop, daemon=True
            )
            self.update_thread.start()

        logger.info("Threat matcher resumed")

    def restart(self) -> None:
        """Restart the threat matcher cleanly"""
        self.stop()
        self.start()
        logger.info("Threat matcher restarted")

    def stop_lan_capture(self) -> bool:
        """Stop LAN PCAP capture"""
        return self.pcap_capture.stop_capture(settings.lan_interface)

    def stop_wan_capture(self) -> bool:
        """Stop WAN PCAP capture"""
        return self.pcap_capture.stop_capture(settings.wan_interface)

    def check_domain(self, domain: str) -> Optional[Alert]:
        """Check a domain against indicators"""
        return self.dns_monitor.match_domain(domain)

    def check_ip(self, ip: str) -> Optional[Alert]:
        """Check an IP address against indicators"""
        indicator = self.db.check_indicator(ip, "ip")
        if indicator:
            alert = Alert(
                id=str(uuid.uuid4()),
                timestamp=datetime.utcnow().isoformat(),
                severity="high",
                destination_ip=ip,
                indicator=ip,
                indicator_type="ip",
                feed_source=indicator.source,
                rule_id=indicator.feed_id,
                message=f"Connection to blocked IP: {ip}",
            )
            self.db.insert_alert(alert)
            self.stats["total_alerts"] += 1
            return alert
        return None

    def analyze_pcap(self, pcap_path: str) -> List[Alert]:
        """Analyze a PCAP file"""
        return self.packet_analyzer.analyze_pcap(pcap_path)

    def get_status(self) -> Dict[str, Any]:
        """Get system status"""
        return {
            "running": self.running,
            "misp": self.misp_feed.get_status(),
            "pfblocker": self.pfblocker_feed.get_status(),
            "abuseipdb": self.abuseipdb_feed.get_status(),
            "active_captures": self.pcap_capture.get_active_captures(),
            "stats": self.stats,
            "indicator_counts": self.db.get_indicator_counts(),
        }

    def generate_security_report(self, days: int = 7) -> Dict[str, Any]:
        """Generate a comprehensive security report"""
        return self.reporter.generate_comprehensive_report(days)

    def generate_html_report(self, days: int = 7) -> str:
        """Generate an HTML security report"""
        return self.reporter.generate_html_report(days)

    def analyze_alert_for_mitre(
        self, alert_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze an alert for MITRE ATT&CK TTP matches"""
        return self.mitre_mapper.map_event_to_ttp(alert_data)

    def get_mitre_techniques(self) -> Dict[str, Dict[str, Any]]:
        """Get all loaded MITRE ATT&CK techniques"""
        return self.mitre_mapper.get_all_techniques()

    def get_mitre_tactics(self) -> Dict[str, Dict[str, Any]]:
        """Get all loaded MITRE ATT&CK tactics"""
        return self.mitre_mapper.get_all_tactics()
