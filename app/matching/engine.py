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
from app.capture.pcap import PCAPCapture, DNSQueryMonitor, PacketAnalyzer
from app.core.config import settings
import uuid

logger = logging.getLogger(__name__)


class ThreatMatcher:
    """Main threat matching engine"""

    def __init__(self, db: Database):
        self.db = db
        self.misp_feed = MISPFeed(db)
        self.pfblocker_feed = PFBlockerFeed(db)
        self.pcap_capture = PCAPCapture(db)
        self.dns_monitor = DNSQueryMonitor(db)
        self.packet_analyzer = PacketAnalyzer(db)

        self.running = False
        self.update_thread: Optional[threading.Thread] = None

        # Statistics
        self.stats = {
            "misp_indicators": 0,
            "pfblocker_indicators": 0,
            "total_alerts": 0,
            "last_misp_update": None,
            "last_pfblocker_update": None
        }

    def configure(self) -> None:
        """Configure all feed integrations"""
        # Configure MISP
        if settings.misp_url and settings.misp_api_key:
            self.misp_feed.configure(
                settings.misp_url,
                settings.misp_api_key,
                settings.misp_verify_ssl
            )
            logger.info(f"Configured MISP: {settings.misp_url}")

        # Configure pfBlocker
        if settings.pfblocker_feeds:
            self.pfblocker_feed.enabled = True
            logger.info(f"Configured pfBlocker with {len(settings.pfblocker_feeds)} feeds")

    def start(self) -> None:
        """Start the threat matching engine"""
        if self.running:
            logger.warning("Threat matcher already running")
            return

        self.running = True
        self.configure()

        # Start initial feed updates
        self._update_feeds()

        # Start background feed update thread
        self.update_thread = threading.Thread(target=self._feed_update_loop, daemon=True)
        self.update_thread.start()

        # Start DNS monitoring
        if settings.match_dns_queries:
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
                    if not last or (datetime.utcnow() - last).total_seconds() > settings.misp_update_interval:
                        self._update_misp()

                # Update pfBlocker if interval passed
                if self.pfblocker_feed.is_enabled():
                    last = self.pfblocker_feed.last_update
                    if not last or (datetime.utcnow() - last).total_seconds() > settings.pfblocker_update_interval:
                        self._update_pfblocker()

            except Exception as e:
                logger.error(f"Error in feed update loop: {e}")

    def _update_feeds(self) -> None:
        """Update all feeds"""
        self._update_misp()
        self._update_pfblocker()
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

    def _load_local_blocklist(self) -> int:
        """Load local blocklist"""
        try:
            return self.pfblocker_feed.load_local_blocklist(settings.pfblocker_local_blocklist)
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
                message=f"Connection to blocked IP: {ip}"
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
            "active_captures": self.pcap_capture.get_active_captures(),
            "stats": self.stats,
            "indicator_counts": self.db.get_indicator_counts()
        }
