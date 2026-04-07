"""
Cyber Intelligence Gateway (CIG)
Main application entry point
"""

import os
import sys
import signal
import logging
import argparse
from pathlib import Path

# Determine project root (repo root)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
LOG_DIR = DATA_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(str(LOG_DIR / "cig.log")),
    ],
)

logger = logging.getLogger(__name__)

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.config import settings
from app.models.database import Database
from app.matching.engine import ThreatMatcher
import uvicorn


# Global instances (for uvicorn direct run and tests)
database: Database = None
threat_matcher: ThreatMatcher = None

# Uvicorn imports at module load
from app.api.routes import app as fastapi_app

# Export the FastAPI app for uvicorn (without initialization)
app = fastapi_app

# Global instances (initialized later)
database: Database = None
threat_matcher: ThreatMatcher = None


def setup_directories():
    """Create necessary directories"""
    Path("data").mkdir(exist_ok=True)
    Path("data/pcaps").mkdir(exist_ok=True)
    Path("data/logs").mkdir(exist_ok=True)
    Path("config").mkdir(exist_ok=True)


def signal_handler(signum, frame):
    """Handle shutdown signals"""
    logger.info("Received shutdown signal, stopping...")
    from app.health_scheduler import stop_health_scheduler

    stop_health_scheduler()
    global threat_matcher
    if threat_matcher:
        threat_matcher.stop()
    sys.exit(0)


def self_heal_from_logs():
    """Scan cig.log for known errors and apply straightforward corrections."""
    log_file = LOG_DIR / "cig.log"
    report = {"checked": False, "issues_found": [], "actions_taken": [], "message": ""}

    if not log_file.exists():
        report["message"] = "No log file found; nothing to heal."
        return report

    report["checked"] = True

    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()[-200:]

    for line in lines:
        if "No module named 'typing.io'" in line:
            report["issues_found"].append("typing.io import error")
            report["actions_taken"].append(
                "MITRE fallback mapping active; no further action required"
            )

        if "database is locked" in line.lower():
            report["issues_found"].append("database locked")
            try:
                import sqlite3

                conn = sqlite3.connect(settings.database_path)
                conn.execute("PRAGMA journal_mode=WAL;")
                conn.execute("VACUUM;")
                conn.commit()
                conn.close()
                report["actions_taken"].append("Performed WAL and VACUUM cleanup")
                logger.info(
                    "Self-heal: performed database WAL/VACUUM to resolve lock conditions"
                )
            except Exception as e:
                report["actions_taken"].append(f"Failed to perform DB cleanup: {e}")
                logger.warning(f"Self-heal unable to fix database lock: {e}")

        if "failed to fetch news" in line.lower():
            report["issues_found"].append("news fetch failure")
            report["actions_taken"].append(
                "User notified that external network may be unavailable; no automatic fix"
            )

    if not report["issues_found"]:
        report["message"] = "No auto-fixable issues found; system is healthy."
    else:
        report["message"] = "Self-heal scan completed."

    return report


# Global instances are initialized above


def main():
    """Main entry point"""
    global database, threat_matcher

    parser = argparse.ArgumentParser(description="Cyber Intelligence Gateway")
    parser.add_argument("--host", default=settings.api_host, help="API host")
    parser.add_argument("--port", type=int, default=settings.api_port, help="API port")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument(
        "--no-capture", action="store_true", help="Disable PCAP capture"
    )
    parser.add_argument("--config", help="Config file path")
    args = parser.parse_args()

    # Setup
    setup_directories()
    logger.info("Starting Cyber Intelligence Gateway...")

    # Initialize database and threat matcher
    logger.info("Initializing database...")
    database = Database(settings.database_path)
    logger.info(f"Database initialized: {settings.database_path}")

    logger.info("Initializing threat matcher...")
    threat_matcher = ThreatMatcher(database)
    logger.info("Threat matcher initialized")

    # Initialize Feed Scheduler
    logger.info("Initializing feed scheduler...")
    from app.scheduling.feed_scheduler import FeedScheduler, FeedPriority
    from app.feeds.dshield_polling import poll_dshield_feed

    scheduler = FeedScheduler()

    # Register DShield feed with midnight UTC refresh
    scheduler.register_feed(
        feed_id="dshield",
        feed_name="DShield Honeypot",
        callback=lambda: poll_dshield_feed(database=database),
        update_interval=300,  # 5 minutes for live polling
        priority=FeedPriority.CRITICAL,
        refresh_at_midnight_utc=True,  # Force refresh at midnight UTC
    )
    logger.info("DShield feed registered with scheduler")

    # Initialize Feed Filter Engine
    logger.info("Initializing feed filter engine...")
    from app.feeds.filtering import FeedFilterEngine

    filter_engine = FeedFilterEngine()
    logger.info("Feed filter engine initialized")

    # Initialize Report Ingestion Connector
    logger.info("Initializing report ingestion connector...")
    from app.feeds.report_ingestion import ReportIngestionConnector

    report_ingestion = ReportIngestionConnector(database=database)
    logger.info("Report ingestion connector initialized")

    # Initialize DShield Poller
    logger.info("Initializing DShield poller...")
    from app.feeds.dshield_polling import get_dshield_poller

    dshield_poller = get_dshield_poller(database=database)
    logger.info("DShield poller initialized")

    # Pre-fetch CVE data on startup (lazy load)
    logger.info("Pre-fetching CVE news data...")
    from app.feeds.cve_news import get_cve_feed

    cve_feed = get_cve_feed()
    # Just get summary without fetching - do fetch on-demand
    try:
        cve_summary = cve_feed.get_summary()
        logger.info(
            f"CVE data initialized: {cve_summary.get('year_count', 0)} year_count"
        )
    except Exception as e:
        logger.warning(f"CVE init check failed (will fetch on demand): {e}")

    # Initialize the API routes with the instances
    from app.api.routes import init_app

    init_app(
        database,
        threat_matcher,
        scheduler=scheduler,
        filter_engine=filter_engine,
        dshield_poller=dshield_poller,
        report_ingestion=report_ingestion,
    )
    logger.info("API routes initialized")

    # Start background health scheduler
    from app.health_scheduler import start_health_scheduler

    start_health_scheduler()
    logger.info("Background health scheduler started")

    # Start threat matching engine
    threat_matcher.start()
    logger.info("Threat matching engine started")

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start API server
    logger.info(f"Starting API server on {args.host}:{args.port}")

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_level="info" if not args.debug else "debug",
    )


if __name__ == "__main__":
    main()
