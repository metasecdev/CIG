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
        logging.FileHandler(str(LOG_DIR / "cig.log"))
    ]
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
    global threat_matcher
    if threat_matcher:
        threat_matcher.stop()
    sys.exit(0)


# Global instances are initialized above


def main():
    """Main entry point"""
    global database, threat_matcher

    parser = argparse.ArgumentParser(description="Cyber Intelligence Gateway")
    parser.add_argument("--host", default=settings.api_host, help="API host")
    parser.add_argument("--port", type=int, default=settings.api_port, help="API port")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--no-capture", action="store_true", help="Disable PCAP capture")
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

    # Initialize the API routes with the instances
    from app.api.routes import init_app
    init_app(database, threat_matcher)
    logger.info("API routes initialized")

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
        log_level="info" if not args.debug else "debug"
    )


if __name__ == "__main__":
    main()
