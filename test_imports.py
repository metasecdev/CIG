#!/usr/bin/env python3
"""
Test script to verify CIG application imports and basic functionality
"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Set environment variables for testing
os.environ['SKIP_FEED_UPDATES'] = 'true'
os.environ['SKIP_DNS_MONITORING'] = 'true'

try:
    # Test core imports
    from app.core.config import settings
    print("✓ Config imported successfully")
    print(f"  App name: {settings.app_name}")
    print(f"  Database path: {settings.database_path}")
    print(f"  Skip feed updates: {settings.skip_feed_updates}")

    from app.models.database import Database
    print("✓ Database imported successfully")

    from app.matching.engine import ThreatMatcher
    print("✓ ThreatMatcher imported successfully")

    from app.api.routes import app as fastapi_app
    print("✓ API app imported successfully")

    # Test new modules
    from app.mitre.attack_mapper import AttackMapper
    print("✓ MITRE AttackMapper imported successfully")

    from app.feeds.abuseipdb import AbuseIPDBFeed
    print("✓ AbuseIPDB feed imported successfully")

    from app.reporting.security_report import SecurityReporter
    print("✓ Security reporter imported successfully")

    print("\n🎉 All imports successful! CIG system components are ready.")

    # Test basic initialization
    print("\nTesting basic initialization...")
    db = Database(settings.database_path)
    print("✓ Database initialized")

    matcher = ThreatMatcher(db)
    print("✓ ThreatMatcher initialized")

    print("\n✅ CIG system is ready for operation!")

except ImportError as e:
    print(f"❌ Import error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)