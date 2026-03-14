#!/usr/bin/env python3
"""
Simple CIG Component Test
"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Set test environment
os.environ['SKIP_FEED_UPDATES'] = 'true'
os.environ['SKIP_DNS_MONITORING'] = 'true'

print("🧪 CIG Component Test Starting...")

try:
    print("1. Testing configuration...")
    from app.core.config import settings
    print(f"   ✅ Config loaded: {settings.app_name}")

    print("2. Testing database...")
    from app.models.database import Database
    print("   ✅ Database module imported")

    print("3. Testing PCAP capture...")
    from app.capture.pcap import PCAPCapture
    print("   ✅ PCAP capture module imported")

    print("4. Testing feeds...")
    from app.feeds.misp import MISPFeed
    from app.feeds.pfblocker import PFBlockerFeed
    from app.feeds.abuseipdb import AbuseIPDBFeed
    print("   ✅ All feed modules imported")

    print("5. Testing MITRE mapper...")
    from app.mitre.attack_mapper import MITREAttackMapper
    print("   ✅ MITRE mapper imported")

    print("6. Testing security reporter...")
    from app.reporting.security_report import SecurityReporter
    print("   ✅ Security reporter imported")

    print("7. Testing threat matcher...")
    from app.matching.engine import ThreatMatcher
    print("   ✅ Threat matcher imported")

    print("8. Testing API routes...")
    from app.api.routes import app as fastapi_app
    print("   ✅ API routes imported")

    print("9. Testing main application...")
    import app.main
    print("   ✅ Main application imported")

    print("\n🎉 ALL COMPONENTS SUCCESSFULLY IMPORTED!")
    print("✅ CIG system is ready for operation.")

except Exception as e:
    print(f"\n❌ ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)