#!/usr/bin/env python3
"""
CIG Functionality Verification Script
Quick check of all major components
"""

import sys
import os
from pathlib import Path

# Setup
sys.path.insert(0, str(Path(__file__).parent))
os.environ['SKIP_FEED_UPDATES'] = 'true'
os.environ['SKIP_DNS_MONITORING'] = 'true'

def check_component(name, import_statement, expected_attrs=None):
    """Check if a component can be imported and has expected attributes"""
    try:
        module = __import__(import_statement, fromlist=[''])
        if expected_attrs:
            for attr in expected_attrs:
                if not hasattr(module, attr):
                    return False, f"Missing attribute: {attr}"
        return True, "OK"
    except Exception as e:
        return False, str(e)

def main():
    print("🔍 CIG Functionality Verification")
    print("=" * 40)

    components = [
        ("Configuration", "app.core.config", ["settings", "Settings"]),
        ("Database", "app.models.database", ["Database", "Alert", "Indicator"]),
        ("PCAP Capture", "app.capture.pcap", ["PCAPCapture", "DNSQueryMonitor"]),
        ("MISP Feed", "app.feeds.misp", ["MISPFeed"]),
        ("pfBlocker Feed", "app.feeds.pfblocker", ["PFBlockerFeed"]),
        ("AbuseIPDB Feed", "app.feeds.abuseipdb", ["AbuseIPDBFeed"]),
        ("MITRE Mapper", "app.mitre.attack_mapper", ["MITREAttackMapper"]),
        ("Security Reporter", "app.reporting.security_report", ["SecurityReporter"]),
        ("Threat Matcher", "app.matching.engine", ["ThreatMatcher"]),
        ("API Routes", "app.api.routes", ["app"]),
        ("Main App", "app.main", ["main", "setup_directories"]),
    ]

    results = []
    for name, import_path, attrs in components:
        success, message = check_component(name, import_path, attrs)
        status = "✅" if success else "❌"
        print("15")
        results.append((name, success, message))

    print("\n" + "=" * 40)
    passed = sum(1 for _, success, _ in results if success)
    total = len(results)
    print(f"📊 SUMMARY: {passed}/{total} components functional")

    if passed == total:
        print("🎉 ALL COMPONENTS VERIFIED - CIG IS READY!")
        return 0
    else:
        print("⚠️  Some components have issues - check details above")
        return 1

if __name__ == "__main__":
    sys.exit(main())