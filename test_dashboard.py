#!/usr/bin/env python3
"""
Test script to verify the CIG dashboard is working
"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    print("Testing CIG dashboard import...")
    from app.main import app
    print("✅ SUCCESS: App imported successfully")
    print(f"   App type: {type(app)}")
    print(f"   App title: {getattr(app, 'title', 'No title')}")

    # Test that routes are registered
    routes = [route.path for route in app.routes]
    print(f"   Routes registered: {len(routes)}")
    print("   Dashboard routes:")
    dashboard_routes = [r for r in routes if r.startswith('/') and not r.startswith('/api/') and r != '/openapi.json' and r != '/docs' and r != '/redoc']
    for route in sorted(dashboard_routes):
        print(f"     - {route}")

    print("\n🎉 Dashboard is ready! Start with:")
    print("   python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000")
    print("\nNote: The full system (database, threat matcher) will initialize when the server starts.")

except Exception as e:
    print(f"❌ ERROR: {str(e)}")
    import traceback
    traceback.print_exc()
    sys.exit(1)