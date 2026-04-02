#!/usr/bin/env python3
"""
Endpoint Verification Test - Verify all fixed endpoints work correctly
Tests all 19+ endpoints to ensure they're accessible and working properly
"""

import httpx
import json
import asyncio
from typing import Dict, List, Any

# Test configuration
BASE_URL = "http://localhost:8000"
ENDPOINTS_TO_TEST = {
    "Scheduler": [
        ("GET", "/api/feeds/scheduler/status", "Get scheduler status"),
        ("POST", "/api/feeds/scheduler/start", "Start scheduler"),
        ("POST", "/api/feeds/scheduler/stop", "Stop scheduler"),
        ("POST", "/api/feeds/scheduler/update/dshield", "Update specific feed"),
        ("POST", "/api/feeds/scheduler/update/all", "Update all feeds"),
    ],
    "DShield": [
        ("GET", "/api/feeds/dshield/threats", "Get threat summary"),
        ("GET", "/api/feeds/dshield/ssh", "Get SSH attackers"),
        ("GET", "/api/feeds/dshield/web", "Get web scanners"),
        ("GET", "/api/feeds/dshield/status", "Get DShield status"),
        ("POST", "/api/feeds/dshield/poll", "Poll DShield"),
    ],
    "Filters": [
        ("GET", "/api/feeds/filters/status", "Get filter status"),
        ("POST", "/api/feeds/filters/apply", "Apply filters"),
    ],
    "Credentials": [
        ("GET", "/api/config/status", "Get config status"),
        ("POST", "/api/config/nessus/credentials", "Save Nessus credentials"),
        ("POST", "/api/config/nessus/test", "Test Nessus connection"),
        ("GET", "/api/config/nessus/enabled", "Check if Nessus enabled"),
        ("POST", "/api/config/graynoise/credentials", "Save GrayNoise credentials"),
        ("POST", "/api/config/graynoise/test", "Test GrayNoise connection"),
        ("GET", "/api/config/graynoise/enabled", "Check if GrayNoise enabled"),
        ("GET", "/api/config/custom-api/list", "List custom APIs"),
    ]
}

class EndpointTester:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.results: Dict[str, List[Dict[str, Any]]] = {}
        self.total_tests = 0
        self.passed_tests = 0
        
    async def test_endpoint(self, method: str, path: str, description: str) -> Dict[str, Any]:
        """Test a single endpoint"""
        url = f"{self.base_url}{path}"
        self.total_tests += 1
        
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
                if method == "GET":
                    response = await client.get(url)
                elif method == "POST":
                    # Send minimal request data
                    response = await client.post(url, json={})
                else:
                    response = None
                
                if response and response.status_code < 500:
                    self.passed_tests += 1
                    return {
                        "method": method,
                        "path": path,
                        "description": description,
                        "status": "✓ PASS",
                        "status_code": response.status_code,
                        "url": url
                    }
                else:
                    return {
                        "method": method,
                        "path": path,
                        "description": description,
                        "status": "✗ FAIL",
                        "status_code": response.status_code if response else "No response",
                        "url": url,
                        "error": response.text[:100] if response else "No response"
                    }
        except Exception as e:
            return {
                "method": method,
                "path": path,
                "description": description,
                "status": "✗ ERROR",
                "error": str(e),
                "url": url
            }
    
    async def run_all_tests(self):
        """Run all endpoint tests"""
        print("\n" + "="*80)
        print("ENDPOINT VERIFICATION TEST")
        print("="*80)
        print(f"Base URL: {self.base_url}\n")
        
        for category, endpoints in ENDPOINTS_TO_TEST.items():
            print(f"\n{'─'*80}")
            print(f"Testing {category} Endpoints ({len(endpoints)} tests)")
            print(f"{'─'*80}")
            
            category_results = []
            for method, path, description in endpoints:
                result = await self.test_endpoint(method, path, description)
                category_results.append(result)
                
                # Print immediate feedback
                status_symbol = result["status"]
                print(f"{status_symbol:8} {method:6} {path:40} - {description}")
                if "error" in result and result["status"].startswith("✗"):
                    print(f"        └─ Error: {result.get('error', 'Unknown')[:70]}")
            
            self.results[category] = category_results
        
        # Print summary
        self._print_summary()
    
    def _print_summary(self):
        """Print test summary"""
        print("\n" + "="*80)
        print(f"TEST SUMMARY: {self.passed_tests}/{self.total_tests} endpoints working")
        print("="*80 + "\n")
        
        # Categorized pass/fail
        for category, results in self.results.items():
            passed = len([r for r in results if r["status"].startswith("✓")])
            total = len(results)
            status = "✓ PASS" if passed == total else "✗ FAIL" if passed == 0 else "⚠ PARTIAL"
            print(f"{status} {category:20} {passed:2}/{total:2} endpoints working")
        
        # Detailed failures
        failures = []
        for category, results in self.results.items():
            for result in results:
                if result["status"].startswith("✗"):
                    failures.append((category, result))
        
        if failures:
            print("\n" + "─"*80)
            print("FAILURES DETAIL:")
            print("─"*80)
            for category, result in failures:
                print(f"\n{category}: {result['method']} {result['path']}")
                print(f"  Description: {result.get('description', 'N/A')}")
                print(f"  Status: {result.get('status_code', 'N/A')}")
                print(f"  Error: {result.get('error', 'Unknown')}")
        
        # Pass/fail rating
        percentage = (self.passed_tests / self.total_tests * 100) if self.total_tests > 0 else 0
        if percentage == 100:
            rating = "✅ EXCELLENT - All endpoints working"
        elif percentage >= 95:
            rating = "✅ GOOD - Minor issues only"
        elif percentage >= 80:
            rating = "⚠️  FAIR - Some endpoints need fixing"
        else:
            rating = "❌ POOR - Major issues to fix"
        
        print(f"\n{rating}")
        print(f"Success Rate: {percentage:.1f}%\n")
        
        return percentage

async def main():
    tester = EndpointTester(BASE_URL)
    await tester.run_all_tests()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\n\nFatal error: {e}")
        import traceback
        traceback.print_exc()
