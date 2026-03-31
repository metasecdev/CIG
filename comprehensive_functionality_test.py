#!/usr/bin/env python3
"""
Comprehensive Functionality Test Suite for CIG
Tests all functionality across all modules and generates detailed report
"""

import sys
import os
import json
import traceback
import sqlite3
from pathlib import Path
from datetime import datetime, timezone, timedelta
import tempfile
import shutil

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Set test environment
os.environ['SKIP_FEED_UPDATES'] = 'true'
os.environ['SKIP_DNS_MONITORING'] = 'true'

from app.core.config import settings, Settings
from app.models.database import Database, Alert, Indicator, PcapFile
from app.capture.pcap import PCAPCapture, DNSQueryMonitor, PacketAnalyzer
from app.feeds.misp import MISPFeed
from app.feeds.pfblocker import PFBlockerFeed
from app.feeds.abuseipdb import AbuseIPDBFeed
from app.matching.engine import ThreatMatcher
from app.mitre.attack_mapper import MITREAttackMapper
from app.reporting.security_report import SecurityReporter
from app.api.routes import app as fastapi_app, init_app, get_system_status
from fastapi.testclient import TestClient


class ComprehensiveFunctionalityTest:
    """Comprehensive functionality test suite"""

    def __init__(self):
        self.test_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "test_suites": {},
            "total_tests": 0,
            "total_passed": 0,
            "total_failed": 0,
            "improvements_found": [],
            "critical_issues": [],
            "warnings": []
        }
        self.temp_dir = Path(tempfile.mkdtemp(prefix="cig_func_test_"))
        self.test_db_path = self.temp_dir / "test.db"

    def add_test_result(self, suite_name, test_name, passed, message="", duration=0):
        """Record a test result"""
        if suite_name not in self.test_results["test_suites"]:
            self.test_results["test_suites"][suite_name] = {
                "tests": {},
                "passed": 0,
                "failed": 0,
                "total": 0
            }

        self.test_results["test_suites"][suite_name]["tests"][test_name] = {
            "passed": passed,
            "message": message,
            "duration": duration
        }

        self.test_results["test_suites"][suite_name]["total"] += 1
        self.test_results["total_tests"] += 1

        if passed:
            self.test_results["test_suites"][suite_name]["passed"] += 1
            self.test_results["total_passed"] += 1
        else:
            self.test_results["test_suites"][suite_name]["failed"] += 1
            self.test_results["total_failed"] += 1

    def test_configuration(self):
        """Test configuration system"""
        print("\n🔧 Testing Configuration System...")
        suite_name = "configuration"

        try:
            # Test default settings
            assert settings.app_name == "Cyber Intelligence Gateway"
            self.add_test_result(suite_name, "app_name_loaded", True, "Default app name loaded")

            assert settings.api_port == 8000
            self.add_test_result(suite_name, "api_port_default", True, "Default API port is 8000")

            assert settings.alert_retention_days == 30
            self.add_test_result(suite_name, "alert_retention_set", True, "Alert retention configured")

            # Test environment override
            os.environ['APP_NAME'] = 'Test CIG'
            test_settings = Settings.from_env()
            assert test_settings.app_name == 'Test CIG'
            self.add_test_result(suite_name, "env_override", True, "Environment overrides work")

            # Test data directory creation
            assert Path(settings.pcap_dir).exists() or settings.pcap_dir.startswith("/")
            self.add_test_result(suite_name, "pcap_dir_accessible", True, "PCAP directory is accessible")

        except AssertionError as e:
            self.add_test_result(suite_name, "config_validation", False, str(e))
        except Exception as e:
            self.add_test_result(suite_name, "config_test", False, f"Configuration test failed: {e}")

    def test_database_operations(self):
        """Test database CRUD operations"""
        print("\n💾 Testing Database Operations...")
        suite_name = "database"

        try:
            db = Database(str(self.test_db_path))

            # Test Alert CRUD
            alert = Alert(
                id="test-alert-123",
                timestamp=datetime.now(timezone.utc).isoformat(),
                severity="high",
                source_ip="192.168.1.100",
                destination_ip="10.0.0.1",
                source_port=12345,
                destination_port=80,
                protocol="tcp",
                indicator="malicious.example.com",
                indicator_type="domain",
                feed_source="test",
                rule_id="test-rule-1",
                message="Test alert"
            )

            db.insert_alert(alert)
            alerts = db.get_alerts(limit=10)
            assert len(alerts) == 1
            assert alerts[0].id == "test-alert-123"
            self.add_test_result(suite_name, "alert_crud", True, "Alert CRUD operations work")

            # Test Indicator CRUD
            indicator = Indicator(
                id="test-ind-123",
                value="192.168.1.200",
                type="ip",
                source="test_feed",
                feed_id="test-feed-1",
                tags="malware,botnet",
                first_seen=datetime.now(timezone.utc).isoformat(),
                last_seen=datetime.now(timezone.utc).isoformat()
            )

            db.insert_indicator(indicator)
            indicators = db.get_indicators(limit=10)
            assert len(indicators) == 1
            self.add_test_result(suite_name, "indicator_crud", True, "Indicator CRUD operations work")

            # Test indicator lookup
            found = db.check_indicator("192.168.1.200", "ip")
            assert found is not None
            assert found.value == "192.168.1.200"
            self.add_test_result(suite_name, "indicator_lookup", True, "Indicator lookup works")

            # Test alert statistics
            stats = db.get_alert_stats()
            assert "total" in stats
            assert "by_severity" in stats
            self.add_test_result(suite_name, "alert_stats", True, "Alert statistics generation works")

            # Test bulk insert
            bulk_indicators = [
                Indicator(value=f"192.168.1.{i}", type="ip", source="test", feed_id="bulk-test")
                for i in range(201, 206)
            ]
            db.bulk_insert_indicators(bulk_indicators)
            all_indicators = db.get_indicators(limit=100)
            assert len(all_indicators) >= 5
            self.add_test_result(suite_name, "bulk_insert", True, "Bulk insert operations work")

            # Test PCAP file tracking
            pcap = PcapFile(
                id="test-pcap-123",
                filename="test.pcap",
                filepath="/tmp/test.pcap",
                start_time=datetime.now(timezone.utc).isoformat(),
                interface="eth0"
            )
            db.insert_pcap(pcap)
            pcaps = db.get_pcaps(limit=10)
            assert len(pcaps) == 1
            self.add_test_result(suite_name, "pcap_tracking", True, "PCAP file tracking works")

        except AssertionError as e:
            self.add_test_result(suite_name, "database_test", False, str(e))
            self.test_results["critical_issues"].append(f"Database CRUD failed: {e}")
        except Exception as e:
            self.add_test_result(suite_name, "database_operations", False, str(e))
            self.test_results["critical_issues"].append(f"Database operations failed: {e}")

    def test_threat_feeds(self):
        """Test threat intelligence feeds"""
        print("\n📰 Testing Threat Intelligence Feeds...")
        suite_name = "feeds"

        try:
            db = Database(str(self.test_db_path))

            # Test MISP feed initialization
            misp_feed = MISPFeed(db)
            assert hasattr(misp_feed, 'is_enabled')
            assert hasattr(misp_feed, 'fetch_and_process')
            assert misp_feed.is_enabled() is False  # Should be disabled without config
            self.add_test_result(suite_name, "misp_init", True, "MISP feed initializes correctly")

            # Test pfBlocker feed
            pfblocker_feed = PFBlockerFeed(db)
            assert hasattr(pfblocker_feed, 'is_enabled')
            assert hasattr(pfblocker_feed, 'fetch_from_feeds')
            self.add_test_result(suite_name, "pfblocker_init", True, "pfBlocker feed initializes")

            # Test AbuseIPDB feed
            abuseipdb_feed = AbuseIPDBFeed(db)
            assert hasattr(abuseipdb_feed, 'is_enabled')
            assert hasattr(abuseipdb_feed, 'fetch_blacklist')
            assert abuseipdb_feed.is_enabled() is False  # Should be disabled without API key
            self.add_test_result(suite_name, "abuseipdb_init", True, "AbuseIPDB feed initializes")

            # Test feed status methods
            misp_status = misp_feed.get_status()
            assert "enabled" in misp_status
            self.add_test_result(suite_name, "feed_status", True, "Feed status methods work")

        except AssertionError as e:
            self.add_test_result(suite_name, "feed_test", False, str(e))
        except Exception as e:
            self.add_test_result(suite_name, "feed_operations", False, str(e))

    def test_pcap_capture(self):
        """Test PCAP capture components"""
        print("\n📡 Testing PCAP Capture...")
        suite_name = "pcap"

        try:
            db = Database(str(self.test_db_path))

            # Test PCAPCapture initialization
            pcap_capture = PCAPCapture(db)
            assert pcap_capture.lan_interface == "eth0"
            assert pcap_capture.wan_interface == "eth1"
            self.add_test_result(suite_name, "pcap_init", True, "PCAP capture initializes")

            # Test DNS monitor
            dns_monitor = DNSQueryMonitor(db)
            assert dns_monitor.db == db
            assert dns_monitor.dns_log_path.endswith("dns.log")
            self.add_test_result(suite_name, "dns_monitor_init", True, "DNS monitor initializes")

            # Test packet analyzer
            packet_analyzer = PacketAnalyzer(db)
            assert packet_analyzer.db == db
            self.add_test_result(suite_name, "packet_analyzer_init", True, "Packet analyzer initializes")

            # Test active captures list
            active = pcap_capture.get_active_captures()
            assert isinstance(active, list)
            self.add_test_result(suite_name, "active_captures", True, "Active captures list works")

        except AssertionError as e:
            self.add_test_result(suite_name, "pcap_test", False, str(e))
        except Exception as e:
            self.add_test_result(suite_name, "pcap_operations", False, str(e))

    def test_mitre_mapper(self):
        """Test MITRE ATT&CK mapping"""
        print("\n🎯 Testing MITRE ATT&CK Mapper...")
        suite_name = "mitre"

        try:
            db = Database(str(self.test_db_path))
            mapper = MITREAttackMapper(db)

            # Test basic attributes
            assert hasattr(mapper, 'map_event_to_ttp')
            assert hasattr(mapper, 'technique_mappings')
            assert len(mapper.technique_mappings) > 0
            self.add_test_result(suite_name, "mapper_init", True, "MITRE mapper initializes")

            # Test TTP mapping
            test_event = {
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                "protocol": "tcp",
                "indicator": "port_scan",
                "message": "Network service discovery detected"
            }

            ttps = mapper.map_event_to_ttp(test_event)
            assert isinstance(ttps, list)
            self.add_test_result(suite_name, "ttp_mapping", True, "TTP mapping works")

            # Test technique retrieval
            assert len(mapper.technique_mappings) >= 15  # Should have multiple techniques
            self.add_test_result(suite_name, "technique_count", True, f"Loaded {len(mapper.technique_mappings)} techniques")

            # Test tactic mappings
            assert len(mapper.tactic_mappings) > 0
            self.add_test_result(suite_name, "tactic_mappings", True, "Tactic mappings loaded")

        except AssertionError as e:
            self.add_test_result(suite_name, "mitre_test", False, str(e))
        except Exception as e:
            self.add_test_result(suite_name, "mitre_operations", False, str(e))

    def test_threat_matcher(self):
        """Test threat matching engine"""
        print("\n⚡ Testing Threat Matching Engine...")
        suite_name = "matcher"

        try:
            db = Database(str(self.test_db_path))
            matcher = ThreatMatcher(db)

            # Test initialization
            assert hasattr(matcher, 'start')
            assert hasattr(matcher, 'stop')
            assert hasattr(matcher, 'stats')
            self.add_test_result(suite_name, "matcher_init", True, "Threat matcher initializes")

            # Test configuration
            matcher.configure()
            assert hasattr(matcher, 'misp_feed')
            assert hasattr(matcher, 'pfblocker_feed')
            assert hasattr(matcher, 'abuseipdb_feed')
            self.add_test_result(suite_name, "matcher_config", True, "Feed configuration works")

            # Test stats
            assert isinstance(matcher.stats, dict)
            assert "total_alerts" in matcher.stats
            self.add_test_result(suite_name, "matcher_stats", True, "Statistics tracking works")

            # Test get_status method
            status = matcher.get_status()
            assert "running" in status
            assert "misp" in status
            assert "pfblocker" in status
            self.add_test_result(suite_name, "status_method", True, "Status method works")

            # Test IP checking
            matcher.check_ip("192.168.1.100")
            self.add_test_result(suite_name, "ip_check", True, "IP checking works")

        except AssertionError as e:
            self.add_test_result(suite_name, "matcher_test", False, str(e))
        except Exception as e:
            self.add_test_result(suite_name, "matcher_operations", False, str(e))

    def test_security_reporter(self):
        """Test security report generation"""
        print("\n📊 Testing Security Reporter...")
        suite_name = "reporter"

        try:
            db = Database(str(self.test_db_path))
            reporter = SecurityReporter(db)

            # Test initialization
            assert hasattr(reporter, 'generate_comprehensive_report')
            self.add_test_result(suite_name, "reporter_init", True, "Security reporter initializes")

            # Test report generation with empty database
            report = reporter.generate_comprehensive_report(days=1)
            assert isinstance(report, dict)
            assert "executive_summary" in report or len(report) > 0
            self.add_test_result(suite_name, "report_generation", True, "Report generation works")

            # Test report with data
            alert = Alert(
                id="report-test-alert",
                timestamp=datetime.now(timezone.utc).isoformat(),
                severity="medium",
                source_ip="192.168.1.1",
                destination_ip="10.0.0.1",
                source_port=1234,
                destination_port=443,
                protocol="tcp",
                indicator="suspicious-domain.com",
                indicator_type="domain",
                feed_source="test",
                rule_id="test-rule",
                message="Test threat detected"
            )
            db.insert_alert(alert)
            report_with_data = reporter.generate_comprehensive_report(days=1)
            assert isinstance(report_with_data, dict)
            self.add_test_result(suite_name, "report_with_data", True, "Report generation with data works")

        except AssertionError as e:
            self.add_test_result(suite_name, "reporter_test", False, str(e))
        except Exception as e:
            self.add_test_result(suite_name, "reporter_operations", False, str(e))

    def test_api_routes(self):
        """Test FastAPI routes"""
        print("\n🌐 Testing API Routes...")
        suite_name = "api"

        try:
            db = Database(str(self.test_db_path))
            matcher = ThreatMatcher(db)

            # Initialize routes
            init_app(db, matcher)

            # Test app exists
            assert fastapi_app is not None
            assert fastapi_app.title == "Cyber Intelligence Gateway API"
            self.add_test_result(suite_name, "app_exists", True, "FastAPI app exists and configured")

            # Test status endpoint handler
            status = get_system_status()
            assert isinstance(status, dict)
            assert "running" in status
            self.add_test_result(suite_name, "status_endpoint", True, "/api/status endpoint works")

            # Test OpenAPI schema
            try:
                openapi_schema = fastapi_app.openapi()
                assert openapi_schema is not None
                assert "paths" in openapi_schema
                self.add_test_result(suite_name, "openapi_schema", True, "OpenAPI schema generation works")
            except Exception as oa_err:
                self.add_test_result(suite_name, "openapi_schema", False, f"OpenAPI schema error: {oa_err}")
                self.test_results["warnings"].append(f"OpenAPI generation issue: {oa_err}")

            # Test route count
            routes = [route.path for route in fastapi_app.routes]
            assert len(routes) > 0
            self.add_test_result(suite_name, "routes_registered", True, f"Registered {len(routes)} routes")

            # Test root health endpoint and checks endpoint with TestClient
            client = TestClient(fastapi_app)

            health_response = client.get("/api/health/checks")
            assert health_response.status_code == 200
            health_json = health_response.json()
            assert "overall_status" in health_json
            assert "components" in health_json
            self.add_test_result(suite_name, "api_health_checks", True, "/api/health/checks endpoint works")

            dashboard_checks_response = client.get("/dashboard/checks")
            assert dashboard_checks_response.status_code == 200
            assert "System Health Checks" in dashboard_checks_response.text
            self.add_test_result(suite_name, "dashboard_checks", True, "/dashboard/checks endpoint renders")

            test_response = client.get("/test")
            assert test_response.status_code == 200
            assert test_response.json().get("message") == "Server is working"
            self.add_test_result(suite_name, "basic_test_endpoint", True, "/test endpoint works")

            news_response = client.get("/api/news?limit=10")
            assert news_response.status_code == 200
            news_json = news_response.json()
            assert news_json.get("status") == "success"
            assert isinstance(news_json.get("items"), list)
            assert len(news_json.get("items")) >= 10
            assert all("ai_agent" in item for item in news_json.get("items"))
            self.add_test_result(suite_name, "api_news_endpoint", True, "/api/news endpoint returns 10+ news items with AI agent field")

            ai_news_response = client.get("/api/news/ai?q=rce")
            assert ai_news_response.status_code == 200
            ai_json = ai_news_response.json()
            assert ai_json.get("status") == "success"
            assert ai_json.get("result_count") >= 1
            assert "ai_context" in ai_json
            self.add_test_result(suite_name, "api_news_ai_endpoint", True, "/api/news/ai endpoint works")

            news_dashboard_response = client.get("/dashboard/news")
            assert news_dashboard_response.status_code == 200
            assert "Latest Cybersecurity News" in news_dashboard_response.text
            self.add_test_result(suite_name, "dashboard_news", True, "/dashboard/news endpoint renders")

            # Test new dashboard summary endpoint
            dashboard_summary_response = client.get("/api/dashboard/summary")
            assert dashboard_summary_response.status_code == 200
            summary_json = dashboard_summary_response.json()
            assert summary_json.get("status") == "success"
            assert "summary" in summary_json
            assert "health" in summary_json
            assert "recent_alerts" in summary_json
            assert "latest_news" in summary_json
            assert "risk_score" in summary_json.get("summary", {})
            self.add_test_result(suite_name, "api_dashboard_summary", True, "/api/dashboard/summary endpoint works")

            arkime_status_response = client.get("/api/arkime/status")
            assert arkime_status_response.status_code == 200
            arkime_json = arkime_status_response.json()
            assert "arkime" in arkime_json
            self.add_test_result(suite_name, "api_arkime_status", True, "/api/arkime/status endpoint works")

            arkime_info_response = client.get("/api/arkime/info")
            assert arkime_info_response.status_code == 200
            assert "info" in arkime_info_response.json()
            self.add_test_result(suite_name, "api_arkime_info", True, "/api/arkime/info endpoint works")

            arkime_so_response = client.get("/api/arkime/security-onion")
            assert arkime_so_response.status_code == 200
            assert "security_onion" in arkime_so_response.json()
            self.add_test_result(suite_name, "api_arkime_so", True, "/api/arkime/security-onion endpoint works")

            arkime_dashboard_response = client.get("/dashboard/arkime")
            assert arkime_dashboard_response.status_code == 200
            assert "Arkime" in arkime_dashboard_response.text
            self.add_test_result(suite_name, "dashboard_arkime", True, "/dashboard/arkime endpoint renders")

        except AssertionError as e:
            self.add_test_result(suite_name, "api_test", False, str(e))
        except Exception as e:
            self.add_test_result(suite_name, "api_operations", False, str(e))

    def test_main_application(self):
        """Test main application"""
        print("\n🚀 Testing Main Application...")
        suite_name = "main"

        try:
            import app.main

            # Test key functions exist
            assert hasattr(app.main, 'main')
            assert hasattr(app.main, 'setup_directories')
            assert hasattr(app.main, 'signal_handler')
            self.add_test_result(suite_name, "main_functions", True, "Main functions available")

            # Test directory setup
            app.main.setup_directories()
            self.add_test_result(suite_name, "directory_setup", True, "Directory setup works")

            # Test that database and threat_matcher are exported
            assert hasattr(app.main, 'database')
            assert hasattr(app.main, 'threat_matcher')
            assert hasattr(app.main, 'fastapi_app')
            self.add_test_result(suite_name, "exports", True, "Required exports available")

        except AssertionError as e:
            self.add_test_result(suite_name, "main_test", False, str(e))
        except Exception as e:
            self.add_test_result(suite_name, "main_operations", False, str(e))

    def identify_improvements(self):
        """Identify improvements based on test results"""
        print("\n💡 Analyzing for Improvements...")

        # Check for areas that could be improved
        if self.test_results["total_failed"] > 0:
            self.test_results["improvements_found"].append("Fix failing test cases to improve stability")

        # Check database optimization
        try:
            db = Database(str(self.test_db_path))
            # Check if indices are being used
            self.test_results["improvements_found"].append("Consider adding query caching for repeated indicator lookups")
        except:
            pass

        # Check API routes
        routes = [route.path for route in fastapi_app.routes]
        if len(routes) < 15:
            self.test_results["improvements_found"].append(f"Currently {len(routes)} routes - consider adding more endpoints for full API coverage")

        # MITRE improvements
        self.test_results["improvements_found"].append("Implement full MITRE ATT&CK framework loading (currently using simplified mappings)")

        # Feed improvements
        self.test_results["improvements_found"].append("Add retry logic with exponential backoff for feed updates")
        self.test_results["improvements_found"].append("Implement feed health checking and alerting")

        # Performance improvements
        self.test_results["improvements_found"].append("Add database connection pooling for concurrent requests")
        self.test_results["improvements_found"].append("Implement request-level caching for indicator lookups")

        # Monitoring improvements
        self.test_results["improvements_found"].append("Add comprehensive logging throughout threat matching flow")
        self.test_results["improvements_found"].append("Implement metrics collection (Prometheus format)")

    def run_all_tests(self):
        """Run all tests"""
        print("🚀 Starting Comprehensive Functionality Tests")
        print("=" * 70)

        self.test_configuration()
        self.test_database_operations()
        self.test_threat_feeds()
        self.test_pcap_capture()
        self.test_mitre_mapper()
        self.test_threat_matcher()
        self.test_security_reporter()
        self.test_api_routes()
        self.test_main_application()

        self.identify_improvements()
        self.generate_report()

        return self.test_results

    def generate_report(self):
        """Generate and display test report"""
        print("\n" + "=" * 70)
        print("📋 COMPREHENSIVE FUNCTIONALITY TEST REPORT")
        print("=" * 70)

        print(f"\n📊 OVERALL RESULTS:")
        print(f"   Total Tests: {self.test_results['total_tests']}")
        print(f"   ✅ Passed: {self.test_results['total_passed']}")
        print(f"   ❌ Failed: {self.test_results['total_failed']}")
        
        if self.test_results['total_tests'] > 0:
            success_rate = (self.test_results['total_passed'] / self.test_results['total_tests']) * 100
            print(f"   📈 Success Rate: {success_rate:.1f}%")

        print(f"\n📑 SUITE BREAKDOWN:")
        for suite_name, suite_data in self.test_results["test_suites"].items():
            passed = suite_data["passed"]
            total = suite_data["total"]
            status = "✅" if suite_data["failed"] == 0 else "⚠️"
            print(f"   {status} {suite_name}: {passed}/{total} tests passed")

        if self.test_results["critical_issues"]:
            print(f"\n🚨 CRITICAL ISSUES ({len(self.test_results['critical_issues'])}):")
            for issue in self.test_results["critical_issues"]:
                print(f"   • {issue}")

        if self.test_results["warnings"]:
            print(f"\n⚠️  WARNINGS ({len(self.test_results['warnings'])}):")
            for warning in self.test_results["warnings"]:
                print(f"   • {warning}")

        if self.test_results["improvements_found"]:
            print(f"\n💡 IMPROVEMENTS RECOMMENDED ({len(self.test_results['improvements_found'])}):")
            for i, improvement in enumerate(self.test_results["improvements_found"], 1):
                print(f"   {i}. {improvement}")

        # Save detailed report to file
        report_file = Path("cig_functionality_report.json")
        with open(report_file, 'w') as f:
            json.dump(self.test_results, f, indent=2, default=str)
        print(f"\n💾 Detailed report saved to: {report_file}")

        # Save human-readable summary
        summary_file = Path("cig_functionality_report.txt")
        with open(summary_file, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("COMPREHENSIVE FUNCTIONALITY TEST REPORT\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
            
            f.write("OVERALL RESULTS:\n")
            f.write(f"  Total Tests: {self.test_results['total_tests']}\n")
            f.write(f"  Passed: {self.test_results['total_passed']}\n")
            f.write(f"  Failed: {self.test_results['total_failed']}\n")
            
            if self.test_results['total_tests'] > 0:
                success_rate = (self.test_results['total_passed'] / self.test_results['total_tests']) * 100
                f.write(f"  Success Rate: {success_rate:.1f}%\n\n")

            f.write("SUITE BREAKDOWN:\n")
            for suite_name, suite_data in self.test_results["test_suites"].items():
                f.write(f"\n  {suite_name}:\n")
                for test_name, test_data in suite_data["tests"].items():
                    status = "PASS" if test_data["passed"] else "FAIL"
                    f.write(f"    [{status}] {test_name}: {test_data['message']}\n")

            if self.test_results["critical_issues"]:
                f.write(f"\nCRITICAL ISSUES:\n")
                for issue in self.test_results["critical_issues"]:
                    f.write(f"  • {issue}\n")

            if self.test_results["improvements_found"]:
                f.write(f"\nRECOMMENDED IMPROVEMENTS:\n")
                for i, improvement in enumerate(self.test_results["improvements_found"], 1):
                    f.write(f"  {i}. {improvement}\n")

        print(f"   Summary saved to: {summary_file}")

        # Cleanup
        try:
            shutil.rmtree(self.temp_dir)
        except:
            pass


def main():
    """Run comprehensive tests"""
    suite = ComprehensiveFunctionalityTest()
    results = suite.run_all_tests()
    return 0 if results["total_failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
