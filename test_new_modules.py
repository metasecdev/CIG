"""
Arkime Integration Test
Validates Arkime connector functionality
"""

import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_arkime_connector_import():
    """Test that Arkime connector can be imported"""
    try:
        from app.integrations.arkime import ArkimeConnector, CIGArkimeBridge

        print("✅ Arkime connector imported successfully")
        return True
    except Exception as e:
        print(f"❌ Arkime connector import failed: {e}")
        return False


def test_arkime_connector_instantiation():
    """Test creating Arkime connector"""
    try:
        from app.integrations.arkime import ArkimeConnector

        connector = ArkimeConnector(
            arkime_url="http://localhost:8005", arkime_secret="testsecret"
        )
        print("✅ Arkime connector instantiated")
        print(f"   URL: {connector.arkime_url}")
        print(f"   API Base: {connector.api_base}")
        return True
    except Exception as e:
        print(f"❌ Arkime connector instantiation failed: {e}")
        return False


def test_cig_bridge():
    """Test CIG-Arkime bridge"""
    try:
        from app.integrations.arkime import ArkimeConnector, CIGArkimeBridge

        connector = ArkimeConnector()
        bridge = CIGArkimeBridge(connector)
        print("✅ CIG-Arkime bridge created")
        return True
    except Exception as e:
        print(f"❌ CIG-Arkime bridge creation failed: {e}")
        return False


def test_spi_creation():
    """Test SPI data creation from alert"""
    try:
        from app.integrations.arkime import ArkimeConnector, CIGArkimeBridge

        connector = ArkimeConnector()
        bridge = CIGArkimeBridge(connector)

        test_alert = {
            "id": "alert-123",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "indicator": "evil.com",
            "indicator_type": "domain",
            "feed_source": "misp",
            "rule_id": "MISP:12345",
            "severity": "high",
            "timestamp": "2026-03-30T00:00:00",
        }

        spi = bridge.create_arkime_spi_from_alert(test_alert)
        print("✅ SPI data created from alert")
        print(f"   {spi}")
        return True
    except Exception as e:
        print(f"❌ SPI creation failed: {e}")
        return False


def test_custom_feeds():
    """Test custom feed source support"""
    try:
        from app.feeds.custom import (
            CustomFeedManager,
            PlainTextParser,
            JSONFeedParser,
            CSVFeedParser,
        )

        manager = CustomFeedManager()
        print("✅ Custom feed sources module works")

        parser = PlainTextParser("ip")
        indicators = parser.parse("1.2.3.4\n5.6.7.8\n# comment\n9.9.9.9")
        print(f"   Parsed {len(indicators)} indicators from plain text")

        return True
    except Exception as e:
        print(f"❌ Custom feed test failed: {e}")
        return False


def test_webhook_alerts():
    """Test webhook alerting"""
    try:
        from app.alerts.webhook import WebhookAlertManager, WebhookConfig, WebhookSender

        manager = WebhookAlertManager()
        print("✅ Webhook alerting module works")
        return True
    except Exception as e:
        print(f"❌ Webhook test failed: {e}")
        return False


def test_retry_logic():
    """Test retry logic"""
    try:
        from app.utils.retry import RetryConfig, retry_on_exception

        config = RetryConfig(max_retries=3)
        print("✅ Retry logic module works")

        delay = config.get_delay(0)
        print(f"   First attempt delay: {delay:.2f}s")

        return True
    except Exception as e:
        print(f"❌ Retry test failed: {e}")
        return False


def test_cache():
    """Test caching layer"""
    try:
        from app.utils.cache import InMemoryCache, RedisCache, CachedIndicatorManager

        cache = InMemoryCache(max_size=100)
        cache.set("test:key", {"value": "test"}, ttl=60)
        result = cache.get("test:key")
        print("✅ Cache module works")

        manager = CachedIndicatorManager(cache=cache)
        print("   CachedIndicatorManager created")

        return True
    except Exception as e:
        print(f"❌ Cache test failed: {e}")
        return False


def test_metrics():
    """Test Prometheus metrics"""
    try:
        from app.utils.metrics import MetricsCollector, PrometheusMetrics

        collector = MetricsCollector()
        collector.increment_alert("high", "misp")
        print("✅ Metrics module works")

        summary = collector.get_summary()
        print(f"   Alerts total: {summary['alerts_total']}")

        return True
    except Exception as e:
        print(f"❌ Metrics test failed: {e}")
        return False


def test_logging():
    """Test logging utilities"""
    try:
        from app.utils.logging_utils import StructuredLogger, JSONFormatter

        print("✅ Logging utilities work")
        return True
    except Exception as e:
        print(f"❌ Logging test failed: {e}")
        return False


def test_all_new_modules():
    """Run all new module tests"""
    print("\n=== Testing New CIG Modules ===\n")

    tests = [
        ("Arkime Connector Import", test_arkime_connector_import),
        ("Arkime Connector Instance", test_arkime_connector_instantiation),
        ("CIG-Arkime Bridge", test_cig_bridge),
        ("SPI Data Creation", test_spi_creation),
        ("Custom Feed Sources", test_custom_feeds),
        ("Webhook Alerting", test_webhook_alerts),
        ("Retry Logic", test_retry_logic),
        ("Caching Layer", test_cache),
        ("Prometheus Metrics", test_metrics),
        ("Logging Utilities", test_logging),
    ]

    passed = 0
    failed = 0

    for name, test_func in tests:
        print(f"\n--- {name} ---")
        if test_func():
            passed += 1
        else:
            failed += 1

    print(f"\n\n=== Results ===")
    print(f"Passed: {passed}/{len(tests)}")
    print(f"Failed: {failed}/{len(tests)}")
    print(f"Success Rate: {(passed / len(tests) * 100):.1f}%")

    return failed == 0


if __name__ == "__main__":
    success = test_all_new_modules()
    sys.exit(0 if success else 1)
