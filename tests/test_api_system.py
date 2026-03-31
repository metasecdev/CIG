import os
from fastapi.testclient import TestClient

from app.api.routes import app, init_app
from app.core.config import settings
from app.models.database import Database
from app.matching.engine import ThreatMatcher


def setup_test_client():
    # Ensure test runs don't trigger external feed updates or DNS polling
    settings.skip_feed_updates = True
    settings.skip_dns_monitoring = True
    settings.match_dns_queries = False
    settings.match_pcap_traffic = False

    db = Database(settings.database_path)
    matcher = ThreatMatcher(db)
    init_app(db, matcher)

    client = TestClient(app)
    return client


def test_system_control_endpoints():
    client = setup_test_client()

    r = client.post("/api/system/start")
    assert r.status_code == 200
    assert r.json().get("status") == "started"

    r = client.post("/api/system/pause")
    assert r.status_code == 200
    assert r.json().get("status") == "paused"

    r = client.post("/api/system/resume")
    assert r.status_code == 200
    assert r.json().get("status") == "resumed"

    r = client.post("/api/system/restart")
    assert r.status_code == 200
    assert r.json().get("status") == "restarted"

    r = client.post("/api/system/shutdown")
    assert r.status_code == 200
    assert r.json().get("status") == "shutdown"


def test_capture_control_endpoints_and_status():
    client = setup_test_client()

    r = client.get("/api/capture/status")
    assert r.status_code == 200
    assert "active" in r.json()

    # Pause/resume endpoints should be callable, even if captures are not active
    r = client.post("/api/capture/lan/pause")
    assert r.status_code == 200
    assert r.json().get("status") in ["paused", "failed"]

    r = client.post("/api/capture/wan/pause")
    assert r.status_code == 200
    assert r.json().get("status") in ["paused", "failed"]

    r = client.post("/api/capture/lan/resume")
    assert r.status_code == 200
    assert r.json().get("status") in ["resumed", "failed"]

    r = client.post("/api/capture/wan/resume")
    assert r.status_code == 200
    assert r.json().get("status") in ["resumed", "failed"]


def test_report_and_dashboard_endpoints():
    client = setup_test_client()

    r = client.get("/api/reports/generate?days=1")
    assert r.status_code == 200
    json_data = r.json()
    assert json_data.get("status") == "success"
    assert "report" in json_data
    assert "executive_summary" in json_data["report"]

    r = client.get("/api/dashboard/summary")
    assert r.status_code == 200
    assert "summary" in r.json()

    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json().get("status") == "healthy"


def test_cyber_news_links_valid():
    from app.feeds.news_feed import get_feed
    from urllib.parse import urlparse

    feed = get_feed()
    items = feed.get_latest(limit=10)

    assert items, "News feed should contain entries"

    for item in items:
        assert "source_url" in item and item["source_url"], f"Missing source_url in {item.get('id')}"
        source_parsed = urlparse(item["source_url"])
        assert source_parsed.scheme in ["http", "https"]
        assert source_parsed.netloc, f"Bad source_url netloc in {item.get('id')}"

        # CVE URLs are optional; when present, check formatting
        if item.get("cve_url"):
            cve_parsed = urlparse(item["cve_url"])
            assert cve_parsed.scheme in ["http", "https"]
            assert cve_parsed.netloc, f"Bad cve_url netloc in {item.get('id')}"

    # Optional real-world reachability check (best effort; non-fatal)
    try:
        import requests

        for item in items:
            url = item.get("source_url")
            if not url:
                continue
            try:
                resp = requests.head(url, timeout=5, allow_redirects=True)
                assert resp.status_code < 400, f"News URL not reachable: {url} ({resp.status_code})"
            except requests.RequestException:
                # skip network failures in restricted environments
                pass
    except ImportError:
        # requests may not be installed in all test environments
        pass
