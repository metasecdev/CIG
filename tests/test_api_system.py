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


def test_news_verify_endpoint():
    client = setup_test_client()

    # parse-only check
    r = client.get("/api/news/verify?network_check=false")
    assert r.status_code == 200
    payload = r.json()
    assert payload.get("status") == "success"
    assert payload.get("network_check") is False
    assert payload.get("verified_count") >= 1

    for item in payload.get("items", []):
        assert "source_url" in item
        assert "source_valid" in item
        assert item.get("source_valid") in [True, False]

    # optional network reachability check (best-effort, may fail due environment network restrictions)
    r2 = client.get("/api/news/verify?network_check=true")
    assert r2.status_code == 200
    payload2 = r2.json()
    assert payload2.get("status") == "success"
    assert payload2.get("network_check") is True
    assert payload2.get("verified_count") >= 1

    for item in payload2.get("items", []):
        assert "source_reachable" in item
        assert item.get("source_reachable") in [True, False, None]
        if item.get("cve_url"):
            assert "cve_reachable" in item


def test_api_pcaps_insert_and_list():
    client = setup_test_client()
    from app.models.database import PcapFile
    from app.api.routes import _db
    import os

    pcap_path = "/tmp/test_capture.pcap"
    pcap_content = b"pcap test data"
    with open(pcap_path, "wb") as f:
        f.write(pcap_content)

    pcap = PcapFile(
        filename="test_capture.pcap",
        filepath=pcap_path,
        start_time="2026-03-31T00:00:00Z",
        end_time="2026-03-31T00:01:00Z",
        size_bytes=len(pcap_content),
        packets_count=100,
        interface="eth0",
        alerts_count=0,
    )

    # use the previously initialized database instance from routes
    _db.insert_pcap(pcap)

    response = client.get("/api/pcaps")
    assert response.status_code == 200
    data = response.json()
    assert "pcaps" in data

    found = [item for item in data["pcaps"] if item.get("id") == pcap.id]
    assert len(found) == 1

    # verify download works and content matches
    download_resp = client.get(f"/api/pcaps/{pcap.id}/download")
    assert download_resp.status_code == 200
    assert download_resp.content == pcap_content

    bad_resp = client.get("/api/pcaps/nonexistent-id/download")
    assert bad_resp.status_code == 404
    assert bad_resp.json().get("detail") in ["PCAP not found", "PCAP file not found"]

    # clean up test file
    if os.path.exists(pcap_path):
        os.remove(pcap_path)


def test_news_verify_summary():
    client = setup_test_client()
    resp = client.get("/api/news/verify/summary")
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("status") == "success"
    assert "total" in data and "confirmed" in data and "invalid" in data
    assert data["total"] == data["confirmed"] + data["invalid"]


def test_system_selfheal_endpoint():
    client = setup_test_client()
    response = client.post("/api/system/selfheal")
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("status") == "success"
    assert "self_heal_report" in payload


def test_health_monitor_endpoint():
    client = setup_test_client()
    response = client.get("/api/health/monitor")
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("status") == "success"
    assert "monitor" in payload
    assert "timestamp" in payload


def test_health_monitor_trigger():
    client = setup_test_client()
    response = client.post("/api/health/monitor/trigger")
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("status") == "success"
    assert "manual_check" in payload
    assert payload["manual_check"].get("last_check") is not None
    assert payload["self_heal_report"].get("checked") is True

