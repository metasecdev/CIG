from fastapi.testclient import TestClient

from app.api.routes import app, init_app
from app.core.config import settings
from app.models.database import Database
from app.matching.engine import ThreatMatcher


def setup_test_client():
    settings.skip_feed_updates = True
    settings.skip_dns_monitoring = True
    settings.match_dns_queries = False
    settings.match_pcap_traffic = False

    db = Database(settings.database_path)
    matcher = ThreatMatcher(db)
    init_app(db, matcher)
    return TestClient(app)


def test_api_dashboard_health_json():
    client = setup_test_client()
    resp = client.get("/api/dashboard/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert "last_checked_at" in data
    assert "health" in data and isinstance(data["health"], dict)
    assert "components" in data["health"]
    assert "database" in data["health"]["components"]


def test_dashboard_cves_route():
    client = setup_test_client()
    resp = client.get("/dashboard/cves")
    assert resp.status_code == 200
    assert "CVE Vulnerability Intelligence" in resp.text
