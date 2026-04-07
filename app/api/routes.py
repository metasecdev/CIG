"""
FastAPI Routes for Cyber Intelligence Gateway
"""

import os
import logging
from typing import Optional, List
from datetime import datetime, UTC
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Response, Request, BackgroundTasks
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import urlparse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from app.models.database import Database, Alert, PcapFile, Indicator
from app.matching.engine import ThreatMatcher
from app.reporting.security_report import SecurityReporter
from app.core.config import settings
from app.health import get_health_status
from app.feeds.news_feed import get_feed
from app.feeds.cve_news import get_cve_feed
from app.integrations.arkime_setup import ArkimeSetupManager, SecurityOnionIntegration

logger = logging.getLogger(__name__)

# Module-level rule store (temporary until DB migration)
_intel_rules: Dict[str, dict] = {}

# Create FastAPI app
app = FastAPI(
    title="Cyber Intelligence Gateway API",
    description="Threat intelligence and network monitoring API",
    version="1.0.0",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Templates and static files
templates = Jinja2Templates(directory=Path(__file__).parent.parent.parent / "templates")
app.mount(
    "/static",
    StaticFiles(directory=Path(__file__).parent.parent.parent / "static"),
    name="static",
)

# Include malware analysis routes
from app.malware.api.routes import router as malware_router
app.include_router(malware_router)

# Global instances (will be initialized in main.py)
_db: Optional[Database] = None
_threat_matcher: Optional[ThreatMatcher] = None
threat_matcher: Optional[ThreatMatcher] = None
_scheduler = None
_filter_engine = None
_dshield_poller = None
_report_ingestion = None


def get_db() -> Database:
    """Get database instance"""
    if _db is None:
        raise HTTPException(status_code=503, detail="Database not initialized")
    return _db


def get_threat_matcher() -> ThreatMatcher:
    """Get threat matcher instance"""
    if _threat_matcher is None:
        raise HTTPException(status_code=503, detail="System not initialized")
    return _threat_matcher


def get_scheduler():
    """Get scheduler instance"""
    if _scheduler is None:
        raise HTTPException(status_code=503, detail="Scheduler not initialized")
    return _scheduler


def get_filter_engine():
    """Get filter engine instance"""
    if _filter_engine is None:
        raise HTTPException(status_code=503, detail="Filter engine not initialized")
    return _filter_engine


def get_dshield_poller():
    """Get DShield poller instance"""
    if _dshield_poller is None:
        raise HTTPException(status_code=503, detail="DShield poller not initialized")
    return _dshield_poller


def get_report_ingestion():
    """Get report ingestion connector instance"""
    if _report_ingestion is None:
        raise HTTPException(status_code=503, detail="Report ingestion not initialized")
    return _report_ingestion


def init_app(
    database: Database,
    matcher: ThreatMatcher,
    scheduler=None,
    filter_engine=None,
    dshield_poller=None,
    report_ingestion=None,
):
    """Initialize global instances"""
    global \
        _db, \
        _threat_matcher, \
        threat_matcher, \
        _scheduler, \
        _filter_engine, \
        _dshield_poller, \
        _report_ingestion
    _db = database
    _threat_matcher = matcher
    threat_matcher = matcher
    _scheduler = scheduler
    _filter_engine = filter_engine
    _dshield_poller = dshield_poller
    _report_ingestion = report_ingestion


# --- Pydantic Models ---


class AlertResponse(BaseModel):
    id: str
    timestamp: str
    severity: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    indicator: str
    indicator_type: str
    feed_source: str
    rule_id: str
    message: str

    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    total: int
    alerts: List[AlertResponse]


class PcapResponse(BaseModel):
    id: str
    filename: str
    filepath: str
    start_time: str
    end_time: str
    size_bytes: int
    packets_count: int
    interface: str
    alerts_count: int

    class Config:
        from_attributes = True


class IndicatorResponse(BaseModel):
    id: str
    value: str
    type: str
    source: str
    feed_id: str
    first_seen: str
    last_seen: str
    tags: str
    count: int

    class Config:
        from_attributes = True


class StatsResponse(BaseModel):
    alerts: dict
    indicators: dict
    feeds: dict
    captures: List[dict]


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str


class DomainCheckRequest(BaseModel):
    domain: str


class DomainCheckResponse(BaseModel):
    domain: str
    matched: bool
    indicator: Optional[dict] = None


# --- Intel Rules Models ---


class IntelRuleRequest(BaseModel):
    name: str
    type: str  # yara, sigma, stix, snort
    content: str
    priority: int = 2  # 1-4
    confidence: float = 0.5  # 0.0-1.0
    attack_technique: Optional[str] = None
    source_sample: Optional[str] = None
    enabled: bool = True


class IntelRuleResponse(BaseModel):
    name: str
    type: str
    content: str
    priority: int
    confidence: float
    attack_technique: Optional[str] = None
    source_sample: Optional[str] = None
    enabled: bool
    created_at: str
    updated_at: str


# --- Health Endpoints ---


@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy", version="1.0.0", timestamp=datetime.now(UTC).isoformat()
    )


@app.get("/api/dashboard/summary")
async def dashboard_summary():
    """Get comprehensive dashboard summary"""
    try:
        if _db is None or _threat_matcher is None:
            raise HTTPException(status_code=503, detail="System not initialized")

        database = _db
        matcher = _threat_matcher

        # Gather all critical info
        health = get_health_status(database, matcher)
        recent_alerts = database.get_alerts(limit=5)
        alert_stats = database.get_alert_stats()
        latest_news = get_feed().get_latest()[:3]

        # Calculate risk score (0-100)
        high_alerts = alert_stats.get("by_severity", {}).get("high", 0)
        medium_alerts = alert_stats.get("by_severity", {}).get("medium", 0)
        risk_score = min(100, (high_alerts * 30) + (medium_alerts * 10))

        return {
            "status": "success",
            "summary": {
                "total_alerts": alert_stats.get("total", 0),
                "high_severity_alerts": high_alerts,
                "risk_score": risk_score,
                "components_healthy": len(
                    [
                        c
                        for c in health.get("components", {}).values()
                        if c.get("status") == "healthy"
                    ]
                ),
                "total_components": len(health.get("components", {})),
            },
            "health": health,
            "recent_alerts": [
                AlertResponse(**a.to_dict()).dict() for a in recent_alerts
            ],
            "latest_news": latest_news,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    except Exception as e:
        logger.error(f"Failed to get dashboard summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to get dashboard summary")


# --- Alert Endpoints ---


@app.get("/api/alerts", response_model=AlertListResponse)
async def get_alerts(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = Query(None),
    indicator_type: Optional[str] = Query(None),
):
    """Get alerts with optional filtering"""
    database = get_db()

    alerts = database.get_alerts(
        limit=limit, offset=offset, severity=severity, indicator_type=indicator_type
    )
    stats = database.get_alert_stats()

    return AlertListResponse(
        total=stats["total"], alerts=[AlertResponse(**a.to_dict()) for a in alerts]
    )


@app.get("/api/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str):
    """Get a specific alert"""
    database = get_db()

    alert = database.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return AlertResponse(**alert.to_dict())


@app.get("/api/alerts/stats")
async def get_alert_stats():
    """Get alert statistics"""
    database = get_db()
    return database.get_alert_stats()


# --- PCAP Endpoints ---


@app.get("/api/pcaps")
async def get_pcaps(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)):
    """Get PCAP file list"""
    database = get_db()

    pcaps = database.get_pcaps(limit=limit, offset=offset)
    return {"pcaps": [PcapResponse(**p.to_dict()).dict() for p in pcaps]}


@app.get("/api/pcaps/{pcap_id}/download")
async def download_pcap(pcap_id: str):
    """Download a PCAP file"""
    database = get_db()

    conn = database.db_path
    import sqlite3

    conn = sqlite3.connect(db.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT filepath, filename FROM pcap_files WHERE id = ?", (pcap_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="PCAP not found")

    filepath, filename = row
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="PCAP file not found")

    # Check for .gz extension (rotated/compressed files)
    gz_filepath = filepath + ".gz"
    if os.path.exists(gz_filepath):
        filepath = gz_filepath

    with open(filepath, "rb") as f:
        content = f.read()

    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/api/pcaps/{pcap_id}/alerts")
async def get_pcap_alerts(pcap_id: str):
    """Get alerts associated with a PCAP file"""
    database = get_db()

    # Get alerts that might be related to this PCAP (by timestamp)
    # This is a simplified implementation
    conn = db.db_path
    import sqlite3

    conn = sqlite3.connect(db.db_path)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT start_time FROM pcap_files WHERE id = ?
    """,
        (pcap_id,),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="PCAP not found")

    return {"alerts": []}


# --- Intelligence Endpoints ---


@app.get("/api/intel/misp")
async def get_misp_status():
    """Get MISP feed status"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    return threat_matcher.misp_feed.get_status()


@app.get("/api/intel/pfblocker")
async def get_pfblocker_status():
    """Get pfBlocker feed status"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    return threat_matcher.pfblocker_feed.get_status()


@app.get("/api/intel/cvedetails")
async def get_cvedetails_status():
    """Get CVE Details feed status"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    return threat_matcher.cvedetails_feed.get_status()


@app.get("/api/intel/cisa_kev")
async def get_cisa_kev_status():
    """Get CISA KEV feed status"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    return threat_matcher.cisa_kev_feed.get_status()


@app.get("/api/intel/shadowserver")
async def get_shadowserver_status():
    """Get Shadowserver feed status"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    return threat_matcher.shadowserver_feed.get_status()


@app.get("/api/intel/sans_isc")
async def get_sans_isc_status():
    """Get SANS ISC feed status"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    return threat_matcher.sans_isc_feed.get_status()


@app.get("/api/intel/indicators")
async def get_indicators(
    limit: int = Query(1000, ge=1, le=10000),
    indicator_type: Optional[str] = Query(None),
):
    """Get threat indicators"""
    database = get_db()

    indicators = database.get_indicators(limit=limit, indicator_type=indicator_type)
    return {"indicators": [IndicatorResponse(**i.to_dict()).dict() for i in indicators]}


@app.post("/api/intel/check/domain", response_model=DomainCheckResponse)
async def check_domain(request: DomainCheckRequest):
    """Check a domain against threat intelligence"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    alert = threat_matcher.check_domain(request.domain)
    if alert:
        return DomainCheckResponse(
            domain=request.domain,
            matched=True,
            indicator={
                "indicator": alert.indicator,
                "type": alert.indicator_type,
                "source": alert.feed_source,
            },
        )

    return DomainCheckResponse(domain=request.domain, matched=False)


@app.post("/api/intel/check/ip")
async def check_ip(ip: str):
    """Check an IP against threat intelligence"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    alert = threat_matcher.check_ip(ip)
    if alert:
        return {
            "ip": ip,
            "matched": True,
            "indicator": {
                "indicator": alert.indicator,
                "type": alert.indicator_type,
                "source": alert.feed_source,
            },
        }

    return {"ip": ip, "matched": False}


# --- Capture Control Endpoints ---


@app.post("/api/capture/lan/start")
async def start_lan_capture():
    """Start PCAP capture on LAN interface"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    result = threat_matcher.start_lan_capture()
    if result:
        return {"status": "started", "pcap_id": result}
    return {"status": "failed", "message": "Capture may already be running"}


@app.post("/api/capture/lan/stop")
async def stop_lan_capture():
    """Stop PCAP capture on LAN interface"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    result = threat_matcher.stop_lan_capture()
    return {"status": "stopped" if result else "failed"}


@app.post("/api/capture/wan/start")
async def start_wan_capture():
    """Start PCAP capture on WAN interface"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    result = threat_matcher.start_wan_capture()
    if result:
        return {"status": "started", "pcap_id": result}
    return {"status": "failed", "message": "Capture may already be running"}


@app.post("/api/capture/wan/stop")
async def stop_wan_capture():
    """Stop PCAP capture on WAN interface"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    result = threat_matcher.stop_wan_capture()
    return {"status": "stopped" if result else "failed"}


@app.post("/api/capture/lan/pause")
async def pause_lan_capture():
    """Pause LAN PCAP capture"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    result = threat_matcher.pcap_capture.pause_capture(settings.lan_interface)
    return {"status": "paused" if result else "failed"}


@app.post("/api/capture/wan/pause")
async def pause_wan_capture():
    """Pause WAN PCAP capture"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    result = threat_matcher.pcap_capture.pause_capture(settings.wan_interface)
    return {"status": "paused" if result else "failed"}


@app.post("/api/capture/lan/resume")
async def resume_lan_capture():
    """Resume LAN capture"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    result = threat_matcher.pcap_capture.resume_capture(settings.lan_interface)
    return {"status": "resumed" if result else "failed"}


@app.post("/api/capture/wan/resume")
async def resume_wan_capture():
    """Resume WAN capture"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    result = threat_matcher.pcap_capture.resume_capture(settings.wan_interface)
    return {"status": "resumed" if result else "failed"}


@app.get("/api/capture/status")
async def get_capture_status():
    """Get capture status"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    return {"active": threat_matcher.pcap_capture.get_active_captures()}


# --- Feed Update Endpoints ---


@app.post("/api/feeds/update/misp")
async def update_misp_feed():
    """Manually trigger MISP feed update"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    count = threat_matcher._update_misp()
    return {"status": "updated", "indicators_count": count}


@app.post("/api/feeds/update/pfblocker")
async def update_pfblocker_feed():
    """Manually trigger pfBlocker feed update"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    count = threat_matcher._update_pfblocker()
    return {"status": "updated", "indicators_count": count}


@app.post("/api/feeds/update/cvedetails")
async def update_cvedetails_feed():
    """Manually trigger CVE Details feed update"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    count = threat_matcher._update_cvedetails()
    return {"status": "updated", "vulnerabilities_count": count}


@app.post("/api/feeds/update/cisa_kev")
async def update_cisa_kev_feed():
    """Manually trigger CISA KEV feed update"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    count = threat_matcher._update_cisa_kev()
    return {"status": "updated", "vulnerabilities_count": count}


@app.post("/api/feeds/update/shadowserver")
async def update_shadowserver_feed():
    """Manually trigger Shadowserver feed update"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    count = threat_matcher._update_shadowserver()
    return {"status": "updated", "indicators_count": count}


@app.post("/api/feeds/update/cve_news")
async def update_cve_news_feed():
    """Manually trigger CVE News feed update"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    count = threat_matcher._update_cve_news()
    return {"status": "updated", "cve_count": count}


@app.post("/api/feeds/update/sans_isc")
async def update_sans_isc_feed():
    """Manually trigger SANS ISC feed update"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    count = threat_matcher._update_sans_isc()
    return {"status": "updated", "indicators_count": count}


@app.post("/api/feeds/update/all")
async def update_all_feeds():
    """Manually trigger all feed updates"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    threat_matcher._update_feeds()
    return {"status": "updated"}


@app.get("/api/feeds/status")
async def get_all_feeds_status():
    """Get status of all feeds"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    return {
        "misp": {
            "enabled": settings.enable_misp,
            "configured": bool(settings.misp_url and settings.misp_api_key),
            "status": "configured" if settings.enable_misp else "disabled",
        },
        "pfblocker": {
            "enabled": settings.enable_pfblocker,
            "configured": bool(settings.pfblocker_feeds),
            "status": "configured" if settings.enable_pfblocker else "disabled",
        },
        "abuseipdb": {
            "enabled": settings.enable_abuseipdb,
            "configured": bool(settings.abuseipdb_api_key),
            "status": "configured" if settings.enable_abuseipdb else "disabled",
        },
        "urlhaus": {
            "enabled": settings.enable_urlhaus,
            "configured": True,
            "status": "configured" if settings.enable_urlhaus else "disabled",
        },
        "threatfox": {
            "enabled": settings.enable_threatfox,
            "configured": True,
            "status": "configured" if settings.enable_threatfox else "disabled",
        },
        "cvedetails": {
            "enabled": settings.enable_cvedetails,
            "configured": True,
            "status": "configured" if settings.enable_cvedetails else "disabled",
        },
        "cisa_kev": {
            "enabled": settings.enable_cisa_kev,
            "configured": True,
            "status": "configured" if settings.enable_cisa_kev else "disabled",
        },
        "shadowserver": {
            "enabled": settings.enable_shadowserver,
            "configured": bool(settings.shadowserver_api_key),
            "status": "configured"
            if settings.enable_shadowserver and settings.shadowserver_api_key
            else "disabled",
        },
        "sans_isc": {
            "enabled": settings.enable_sans_isc,
            "configured": True,
            "status": "configured" if settings.enable_sans_isc else "disabled",
        },
    }


class FeedToggleRequest(BaseModel):
    feed: str
    enabled: bool


@app.post("/api/feeds/toggle")
async def toggle_feed(request: FeedToggleRequest):
    """Enable or disable a feed"""
    feed = request.feed.lower()
    enabled = request.enabled

    if feed == "misp":
        settings.enable_misp = enabled
    elif feed == "pfblocker":
        settings.enable_pfblocker = enabled
    elif feed == "abuseipdb":
        settings.enable_abuseipdb = enabled
    elif feed == "urlhaus":
        settings.enable_urlhaus = enabled
    elif feed == "threatfox":
        settings.enable_threatfox = enabled
    elif feed == "cvedetails":
        settings.enable_cvedetails = enabled
    elif feed == "cisa_kev":
        settings.enable_cisa_kev = enabled
    elif feed == "shadowserver":
        settings.enable_shadowserver = enabled
    elif feed == "sans_isc":
        settings.enable_sans_isc = enabled
    else:
        raise HTTPException(status_code=400, detail=f"Unknown feed: {feed}")

    return {"feed": feed, "enabled": enabled, "status": "ok"}


@app.get("/api/intel/urlhaus")
async def get_urlhaus_status():
    """Get URLhaus feed status"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    if not hasattr(threat_matcher, "abusech_feeds"):
        return {"enabled": settings.enable_urlhaus, "status": "not_configured"}

    return threat_matcher.abusech_feeds.get_status().get("urlhaus", {})


@app.get("/api/intel/threatfox")
async def get_threatfox_status():
    """Get ThreatFox feed status"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    if not hasattr(threat_matcher, "abusech_feeds"):
        return {"enabled": settings.enable_threatfox, "status": "not_configured"}

    return threat_matcher.abusech_feeds.get_status().get("threatfox", {})


# --- Intel Rules Endpoints ---


@app.post("/api/intel/rules")
async def create_intel_rule(request: IntelRuleRequest):
    """Add a new rule to the database."""
    rule_name = request.name

    now = datetime.now(UTC).isoformat()
    rule_data = {
        "name": rule_name,
        "type": request.type,
        "content": request.content,
        "priority": request.priority,
        "confidence": request.confidence,
        "attack_technique": request.attack_technique,
        "source_sample": request.source_sample,
        "enabled": request.enabled,
        "created_at": now,
        "updated_at": now,
    }

    _intel_rules[rule_name] = rule_data

    logger.info(f"Created intel rule: {rule_name}")
    return {
        "status": "created",
        "rule": IntelRuleResponse(**rule_data).dict(),
    }


@app.get("/api/intel/rules")
async def list_intel_rules(
    type: Optional[str] = Query(None, description="Filter by rule type"),
    enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
):
    """List all rules with optional filtering."""
    rules = list(_intel_rules.values())

    if type:
        rules = [r for r in rules if r.get("type") == type]
    if enabled is not None:
        rules = [r for r in rules if r.get("enabled") == enabled]

    return {
        "rules": [IntelRuleResponse(**r).dict() for r in rules],
        "total": len(rules),
    }


@app.get("/api/intel/rules/{rule_name}")
async def get_intel_rule(rule_name: str):
    """Get a specific rule by name."""
    if rule_name not in _intel_rules:
        raise HTTPException(status_code=404, detail="Rule not found")

    return {"rule": IntelRuleResponse(**_intel_rules[rule_name]).dict()}


@app.delete("/api/intel/rules/{rule_name}")
async def delete_intel_rule(rule_name: str):
    """Delete/disable a rule by name."""
    if rule_name not in _intel_rules:
        raise HTTPException(status_code=404, detail="Rule not found")

    # Disable instead of deleting
    _intel_rules[rule_name]["enabled"] = False
    _intel_rules[rule_name]["updated_at"] = datetime.now(UTC).isoformat()

    return {
        "status": "deleted",
        "rule_name": rule_name,
        "message": "Rule disabled (not permanently deleted)",
    }


@app.post("/api/intel/rules/{rule_name}/enable")
async def enable_intel_rule(rule_name: str):
    """Enable a rule."""
    if rule_name not in _intel_rules:
        raise HTTPException(status_code=404, detail="Rule not found")

    _intel_rules[rule_name]["enabled"] = True
    _intel_rules[rule_name]["updated_at"] = datetime.now(UTC).isoformat()

    return {
        "status": "enabled",
        "rule": IntelRuleResponse(**_intel_rules[rule_name]).dict(),
    }


@app.post("/api/intel/rules/{rule_name}/disable")
async def disable_intel_rule(rule_name: str):
    """Disable a rule."""
    if rule_name not in _intel_rules:
        raise HTTPException(status_code=404, detail="Rule not found")

    _intel_rules[rule_name]["enabled"] = False
    _intel_rules[rule_name]["updated_at"] = datetime.now(UTC).isoformat()

    return {
        "status": "disabled",
        "rule": IntelRuleResponse(**_intel_rules[rule_name]).dict(),
    }


@app.post("/api/feeds/update/urlhaus")
async def update_urlhaus_feed():
    """Manually trigger URLhaus feed update"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    if not hasattr(threat_matcher, "abusech_feeds"):
        return {"status": "error", "message": "Abuse.ch feeds not configured"}

    count = threat_matcher.abusech_feeds.urlhaus.fetch_urls()
    return {"status": "updated", "indicators_count": count}


@app.post("/api/feeds/update/threatfox")
async def update_threatfox_feed():
    """Manually trigger ThreatFox feed update"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    if not hasattr(threat_matcher, "abusech_feeds"):
        return {"status": "error", "message": "Abuse.ch feeds not configured"}

    count = threat_matcher.abusech_feeds.threatfox.fetch_indicators()
    return {"status": "updated", "indicators_count": count}


# --- System Endpoints ---


@app.get("/api/status")
async def get_system_status():
    """Get full system status"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    return threat_matcher.get_status()


@app.post("/api/system/start")
async def api_system_start():
    """Start the threat matcher"""
    if not _db or not _threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    threat_matcher.start()
    return {"status": "started"}


@app.post("/api/system/pause")
async def api_system_pause():
    """Pause the threat matcher"""
    if not _db or not _threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    threat_matcher.pause()
    return {"status": "paused"}


@app.post("/api/system/resume")
async def api_system_resume():
    """Resume the threat matcher"""
    if not _db or not _threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    threat_matcher.resume()
    return {"status": "resumed"}


@app.post("/api/system/restart")
async def api_system_restart():
    """Restart the threat matcher"""
    if not _db or not _threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    threat_matcher.restart()
    logger.info("API system restart invoked: threat matcher restarted")
    return {"status": "restarted"}


@app.post("/api/system/shutdown")
async def api_system_shutdown():
    """Shutdown the threat matcher"""
    if not _db or not _threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    threat_matcher.stop()
    logger.info("API system shutdown invoked: threat matcher stopped")
    return {"status": "shutdown"}


@app.post("/api/system/selfheal")
async def api_system_selfheal():
    """Self-healing endpoint triggered manually or on startup"""
    from app.main import self_heal_from_logs

    report = self_heal_from_logs()
    return {"status": "success", "self_heal_report": report}


@app.get("/api/health/monitor")
async def api_health_monitor():
    """Get health monitoring status and last self-heal report"""
    from app.health_scheduler import get_health_report

    report = get_health_report()
    return {
        "status": "success",
        "monitor": report,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.post("/api/health/monitor/trigger")
async def api_health_monitor_trigger():
    """Manually trigger a health check (outside the normal 60-second cycle)"""
    from app.health_scheduler import trigger_health_check

    report = trigger_health_check()
    return {
        "status": "success",
        "manual_check": report,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get("/api/reports/generate")
async def api_generate_report(days: int = Query(7, ge=1, le=30)):
    """Generate a comprehensive security report"""
    if not _db:
        raise HTTPException(status_code=503, detail="Database not initialized")

    reporter = SecurityReporter(_db)
    try:
        report = reporter.generate_comprehensive_report(days)
        return {"status": "success", "report": report}
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report")


@app.get("/api/reports/generate/html")
async def api_generate_report_html(days: int = Query(7, ge=1, le=30)):
    """Generate and retrieve HTML report file"""
    if not _db:
        raise HTTPException(status_code=503, detail="Database not initialized")

    reporter = SecurityReporter(_db)
    try:
        html_path = reporter.generate_html_report(days)
        return FileResponse(html_path, media_type="text/html")
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate HTML report")


# --- Dashboard Endpoints ---


@app.get("/test")
async def test_route():
    """Simple test route"""
    return {"message": "Server is working", "timestamp": datetime.now(UTC).isoformat()}


@app.get("/")
async def dashboard(request: Request):
    """Main dashboard page"""
    try:
        # Check if system is initialized
        if _db is None or _threat_matcher is None:
            return templates.TemplateResponse(
                "error.html",
                {
                    "request": request,
                    "error": "System not initialized. Please ensure the database and threat matcher are properly configured.",
                },
            )

        database = _db
        matcher = _threat_matcher

        # Get system stats
        stats = {
            "alerts": database.get_alert_stats(),
            "indicator_breakdown": database.get_indicator_counts(),
            "feeds": {
                "misp": matcher.misp_feed.get_status(),
                "pfblocker": matcher.pfblocker_feed.get_status(),
                "abuseipdb": matcher.abuseipdb_feed.get_status(),
                "cvedetails": getattr(matcher, "cvedetails_feed", None).get_status()
                if getattr(matcher, "cvedetails_feed", None)
                else {"status": "not_configured"},
                "cisa_kev": getattr(matcher, "cisa_kev_feed", None).get_status()
                if getattr(matcher, "cisa_kev_feed", None)
                else {"status": "not_configured"},
                "shadowserver": getattr(matcher, "shadowserver_feed", None).get_status()
                if getattr(matcher, "shadowserver_feed", None)
                else {"status": "not_configured"},
            },
            "captures": matcher.pcap_capture.get_active_captures(),
            "system": matcher.get_status(),
            "map": {
                "status": "online",
                "last_checked_at": datetime.now(UTC).isoformat(),
                "known_threat_locations": [],
            },
            "indicators": {
                "count": sum(database.get_indicator_counts().values()),
                "last_checked_at": datetime.now(UTC).isoformat(),
            },
        }

        # Get recent alerts
        recent_alerts = database.get_alerts(limit=10, offset=0)
        alerts_data = [AlertResponse(**a.to_dict()) for a in recent_alerts]

        # Get health status
        health_status = get_health_status(database, matcher)
        health_components = health_status.get("components", {})
        health_checks = []
        for component, detail in health_components.items():
            health_checks.append(
                {
                    "component": component,
                    "status": detail.get("status", "unknown"),
                    "message": detail.get("message", ""),
                }
            )

        # Get latest news
        latest_news = get_feed().get_latest(limit=100)  # Top 100 news items

        # Get Arkime status
        try:
            arkime_setup = ArkimeSetupManager()
            arkime_info = arkime_setup.check_installation()
        except:
            arkime_info = None

        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "stats": stats,
                "recent_alerts": alerts_data,
                "health_checks": health_checks,
                "health_components": health_components,
                "latest_news": latest_news,
                "arkime_status": arkime_info,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        import traceback

        logger.error(f"Traceback: {traceback.format_exc()}")
        return templates.TemplateResponse(
            "error.html", {"request": request, "error": str(e)}
        )


@app.get("/dashboard/status")
async def status_dashboard(request: Request):
    """System status dashboard"""
    try:
        if _threat_matcher is None:
            return templates.TemplateResponse(
                "error.html", {"request": request, "error": "System not initialized."}
            )

        matcher = _threat_matcher

        status_data = {
            "system": matcher.get_status(),
            "feeds": {
                "misp": matcher.misp_feed.get_status(),
                "pfblocker": matcher.pfblocker_feed.get_status(),
                "abuseipdb": matcher.abuseipdb_feed.get_status()
                if hasattr(matcher, "abuseipdb_feed")
                else {"status": "not_configured"},
                "cvedetails": matcher.cvedetails_feed.get_status(),
                "cisa_kev": matcher.cisa_kev_feed.get_status(),
                "shadowserver": matcher.shadowserver_feed.get_status(),
            },
            "captures": matcher.pcap_capture.get_active_captures(),
        }

        return templates.TemplateResponse(
            "status.html",
            {
                "request": request,
                "status": status_data,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"Status dashboard error: {e}")
        return templates.TemplateResponse(
            "error.html", {"request": request, "error": str(e)}
        )


@app.get("/api/dashboard/health")
async def api_dashboard_health():
    """API endpoint for dashboard health JSON"""
    if _db is None or _threat_matcher is None:
        raise HTTPException(status_code=503, detail="System not initialized")

    health_data = get_health_status(_db, _threat_matcher)
    return {
        "status": "success",
        "last_checked_at": datetime.now(UTC).isoformat(),
        "health": health_data,
    }


@app.get("/dashboard/health")
async def health_dashboard(request: Request):
    """System health dashboard"""
    try:
        if _db is None or _threat_matcher is None:
            return templates.TemplateResponse(
                "error.html", {"request": request, "error": "System not initialized."}
            )

        database = _db
        matcher = _threat_matcher

        health_data = {
            "database": {
                "status": "healthy",
                "alerts_count": database.get_alert_stats().get("total", 0),
                "indicators_count": sum(database.get_indicator_counts().values()),
            },
            "feeds": {
                "misp": matcher.misp_feed.get_status(),
                "pfblocker": matcher.pfblocker_feed.get_status(),
                "abuseipdb": matcher.abuseipdb_feed.get_status()
                if hasattr(matcher, "abuseipdb_feed")
                else {"status": "not_configured"},
                "cvedetails": matcher.cvedetails_feed.get_status(),
                "cisa_kev": matcher.cisa_kev_feed.get_status(),
                "shadowserver": matcher.shadowserver_feed.get_status(),
            },
            "capture": {
                "active_captures": len(matcher.pcap_capture.get_active_captures()),
                "status": "operational",
            },
            "system": matcher.get_status(),
        }

        return templates.TemplateResponse(
            "health.html",
            {
                "request": request,
                "health": health_data,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"Health dashboard error: {e}")
        return templates.TemplateResponse(
            "error.html", {"request": request, "error": str(e)}
        )


@app.get("/dashboard/checks")
async def checks_dashboard(request: Request):
    """Health checks checkmarks dashboard"""
    try:
        if _db is None or _threat_matcher is None:
            return templates.TemplateResponse(
                "error.html", {"request": request, "error": "System not initialized."}
            )

        health_status = get_health_status(_db, _threat_matcher)

        checks = []
        for component, detail in health_status.get("components", {}).items():
            status = detail.get("status", "unknown")
            check_pass = status in ["healthy", "configured", "operational", "available"]
            checks.append(
                {
                    "component": component,
                    "status": status,
                    "message": detail.get("message", ""),
                    "details": detail.get("details", {}),
                    "pass": check_pass,
                }
            )

        return templates.TemplateResponse(
            "checks.html",
            {
                "request": request,
                "health_status": health_status,
                "checks": checks,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"Checks dashboard error: {e}")
        return templates.TemplateResponse(
            "error.html", {"request": request, "error": str(e)}
        )


@app.get("/dashboard/events")
async def events_dashboard(request: Request):
    """Events/Alerts dashboard"""
    try:
        if _db is None:
            return templates.TemplateResponse(
                "error.html", {"request": request, "error": "Database not initialized."}
            )

        database = _db

        # Get alerts with pagination
        alerts = database.get_alerts(limit=50, offset=0)
        alerts_data = [AlertResponse(**a.to_dict()) for a in alerts]
        stats = database.get_alert_stats()

        return templates.TemplateResponse(
            "events.html",
            {
                "request": request,
                "alerts": alerts_data,
                "stats": stats,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"Events dashboard error: {e}")
        return templates.TemplateResponse(
            "error.html", {"request": request, "error": str(e)}
        )


@app.get("/dashboard/news")
async def news_dashboard(request: Request):
    """Cybersecurity news dashboard - curated threat intelligence"""
    try:
        news_items = get_feed().get_latest(limit=50)

        # Get GrayNoise recent activity if configured
        graynoise_items = []
        graynoise_error = None
        try:
            from app.config.feed_credentials import FeedCredentialManager
            from app.feeds.greynoise import get_greynoise_connector

            cred_manager = FeedCredentialManager()
            creds = cred_manager.get_graynoise_credentials()

            if creds and creds.get("api_key") and creds.get("enabled"):
                connector = get_greynoise_connector(
                    api_key=creds.get("api_key", ""),
                    use_community=(creds.get("api_type") == "community"),
                    database=None,
                )
                gn_results, _ = connector.query_ips_by_age(days=2, limit=20)
                graynoise_items = gn_results
        except Exception as e:
            graynoise_error = str(e)

        return templates.TemplateResponse(
            "news.html",
            {
                "request": request,
                "news_items": news_items,
                "graynoise_items": graynoise_items,
                "graynoise_error": graynoise_error,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"News dashboard error: {e}")
        return templates.TemplateResponse(
            "error.html", {"request": request, "error": str(e)}
        )


@app.get("/dashboard/cves")
async def cve_dashboard(request: Request, limit: int = 50):
    """CVE vulnerability news dashboard with severity tracking"""
    try:
        cve_feed = get_cve_feed()
        cve_summary = cve_feed.get_summary()

        if (
            cve_summary.get("year_count", 0) == 0
            and cve_summary.get("month_count", 0) == 0
        ):
            try:
                cve_feed.fetch_all_periods()
                cve_summary = cve_feed.get_summary()
            except Exception as refresh_err:
                logger.warning(f"Could not refresh CVE feed: {refresh_err}")

        return templates.TemplateResponse(
            "cve_news.html",
            {
                "request": request,
                "cve_summary": cve_summary,
                "cve_limit": limit,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"CVE dashboard error: {e}")
        return templates.TemplateResponse(
            "error.html", {"request": request, "error": str(e)}
        )


@app.get("/dashboard/actors")
async def threat_actors_dashboard(request: Request, refresh: bool = False):
    """Threat actors dashboard - organized by country"""
    try:
        from app.threat_intel.actors import get_threat_intelligence
        from app.models.database import Database

        db = Database(db_path=getattr(settings, "database_path", "data/cig.db"))

        threat_intel = get_threat_intelligence(db)

        # Initialize default actors if none exist or refresh requested
        existing_actors = db.get_threat_actors_by_country()
        if not existing_actors or refresh:
            threat_intel.initialize_default_actors(db)
            existing_actors = db.get_threat_actors_by_country()

        # Get stats
        stats = threat_intel.get_stats()

        # Get countries
        countries = db.get_all_countries_with_actors()

        # Group actors by country
        actors_by_country = {}
        for actor in existing_actors:
            country = actor.get("country", "Unknown")
            if country not in actors_by_country:
                actors_by_country[country] = []
            actors_by_country[country].append(actor)

        return templates.TemplateResponse(
            "threat_actors.html",
            {
                "request": request,
                "actors_by_country": actors_by_country,
                "countries": countries,
                "stats": stats,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"Threat actors dashboard error: {e}")
        import traceback

        traceback.print_exc()
        return templates.TemplateResponse(
            "error.html", {"request": request, "error": str(e)}
        )


@app.get("/dashboard/actors/{actor_id}")
async def threat_actor_detail(request: Request, actor_id: str):
    """Threat actor detail page with activities and assessment"""
    try:
        from app.threat_intel.actors import get_threat_intelligence
        from app.models.database import Database

        db = Database(db_path=getattr(settings, "database_path", "data/cig.db"))
        threat_intel = get_threat_intelligence(db)

        # Get actor details
        actor = threat_intel.get_actor_by_id(actor_id)
        if not actor:
            raise HTTPException(status_code=404, detail="Threat actor not found")

        # Get activities
        activities = threat_intel.get_actor_activities(actor_id, limit=50)

        # Generate assessment
        assessment = threat_intel.generate_assessment(actor_id)

        # Get malware links for associated malware
        malware_links = threat_intel.get_all_malware_links(actor)

        # Get OpenCTI status
        opencti_status = threat_intel.get_opencti_status()

        # Get related alerts based on actor indicators
        related_alerts = []
        if actor.get("associated_malware"):
            # Could query alerts for related indicators
            pass

        return templates.TemplateResponse(
            "actor_detail.html",
            {
                "request": request,
                "actor": actor,
                "activities": activities,
                "assessment": assessment,
                "related_alerts": related_alerts,
                "malware_links": malware_links,
                "opencti_status": opencti_status,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Threat actor detail error: {e}")
        import traceback

        traceback.print_exc()
        return templates.TemplateResponse(
            "error.html", {"request": request, "error": str(e)}
        )


@app.get("/dashboard/arkime")
async def arkime_dashboard(request: Request):
    """Arkime installation and management dashboard"""
    try:
        arkime_setup = ArkimeSetupManager()
        so_integration = SecurityOnionIntegration()

        arkime_status = arkime_setup.check_installation()
        so_info = so_integration.get_deployment_info()
        arkime_info = arkime_setup.get_system_info()

        return templates.TemplateResponse(
            "arkime.html",
            {
                "request": request,
                "arkime_status": arkime_status,
                "so_info": so_info,
                "arkime_info": arkime_info,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"Arkime dashboard error: {e}")
        return templates.TemplateResponse(
            "error.html", {"request": request, "error": str(e)}
        )


@app.get("/dashboard/reports")
async def reports_dashboard(request: Request):
    """Reports dashboard"""
    try:
        if _threat_matcher is None:
            return templates.TemplateResponse(
                "error.html", {"request": request, "error": "System not initialized."}
            )

        matcher = _threat_matcher

        # Generate quick report data
        report_data = {
            "summary": {
                "total_alerts": 0,
                "active_feeds": 0,
                "system_status": "operational",
            },
            "recent_reports": [],
        }

        # Try to get basic stats
        try:
            if _db:
                database = _db
                alert_stats = database.get_alert_stats()
                report_data["summary"]["total_alerts"] = alert_stats.get("total", 0)
        except:
            pass

        return templates.TemplateResponse(
            "reports.html",
            {
                "request": request,
                "report_data": report_data,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"Reports dashboard error: {e}")
        return templates.TemplateResponse(
            "error.html", {"request": request, "error": str(e)}
        )


# --- Reporting Endpoints ---


@app.get("/api/reports/security")
async def generate_security_report(days: int = Query(7, ge=1, le=90)):
    """Generate a comprehensive security report"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    try:
        report = threat_matcher.generate_security_report(days)
        return report
    except Exception as e:
        logger.error(f"Failed to generate security report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report")


@app.get("/api/news")
async def api_cyber_news(
    limit: int = Query(100, ge=1, le=100),
    source: str = Query(
        "", description="Filter by source: SANS, CVE, APT, or empty for all"
    ),
):
    """Latest curated cybersecurity news, IOC and mitigation signatures with optional source filtering"""
    try:
        news_items = get_feed().get_latest(limit=limit)

        # Filter by source if specified
        if source:
            source_lower = source.lower()
            filtered = []
            for item in news_items:
                item_source = item.get("source", "").lower()
                item_id = item.get("id", "").lower()

                # Match by source field or ID prefix
                if source_lower in item_source or source_lower in item_id:
                    filtered.append(item)
            news_items = filtered

        return {
            "status": "success",
            "items": news_items,
            "count": len(news_items),
            "source_filter": source if source else "all",
        }
    except Exception as e:
        logger.error(f"Failed to fetch news: {e}")
        raise HTTPException(status_code=500, detail="Failed to load cyber news")


@app.get("/api/news/sources")
async def api_news_sources():
    """Get available news feed sources"""
    try:
        news_items = get_feed().get_latest(limit=100)

        # Extract unique sources
        sources = set()
        for item in news_items:
            source = item.get("source", "Unknown")
            sources.add(source)

        # Detect feed types from IDs
        feed_types = set()
        for item in news_items:
            item_id = item.get("id", "")
            if "sans" in item_id.lower():
                feed_types.add("SANS")
            elif "cve" in item_id.lower() or "cve" in item.get("cve", "").lower():
                feed_types.add("CVE")
            if "apt" in item.get("summary", "").lower():
                feed_types.add("APT")

        return {
            "status": "success",
            "sources": sorted(list(sources)),
            "feed_types": sorted(list(feed_types)),
        }
    except Exception as e:
        logger.error(f"Failed to fetch news sources: {e}")
        raise HTTPException(status_code=500, detail="Failed to load news sources")


@app.get("/api/feeds/dshield/threats")
async def api_dshield_threats():
    """Get real-time DShield honeypot threat summary"""
    try:
        from app.feeds.dshield_polling import get_dshield_poller

        poller = get_dshield_poller()
        threats = poller.summarize_threats()

        return {
            "status": "success",
            "dshield_threats": threats,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    except Exception as e:
        logger.error(f"Failed to fetch DShield threats: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch DShield data")


@app.get("/api/feeds/dshield/ssh")
async def api_dshield_ssh(limit: int = Query(100, ge=1, le=500)):
    """Get latest DShield SSH honeypot attackers"""
    try:
        from app.feeds.dshield_polling import get_dshield_poller

        poller = get_dshield_poller()
        attackers = poller.poll_ssh_attackers(limit=limit)

        return {
            "status": "success",
            "ssh_attackers": attackers,
            "count": len(attackers),
            "last_updated": poller.last_ssh_poll.isoformat()
            if poller.last_ssh_poll
            else None,
        }
    except Exception as e:
        logger.error(f"Failed to fetch DShield SSH data: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch DShield SSH data")


@app.get("/api/feeds/dshield/web")
async def api_dshield_web(limit: int = Query(100, ge=1, le=500)):
    """Get latest DShield web honeypot scanners"""
    try:
        from app.feeds.dshield_polling import get_dshield_poller

        poller = get_dshield_poller()
        scanners = poller.poll_web_attackers(limit=limit)

        return {
            "status": "success",
            "web_scanners": scanners,
            "count": len(scanners),
            "last_updated": poller.last_web_poll.isoformat()
            if poller.last_web_poll
            else None,
        }
    except Exception as e:
        logger.error(f"Failed to fetch DShield Web data: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch DShield Web data")


@app.get("/api/news/cve")
async def api_cve_news(
    limit: int = Query(10, ge=1, le=100),
    period: str = Query(
        "day", description="Time period: day, week, month, year, historical, all"
    ),
    search: str = Query(
        "", description="Search term (cve id, vendor, product, keyword)"
    ),
    severity: str = Query("", description="Filter by severity: critical, high, medium"),
):
    """High-level CVE news with IOCs, signatures, and MITRE T-codes"""
    try:
        cve_feed = get_cve_feed()

        # Get CVEs by time period
        if period and period != "all":
            cve_items = cve_feed.get_by_period(period)
        else:
            cve_items = cve_feed.get_latest(limit=100)  # Get more for searching

        # Apply search filter
        if search:
            search_lower = search.lower()
            filtered_items = []
            for item in cve_items:
                # Search in CVE ID, title, summary, vendor, product, cves
                searchable_text = " ".join(
                    [
                        str(item.get("cve", "")),
                        str(item.get("title", "")),
                        str(item.get("summary", "")),
                        str(item.get("vendor", "")),
                        str(item.get("product", "")),
                        " ".join(item.get("cwes", [])),
                    ]
                ).lower()

                if search_lower in searchable_text:
                    filtered_items.append(item)
            cve_items = filtered_items

        # Apply severity filter
        if severity:
            severity_lower = severity.lower()
            cve_items = [
                item
                for item in cve_items
                if item.get("severity", "").lower() == severity_lower
            ]

        # Add threat matcher CVE news if available
        if threat_matcher and hasattr(threat_matcher, "cve_news_feed"):
            try:
                news_items = threat_matcher.cve_news_feed.get_latest(limit=limit)
                if news_items and not cve_items:
                    cve_items = news_items
            except Exception:
                pass

        return {
            "status": "success",
            "items": cve_items[:limit],
            "count": len(cve_items),
            "period": period,
            "search": search,
            "filters": {"severity": severity} if severity else None,
            "summary": cve_feed.get_summary(),
            "last_update": cve_feed.last_fetch.isoformat()
            if cve_feed.last_fetch
            else None,
        }
    except Exception as e:
        logger.error(f"Failed to fetch CVE news: {e}")
        raise HTTPException(status_code=500, detail="Failed to load CVE news")


import asyncio
import threading

# Background fetch state
cve_fetch_in_progress = False
cve_fetch_status = {"status": "idle", "message": "", "progress": 0}


def fetch_cve_data_background():
    """Background thread function to fetch CVE data"""
    global cve_fetch_in_progress, cve_fetch_status
    try:
        cve_feed = get_cve_feed()
        cve_fetch_status = {
            "status": "fetching",
            "message": "Fetching CVE data...",
            "progress": 10,
        }

        counts = cve_feed.fetch_all_periods()

        cve_fetch_status = {
            "status": "complete",
            "message": "CVE data refreshed successfully",
            "progress": 100,
        }
    except Exception as e:
        logger.error(f"Background CVE fetch failed: {e}")
        cve_fetch_status = {"status": "error", "message": str(e), "progress": 0}
    finally:
        cve_fetch_in_progress = False


@app.get("/api/news/cve/status")
async def api_cve_status():
    """Get CVE background fetch status"""
    cve_feed = get_cve_feed()
    summary = cve_feed.get_summary()

    # Get severity counts too
    severity_counts = {"critical": 0, "high": 0, "medium": 0}
    try:
        all_severities = cve_feed.get_all_severities(limit_per_severity=5000)
        severity_counts = {
            "critical": len(all_severities.get("critical", [])),
            "high": len(all_severities.get("high", [])),
            "medium": len(all_severities.get("medium", [])),
        }
    except:
        pass

    return {
        "status": "success",
        "in_progress": cve_fetch_in_progress,
        "fetch_status": cve_fetch_status,
        "summary": summary,
        "critical_count": severity_counts["critical"],
        "high_count": severity_counts["high"],
        "medium_count": severity_counts["medium"],
    }


@app.post("/api/news/cve/refresh")
async def api_cve_news_refresh(background_tasks: BackgroundTasks):
    """Refresh all CVE news data in background (day/week/month/year/historical)"""
    global cve_fetch_in_progress, cve_fetch_status

    if cve_fetch_in_progress:
        return {
            "status": "already_running",
            "message": "CVE refresh already in progress",
            "fetch_status": cve_fetch_status,
        }

    cve_fetch_in_progress = True
    cve_fetch_status = {
        "status": "starting",
        "message": "Starting CVE data refresh...",
        "progress": 0,
    }

    # Run in background
    background_tasks.add_task(run_cve_refresh)

    return {
        "status": "started",
        "message": "CVE data refresh started in background",
    }


@app.post("/api/news/cve/fetch-all")
async def api_cve_fetch_all(background_tasks: BackgroundTasks):
    """Fetch ALL CVEs from 1999 to present - comprehensive historical data"""
    global cve_fetch_in_progress, cve_fetch_status

    if cve_fetch_in_progress:
        return {
            "status": "already_running",
            "message": "CVE fetch already in progress",
            "fetch_status": cve_fetch_status,
        }

    cve_fetch_in_progress = True
    cve_fetch_status = {
        "status": "starting",
        "message": "Starting comprehensive CVE fetch from 1999 to present...",
        "progress": 0,
    }

    background_tasks.add_task(run_cve_comprehensive)

    return {
        "status": "started",
        "message": "Comprehensive CVE fetch started in background - this will take some time but will fetch all historical CVEs",
    }


async def run_cve_refresh():
    """Async wrapper to run CVE refresh"""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, fetch_cve_data_background)


async def run_cve_comprehensive():
    """Async wrapper to run comprehensive CVE fetch"""
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, fetch_cve_comprehensive_background)


def fetch_cve_comprehensive_background():
    """Background task to fetch ALL CVEs from 1999 to present"""
    global cve_fetch_in_progress, cve_fetch_status
    try:
        cve_fetch_status = {
            "status": "starting",
            "message": "Starting comprehensive CVE fetch (1999-present)...",
            "progress": 0,
        }
        cve_feed = get_cve_feed()
        result = cve_feed.fetch_comprehensive()

        cve_fetch_status = {
            "status": "complete",
            "message": f"Comprehensive CVE fetch complete: {result.get('total', 0)} total CVEs",
            "progress": 100,
        }
    except Exception as e:
        logger.error(f"Comprehensive CVE fetch failed: {e}")
        cve_fetch_status = {"status": "error", "message": str(e), "progress": 0}
    finally:
        cve_fetch_in_progress = False


@app.get("/api/news/cve/severity")
async def api_cve_by_severity(
    limit: int = Query(5000, ge=1),
    severity: str = "",
):
    """Get CVEs by severity level - default 5000 per severity"""
    try:
        cve_feed = get_cve_feed()

        if severity:
            # Return specific severity
            items = cve_feed.get_by_severity(severity, limit)
            return {
                "status": "success",
                "severity": severity.lower(),
                "items": items,
                "count": len(items),
            }
        else:
            # Return all severities with the requested limit each
            result = cve_feed.get_all_severities(limit_per_severity=limit)
            return {
                "status": "success",
                "critical_count": len(result["critical"]),
                "high_count": len(result["high"]),
                "medium_count": len(result["medium"]),
                "critical": result["critical"],
                "high": result["high"],
                "medium": result["medium"],
            }
    except Exception as e:
        logger.error(f"Failed to fetch CVE by severity: {e}")
        raise HTTPException(status_code=500, detail="Failed to load CVE by severity")


@app.get("/api/news/ai")
async def api_cyber_news_ai(
    query: str = Query(
        ..., min_length=3, description="Search term for AI-driven threat hunting"
    ),
):
    """AI incident hunter for exploratory threat matching and playbook recommendations"""
    try:
        feed = get_feed()
        news_items = feed.get_latest(limit=50)
        q = query.strip().lower()

        matched = []
        for item in news_items:
            text = " ".join(
                [
                    str(item.get(field, "")).lower()
                    for field in ["title", "summary", "source", "cve", "iocs"]
                ]
            )
            if q in text:
                matched.append(item)

        playbook = [
            "Validate included IOCs in detection pipeline (IDS/WAF/EPP)",
            "Cross-check CVE details and apply vendor patches immediately",
            "Populate SIEM with behavior rules from article signature sections",
        ]

        ai_context = {
            "query": query,
            "matches": len(matched),
            "ai_hypotheses": [
                f"Potential campaign type aligned to {item.get('source')} feed"
                for item in matched[:3]
            ],
            "suggested_actions": playbook,
        }

        return {
            "status": "success",
            "query": query,
            "result_count": len(matched),
            "matches": matched,
            "ai_context": ai_context,
        }
    except Exception as e:
        logger.error(f"AI news hunter failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to run AI incident hunter")


@app.get("/api/news/verify")
async def api_cyber_news_verify(
    network_check: bool = Query(
        False, description="Perform network reachability check if True"
    ),
):
    """Return all news feed URLs with parsed validation and optional reachable status"""
    try:
        feed = get_feed()
        news_items = feed.get_latest(limit=50)
        verified_items = []

        for item in news_items:
            source_url = item.get("source_url")
            cve_url = item.get("cve_url")

            source_parsed = urlparse(source_url) if source_url else None
            cve_parsed = urlparse(cve_url) if cve_url else None

            source_valid = bool(
                source_parsed
                and source_parsed.scheme in ["http", "https"]
                and source_parsed.netloc
            )
            cve_valid = bool(
                cve_parsed
                and cve_parsed.scheme in ["http", "https"]
                and cve_parsed.netloc
            )

            source_reachable = None
            cve_reachable = None
            if network_check:
                # Try requests first, then urllib as fallback
                try:
                    import requests

                    http_head = lambda url: requests.head(
                        url, timeout=5, allow_redirects=True
                    )
                except ImportError:
                    import urllib.request

                    def urllib_head(url):
                        req = urllib.request.Request(
                            url, method="HEAD", headers={"User-Agent": "CIG/1.0"}
                        )
                        with urllib.request.urlopen(req, timeout=5) as resp:
                            return resp

                    http_head = urllib_head

                if source_valid:
                    try:
                        r = http_head(source_url)
                        source_reachable = (
                            getattr(r, "status", None)
                            or getattr(r, "getcode", lambda: None)()
                        ) < 400
                    except Exception:
                        source_reachable = False

                if cve_url and cve_valid:
                    try:
                        r = http_head(cve_url)
                        cve_reachable = (
                            getattr(r, "status", None)
                            or getattr(r, "getcode", lambda: None)()
                        ) < 400
                    except Exception:
                        cve_reachable = False

            verified_items.append(
                {
                    "id": item.get("id"),
                    "title": item.get("title"),
                    "source_url": source_url,
                    "source_valid": source_valid,
                    "source_reachable": source_reachable,
                    "cve_url": cve_url,
                    "cve_valid": cve_valid,
                    "cve_reachable": cve_reachable,
                }
            )

        return {
            "status": "success",
            "network_check": network_check,
            "verified_count": len(verified_items),
            "items": verified_items,
        }
    except Exception as e:
        logger.error(f"Failed to verify news links: {e}")
        raise HTTPException(status_code=500, detail="Failed to verify news links")


@app.get("/api/news/verify/summary")
async def api_cyber_news_verify_summary():
    """Summary of news link verification result counts"""
    try:
        feed = get_feed()
        news_items = feed.get_latest(limit=50)
        confirmed = 0
        invalid = 0

        for item in news_items:
            source_url = item.get("source_url")
            cve_url = item.get("cve_url")
            source_parsed = urlparse(source_url) if source_url else None
            cve_parsed = urlparse(cve_url) if cve_url else None

            source_valid = bool(
                source_parsed
                and source_parsed.scheme in ["http", "https"]
                and source_parsed.netloc
            )
            cve_valid = bool(
                cve_parsed
                and cve_parsed.scheme in ["http", "https"]
                and cve_parsed.netloc
            )

            if source_valid and (cve_url is None or cve_valid):
                confirmed += 1
            else:
                invalid += 1

        return {
            "status": "success",
            "total": len(news_items),
            "confirmed": confirmed,
            "invalid": invalid,
        }
    except Exception as e:
        logger.error(f"Failed to generate verify summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate verify summary")


# --- Arkime Integration Endpoints ---


@app.get("/api/arkime/status")
async def arkime_status():
    """Check Arkime installation and status"""
    try:
        arkime_setup = ArkimeSetupManager()
        status = arkime_setup.check_installation()
        return {"status": "success", "arkime": status}
    except Exception as e:
        logger.error(f"Failed to check Arkime status: {e}")
        raise HTTPException(status_code=500, detail="Failed to check Arkime status")


@app.get("/api/arkime/info")
async def arkime_info():
    """Get Arkime system information"""
    try:
        arkime_setup = ArkimeSetupManager()
        info = arkime_setup.get_system_info()
        validation = arkime_setup.validate_configuration()
        return {
            "status": "success",
            "info": info,
            "configuration": validation,
        }
    except Exception as e:
        logger.error(f"Failed to get Arkime info: {e}")
        raise HTTPException(status_code=500, detail="Failed to get Arkime info")


@app.get("/api/arkime/installation-guide")
async def arkime_installation_guide():
    """Get Arkime installation guide"""
    try:
        arkime_setup = ArkimeSetupManager()
        guide = arkime_setup.get_installation_guide()
        return {"status": "success", "guide": guide}
    except Exception as e:
        logger.error(f"Failed to get installation guide: {e}")
        raise HTTPException(status_code=500, detail="Failed to get installation guide")


@app.get("/api/arkime/security-onion")
async def arkime_security_onion_info():
    """Get Security Onion + Arkime integration info"""
    try:
        so_integration = SecurityOnionIntegration()
        info = so_integration.get_deployment_info()
        return {"status": "success", "security_onion": info}
    except Exception as e:
        logger.error(f"Failed to get Security Onion info: {e}")
        raise HTTPException(status_code=500, detail="Failed to get Security Onion info")


@app.get("/api/reports/html")
async def generate_html_report(days: int = Query(7, ge=1, le=90)):
    """Generate an HTML security report"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    try:
        html_path = threat_matcher.generate_html_report(days)
        return {
            "html_report_path": html_path,
            "message": "HTML report generated successfully",
        }
    except Exception as e:
        logger.error(f"Failed to generate HTML report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate HTML report")


# --- MITRE ATT&CK Endpoints ---


@app.post("/api/mitre/analyze")
async def analyze_alert_for_mitre(alert_data: dict):
    """Analyze an alert for MITRE ATT&CK TTP matches"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    try:
        ttps = threat_matcher.analyze_alert_for_mitre(alert_data)
        return {"ttps": ttps}
    except Exception as e:
        logger.error(f"Failed to analyze alert for MITRE: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze alert")


@app.get("/api/mitre/techniques")
async def get_mitre_techniques():
    """Get all MITRE ATT&CK techniques"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    try:
        techniques = threat_matcher.get_mitre_techniques()
        return {"techniques": techniques}
    except Exception as e:
        logger.error(f"Failed to get MITRE techniques: {e}")
        raise HTTPException(status_code=500, detail="Failed to get techniques")


@app.get("/api/mitre/tactics")
async def get_mitre_tactics():
    """Get all MITRE ATT&CK tactics"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    try:
        tactics = threat_matcher.get_mitre_tactics()
        return {"tactics": tactics}
    except Exception as e:
        logger.error(f"Failed to get MITRE tactics: {e}")
        raise HTTPException(status_code=500, detail="Failed to get tactics")


# --- Feed Management Endpoints ---


@app.post("/api/feeds/update/abuseipdb")
async def update_abuseipdb_feed():
    """Manually trigger AbuseIPDB feed update"""
    if not threat_matcher:
        raise HTTPException(status_code=503, detail="System not initialized")

    try:
        count = threat_matcher._update_abuseipdb()
        return {"status": "updated", "indicators_count": count}
    except Exception as e:
        logger.error(f"Failed to update AbuseIPDB: {e}")
        raise HTTPException(status_code=500, detail="Failed to update AbuseIPDB feed")


# --- Feed Scheduler Endpoints ---


@app.get("/api/feeds/scheduler/status")
@app.get("/api/scheduler/status")
async def scheduler_status():
    """Get feed scheduler status"""
    try:
        scheduler = get_scheduler()
        status = scheduler.get_feed_status()
        return {
            "status": "success",
            "scheduler_running": scheduler.scheduler_running,
            "feeds": status,
            "config_file": str(scheduler.state_file),
        }
    except Exception as e:
        logger.error(f"Failed to get scheduler status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scheduler status")


@app.post("/api/feeds/scheduler/start")
@app.post("/api/scheduler/start")
async def scheduler_start():
    """Start the feed scheduler"""
    try:
        scheduler = get_scheduler()
        await scheduler.start_scheduler()
        return {
            "status": "success",
            "message": "Feed scheduler started",
            "running": scheduler.scheduler_running,
        }
    except Exception as e:
        logger.error(f"Failed to start scheduler: {e}")
        raise HTTPException(status_code=500, detail="Failed to start scheduler")


@app.post("/api/feeds/scheduler/stop")
@app.post("/api/scheduler/stop")
async def scheduler_stop():
    """Stop the feed scheduler"""
    try:
        scheduler = get_scheduler()
        await scheduler.stop_scheduler()
        return {
            "status": "success",
            "message": "Feed scheduler stopped",
            "running": scheduler.scheduler_running,
        }
    except Exception as e:
        logger.error(f"Failed to stop scheduler: {e}")
        raise HTTPException(status_code=500, detail="Failed to stop scheduler")


@app.post("/api/feeds/scheduler/update/{feed_id}")
@app.post("/api/scheduler/feed/{feed_id}/update")
async def scheduler_update_feed(feed_id: str, force: bool = False):
    """Trigger immediate feed update"""
    try:
        scheduler = get_scheduler()
        success, error = await scheduler.update_feed(feed_id, force=force)
        return {
            "status": "success" if success else "failed",
            "feed_id": feed_id,
            "message": error if error else "Feed updated successfully",
        }
    except Exception as e:
        logger.error(f"Failed to update feed {feed_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update feed: {e}")


@app.post("/api/feeds/scheduler/update/all")
@app.post("/api/scheduler/update-all")
async def scheduler_update_all(force: bool = False):
    """Trigger updates for all registered feeds"""
    try:
        scheduler = get_scheduler()
        results = await scheduler.update_all_feeds(force=force)
        return {"status": "success", "message": "All feeds updated", "results": results}
    except Exception as e:
        logger.error(f"Failed to update all feeds: {e}")
        raise HTTPException(status_code=500, detail="Failed to update all feeds")


# --- DShield Polling Endpoints ---


@app.get("/api/feeds/dshield/status")
async def dshield_status():
    """Get DShield feed status and statistics"""
    try:
        dshield = get_dshield_poller()
        stats = dshield.get_stats()
        return {
            "status": "success",
            "stats": {
                "last_update": stats.last_update_time,
                "total_ssh_attacks": stats.total_ssh_attacks,
                "total_web_attacks": stats.total_web_attacks,
                "failed_polls": stats.failed_polls,
                "last_error": stats.last_error,
            },
        }
    except Exception as e:
        logger.error(f"Failed to get DShield status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get DShield status")


@app.post("/api/feeds/dshield/poll")
async def dshield_poll(poll_type: str = "all"):
    """Manually trigger DShield polling"""
    try:
        dshield = get_dshield_poller()

        if poll_type == "ssh":
            attacks, success = dshield.poll_ssh_attackers()
            return {
                "status": "success" if success else "failed",
                "type": "ssh",
                "count": len(attacks),
                "attacks": attacks[:10],  # Return first 10
            }
        elif poll_type == "web":
            attacks, success = dshield.poll_web_attackers()
            return {
                "status": "success" if success else "failed",
                "type": "web",
                "count": len(attacks),
                "attacks": attacks[:10],
            }
        else:  # all
            ssh_attacks, ssh_success = dshield.poll_ssh_attackers()
            web_attacks, web_success = dshield.poll_web_attackers()
            return {
                "status": "success" if (ssh_success or web_success) else "failed",
                "ssh": {"count": len(ssh_attacks), "success": ssh_success},
                "web": {"count": len(web_attacks), "success": web_success},
            }
    except Exception as e:
        logger.error(f"Failed to poll DShield: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to poll DShield: {e}")


@app.get("/api/feeds/dshield/threats")
async def dshield_threat_summary():
    """Get DShield threat summary"""
    try:
        dshield = get_dshield_poller()
        summary = dshield.summarize_threats()
        return {"status": "success", "summary": summary}
    except Exception as e:
        logger.error(f"Failed to get DShield summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to get threat summary")


# --- Filter Engine Endpoints ---


class FilterConfigRequest(BaseModel):
    filter_id: str
    filter_name: str
    indicator_types: Optional[List[str]] = None
    min_severity: str = "LOW"
    max_age_days: int = 30
    exclude_feeds: Optional[List[str]] = None
    enabled: bool = False


@app.get("/api/feeds/filters/status")
@app.get("/api/filters/status")
async def filters_status():
    """Get filter engine status"""
    try:
        filter_engine = get_filter_engine()
        filters = filter_engine.list_filters()
        return {
            "status": "success",
            "active_filters": len([f for f in filters if f.get("enabled")]),
            "total_filters": len(filters),
            "filters": filters,
        }
    except Exception as e:
        logger.error(f"Failed to get filters status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get filters status")


@app.post("/api/feeds/filters/apply")
@app.post("/api/filters/apply")
async def filters_apply(feed_id: str, filter_id: Optional[str] = None):
    """Apply filter to a specific feed's indicators"""
    try:
        filter_engine = get_filter_engine()
        db = get_db()
        indicators = db.get_indicators_by_feed(feed_id)

        if filter_id:
            filtered = filter_engine.filter_indicators(indicators, filter_id=filter_id)
        else:
            filtered = filter_engine.filter_indicators(indicators, feed_id=feed_id)

        return {
            "status": "success",
            "feed_id": feed_id,
            "original_count": len(indicators),
            "filtered_count": len(filtered),
            "filtered_indicators": filtered[:20],  # Return first 20
        }
    except Exception as e:
        logger.error(f"Failed to apply filters: {e}")
        raise HTTPException(status_code=500, detail="Failed to apply filters")


# --- Feed Credentials & Configuration Endpoints ---


class NessusCredentialsRequest(BaseModel):
    api_key: str
    api_secret: str
    host: str = "https://cloud.nessus.com"
    enabled: bool = False


class GrayNoiseCredentialsRequest(BaseModel):
    api_key: str
    api_type: str = "enterprise"
    enabled: bool = False


class CustomAPIFeedRequest(BaseModel):
    feed_id: str
    feed_name: str
    api_url: str
    auth_type: str
    auth_value: str
    custom_headers: Optional[Dict[str, str]] = None
    polling_interval_hours: int = 24
    enabled: bool = False


@app.get("/api/config/status")
async def config_status():
    """Get overall configuration status"""
    try:
        from app.config.feed_credentials import FeedCredentialManager

        cred_manager = FeedCredentialManager()
        status = cred_manager.get_status()
        return {"status": "success", "configuration": status}
    except Exception as e:
        logger.error(f"Failed to get config status: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to get configuration status"
        )


@app.post("/api/config/nessus/credentials")
async def config_nessus_credentials(request: NessusCredentialsRequest):
    """Set Nessus API credentials"""
    try:
        from app.config.feed_credentials import FeedCredentialManager

        cred_manager = FeedCredentialManager()
        success = cred_manager.set_nessus_credentials(
            api_key=request.api_key,
            api_secret=request.api_secret,
            host=request.host,
            enabled=request.enabled,
        )

        if success:
            return {
                "status": "success",
                "message": "Nessus credentials updated",
                "enabled": request.enabled,
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to save credentials")
    except Exception as e:
        logger.error(f"Failed to set Nessus credentials: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to set credentials: {e}")


@app.post("/api/config/graynoise/credentials")
async def config_graynoise_credentials(request: GrayNoiseCredentialsRequest):
    """Set GrayNoise API credentials"""
    try:
        from app.config.feed_credentials import FeedCredentialManager

        cred_manager = FeedCredentialManager()
        success = cred_manager.set_graynoise_credentials(
            api_key=request.api_key, api_type=request.api_type, enabled=request.enabled
        )

        if success:
            return {
                "status": "success",
                "message": "GrayNoise credentials updated",
                "enabled": request.enabled,
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to save credentials")
    except Exception as e:
        logger.error(f"Failed to set GrayNoise credentials: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to set credentials: {e}")


@app.post("/api/config/nessus/test")
async def test_nessus_connection():
    """Test Nessus API connection with saved credentials"""
    try:
        from app.config.feed_credentials import FeedCredentialManager

        cred_manager = FeedCredentialManager()
        creds = cred_manager.get_nessus_credentials()

        if not creds:
            raise HTTPException(
                status_code=400, detail="No Nessus credentials configured"
            )

        # Try to connect to Nessus API
        try:
            import httpx

            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                headers = {
                    "X-API-Token": creds.get("api_key", ""),
                }
                # Try a simple API call to verify credentials
                response = await client.get(
                    f"{creds.get('host', 'https://cloud.nessus.com')}/api/v2/scans",
                    headers=headers,
                )

                if response.status_code == 200:
                    return {
                        "status": "success",
                        "message": "Nessus connection successful",
                        "host": creds.get("host", "https://cloud.nessus.com"),
                        "credential_configured": True,
                    }
                elif response.status_code == 401:
                    return {
                        "status": "failed",
                        "message": "Nessus credentials are invalid (401 Unauthorized)",
                        "error": "Invalid API key or secret",
                    }
                else:
                    return {
                        "status": "failed",
                        "message": f"Nessus API returned status code {response.status_code}",
                        "error": response.text[:200]
                        if response.text
                        else "Unknown error",
                    }
        except httpx.TimeoutException:
            return {
                "status": "failed",
                "message": "Connection timeout - Nessus server not responding",
                "error": "Timeout after 10 seconds",
            }
        except Exception as conn_error:
            return {
                "status": "failed",
                "message": "Failed to connect to Nessus",
                "error": str(conn_error),
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to test Nessus connection: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to test connection: {e}")


@app.post("/api/config/graynoise/test")
async def test_graynoise_connection():
    """Test GrayNoise API connection with saved credentials"""
    try:
        from app.config.feed_credentials import FeedCredentialManager

        cred_manager = FeedCredentialManager()
        creds = cred_manager.get_graynoise_credentials()

        if not creds:
            raise HTTPException(
                status_code=400, detail="No GrayNoise credentials configured"
            )

        # Try to connect to GrayNoise API
        try:
            import httpx

            api_type = creds.get("api_type", "community")
            api_key = creds.get("api_key", "")

            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                headers = {
                    "Authorization": f"Bearer {api_key}",
                }

                # Different endpoints for community vs enterprise
                if api_type == "community":
                    url = "https://api.greynoise.io/v3/community/ip/8.8.8.8"
                else:
                    url = "https://api.greynoise.io/v3/query/listLimited?limit=1"

                response = await client.get(url, headers=headers)

                if response.status_code == 200:
                    return {
                        "status": "success",
                        "message": "GrayNoise connection successful",
                        "api_type": api_type,
                        "credential_configured": True,
                    }
                elif response.status_code == 401:
                    return {
                        "status": "failed",
                        "message": "GrayNoise credentials are invalid (401 Unauthorized)",
                        "error": "Invalid API key",
                    }
                elif response.status_code == 403:
                    return {
                        "status": "failed",
                        "message": "GrayNoise access forbidden (403 Forbidden)",
                        "error": "API key does not have permission for this endpoint",
                    }
                else:
                    return {
                        "status": "failed",
                        "message": f"GrayNoise API returned status code {response.status_code}",
                        "error": response.text[:200]
                        if response.text
                        else "Unknown error",
                    }
        except httpx.TimeoutException:
            return {
                "status": "failed",
                "message": "Connection timeout - GrayNoise server not responding",
                "error": "Timeout after 10 seconds",
            }
        except Exception as conn_error:
            return {
                "status": "failed",
                "message": "Failed to connect to GrayNoise",
                "error": str(conn_error),
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to test GrayNoise connection: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to test connection: {e}")


@app.get("/api/threats/graynoise/recent")
async def api_graynoise_recent(
    days: int = Query(2, ge=1, le=30, description="Days to look back (1-30)"),
    limit: int = Query(100, ge=1, le=500, description="Max results to return"),
):
    """Get recent malicious IPs from GrayNoise - similar to viz.greynoise.io query"""
    try:
        from app.feeds.greynoise import get_greynoise_connector
        from app.config.feed_credentials import FeedCredentialManager

        cred_manager = FeedCredentialManager()
        creds = cred_manager.get_graynoise_credentials()

        if not creds or not creds.get("api_key"):
            raise HTTPException(
                status_code=400, detail="GrayNoise API key not configured"
            )

        connector = get_greynoise_connector(
            api_key=creds.get("api_key", ""),
            use_community=(creds.get("api_type") == "community"),
            database=None,
        )

        # Query for recent malicious IPs
        results, success = connector.query_ips_by_age(days=days, limit=limit)

        if not success:
            return {
                "status": "partial",
                "message": "Some errors occurred during query",
                "days": days,
                "count": len(results),
                "items": results,
            }

        return {
            "status": "success",
            "query": f"last_seen:{days}d classification:malicious",
            "days": days,
            "count": len(results),
            "items": results[:limit],
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to query GrayNoise recent activity: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to query GrayNoise: {e}")


@app.get("/api/threats/graynoise/query")
async def api_graynoise_query(
    query: str = Query("last_seen:2d", description="GrayNoise query string"),
    limit: int = Query(100, ge=1, le=500, description="Max results"),
):
    """Execute custom GrayNoise query"""
    try:
        from app.feeds.greynoise import get_greynoise_connector
        from app.config.feed_credentials import FeedCredentialManager

        cred_manager = FeedCredentialManager()
        creds = cred_manager.get_graynoise_credentials()

        if not creds or not creds.get("api_key"):
            raise HTTPException(
                status_code=400, detail="GrayNoise API key not configured"
            )

        connector = get_greynoise_connector(
            api_key=creds.get("api_key", ""),
            use_community=(creds.get("api_type") == "community"),
            database=None,
        )

        results, success = connector.get_query_results(query=query, limit=limit)

        return {
            "status": "success" if success else "error",
            "query": query,
            "count": len(results),
            "items": results[:limit],
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"GrayNoise query failed: {e}")
        raise HTTPException(status_code=500, detail=f"Query failed: {e}")


@app.get("/api/config/nessus/enabled")
async def config_nessus_enabled():
    """Check if Nessus is enabled"""
    try:
        from app.config.feed_credentials import FeedCredentialManager

        cred_manager = FeedCredentialManager()
        enabled = cred_manager.is_nessus_enabled()
        configured = cred_manager.get_nessus_credentials() is not None

        return {
            "status": "success",
            "nessus_enabled": enabled,
            "nessus_configured": configured,
        }
    except Exception as e:
        logger.error(f"Failed to check Nessus status: {e}")
        raise HTTPException(status_code=500, detail="Failed to check Nessus status")


@app.get("/api/config/graynoise/enabled")
async def config_graynoise_enabled():
    """Check if GrayNoise is enabled"""
    try:
        from app.config.feed_credentials import FeedCredentialManager

        cred_manager = FeedCredentialManager()
        enabled = cred_manager.is_graynoise_enabled()
        configured = cred_manager.get_graynoise_credentials() is not None

        return {
            "status": "success",
            "graynoise_enabled": enabled,
            "graynoise_configured": configured,
        }
    except Exception as e:
        logger.error(f"Failed to check GrayNoise status: {e}")
        raise HTTPException(status_code=500, detail="Failed to check GrayNoise status")


@app.post("/api/config/custom-api/add")
async def config_custom_api_add(request: CustomAPIFeedRequest):
    """Add or update a custom API feed"""
    try:
        from app.config.feed_credentials import FeedCredentialManager

        cred_manager = FeedCredentialManager()
        success = cred_manager.add_custom_api_feed(
            feed_id=request.feed_id,
            feed_name=request.feed_name,
            api_url=request.api_url,
            auth_type=request.auth_type,
            auth_value=request.auth_value,
            custom_headers=request.custom_headers,
            polling_interval_hours=request.polling_interval_hours,
            enabled=request.enabled,
        )

        if success:
            return {
                "status": "success",
                "message": f"Custom API feed '{request.feed_id}' added/updated",
                "feed_id": request.feed_id,
                "enabled": request.enabled,
            }
        else:
            raise HTTPException(
                status_code=500, detail="Failed to save custom API feed"
            )
    except Exception as e:
        logger.error(f"Failed to add custom API feed: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to add custom API feed: {e}"
        )


@app.get("/api/config/custom-api/list")
async def config_custom_api_list():
    """List all custom API feeds"""
    try:
        from app.config.feed_credentials import FeedCredentialManager

        cred_manager = FeedCredentialManager()
        feeds = cred_manager.list_custom_api_feeds()

        # Remove sensitive auth_value from response
        safe_feeds = {}
        for feed_id, config in feeds.items():
            safe_config = {**config}
            safe_config["auth_value"] = "***" if config.get("auth_value") else ""
            safe_feeds[feed_id] = safe_config

        return {"status": "success", "feeds": safe_feeds, "count": len(feeds)}
    except Exception as e:
        logger.error(f"Failed to list custom API feeds: {e}")
        raise HTTPException(status_code=500, detail="Failed to list custom API feeds")


@app.delete("/api/config/custom-api/{feed_id}")
async def config_custom_api_remove(feed_id: str):
    """Remove a custom API feed"""
    try:
        from app.config.feed_credentials import FeedCredentialManager

        cred_manager = FeedCredentialManager()
        success = cred_manager.remove_custom_api_feed(feed_id)

        if success:
            return {
                "status": "success",
                "message": f"Custom API feed '{feed_id}' removed",
                "feed_id": feed_id,
            }
        else:
            raise HTTPException(status_code=404, detail="Feed not found")
    except Exception as e:
        logger.error(f"Failed to remove custom API feed: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to remove custom API feed: {e}"
        )


# --- Report Ingestion Endpoints ---


@app.get("/api/reports/ingestion/status")
async def reports_ingestion_status():
    """Get report ingestion status"""
    try:
        ingestion = get_report_ingestion()
        return {
            "status": "success",
            "ingestion_ready": True,
            "message": "Report ingestion service is ready",
        }
    except Exception as e:
        logger.error(f"Failed to get ingestion status: {e}")
        raise HTTPException(status_code=500, detail="Failed to get ingestion status")


@app.post("/api/reports/ingest")
async def reports_ingest_from_file(file_path: str, report_format: str = "json"):
    """Ingest a security report file"""
    try:
        from app.feeds.report_ingestion import ReportFormat

        ingestion = get_report_ingestion()

        # Map format string to ReportFormat enum
        format_map = {
            "json": ReportFormat.JSON,
            "csv": ReportFormat.CSV,
            "text": ReportFormat.TEXT,
            "pdf": ReportFormat.PDF,
            "xml": ReportFormat.XML,
            "stix": ReportFormat.STIX,
        }

        fmt = format_map.get(report_format.lower())
        if not fmt:
            raise HTTPException(
                status_code=400, detail=f"Unsupported format: {report_format}"
            )

        indicators, success = ingestion.ingest_report(file_path, fmt)

        return {
            "status": "success" if success else "partial",
            "file_path": file_path,
            "format": report_format,
            "indicators_extracted": len(indicators),
            "indicators": indicators[:20],  # Return first 20
        }
    except Exception as e:
        logger.error(f"Failed to ingest report: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to ingest report: {e}")


# --- Configuration Dashboard HTML Endpoints ---


@app.get("/dashboard/config")
async def config_dashboard(request: Request):
    """Configuration management dashboard"""
    try:
        from app.config.feed_credentials import FeedCredentialManager

        cred_manager = FeedCredentialManager()
        status = cred_manager.get_status()

        return templates.TemplateResponse(
            "config.html",
            {
                "request": request,
                "config": status,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"Config dashboard error: {e}")
        return templates.TemplateResponse(
            "error.html", {"request": request, "error": str(e)}
        )


@app.get("/dashboard/feeds")
async def feeds_dashboard(request: Request):
    """Feed management dashboard"""
    try:
        scheduler = get_scheduler()
        status = scheduler.get_feed_status()

        return templates.TemplateResponse(
            "feeds.html",
            {
                "request": request,
                "feeds": status,
                "timestamp": datetime.now(UTC).isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"Feeds dashboard error: {e}")
        return templates.TemplateResponse(
            "error.html", {"request": request, "error": str(e)}
        )
