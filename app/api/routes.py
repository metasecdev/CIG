"""
FastAPI Routes for Cyber Intelligence Gateway
"""

import os
import logging
from typing import Optional, List
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from app.models.database import Database, Alert, PcapFile, Indicator
from app.matching.engine import ThreatMatcher
from app.core.config import settings

logger = logging.getLogger(__name__)

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

# Global instances (will be initialized in main.py)
_db: Optional[Database] = None
_threat_matcher: Optional[ThreatMatcher] = None
threat_matcher: Optional[ThreatMatcher] = None


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


def init_app(database: Database, matcher: ThreatMatcher):
    """Initialize global instances"""
    global _db, _threat_matcher, threat_matcher
    _db = database
    _threat_matcher = matcher
    threat_matcher = matcher


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


# --- Health Endpoints ---


@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy", version="1.0.0", timestamp=datetime.utcnow().isoformat()
    )


@app.get("/api/stats", response_model=StatsResponse)
async def get_stats():
    """Get system statistics"""
    database = get_db()
    matcher = get_threat_matcher()

    return StatsResponse(
        alerts=database.get_alert_stats(),
        indicators=database.get_indicator_counts(),
        feeds={
            "misp": matcher.misp_feed.get_status(),
            "pfblocker": matcher.pfblocker_feed.get_status(),
        },
        captures=matcher.pcap_capture.get_active_captures(),
    )


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
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")

    pcaps = db.get_pcaps(limit=limit, offset=offset)
    return {"pcaps": [PcapResponse(**p.to_dict()).dict() for p in pcaps]}


@app.get("/api/pcaps/{pcap_id}/download")
async def download_pcap(pcap_id: str):
    """Download a PCAP file"""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")

    conn = db.db_path
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
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")

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


@app.get("/api/intel/indicators")
async def get_indicators(
    limit: int = Query(1000, ge=1, le=10000),
    indicator_type: Optional[str] = Query(None),
):
    """Get threat indicators"""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")

    indicators = db.get_indicators(limit=limit, indicator_type=indicator_type)
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


# --- Dashboard Endpoints ---


@app.get("/test")
async def test_route():
    """Simple test route"""
    return {"message": "Server is working", "timestamp": datetime.utcnow().isoformat()}


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
            "indicators": database.get_indicator_counts(),
            "feeds": {
                "misp": matcher.misp_feed.get_status(),
                "pfblocker": matcher.pfblocker_feed.get_status(),
                "abuseipdb": matcher.abuseipdb_feed.get_status(),
            },
            "captures": matcher.pcap_capture.get_active_captures(),
            "system": matcher.get_status(),
        }

        # Get recent alerts
        recent_alerts = database.get_alerts(limit=10, offset=0)
        alerts_data = [AlertResponse(**a.to_dict()) for a in recent_alerts]

        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "stats": stats,
                "recent_alerts": alerts_data,
                "timestamp": datetime.utcnow().isoformat(),
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
            },
            "captures": matcher.pcap_capture.get_active_captures(),
        }

        return templates.TemplateResponse(
            "status.html",
            {
                "request": request,
                "status": status_data,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"Status dashboard error: {e}")
        return templates.TemplateResponse(
            "error.html", {"request": request, "error": str(e)}
        )


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
                "timestamp": datetime.utcnow().isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"Health dashboard error: {e}")
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
                "timestamp": datetime.utcnow().isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"Events dashboard error: {e}")
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
                "timestamp": datetime.utcnow().isoformat(),
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
