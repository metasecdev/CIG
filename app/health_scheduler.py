"""Background health scheduler for CIG system monitoring"""

import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Global state for health scheduler
_scheduler_running = False
_scheduler_thread = None
_last_health_report: Dict[str, Any] = {"status": "not_run", "last_check": None, "report": None}
_health_lock = threading.Lock()
_last_daily_refresh: Optional[datetime] = None


def start_health_scheduler():
    """Start background health scheduler (runs self_heal every 60 seconds)"""
    global _scheduler_running, _scheduler_thread
    
    if _scheduler_running:
        logger.warning("Health scheduler already running")
        return
    
    _scheduler_running = True
    _scheduler_thread = threading.Thread(target=_health_loop, daemon=True)
    _scheduler_thread.start()
    logger.info("Health scheduler started (60 second interval + daily refresh at 00:00 UTC)")


def stop_health_scheduler():
    """Stop background health scheduler"""
    global _scheduler_running
    _scheduler_running = False
    logger.info("Health scheduler stopped")


def _health_loop():
    """Main loop for health monitoring"""
    import time
    
    global _last_daily_refresh
    _last_daily_refresh = datetime.utcnow()
    
    while _scheduler_running:
        try:
            # Check if it's time for daily refresh (00:00 UTC)
            now = datetime.utcnow()
            if _last_daily_refresh is None or (now.date() > _last_daily_refresh.date() and now.hour == 0):
                _refresh_daily_news()
                _last_daily_refresh = now
            
            # Import here to avoid circular imports
            from app.main import self_heal_from_logs
            
            report = self_heal_from_logs()
            
            with _health_lock:
                global _last_health_report
                _last_health_report = {
                    "status": "success",
                    "last_check": datetime.utcnow().isoformat(),
                    "report": report,
                }
            
            logger.debug(f"Health check completed: {len(report.get('issues_found', []))} issues")
        except Exception as e:
            logger.error(f"Health scheduler error: {e}")
            with _health_lock:
                _last_health_report = {
                    "status": "error",
                    "last_check": datetime.utcnow().isoformat(),
                    "error": str(e),
                }
        
        # Sleep 60 seconds before next check
        time.sleep(60)


def _refresh_daily_news():
    """Refresh news feed daily at 00:00 UTC"""
    try:
        from app.feeds.news_feed import get_feed
        
        feed = get_feed()
        # Force refresh by clearing cache
        feed._cache_items(feed.news)
        logger.info("Daily news refresh completed at 00:00 UTC")
    except Exception as e:
        logger.error(f"Daily news refresh failed: {e}")


def get_health_report() -> Dict[str, Any]:
    """Get the last health report"""
    with _health_lock:
        return _last_health_report.copy()


def trigger_health_check() -> Dict[str, Any]:
    """Manually trigger a health check"""
    try:
        from app.main import self_heal_from_logs
        
        report = self_heal_from_logs()
        
        with _health_lock:
            global _last_health_report
            _last_health_report = {
                "status": "success",
                "last_check": datetime.utcnow().isoformat(),
                "report": report,
            }
        
        return _last_health_report.copy()
    except Exception as e:
        logger.error(f"Manual health check failed: {e}")
        return {
            "status": "error",
            "last_check": datetime.utcnow().isoformat(),
            "error": str(e),
        }
