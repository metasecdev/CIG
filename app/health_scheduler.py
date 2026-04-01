"""Background health scheduler for CIG system monitoring"""

import logging
import threading
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Global state for health scheduler
_scheduler_running = False
_scheduler_thread = None
_last_health_report: Dict[str, Any] = {"status": "not_run", "last_check": None, "report": None}
_health_lock = threading.Lock()


def start_health_scheduler():
    """Start background health scheduler (runs self_heal every 60 seconds)"""
    global _scheduler_running, _scheduler_thread
    
    if _scheduler_running:
        logger.warning("Health scheduler already running")
        return
    
    _scheduler_running = True
    _scheduler_thread = threading.Thread(target=_health_loop, daemon=True)
    _scheduler_thread.start()
    logger.info("Health scheduler started (60 second interval)")


def stop_health_scheduler():
    """Stop background health scheduler"""
    global _scheduler_running
    _scheduler_running = False
    logger.info("Health scheduler stopped")


def _health_loop():
    """Main loop for health monitoring"""
    import time
    
    while _scheduler_running:
        try:
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
