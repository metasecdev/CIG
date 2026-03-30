"""
Historical analysis and threat trends
"""

from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import statistics
import logging

logger = logging.getLogger(__name__)


class TrendAnalyzer:
    """Analyze threat trends over time"""

    def __init__(self, window_days: int = 30):
        """
        Initialize trend analyzer.
        
        Args:
            window_days: Days of history to analyze
        """
        self.window_days = window_days

    def analyze_alert_trends(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze alert trends.
        
        Args:
            alerts: List of alerts with timestamps
        
        Returns:
            Trend analysis results
        """
        if not alerts:
            return {"error": "No alerts to analyze"}

        # Group by day
        daily_counts = {}
        for alert in alerts:
            try:
                ts = datetime.fromisoformat(alert["timestamp"])
                day = ts.date()
                daily_counts[day] = daily_counts.get(day, 0) + 1
            except (KeyError, ValueError):
                continue

        if not daily_counts:
            return {"error": "No valid alert timestamps"}

        counts = list(daily_counts.values())
        
        return {
            "total_alerts": len(alerts),
            "daily_average": statistics.mean(counts),
            "peaks": max(counts) if counts else 0,
            "troughs": min(counts) if counts else 0,
            "trend": self._calculate_trend(counts),
            "volatility": statistics.stdev(counts) if len(counts) > 1 else 0,
        }

    def analyze_severity_trends(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze severity distribution trends"""
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for alert in alerts:
            severity = alert.get("severity", "info")
            if severity in severity_counts:
                severity_counts[severity] += 1

        total = sum(severity_counts.values())
        percentages = {
            k: (v / total * 100) if total > 0 else 0
            for k, v in severity_counts.items()
        }

        return {
            "counts": severity_counts,
            "percentages": percentages,
            "high_severity_pct": (
                (severity_counts["critical"] + severity_counts["high"]) / total * 100
                if total > 0 else 0
            ),
        }

    def analyze_source_trends(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze alert source trends"""
        source_counts = {}
        for alert in alerts:
            source = alert.get("feed_source", "unknown")
            source_counts[source] = source_counts.get(source, 0) + 1

        total = sum(source_counts.values())
        return {
            "by_source": source_counts,
            "top_source": max(source_counts.items(), key=lambda x: x[1])[0]
            if source_counts else None,
        }

    def forecast_alerts(self, alerts: List[Dict[str, Any]], days_ahead: int = 7) -> Dict[str, Any]:
        """Simple alert volume forecast"""
        if not alerts:
            return {"error": "No data for forecasting"}

        # Group by day
        daily_counts = {}
        for alert in alerts:
            try:
                ts = datetime.fromisoformat(alert["timestamp"])
                day = ts.date()
                daily_counts[day] = daily_counts.get(day, 0) + 1
            except (KeyError, ValueError):
                continue

        if len(daily_counts) < 3:
            return {
                "error": "Insufficient data",
                "recommendation": "Need at least 3 days of data"
            }

        counts = list(daily_counts.values())
        avg = statistics.mean(counts)

        # Simple moving average forecast
        forecast = []
        for _ in range(days_ahead):
            # Add some variance
            import random
            variance = random.uniform(-0.1, 0.1) * avg
            forecast.append(int(avg + variance))

        return {
            "forecast": forecast,
            "average": avg,
            "confidence": "low" if len(daily_counts) < 7 else "medium",
        }

    @staticmethod
    def _calculate_trend(values: List[float]) -> str:
        """Calculate trend direction"""
        if len(values) < 2:
            return "insufficient_data"

        # Compare first half vs second half
        mid = len(values) // 2
        first_half = statistics.mean(values[:mid]) if mid > 0 else 0
        second_half = statistics.mean(values[mid:])

        if second_half > first_half * 1.1:
            return "increasing"
        elif second_half < first_half * 0.9:
            return "decreasing"
        else:
            return "stable"


class AnomalyDetector:
    """Detect anomalies in threat data"""

    def __init__(self, std_dev_threshold: float = 2.0):
        """
        Initialize anomaly detector.
        
        Args:
            std_dev_threshold: Standard deviation threshold for anomalies
        """
        self.std_dev_threshold = std_dev_threshold

    def detect_volume_anomalies(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect unusual alert volumes"""
        # Group by day
        daily_counts = {}
        dates = []
        for alert in alerts:
            try:
                ts = datetime.fromisoformat(alert["timestamp"])
                day = ts.date()
                if day not in daily_counts:
                    dates.append(day)
                    daily_counts[day] = 0
                daily_counts[day] += 1
            except (KeyError, ValueError):
                continue

        if len(daily_counts) < 3:
            return []

        counts = [daily_counts[d] for d in sorted(dates)]
        mean = statistics.mean(counts)
        std_dev = statistics.stdev(counts) if len(counts) > 1 else 0

        anomalies = []
        for date, count in zip(sorted(dates), counts):
            if std_dev > 0:
                z_score = (count - mean) / std_dev
                if abs(z_score) > self.std_dev_threshold:
                    anomalies.append({
                        "date": str(date),
                        "count": count,
                        "expected": mean,
                        "severity": "high" if abs(z_score) > 3 else "medium",
                        "z_score": z_score,
                    })

        return anomalies

    def detect_pattern_anomalies(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect unusual patterns"""
        anomalies = []

        # Check for unexpected indicator types
        type_counts = {}
        for alert in alerts:
            itype = alert.get("indicator_type", "unknown")
            type_counts[itype] = type_counts.get(itype, 0) + 1

        total = sum(type_counts.values())
        for itype, count in type_counts.items():
            percentage = (count / total * 100) if total > 0 else 0
            if percentage > 50:
                anomalies.append({
                    "type": "unusual_indicator_type",
                    "value": itype,
                    "percentage": percentage,
                    "note": f"{itype} represents {percentage:.1f}% of alerts"
                })

        return anomalies


class HistoricalAnalyzer:
    """Historical threat analysis"""

    def __init__(self, db_connection=None):
        """Initialize historical analyzer"""
        self.db = db_connection
        self.trend_analyzer = TrendAnalyzer()
        self.anomaly_detector = AnomalyDetector()

    def analyze_period(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Analyze a time period"""
        # This would query the database in production
        return {
            "period": f"{start_date.date()} to {end_date.date()}",
            "days": (end_date - start_date).days,
            # Results would include trends, anomalies, insights
        }

    def generate_report(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive analysis report"""
        return {
            "summary": {
                "total_alerts": len(alerts),
                "period": self._get_period(alerts),
            },
            "trends": self.trend_analyzer.analyze_alert_trends(alerts),
            "severity": self.trend_analyzer.analyze_severity_trends(alerts),
            "sources": self.trend_analyzer.analyze_source_trends(alerts),
            "forecast": self.trend_analyzer.forecast_alerts(alerts),
            "anomalies": self.anomaly_detector.detect_volume_anomalies(alerts),
            "patterns": self.anomaly_detector.detect_pattern_anomalies(alerts),
        }

    @staticmethod
    def _get_period(alerts: List[Dict[str, Any]]) -> Optional[str]:
        """Get period covered by alerts"""
        if not alerts:
            return None

        dates = []
        for alert in alerts:
            try:
                ts = datetime.fromisoformat(alert["timestamp"])
                dates.append(ts)
            except (KeyError, ValueError):
                continue

        if not dates:
            return None

        start = min(dates)
        end = max(dates)
        return f"{start.date()} to {end.date()}"


def compare_periods(earlier_alerts: List[Dict[str, Any]],
                   recent_alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compare two time periods"""
    analyzer = HistoricalAnalyzer()

    earlier_report = analyzer.generate_report(earlier_alerts)
    recent_report = analyzer.generate_report(recent_alerts)

    return {
        "earlier_period": earlier_report.get("summary", {}),
        "recent_period": recent_report.get("summary", {}),
        "change": {
            "alerts_pct": (
                (recent_report["summary"]["total_alerts"] - 
                 earlier_report["summary"]["total_alerts"]) /
                earlier_report["summary"]["total_alerts"] * 100
                if earlier_report["summary"]["total_alerts"] > 0 else 0
            ),
        },
    }
