"""
Database models for Cyber Intelligence Gateway
"""

import sqlite3
import json
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field, asdict
from pathlib import Path
import uuid


@dataclass
class Alert:
    """Threat alert model"""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    severity: str = "info"  # critical, high, medium, low, info
    source_ip: str = ""
    destination_ip: str = ""
    source_port: int = 0
    destination_port: int = 0
    protocol: str = ""
    indicator: str = ""
    indicator_type: str = ""  # domain, ip, hash, url
    feed_source: str = ""  # misp, pfblocker
    rule_id: str = ""
    message: str = ""
    raw_log: str = ""  # JSON string

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Alert":
        return cls(**data)


@dataclass
class PcapFile:
    """PCAP file metadata"""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    filename: str = ""
    filepath: str = ""
    start_time: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    end_time: str = ""
    size_bytes: int = 0
    packets_count: int = 0
    interface: str = ""
    alerts_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Indicator:
    """Threat indicator model"""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    value: str = ""
    type: str = ""  # ip, domain, hash, url, email
    source: str = ""  # misp, pfblocker
    feed_id: str = ""
    first_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    tags: str = ""  # comma-separated
    count: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Database:
    """SQLite database manager"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database schema"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                indicator TEXT,
                indicator_type TEXT,
                feed_source TEXT,
                rule_id TEXT,
                message TEXT,
                raw_log TEXT
            )
        """)

        # PCAP files table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS pcap_files (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                size_bytes INTEGER,
                packets_count INTEGER,
                interface TEXT,
                alerts_count INTEGER DEFAULT 0
            )
        """)

        # Indicators table (for fast lookups)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS indicators (
                id TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                type TEXT NOT NULL,
                source TEXT NOT NULL,
                feed_id TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                tags TEXT,
                count INTEGER DEFAULT 1
            )
        """)

        # Create indexes for fast lookups
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_indicator_value ON indicators(value)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_indicator_type ON indicators(type)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON alerts(timestamp)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_alert_indicator ON alerts(indicator)"
        )

        conn.commit()
        conn.close()

    def insert_alert(self, alert: Alert) -> None:
        """Insert a new alert"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO alerts (id, timestamp, severity, source_ip, destination_ip,
                source_port, destination_port, protocol, indicator, indicator_type,
                feed_source, rule_id, message, raw_log)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                alert.id,
                alert.timestamp,
                alert.severity,
                alert.source_ip,
                alert.destination_ip,
                alert.source_port,
                alert.destination_port,
                alert.protocol,
                alert.indicator,
                alert.indicator_type,
                alert.feed_source,
                alert.rule_id,
                alert.message,
                alert.raw_log,
            ),
        )
        conn.commit()
        conn.close()

    def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[str] = None,
        indicator_type: Optional[str] = None,
    ) -> List[Alert]:
        """Get alerts with optional filtering"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM alerts WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if indicator_type:
            query += " AND indicator_type = ?"
            params.append(indicator_type)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [
            Alert(
                id=row["id"],
                timestamp=row["timestamp"],
                severity=row["severity"],
                source_ip=row["source_ip"],
                destination_ip=row["destination_ip"],
                source_port=row["source_port"],
                destination_port=row["destination_port"],
                protocol=row["protocol"],
                indicator=row["indicator"],
                indicator_type=row["indicator_type"],
                feed_source=row["feed_source"],
                rule_id=row["rule_id"],
                message=row["message"],
                raw_log=row["raw_log"],
            )
            for row in rows
        ]

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get a single alert by ID"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return Alert(
            id=row["id"],
            timestamp=row["timestamp"],
            severity=row["severity"],
            source_ip=row["source_ip"],
            destination_ip=row["destination_ip"],
            source_port=row["source_port"],
            destination_port=row["destination_port"],
            protocol=row["protocol"],
            indicator=row["indicator"],
            indicator_type=row["indicator_type"],
            feed_source=row["feed_source"],
            rule_id=row["rule_id"],
            message=row["message"],
            raw_log=row["raw_log"],
        )

    def get_alert_stats(self) -> Dict[str, Any]:
        """Get alert statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Total count
        cursor.execute("SELECT COUNT(*) as total FROM alerts")
        total = cursor.fetchone()[0]

        # By severity
        cursor.execute(
            "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity"
        )
        by_severity = {row[0]: row[1] for row in cursor.fetchall()}

        # By indicator type
        cursor.execute(
            "SELECT indicator_type, COUNT(*) as count FROM alerts GROUP BY indicator_type"
        )
        by_type = {row[0]: row[1] for row in cursor.fetchall()}

        # By feed source
        cursor.execute(
            "SELECT feed_source, COUNT(*) as count FROM alerts GROUP BY feed_source"
        )
        by_source = {row[0]: row[1] for row in cursor.fetchall()}

        # Last 24 hours
        cursor.execute("""
            SELECT COUNT(*) FROM alerts
            WHERE timestamp > datetime('now', '-1 day')
        """)
        last_24h = cursor.fetchone()[0]

        conn.close()

        return {
            "total": total,
            "by_severity": by_severity,
            "by_type": by_type,
            "by_source": by_source,
            "last_24h": last_24h,
        }

    def insert_indicator(self, indicator: Indicator) -> None:
        """Insert or update an indicator"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Check if exists
        cursor.execute(
            "SELECT id, count FROM indicators WHERE value = ? AND type = ? AND source = ?",
            (indicator.value, indicator.type, indicator.source),
        )
        existing = cursor.fetchone()

        if existing:
            # Update
            cursor.execute(
                """
                UPDATE indicators SET last_seen = ?, count = count + 1
                WHERE value = ? AND type = ? AND source = ?
            """,
                (
                    indicator.last_seen,
                    indicator.value,
                    indicator.type,
                    indicator.source,
                ),
            )
        else:
            # Insert
            cursor.execute(
                """
                INSERT INTO indicators (id, value, type, source, feed_id, first_seen, last_seen, tags, count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    indicator.id,
                    indicator.value,
                    indicator.type,
                    indicator.source,
                    indicator.feed_id,
                    indicator.first_seen,
                    indicator.last_seen,
                    indicator.tags,
                    indicator.count,
                ),
            )

        conn.commit()
        conn.close()

    def bulk_insert_indicators(self, indicators: List[Indicator]) -> None:
        """Bulk insert indicators"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        data = []
        for ind in indicators:
            data.append(
                (
                    ind.id,
                    ind.value,
                    ind.type,
                    ind.source,
                    ind.feed_id,
                    ind.first_seen,
                    ind.last_seen,
                    ind.tags,
                    ind.count,
                )
            )

        cursor.executemany(
            """
            INSERT OR REPLACE INTO indicators
            (id, value, type, source, feed_id, first_seen, last_seen, tags, count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            data,
        )

        conn.commit()
        conn.close()

    def get_indicators(
        self,
        limit: int = 1000,
        indicator_type: Optional[str] = None,
        feed_source: Optional[str] = None,
    ) -> List[Indicator]:
        """Get indicators"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM indicators WHERE 1=1"
        params = []

        if indicator_type:
            query += " AND type = ?"
            params.append(indicator_type)
        if feed_source:
            query += " AND source = ?"
            params.append(feed_source)

        query += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)

        rows = cursor.fetchall()
        conn.close()

        return [
            Indicator(
                id=row["id"],
                value=row["value"],
                type=row["type"],
                source=row["source"],
                feed_id=row["feed_id"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                tags=row["tags"],
                count=row["count"],
            )
            for row in rows
        ]

    def check_indicator(self, value: str, indicator_type: str) -> Optional[Indicator]:
        """Check if an indicator exists in the database"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM indicators WHERE value = ? AND type = ?
        """,
            (value, indicator_type),
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return Indicator(
            id=row["id"],
            value=row["value"],
            type=row["type"],
            source=row["source"],
            feed_id=row["feed_id"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            tags=row["tags"],
            count=row["count"],
        )

    def insert_pcap(self, pcap: PcapFile) -> None:
        """Insert PCAP metadata"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO pcap_files (id, filename, filepath, start_time, end_time,
                size_bytes, packets_count, interface, alerts_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                pcap.id,
                pcap.filename,
                pcap.filepath,
                pcap.start_time,
                pcap.end_time,
                pcap.size_bytes,
                pcap.packets_count,
                pcap.interface,
                pcap.alerts_count,
            ),
        )
        conn.commit()
        conn.close()

    def get_pcaps(self, limit: int = 50, offset: int = 0) -> List[PcapFile]:
        """Get PCAP files"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM pcap_files ORDER BY start_time DESC LIMIT ? OFFSET ?
        """,
            (limit, offset),
        )
        rows = cursor.fetchall()
        conn.close()

        return [
            PcapFile(
                id=row["id"],
                filename=row["filename"],
                filepath=row["filepath"],
                start_time=row["start_time"],
                end_time=row["end_time"],
                size_bytes=row["size_bytes"],
                packets_count=row["packets_count"],
                interface=row["interface"],
                alerts_count=row["alerts_count"],
            )
            for row in rows
        ]

    def delete_old_alerts(self, retention_days: int) -> int:
        """Delete alerts older than retention period"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            DELETE FROM alerts
            WHERE timestamp < datetime('now', '-' || ? || ' days')
        """,
            (retention_days,),
        )
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted

    def get_indicator_counts(self) -> Dict[str, int]:
        """Get indicator counts by type"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT type, COUNT(*) as count FROM indicators GROUP BY type")
        counts = {row[0]: row[1] for row in cursor.fetchall()}
        conn.close()
        return counts
