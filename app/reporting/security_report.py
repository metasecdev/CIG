"""
Reporting Module
Generates comprehensive security reports based on network findings
"""

import logging
import json
import subprocess
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path
import pandas as pd
from jinja2 import Template

from app.models.database import Database
from app.mitre.attack_mapper import MITREAttackMapper
from app.core.config import settings

logger = logging.getLogger(__name__)


class SecurityReporter:
    """Generates security reports from network monitoring data"""

    def __init__(self, db: Database):
        self.db = db
        self.mitre_mapper = MITREAttackMapper(db)
        self.reports_dir = Path(settings.pcap_dir).parent / "reports"
        self.reports_dir.mkdir(exist_ok=True)

        # Matplotlib/seaborn are imported lazily to avoid macOS font scan delays
        self._charting_initialized = False
        self._plt = None
        self._sns = None

    def generate_comprehensive_report(self, days: int = 7) -> Dict[str, Any]:
        """Generate a comprehensive security report"""
        logger.info(f"Generating comprehensive security report for last {days} days")

        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        report = {
            "report_metadata": {
                "generated_at": end_date.isoformat(),
                "period_start": start_date.isoformat(),
                "period_end": end_date.isoformat(),
                "days_covered": days
            },
            "executive_summary": {},
            "threat_intelligence": {},
            "network_activity": {},
            "mitre_attack_analysis": {},
            "recommendations": [],
            "charts": {}
        }

        # Gather data
        alerts = self._get_alerts_in_period(start_date, end_date)
        indicators = self._get_indicators_in_period(start_date, end_date)
        pcaps = self._get_pcaps_in_period(start_date, end_date)

        # Executive Summary
        report["executive_summary"] = self._generate_executive_summary(alerts, indicators, pcaps)

        # Threat Intelligence
        report["threat_intelligence"] = self._analyze_threat_intelligence(indicators)

        # Network Activity
        report["network_activity"] = self._analyze_network_activity(alerts, pcaps)

        # MITRE ATT&CK Analysis
        report["mitre_attack_analysis"] = self._analyze_mitre_attack(alerts)

        # Event table for forensics and sessions
        report["event_table"] = self._generate_event_table(alerts)

        # Tunnels and de-encapsulation hints
        report["tunnels"] = self._analyze_tunnels(pcaps)

        # Carve content from PCAPs and prepare sandbox exports
        report["carved_artifacts"] = self._carve_content(pcaps)

        # Recommendations
        report["recommendations"] = self._generate_recommendations(report)

        # Generate charts
        report["charts"] = self._generate_charts(alerts, indicators, days)

        # Save report
        self._save_report(report)

        return report

    def _get_alerts_in_period(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Get alerts within the reporting period"""
        conn = self.db.db_path
        import sqlite3
        conn = sqlite3.connect(self.db.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM alerts
            WHERE timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp DESC
        """, (start_date.isoformat(), end_date.isoformat()))

        alerts = []
        for row in cursor.fetchall():
            alerts.append({
                "id": row["id"],
                "timestamp": row["timestamp"],
                "severity": row["severity"],
                "source_ip": row["source_ip"],
                "destination_ip": row["destination_ip"],
                "source_port": row["source_port"],
                "destination_port": row["destination_port"],
                "protocol": row["protocol"],
                "indicator": row["indicator"],
                "indicator_type": row["indicator_type"],
                "feed_source": row["feed_source"],
                "rule_id": row["rule_id"],
                "message": row["message"]
            })

        conn.close()
        return alerts

    def _get_indicators_in_period(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Get indicators updated within the reporting period"""
        conn = self.db.db_path
        import sqlite3
        conn = sqlite3.connect(self.db.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM indicators
            WHERE last_seen >= ? AND last_seen <= ?
            ORDER BY last_seen DESC
        """, (start_date.isoformat(), end_date.isoformat()))

        indicators = []
        for row in cursor.fetchall():
            indicators.append({
                "id": row["id"],
                "value": row["value"],
                "type": row["type"],
                "source": row["source"],
                "feed_id": row["feed_id"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "tags": row["tags"],
                "count": row["count"]
            })

        conn.close()
        return indicators

    def _get_pcaps_in_period(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Get PCAP files captured within the reporting period"""
        conn = self.db.db_path
        import sqlite3
        conn = sqlite3.connect(self.db.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM pcap_files
            WHERE start_time >= ? AND start_time <= ?
            ORDER BY start_time DESC
        """, (start_date.isoformat(), end_date.isoformat()))

        pcaps = []
        for row in cursor.fetchall():
            pcaps.append({
                "id": row["id"],
                "filename": row["filename"],
                "filepath": row["filepath"],
                "start_time": row["start_time"],
                "end_time": row["end_time"],
                "size_bytes": row["size_bytes"],
                "packets_count": row["packets_count"],
                "interface": row["interface"],
                "alerts_count": row["alerts_count"]
            })

        conn.close()
        return pcaps

    def _generate_executive_summary(self, alerts: List[Dict], indicators: List[Dict], pcaps: List[Dict]) -> Dict[str, Any]:
        """Generate executive summary statistics"""
        total_alerts = len(alerts)
        total_indicators = len(indicators)
        total_pcaps = len(pcaps)

        # Severity breakdown
        severity_counts = {}
        for alert in alerts:
            severity = alert["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Indicator type breakdown
        indicator_type_counts = {}
        for indicator in indicators:
            ind_type = indicator["type"]
            indicator_type_counts[ind_type] = indicator_type_counts.get(ind_type, 0) + 1

        # Source breakdown
        source_counts = {}
        for indicator in indicators:
            source = indicator["source"]
            source_counts[source] = source_counts.get(source, 0) + 1

        # Risk assessment
        risk_level = "Low"
        if total_alerts > 100 or any(alert["severity"] == "critical" for alert in alerts):
            risk_level = "High"
        elif total_alerts > 50 or any(alert["severity"] == "high" for alert in alerts):
            risk_level = "Medium"

        return {
            "total_alerts": total_alerts,
            "total_indicators": total_indicators,
            "total_pcaps": total_pcaps,
            "severity_breakdown": severity_counts,
            "indicator_type_breakdown": indicator_type_counts,
            "source_breakdown": source_counts,
            "risk_level": risk_level,
            "period_summary": f"Detected {total_alerts} security events from {total_indicators} threat indicators across {total_pcaps} network captures"
        }

    def _analyze_threat_intelligence(self, indicators: List[Dict]) -> Dict[str, Any]:
        """Analyze threat intelligence data"""
        # Group by source
        sources = {}
        for indicator in indicators:
            source = indicator["source"]
            if source not in sources:
                sources[source] = []
            sources[source].append(indicator)

        # Analyze each source
        source_analysis = {}
        for source, inds in sources.items():
            source_analysis[source] = {
                "total_indicators": len(inds),
                "types": {},
                "top_indicators": sorted(inds, key=lambda x: x["count"], reverse=True)[:10]
            }

            for ind in inds:
                ind_type = ind["type"]
                source_analysis[source]["types"][ind_type] = source_analysis[source]["types"].get(ind_type, 0) + 1

        return {
            "sources": source_analysis,
            "total_unique_indicators": len(set(ind["value"] for ind in indicators)),
            "most_active_feeds": sorted(source_analysis.items(), key=lambda x: x[1]["total_indicators"], reverse=True)
        }

    def _analyze_network_activity(self, alerts: List[Dict], pcaps: List[Dict]) -> Dict[str, Any]:
        """Analyze network activity patterns"""
        # Protocol analysis
        protocols = {}
        for alert in alerts:
            protocol = alert.get("protocol", "unknown")
            protocols[protocol] = protocols.get(protocol, 0) + 1

        # Port analysis
        ports = {}
        for alert in alerts:
            dst_port = alert.get("destination_port")
            if dst_port:
                ports[dst_port] = ports.get(dst_port, 0) + 1

        # IP analysis
        source_ips = {}
        dest_ips = {}
        for alert in alerts:
            src_ip = alert.get("source_ip")
            dst_ip = alert.get("destination_ip")

            if src_ip:
                source_ips[src_ip] = source_ips.get(src_ip, 0) + 1
            if dst_ip:
                dest_ips[dst_ip] = dest_ips.get(dst_ip, 0) + 1

        # PCAP statistics
        total_packets = sum(pcap["packets_count"] for pcap in pcaps)
        total_size = sum(pcap["size_bytes"] for pcap in pcaps)

        return {
            "protocols": protocols,
            "top_ports": sorted(ports.items(), key=lambda x: x[1], reverse=True)[:20],
            "top_source_ips": sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:20],
            "top_destination_ips": sorted(dest_ips.items(), key=lambda x: x[1], reverse=True)[:20],
            "pcap_statistics": {
                "total_captures": len(pcaps),
                "total_packets": total_packets,
                "total_size_bytes": total_size,
                "average_packets_per_capture": total_packets / len(pcaps) if pcaps else 0
            }
        }

    def _analyze_mitre_attack(self, alerts: List[Dict]) -> Dict[str, Any]:
        """Analyze alerts for MITRE ATT&CK TTP matches"""
        ttp_matches = []

        for alert in alerts:
            # Map alert to TTPs
            ttps = self.mitre_mapper.map_event_to_ttp(alert)
            for ttp in ttps:
                ttp_matches.append({
                    "alert_id": alert["id"],
                    "technique_id": ttp["technique_id"],
                    "technique_name": ttp["technique_name"],
                    "tactic_id": ttp["tactic_id"],
                    "tactic_name": ttp["tactic_name"],
                    "confidence": ttp["confidence"],
                    "matched_indicators": ttp["matched_indicators"]
                })

        # Aggregate by technique
        technique_counts = {}
        for match in ttp_matches:
            tech_id = match["technique_id"]
            technique_counts[tech_id] = technique_counts.get(tech_id, 0) + 1

        # Aggregate by tactic
        tactic_counts = {}
        for match in ttp_matches:
            tact_id = match["tactic_id"]
            tactic_counts[tact_id] = tactic_counts.get(tact_id, 0) + 1

        return {
            "total_ttp_matches": len(ttp_matches),
            "techniques_detected": technique_counts,
            "tactics_detected": tactic_counts,
            "high_confidence_matches": [m for m in ttp_matches if m["confidence"] >= 70],
            "sample_matches": ttp_matches[:50]  # First 50 matches
        }

    def _generate_event_table(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Create an event table for the report, even when no alerts exist"""
        if not alerts:
            return [{
                "id": "none",
                "timestamp": datetime.utcnow().isoformat(),
                "severity": "none",
                "source_ip": "N/A",
                "destination_ip": "N/A",
                "source_port": 0,
                "destination_port": 0,
                "protocol": "N/A",
                "indicator": "No events detected",
                "indicator_type": "N/A",
                "feed_source": "N/A",
                "rule_id": "N/A",
                "message": "No alerts were generated during this period."
            }]

        event_rows = []
        for alert in alerts:
            event_rows.append({
                "id": alert.get("id"),
                "timestamp": alert.get("timestamp"),
                "severity": alert.get("severity"),
                "source_ip": alert.get("source_ip"),
                "destination_ip": alert.get("destination_ip"),
                "source_port": alert.get("source_port"),
                "destination_port": alert.get("destination_port"),
                "protocol": alert.get("protocol"),
                "indicator": alert.get("indicator"),
                "indicator_type": alert.get("indicator_type"),
                "feed_source": alert.get("feed_source"),
                "rule_id": alert.get("rule_id"),
                "message": alert.get("message"),
            })

        return event_rows

    def _analyze_tunnels(self, pcaps: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect tunnel or encapsulation protocols in PCAP files and provide de-encapsulation hints"""
        if not pcaps:
            return {
                "detected": False,
                "details": [],
                "deencapsulated_pcaps": []
            }

        tunnels = []
        deencap_files = []

        for pcap in pcaps:
            pcap_path = pcap.get("filepath")
            if not pcap_path or not Path(pcap_path).exists():
                continue

            try:
                # Check for tunnel protocols via tshark if available
                proc = subprocess.run(
                    ["tshark", "-r", pcap_path, "-Y", "gre || esp || vxl || ipencap", "-T", "fields", "-e", "frame.number"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                frame_ids = [line for line in proc.stdout.splitlines() if line.strip()]

                if frame_ids:
                    tunnels.append({
                        "pcap_id": pcap.get("id"),
                        "pcap_file": pcap_path,
                        "frames_with_tunnels": len(frame_ids),
                        "sample_frame_numbers": frame_ids[:10],
                    })

                    # Attempt simple de-encapsulation output file
                    deencap_path = self.reports_dir / f"deencapsulated_{Path(pcap_path).stem}.pcap"
                    try:
                        subprocess.run(
                            ["tshark", "-r", pcap_path, "-Y", "gre || esp || vxl || ipencap", "-w", str(deencap_path)],
                            capture_output=True,
                            text=True,
                            timeout=120,
                        )
                        if deencap_path.exists():
                            deencap_files.append(str(deencap_path))
                    except Exception as exc:
                        logger.warning(f"Failed to de-encapsulate {pcap_path}: {exc}")

            except FileNotFoundError:
                logger.info("tshark not found; skipping tunnel detection")
                break
            except Exception as e:
                logger.warning(f"Tunnel analysis failed for {pcap_path}: {e}")

        return {
            "detected": bool(tunnels),
            "details": tunnels,
            "deencapsulated_pcaps": deencap_files,
        }

    def _carve_content(self, pcaps: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Carve potential payloads and suspicious artifacts from PCAP files for sandbox analysis"""
        artifact_root = self.reports_dir / "artifacts"
        artifact_root.mkdir(parents=True, exist_ok=True)

        artifacts_output = []

        if not pcaps:
            return {
                "carved": False,
                "artifacts": [],
                "message": "No pcap captures available for carving"
            }

        for pcap in pcaps:
            pcap_path = pcap.get("filepath")
            if not pcap_path or not Path(pcap_path).exists():
                continue

            pcap_artifact_dir = artifact_root / f"{pcap.get('id', 'unknown')}"
            pcap_artifact_dir.mkdir(parents=True, exist_ok=True)

            extracted = []

            # Attempt to extract objects via tshark
            try:
                tshark_export_cmds = [
                    ["tshark", "-r", pcap_path, "--export-objects", f"http,{pcap_artifact_dir}"]
                ]

                for cmd in tshark_export_cmds:
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    if proc.returncode == 0:
                        extracted += [str(p) for p in pcap_artifact_dir.iterdir() if p.is_file()]
            except FileNotFoundError:
                logger.info("tshark not found; skipping object export carving")
            except Exception as e:
                logger.warning(f"PCAP carving failed for {pcap_path}: {e}")

            # Fallback: simple strings scan on raw bytes for suspicious patterns
            try:
                with open(pcap_path, "rb") as f:
                    content = f.read()
                    if b"MZ" in content or b"\x7fELF" in content:
                        indicator_file = pcap_artifact_dir / "binary_object_detected.txt"
                        indicator_file.write_text("Potential binary payload detected in pcap data")
                        extracted.append(str(indicator_file))
            except Exception as e:
                logger.warning(f"Failed to scan pcap bytes for carving: {e}")

            artifacts_output.append({
                "pcap_id": pcap.get("id"),
                "source_pcap": pcap_path,
                "extracted_artifacts": extracted,
                "artifact_directory": str(pcap_artifact_dir),
            })

        return {
            "carved": bool(artifacts_output and any(item["extracted_artifacts"] for item in artifacts_output)),
            "artifacts": artifacts_output,
        }

    def _generate_recommendations(self, report: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []

        exec_summary = report["executive_summary"]
        mitre_analysis = report["mitre_attack_analysis"]

        # Risk-based recommendations
        risk_level = exec_summary["risk_level"]

        if risk_level == "High":
            recommendations.extend([
                "URGENT: Implement immediate containment measures for critical alerts",
                "Review and update firewall rules to block detected malicious IPs",
                "Conduct forensic analysis of affected systems",
                "Consider network segmentation to limit lateral movement"
            ])
        elif risk_level == "Medium":
            recommendations.extend([
                "Monitor high-severity alerts closely",
                "Update threat intelligence feeds and signatures",
                "Review access controls and authentication mechanisms",
                "Implement additional logging for suspicious activities"
            ])
        else:
            recommendations.extend([
                "Continue monitoring with current security controls",
                "Regular review of security policies and procedures",
                "Keep threat intelligence feeds updated"
            ])

        # MITRE ATT&CK specific recommendations
        if mitre_analysis["total_ttp_matches"] > 0:
            recommendations.append("Review MITRE ATT&CK techniques detected and implement specific countermeasures")

            # Add technique-specific recommendations
            for technique_id, count in mitre_analysis["techniques_detected"].items():
                if count > 5:  # Frequent technique
                    tech_info = self.mitre_mapper.get_technique_info(technique_id)
                    if tech_info:
                        recommendations.append(f"Address frequent {tech_info['name']} (T{technique_id}) detections")

        # Network-specific recommendations
        network_activity = report["network_activity"]
        if network_activity["top_ports"]:
            top_port = max(network_activity["top_ports"], key=lambda x: x[1])
            if top_port[1] > 10:  # High activity on a port
                recommendations.append(f"Review high activity on port {top_port[0]} ({top_port[1]} events)")

        return recommendations

    def _generate_charts(self, alerts: List[Dict], indicators: List[Dict], days: int) -> Dict[str, str]:
        """Generate charts for the report"""
        charts = {}

        try:
                # Only import matplotlib/seaborn when needed (avoid slow macOS font scanning)
            if not self._charting_initialized:
                import matplotlib
                matplotlib.use('Agg')
                import matplotlib.pyplot as plt
                import seaborn as sns
                self._plt = plt
                self._sns = sns
                self._charting_initialized = True

            plt = self._plt
            sns = self._sns

            # Alerts over time
            if alerts:
                df_alerts = pd.DataFrame(alerts)
                df_alerts['timestamp'] = pd.to_datetime(df_alerts['timestamp'])
                df_alerts.set_index('timestamp', inplace=True)

                plt.figure(figsize=(12, 6))
                df_alerts.resample('D').size().plot(kind='line', marker='o')
                plt.title(f'Security Alerts Over Last {days} Days')
                plt.xlabel('Date')
                plt.ylabel('Number of Alerts')
                plt.grid(True)
                plt.tight_layout()

                chart_path = self.reports_dir / f"alerts_over_time_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.png"
                plt.savefig(chart_path)
                plt.close()
                charts["alerts_over_time"] = str(chart_path)

            # Severity distribution
            if alerts:
                severity_counts = {}
                for alert in alerts:
                    severity = alert["severity"]
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1

                plt.figure(figsize=(8, 6))
                plt.bar(severity_counts.keys(), severity_counts.values(), color=['red', 'orange', 'yellow', 'blue'])
                plt.title('Alert Severity Distribution')
                plt.xlabel('Severity')
                plt.ylabel('Count')
                plt.tight_layout()

                chart_path = self.reports_dir / f"severity_distribution_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.png"
                plt.savefig(chart_path)
                plt.close()
                charts["severity_distribution"] = str(chart_path)

            # Indicator sources
            if indicators:
                source_counts = {}
                for indicator in indicators:
                    source = indicator["source"]
                    source_counts[source] = source_counts.get(source, 0) + 1

                plt.figure(figsize=(10, 6))
                plt.bar(source_counts.keys(), source_counts.values())
                plt.title('Threat Intelligence Sources')
                plt.xlabel('Source')
                plt.ylabel('Number of Indicators')
                plt.xticks(rotation=45)
                plt.tight_layout()

                chart_path = self.reports_dir / f"indicator_sources_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.png"
                plt.savefig(chart_path)
                plt.close()
                charts["indicator_sources"] = str(chart_path)

        except Exception as e:
            logger.error(f"Failed to generate charts: {e}")

        return charts

    def _save_report(self, report: Dict[str, Any]) -> str:
        """Save the report to file"""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        report_file = self.reports_dir / f"security_report_{timestamp}.json"

        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        logger.info(f"Security report saved to {report_file}")
        return str(report_file)

    def generate_html_report(self, days: int = 7) -> str:
        """Generate an HTML report"""
        data = self.generate_comprehensive_report(days)

        # Simple HTML template
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Cyber Intelligence Gateway - Security Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background: #f0f0f0; padding: 20px; border-radius: 5px; }
                .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
                .metric { display: inline-block; margin: 10px; padding: 10px; background: #e8f4f8; border-radius: 3px; }
                .high-risk { color: red; }
                .medium-risk { color: orange; }
                .low-risk { color: green; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Cyber Intelligence Gateway - Security Report</h1>
                <p>Generated: {{ report_metadata.generated_at }}</p>
                <p>Period: {{ report_metadata.period_start }} to {{ report_metadata.period_end }}</p>
            </div>

            <div class="section">
                <h2>Executive Summary</h2>
                <div class="metric">Total Alerts: {{ executive_summary.total_alerts }}</div>
                <div class="metric">Total Indicators: {{ executive_summary.total_indicators }}</div>
                <div class="metric">Risk Level: <span class="{{ 'high-risk' if executive_summary.risk_level == 'High' else 'medium-risk' if executive_summary.risk_level == 'Medium' else 'low-risk' }}">{{ executive_summary.risk_level }}</span></div>
                <p>{{ executive_summary.period_summary }}</p>
            </div>

            <div class="section">
                <h2>MITRE ATT&CK Analysis</h2>
                <p>Total TTP Matches: {{ mitre_attack_analysis.total_ttp_matches }}</p>
                <h3>Detected Techniques</h3>
                <table>
                    <tr><th>Technique ID</th><th>Count</th></tr>
                    {% for tech_id, count in mitre_attack_analysis.techniques_detected.items() %}
                    <tr><td>{{ tech_id }}</td><td>{{ count }}</td></tr>
                    {% endfor %}
                </table>
            </div>

            <div class="section">
                <h2>Event Table</h2>
                <table>
                    <tr>
                        <th>ID</th><th>Timestamp</th><th>Severity</th><th>Source IP</th><th>Destination IP</th><th>Protocol</th><th>Message</th>
                    </tr>
                    {% for evt in event_table %}
                    <tr>
                        <td>{{ evt.id }}</td>
                        <td>{{ evt.timestamp }}</td>
                        <td>{{ evt.severity }}</td>
                        <td>{{ evt.source_ip }}</td>
                        <td>{{ evt.destination_ip }}</td>
                        <td>{{ evt.protocol }}</td>
                        <td>{{ evt.message }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>

            <div class="section">
                <h2>Tunnel Detection and De-Encapsulation</h2>
                <p>Detected tunnel traffic: {{ 'Yes' if tunnels.detected else 'No' }}</p>
                {% if tunnels.details %}
                <ul>
                {% for t in tunnels.details %}
                    <li>{{ t.pcap_file }} - {{ t.frames_with_tunnels }} encapsulated frames</li>
                {% endfor %}
                </ul>
                {% endif %}
                {% if tunnels.deencapsulated_pcaps %}
                <p>Generated de-encapsulated PCAP files:</p>
                <ul>
                {% for f in tunnels.deencapsulated_pcaps %}
                    <li>{{ f }}</li>
                {% endfor %}
                </ul>
                {% endif %}
            </div>

            <div class="section">
                <h2>Carved Artifacts for Sandbox Analysis</h2>
                {% if carved_artifacts.carved %}
                <ul>
                {% for item in carved_artifacts.artifacts %}
                    <li>PCAP: {{ item.source_pcap }}
                        <ul>
                        {% for artifact in item.extracted_artifacts %}
                            <li>{{ artifact }}</li>
                        {% endfor %}
                        </ul>
                    </li>
                {% endfor %}
                </ul>
                {% else %}
                <p>No artifacts carved from PCAP captures.</p>
                {% endif %}
            </div>

            <div class="section">
                <h2>Recommendations</h2>
                <ul>
                {% for rec in recommendations %}
                    <li>{{ rec }}</li>
                {% endfor %}
                </ul>
            </div>
        </body>
        </html>
        """

        template = Template(html_template)
        html_content = template.render(**data)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        html_file = self.reports_dir / f"security_report_{timestamp}.html"

        with open(html_file, 'w') as f:
            f.write(html_content)

        logger.info(f"HTML security report saved to {html_file}")
        return str(html_file)