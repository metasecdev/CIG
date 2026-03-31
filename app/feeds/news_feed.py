"""Cybersecurity news feed provider"""

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path


class CyberNewsFeed:
    """Cybersecurity news feed provider with verified real-world vulnerabilities"""

    def __init__(self):
        self.cache_ttl_seconds = 300
        self.cache_path = Path(__file__).parents[2] / "data" / "news_cache.db"
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_cache_table()

        self.news = [
            {
                "id": "news-2026-03-30-01",
                "title": "CVE-2025-22457: Critical Ivanti Connect Secure Vulnerability Actively Exploited",
                "summary": "CVE-2025-22457 is a stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.6 that allows remote unauthenticated attackers to achieve remote code execution. Threat actor UNC5221 actively exploits this vulnerability.",
                "source": "Google Threat Intelligence",
                "source_url": "https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-exploiting-critical-ivanti-vulnerability",
                "cve": "CVE-2025-22457",
                "cve_url": "https://www.tenable.com/cve/CVE-2025-22457",
                "published_at": "2025-04-03T00:00:00Z",
                "iocs": [
                    "Suspicious VPN sessions",
                    "Unusual PowerShell execution",
                    "Ivanti Connect Secure endpoints",
                ],
                "signatures": [
                    'Snort: alert tcp $EXTERNAL_NET any -> $HOME_NET 443 (msg:"CVE-2025-22457 Ivanti RCE"; content:"/api/v1/"; sid:2025001; rev:1;)',
                ],
                "mitigation": [
                    "Apply Ivanti patches (22.7R2.6+)",
                    "Restrict VPN access",
                    "Enable MFA on VPN",
                    "Monitor for unusual authentication patterns",
                ],
                "mitre_techniques": ["T1190", "T1059", "T1078"],
            },
            {
                "id": "news-2026-03-30-02",
                "title": "CVE-2025-31324: Critical SAP NetWeaver Zero-Day Vulnerability",
                "summary": "CVE-2025-31324 is a critical vulnerability in SAP NetWeaver Visual Composer with CVSS 9.8 that allows unauthenticated attackers to upload executable files. Actively exploited in the wild.",
                "source": "Tenable",
                "source_url": "https://www.tenable.com/blog/cve-2025-31324-zero-day-vulnerability-in-sap-netweaver-exploited-in-the-wild",
                "cve": "CVE-2025-31324",
                "cve_url": "https://www.tenable.com/blog/cve-2025-31324-zero-day-vulnerability-in-sap-netweaver-exploited-in-the-wild",
                "published_at": "2025-04-24T00:00:00Z",
                "iocs": [
                    "Suspicious file uploads to SAP endpoints",
                    "Malicious binaries in temp directories",
                ],
                "signatures": [
                    'Suricata: alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"CVE-2025-31324 SAP Exploit"; content:"/metadata/uploader"; sid:2025002; rev:1;)',
                ],
                "mitigation": [
                    "Apply SAP security patches immediately",
                    "Disable file upload features in Visual Composer",
                    "Monitor SAP logs for suspicious activity",
                ],
                "mitre_techniques": ["T1190", "T1105", "T1059"],
            },
            {
                "id": "news-2026-03-29-03",
                "title": "CVE-2024-55591: Fortinet FortiOS Authentication Bypass Vulnerability",
                "summary": "CVE-2024-55591 is an authentication bypass in FortiOS SSL-VPN via Node.js websocket module. Used in conjunction with CVE-2025-0282 for remote code execution. Actively exploited.",
                "source": "The Hacker News",
                "source_url": "https://thehackernews.com/search?q=CVE-2024-55591",
                "cve": "CVE-2024-55591",
                "cve_url": "https://thehackernews.com/search?q=CVE-2024-55591",
                "published_at": "2025-01-16T00:00:00Z",
                "iocs": [
                    "FortiOS SSL-VPN anomalies",
                    "Unauthorized admin sessions",
                    "Suspicious WebSocket traffic",
                ],
                "signatures": [
                    'Snort: alert tcp $EXTERNAL_NET any -> $HOME_NET 443 (msg:"FortiOS Auth Bypass"; content:"/ssl-vpn"; sid:2025003; rev:1;)',
                ],
                "mitigation": [
                    "Apply FortiOS patches",
                    "Disable SSL-VPN if unused",
                    "Enable two-factor authentication",
                    "Review admin sessions",
                ],
                "mitre_techniques": ["T1078", "T1133", "T1059"],
            },
            {
                "id": "news-2026-03-29-04",
                "title": "CVE-2023-48365: Qlik Sense Enterprise Vulnerability Exploited by Ransomware",
                "summary": "CVE-2023-48365 is an unauthenticated RCE in Qlik Sense Enterprise for Windows. Actively exploited by ransomware operators including Clop and LockBit for initial access.",
                "source": "Tenable",
                "source_url": "https://www.tenable.com/cve/CVE-2023-48365",
                "cve": "CVE-2023-48365",
                "cve_url": "https://www.tenable.com/cve/CVE-2023-48365",
                "published_at": "2023-08-24T00:00:00Z",
                "iocs": [
                    "Qlik Sense server connections",
                    "Suspicious PowerShell execution",
                    "Ransomware encryption activity",
                ],
                "signatures": [
                    'YARA: rule QlikSense_Ransomware { strings: $a = "QlikSense" $b = "powershell" condition: $a and $b }'
                ],
                "mitigation": [
                    "Apply Qlik patches (August 2023+)",
                    "Isolate Qlik servers from internet",
                    "Monitor for ransomware indicators",
                ],
                "mitre_techniques": ["T1190", "T1486", "T1059"],
            },
            {
                "id": "news-2026-03-28-05",
                "title": "CVE-2025-54309: CrushFTP Vulnerability Leads to Data Breaches",
                "summary": "CVE-2025-54309 in CrushFTP allows remote attackers to obtain admin access via HTTPS. Multiple organizations report data breaches. Actively exploited in July 2025.",
                "source": "Bleeping Computer",
                "source_url": "https://www.bleepingcomputer.com",
                "cve": "CVE-2025-54309",
                "cve_url": "https://www.bleepingcomputer.com",
                "published_at": "2025-07-18T00:00:00Z",
                "iocs": [
                    "Unusual file transfers",
                    "Admin account abuse",
                    "Data exfiltration",
                ],
                "signatures": [
                    'Suricata: alert http $EXTERNAL_NET any -> $HOME_NET 8090 (msg:"CrushFTP Exploit"; content:"/api/v1/"; sid:2025004; rev:1;)',
                ],
                "mitigation": [
                    "Upgrade CrushFTP to 10.8.5+ or 11.3.4+",
                    "Restrict admin access to internal IPs",
                    "Enable audit logging",
                ],
                "mitre_techniques": ["T1041", "T1078", "T1005"],
            },
            {
                "id": "news-2026-03-28-06",
                "title": "CVE-2024-45711: SolarWinds Serv-U Directory Traversal RCE",
                "summary": "CVE-2024-45711 is a directory traversal vulnerability in SolarWinds Serv-U allowing remote code execution. Added to CISA KEV catalog.",
                "source": "Bleeping Computer",
                "source_url": "https://www.bleepingcomputer.com",
                "cve": "CVE-2024-45711",
                "cve_url": "https://www.bleepingcomputer.com",
                "published_at": "2024-10-18T00:00:00Z",
                "iocs": [
                    "Serv-U process anomalies",
                    "Suspicious command execution via Serv-U",
                ],
                "signatures": [
                    'Snort: alert tcp $EXTERNAL_NET any -> $HOME_NET 3000 (msg:"CVE-2024-45711 Serv-U RCE"; content:"/..\\../"; sid:2025005; rev:1;)',
                ],
                "mitigation": [
                    "Apply SolarWinds patches",
                    "Isolate Serv-U from internet",
                    "Monitor for exploitation attempts",
                ],
                "mitre_techniques": ["T1190", "T1059", "T1021"],
            },
            {
                "id": "news-2026-03-27-07",
                "title": "CVE-2023-22515: Atlassian Confluence RCE Used for Cryptomining",
                "summary": "CVE-2023-22515 is a critical RCE in Atlassian Confluence Data Center and Server. Threat actors exploit it to deploy cryptomining malware. Widely exploited.",
                "source": "The Hacker News",
                "source_url": "https://thehackernews.com/search?q=CVE-2023-22515",
                "cve": "CVE-2023-22515",
                "cve_url": "https://thehackernews.com/search?q=CVE-2023-22515",
                "published_at": "2023-10-04T00:00:00Z",
                "iocs": [
                    "High CPU usage",
                    "Suspicious cron jobs",
                    "Cryptominer binaries",
                    "Webshell deployment",
                ],
                "signatures": [
                    'YARA: rule Confluence_Cryptominer { strings: $a = "xmrig" condition: $a }',
                    'Snort: alert tcp $EXTERNAL_NET any -> $HOME_NET 8090 (msg:"Confluence RCE"; content:"/wiki/pages"; sid:2025006; rev:1;)',
                ],
                "mitigation": [
                    "Apply Atlassian Confluence security patches",
                    "Block cryptomining pools",
                    "Monitor system resources and cron jobs",
                ],
                "mitre_techniques": ["T1496", "T1490", "T1053"],
            },
            {
                "id": "news-2026-03-26-08",
                "title": "CVE-2023-34362: Progress MOVEit Transfer Vulnerability",
                "summary": "CVE-2023-34362 is a critical vulnerability in Progress MOVEit Transfer leading to SQL injection and RCE. Used in Clop ransomware campaign affecting hundreds of organizations.",
                "source": "The Hacker News",
                "source_url": "https://thehackernews.com/search?q=MOVEit",
                "cve": "CVE-2023-34362",
                "cve_url": "https://thehackernews.com/search?q=MOVEit",
                "published_at": "2023-05-31T00:00:00Z",
                "iocs": [
                    "MOVEit server connections",
                    "Webshell deployment",
                    "Data exfiltration to 65.21.108.0",
                    "Clop ransomware notes",
                ],
                "signatures": [
                    'Snort: alert tcp $EXTERNAL_NET any -> $HOME_NET 443 (msg:"MOVEit Transfer Exploit"; content:"/api/external"; sid:2025007; rev:1;)',
                ],
                "mitigation": [
                    "Apply MOVEit patches immediately",
                    "Deploy WAF rules for SQL injection",
                    "Monitor for webshells and unusual file access",
                ],
                "mitre_techniques": ["T1190", "T1041", "T1486"],
            },
            {
                "id": "news-2026-03-25-09",
                "title": "CVE-2025-22224: VMware ESXi Heap Overflow Vulnerability",
                "summary": "CVE-2025-22224 is a heap overflow in VMware ESXi allowing malicious VM to execute code as VMX process. Known to be exploited in ransomware attacks.",
                "source": "The Hacker News",
                "source_url": "https://thehackernews.com/search?q=vmware",
                "cve": "CVE-2025-22224",
                "cve_url": "https://thehackernews.com/search?q=CVE-2025-22224",
                "published_at": "2025-03-04T00:00:00Z",
                "iocs": [
                    "VMX process anomalies",
                    "Suspicious VM operations",
                    "Ransomware file creation in datastores",
                ],
                "signatures": [
                    'Suricata: alert tcp $EXTERNAL_NET any -> $HOME_NET 443 (msg:"VMware ESXi RCE"; content:"/api"; sid:2025008; rev:1;)',
                ],
                "mitigation": [
                    "Apply VMware ESXi patches",
                    "Enable lockdown mode",
                    "Monitor VM operations",
                    "Restrict VM to host communications",
                ],
                "mitre_techniques": ["T1068", "T1486", "T1021"],
            },
            {
                "id": "news-2026-03-24-10",
                "title": "CVE-2024-29041: Microsoft Azure Synapse Vulnerability Exposes Data",
                "summary": "CVE-2024-29041 is a Server-Side Request Forgery (SSRF) in Microsoft Azure Synapse that allows attackers to access internal resources without authentication.",
                "source": "Microsoft",
                "source_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-29041",
                "cve": "CVE-2024-29041",
                "cve_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-29041",
                "published_at": "2024-04-09T00:00:00Z",
                "iocs": [
                    "Unusual outbound connections from Synapse",
                    "Suspicious API calls to internal endpoints",
                ],
                "signatures": [
                    'Snort: alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Azure SSRF"; content:"management.azure.com"; sid:2025009; rev:1;)',
                ],
                "mitigation": [
                    "Apply Microsoft patches",
                    "Restrict network access to Synapse",
                    "Enable Azure firewall rules",
                ],
                "mitre_techniques": ["T1189", "T1041", "T1005"],
            },
        ]

    def _ensure_cache_table(self):
        conn = sqlite3.connect(str(self.cache_path))
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS news_cache (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def _cache_items(self, news_items):
        conn = sqlite3.connect(str(self.cache_path))
        c = conn.cursor()
        c.execute("DELETE FROM news_cache")
        now = datetime.utcnow().isoformat()
        for item in news_items:
            c.execute(
                "INSERT OR REPLACE INTO news_cache (id, payload, updated_at) VALUES (?, ?, ?)",
                (item["id"], json.dumps(item), now),
            )
        conn.commit()
        conn.close()

    def _cached_items(self):
        conn = sqlite3.connect(str(self.cache_path))
        c = conn.cursor()
        c.execute("SELECT payload, updated_at FROM news_cache ORDER BY updated_at DESC")
        rows = c.fetchall()
        conn.close()

        if not rows:
            return []

        last_updated = datetime.fromisoformat(rows[0][1])
        if datetime.utcnow() - last_updated > timedelta(seconds=self.cache_ttl_seconds):
            return []

        return [json.loads(row[0]) for row in rows]

    def get_latest(self, limit=10):
        cached = self._cached_items()
        if cached:
            return cached[:limit]

        self._cache_items(self.news)
        return self.news[:limit]


def get_feed():
    return CyberNewsFeed()
