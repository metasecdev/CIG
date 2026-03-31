"""Cybersecurity news feed provider"""
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path


class CyberNewsFeed:
    """Simple in-memory cybersecurity news feed provider"""

    def __init__(self):
        self.cache_ttl_seconds = 300
        self.cache_path = Path(__file__).parents[2] / 'data' / 'news_cache.db'
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_cache_table()

        self.news = [
            {
                "id": "news-2026-03-30-01",
                "title": "Critical Apache HTTP Server RCE (CVE-2026-1234) Exploited in the Wild",
                "summary": "Open source reports show active exploitation of Apache HTTP Server 2.4.x via RCE flaw.",
                "source": "opensource-threat-intel",
                "source_url": "https://www.example-intel.com/vuln/CVE-2026-1234",
                "cve": "CVE-2026-1234",
                "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
                "published_at": datetime.utcnow().isoformat(),
                "iocs": [
                    "192.0.2.100", "203.0.113.55", "malicious.example[.]domain"
                ],
                "signatures": [
                    "Snort: alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:\"CVE-2026-1234 Apache HTTP RCE\"; flow:to_server,established; content:\"/cgi-bin/\"; pcre:\"/\.\./\.\./\w+/bin\/sh/\"; sid:1000001; rev:1;)",
                    "YARA: rule CVE_2026_1234 { strings: $a = 'Apache/2.4' condition: $a }"
                ],
                "mitigation": [
                    "Apply vendor patch Apache 2.4.58+", "Disable mod_cgi for untrusted content", "Enable WAF rules for RCE payloads"
                ],
            },
            {
                "id": "news-2026-03-30-02",
                "title": "New Botnet Campaign Uses Windows PrintNightmare Variant",
                "summary": "Intel feeds indicate a variant of PrintNightmare being used to deploy botnet payloads on SMB-exposed hosts.",
                "source": "abuseipdb",
                "source_url": "https://www.abuseipdb.com/news/printnightmare-botnet",
                "published_at": datetime.utcnow().isoformat(),
                "iocs": ["10.0.0.22", "23.45.67.89", "evilbotnet[.]com"],
                "signatures": [
                    "Suricata: alert tcp $HOME_NET any -> $EXTERNAL_NET 445 (msg:\"PrintNightmare maldoc download\"; flow:to_server,established; content:\"/printnightmare\"; sid:1000002; rev:1;)",
                ],
                "mitigation": [
                    "Apply Microsoft KB5019260 or later", "Disable SMBv1", "Use endpoint detection for suspicious libcalls"],
            },
            {
                "id": "news-2026-03-30-03",
                "title": "Zero-day iOS Kernel Escalation Tracked to APT-29",
                "summary": "The cyber community is tracking an iOS zero-day with kernel exploit used in espionage campaigns.",
                "source": "misp",
                "source_url": "https://www.misp-project.org/notes/apt29-ios-zero-day",
                "published_at": datetime.utcnow().isoformat(),
                "iocs": ["C2: c2s.example[.]net", "SHA256: abc123...", "URL: hxxps://pwned[.]example/download"],
                "signatures": [
                    "Zeek: event http_request(c) { if (c$uri contains \"/download/payload\") { NOTICE([$note=\"APT29_iOS_zeroday\"]); }}"
                ],
                "mitigation": [
                    "Deploy iOS updates immediately", "Disable untrusted provisioning profiles", "Enable endpoint security monitoring"
                ],
                "ai_agent": "AI Analyst: correlate telemetry with known APT-29 TTPs and isolate infected hosts.",
            },
            {
                "id": "news-2026-03-29-04",
                "title": "Massive DDoS Campaign Hits Banking Sector",
                "summary": "A new botnet abusing home router UPnP vulnerabilities is flooding financial institutions with volumetric attacks.",
                "source": "threatpost",
                "source_url": "https://threatpost.com/ddos-banking-upnp/",
                "cve": "CVE-2025-3456",
                "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-3456",
                "published_at": datetime.utcnow().isoformat(),
                "iocs": ["198.51.100.1", "198.51.100.2", "198.51.100.3"],
                "signatures": [
                    "Snort: alert udp $EXTERNAL_NET any -> $HOME_NET any (msg:\"DDoS botnet UDP flood\"; threshold:type both, track by_src, count 100, seconds 1; sid:1000003; rev:1;)"
                ],
                "mitigation": [
                    "Rate-limit incoming UDP", "Implement scrubbing services", "Patch UPnP firmware"
                ],
                "ai_agent": "AI Analyst: recommend anomaly detection thresholds and upstream white-list policies.",
            },
            {
                "id": "news-2026-03-29-05",
                "title": "Phishing Campaign Using Microsoft 365 MFA Bypass",
                "summary": "Attackers use OAuth consent phishing to bypass MFA and access mailboxes.",
                "source": "cisa",
                "source_url": "https://www.cisa.gov/uscert/ncas/alerts/aa22-273a",
                "cve": "CVE-2025-9999",
                "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-9999",
                "published_at": datetime.utcnow().isoformat(),
                "iocs": ["login.microsoftonline.com", "fake-mfa.example[.]net"],
                "signatures": [
                    "Suricata: alert http $EXTERNAL_NET any -> $HOME_NET any (msg:\"OAuth consent phishing\"; content:\"/login/oauth2/authorize\"; pcre:\"/id_token\\?scope=offline_access/\"; sid:1000004; rev:1;)"
                ],
                "mitigation": [
                    "Enforce conditional access policies", "Revoke stale OAuth tokens", "Educate users on phishing links"
                ],
                "ai_agent": "AI Analyst: generate customized user training topics for this campaign.",
            },
            {
                "id": "news-2026-03-29-06",
                "title": "OpenSSL Heartbeat-like DoS Discovered in 1.1.1",
                "summary": "A DoS vector allowing memory exhaustion via malformed heartbeat-style packets was discovered in OpenSSL 1.1.1.",
                "source": "nvd",
                "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0006",
                "cve": "CVE-2026-0006",
                "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0006",
                "published_at": datetime.utcnow().isoformat(),
                "iocs": ["TCP 443 malformed heartbeat frames", "SHA256:deadbeef..."],
                "signatures": [
                    "Snort: alert tcp $EXTERNAL_NET any -> $HOME_NET 443 (msg:\"OpenSSL heartbeat DoS\"; flow:to_server,established; content:\"\\x18\\x03\\x03\"; dsize:>1000; sid:1000005; rev:1;)"
                ],
                "mitigation": [
                    "Upgrade to OpenSSL 3.0.10+", "Enable connection rate limiting", "Use TLS inspection policies"
                ],
                "ai_agent": "AI Analyst: suggest TLS session caching heuristics for malformed packet bursts.",
            },
            {
                "id": "news-2026-03-29-07",
                "title": "Linux Kernel Privilege Escalation via futex in 6.1",
                "summary": "Exploit code released for futex double-free leading to local privilege escalation.",
                "source": "exploit-db",
                "source_url": "https://www.exploit-db.com/exploits/51289",
                "cve": "CVE-2026-0420",
                "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0420",
                "published_at": datetime.utcnow().isoformat(),
                "iocs": ["futex syscall anomalies", "untrusted local binary execution"],
                "signatures": [
                    "Sysmon: EventID 10 with Image paths under /tmp/ suspicious process creation"
                ],
                "mitigation": [
                    "Apply kernel updates", "Disable unneeded local access", "Monitor for escalation patterns"
                ],
                "ai_agent": "AI Analyst: automatically profile new futex behavior anomalies and escalate.",
            },
            {
                "id": "news-2026-03-29-08",
                "title": "Credential Stuffing Botnet Abuses API Rate Limiters",
                "summary": "Threat actors use distributed proxy pools for large-scale credential stuffing targeting SaaS portals.",
                "source": "darkreading",
                "source_url": "https://www.darkreading.com/oss-security/credential-stuffing-botnet",
                "cve": "CVE-2025-5598",
                "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2025-5598",
                "published_at": datetime.utcnow().isoformat(),
                "iocs": ["api.example.com/login", "repeat IP burst pattern"],
                "signatures": [
                    "WAF: block requests with malformed user-agent and repeated password attempts."
                ],
                "mitigation": [
                    "Enable MFA", "Account lockout after failed login", "Use device fingerprinting"
                ],
                "ai_agent": "AI Analyst: propose decoy login pages and attack path modeling.",
            },
            {
                "id": "news-2026-03-29-09",
                "title": "Supply Chain Vendor Breach Impacts Healthcare Providers",
                "summary": "Compromise of a third-party vendor led to unauthorized access to patient data and EMR systems.",
                "source": "healthitsecurity",
                "source_url": "https://healthitsecurity.com/news/supply-chain-vendor-breach-2026",
                "published_at": datetime.utcnow().isoformat(),
                "iocs": ["vendor-ssh.example.com", "stolen API token"],
                "signatures": [
                    "Wazuh: rule for anomalous external vendor connections to EMR database ports."
                ],
                "mitigation": [
                    "Review vendor access controls", "Rotate API keys", "Monitor third-party logs"
                ],
                "ai_agent": "AI Analyst: perform risk-based vendor segmentation and continuous verification.",
            },
            {
                "id": "news-2026-03-29-10",
                "title": "Critical VMware vSphere Authentication Bypass (CVE-2026-7200)",
                "summary": "Unauthenticated access via vCenter endpoint allows arbitrary code execution.",
                "source": "vmware-advisory",
                "source_url": "https://www.vmware.com/security/advisories/VMSA-2026-0001.html",
                "cve": "CVE-2026-7200",
                "cve_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-7200",
                "published_at": datetime.utcnow().isoformat(),
                "iocs": ["vcenter.example.com/login", "malicious POST /ui/login"],
                "signatures": [
                    "Snort: alert tcp $EXTERNAL_NET any -> $HOME_NET 443 (msg:\"VMware vCenter auth bypass exploit\"; flow:to_server,established; content:\"/ui/login?action=\"; sid:1000006; rev:1;)"
                ],
                "mitigation": [
                    "Patch to vCenter 8.0u2g+", "Restrict management network", "Enable MFA"
                ],
                "ai_agent": "AI Analyst: map to event log patterns and create immediate alert triggers.",
            }
        ]

    def _ensure_cache_table(self):
        conn = sqlite3.connect(str(self.cache_path))
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS news_cache (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

    def _cache_items(self, news_items):
        conn = sqlite3.connect(str(self.cache_path))
        c = conn.cursor()
        c.execute('DELETE FROM news_cache')
        now = datetime.utcnow().isoformat()
        for item in news_items:
            c.execute(
                'INSERT OR REPLACE INTO news_cache (id, payload, updated_at) VALUES (?, ?, ?)',
                (item['id'], json.dumps(item), now)
            )
        conn.commit()
        conn.close()

    def _cached_items(self):
        conn = sqlite3.connect(str(self.cache_path))
        c = conn.cursor()
        c.execute('SELECT payload, updated_at FROM news_cache ORDER BY updated_at DESC')
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