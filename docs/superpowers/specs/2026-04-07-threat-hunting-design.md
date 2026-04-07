# Threat Hunting — Design Specification

## Metadata

- **Date:** 2026-04-07
- **Project:** Cyber Intelligence Gateway (CIG) — Phase C Threat Hunting
- **Phase:** C (Threat Hunting)

---

## 1. Overview

### Purpose

Proactively hunt for malware TTPs (Tactics, Techniques, and Procedures) in captured network traffic. Using indicators, signatures, and TTPs generated from Phase B malware analysis, hunt operators construct hypotheses and search PCAP captures, DNS query logs, HTTP flow logs, and alert history to identify previously undetected threats.

### Scope

Threat hunting in CIG is a manual + semi-automated process:

1. **Hypothesis Formation** — Based on malware analysis TTPs, current threat intel, or analyst experience
2. **Data Source Identification** — PCAP, DNS logs, HTTP flows, alert history
3. **Search Query Execution** — YARA scan on PCAP, Sigma rule matching on logs, direct indicator lookup
4. **Findings Documentation** — Alert creation, signature updates, hunt report

### Dependencies

- Phase B malware analysis output (IOCs, signatures, ATT&CK mappings)
- PCAP capture infrastructure (`app/capture/pcap.py`)
- DNS query monitoring (`app/capture/pcap.py`)
- ThreatMatcher (`app/matching/engine.py`)
- CIG indicator database

---

## 2. Hunt Playbook Framework

Each hunt follows a structured playbook format:

```yaml
hunt_playbook:
  id: "HUNT-XXXX"
  name: "Hunt Name"
  author: "Analyst"
  created: "YYYY-MM-DD"
  updated: "YYYY-MM-DD"
  status: "active" | "archived"

  hypothesis:
    statement: "Description of what we expect to find"
    confidence: "high" | "medium" | "low"
    affected_malware: ["list of related malware families"]

  ttps:
    - technique_id: "T1059"
      name: "Command and Scripting Interpreter"
      hunt_queries:
        - data_source: "pcap"
          query: "search query or yara rule"
        - data_source: "dns_logs"
          query: "search query"

  data_sources:
    - name: "PCAP captures"
      location: "data/pcaps/"
      retention: "30 days"
    - name: "DNS query logs"
      location: "data/logs/dns/"
      retention: "30 days"
    - name: "HTTP flow logs"
      location: "data/logs/http/"
      retention: "30 days"
    - name: "Alert history"
      location: "SQLite: data/cig.db"
      retention: "30 days"

  workflow:
    manual_steps:
      - "Step 1"
      - "Step 2"
    automated_rules:
      - rule_name: "sigma_rule_name"
        type: "sigma"
      - rule_name: "yara_rule_name"
        type: "yara"

  findings:
    alert_template:
      severity: "high" | "medium" | "low"
      description: "Finding description"
      indicators: ["list of matched IOCs"]
      recommended_actions: ["list of actions"]

  references:
    - type: "mitre_attack"
      id: "T1059"
    - type: "malware_analysis"
      sample_id: "UUID"
```

---

## 3. Hunt Playbooks

### 3.1 Hunt: PowerShell-based C2 (T1059)

**Hypothesis:** Malware using PowerShell for command and control will exhibit distinctive patterns in DNS queries or HTTP requests — particularly encoded commands, long random subdomain strings, or frequent queries to dynamic DNS providers.

**TTP:** T1059 — Command and Scripting Interpreter (PowerShell)

**Data Sources:**
- PCAP captures (DNS and HTTP traffic)
- DNS query logs
- Alert history (PowerShell-related alerts)

**Hunt Queries:**

| Data Source | Query | Purpose |
|------------|-------|---------|
| PCAP | `dns and query contains "powershell"` | Find DNS queries for PowerShell-related domains |
| PCAP | `http and user-agent contains "powershell"` | Find HTTP requests from PowerShell |
| DNS Logs | Pattern: `substring in domain [8-16 chars].*[a-z]{5,}` | Detect domain generation algorithms (DGA) |
| DNS Logs | High query volume to dynamic DNS (noaas.biz, freednss.org) | Detect dynamic DNS C2 |
| Alert History | `source: malware_analysis AND technique: T1059` | Correlate with known PowerShell malware |

**Manual Investigation Steps:**
1. Export PCAP for suspect time window
2. Analyze DNS queries for patterns (entropy, length, frequency)
3. Extract any HTTP payloads for further analysis
4. Submit suspicious samples to malware analysis
5. Document findings and update indicators

**Automated Rules:**
- Sigma rule: PowerShell command execution detection
- YARA rule: PowerShell script content in PCAP payloads

**Findings Template:**
```json
{
  "severity": "high",
  "description": "Suspicious PowerShell C2 detected",
  "matched_patterns": ["encoded PowerShell commands in DNS"],
  "source_ips": ["list"],
  "destination_ips": ["list"],
  "indicators": ["malware family if identified"],
  "recommended_actions": [
    "Isolate affected host",
    "Submit samples for analysis",
    "Update firewall rules",
    "Block associated domains/IPs"
  ]
}
```

---

### 3.2 Hunt: Process Injection Indicators (T1055)

**Hypothesis:** Malware performing process injection will exhibit suspicious DLL loading patterns, memory allocation with executable permissions, or cross-process thread creation visible in network behavior.

**TTP:** T1055 — Process Injection

**Data Sources:**
- PCAP captures (DLL loading patterns in HTTP)
- HTTP flow logs (suspicious DLL downloads)
- Alert history (process injection alerts)

**Hunt Queries:**

| Data Source | Query | Purpose |
|------------|-------|---------|
| PCAP | `http.request.uri contains ".dll"` | Find DLL download requests |
| PCAP | `tcp.flags.push and tcp.window_size < 1000` | Detect potential hollow process behavior |
| HTTP Logs | URI pattern: `/*\?.*dl.*=.*` or `/*\.dll$` | Detect DLL exfiltration/download |
| Alert History | `technique: T1055` | Correlate with known process injection |

**Manual Investigation Steps:**
1. Extract DLL-related HTTP flows from PCAP
2. Calculate entropy of downloaded DLLs (packed = high entropy)
3. Submit suspicious DLLs to malware analysis
4. Check VirusTotal for known malicious DLLs
5. Look for Parent/Child process relationship anomalies

**Automated Rules:**
- YARA rule: High-entropy DLL detection in PCAP
- Sigma rule: Suspicious process creation events

**Findings Template:**
```json
{
  "severity": "high",
  "description": "Suspicious process injection indicators",
  "matched_patterns": ["high entropy DLL download", "suspicious DLL path"],
  "source_ips": ["list"],
  "destination_ips": ["list"],
  "indicators": ["DLL hash if extracted"],
  "recommended_actions": [
    "Analyze DLL in sandbox",
    "Block associated domains",
    "Monitor for follow-up C2 activity"
  ]
}
```

---

### 3.3 Hunt: Obfuscated File Delivery (T1027)

**Hypothesis:** Malware delivering obfuscated files via HTTP will transmit base64-encoded content, XOR-obfuscated payloads, or encrypted archives that can be detected by examining HTTP body entropy and content patterns.

**TTP:** T1027 — Obfuscated Files or Information

**Data Sources:**
- PCAP captures (HTTP payloads)
- HTTP flow logs
- Alert history

**Hunt Queries:**

| Data Source | Query | Purpose |
|------------|-------|---------|
| PCAP | `http.content_type contains "octet-stream"` | Find binary file downloads |
| PCAP | Content regex: `[A-Za-z0-9+/]{100,}={0,2}$` | Detect base64-encoded content |
| PCAP | Entropy scan: `entropy > 6.5` in payload | Detect encrypted/packed content |
| HTTP Logs | Content-Encoding: `identity` but binary content | Detect tunneling |
| Alert History | `technique: T1027` | Correlate with known obfuscated malware |

**Manual Investigation Steps:**
1. Extract HTTP POST/GET bodies from suspect flows
2. Attempt base64 decoding — if successful and contains binary headers (MZ, ELF), flag as suspicious
3. Calculate entropy of payloads — values > 6.5 may indicate encryption/packing
4. Submit decoded content to malware analysis
5. Check for embedded URLs or IPs in decoded content

**Automated Rules:**
- YARA rule: base64-encoded PE/MZ headers
- YARA rule: High entropy detection (>6.5)
- Sigma rule: Suspicious HTTP binary downloads

**Findings Template:**
```json
{
  "severity": "medium",
  "description": "Obfuscated file delivery detected",
  "matched_patterns": ["base64-encoded content in HTTP", "high entropy payload"],
  "source_ips": ["list"],
  "destination_ips": ["list"],
  "indicators": ["decoded content hash"],
  "recommended_actions": [
    "Decode and analyze payload",
    "Submit to malware analysis",
    "Block associated download source"
  ]
}
```

---

### 3.4 Hunt: Rundll32 Execution (T1218)

**Hypothesis:** Malware using rundll32.exe for signed binary proxy execution will exhibit distinctive process creation patterns, DLL loads via command-line invocation, or network connections from unusual source processes.

**TTP:** T1218 — System Binary Proxy Execution (Rundll32)

**Data Sources:**
- PCAP captures (network activity from rundll32)
- HTTP flow logs
- Alert history (rundll32 execution alerts)

**Hunt Queries:**

| Data Source | Query | Purpose |
|------------|-------|---------|
| PCAP | `tcp and ip.src != internal and (http contains "rundll32" or http contains "DLL")` | Find rundll32 network activity |
| DNS Logs | Query for suspicious DLL-related hostnames | Detect DLL delivery |
| HTTP Logs | `User-Agent` contains `rundll32` or `Microsoft-CryptoAPI` | Detect CAPI network activity |
| Alert History | `source: endpoint AND process: rundll32.exe` | Correlate endpoint alerts |

**Manual Investigation Steps:**
1. Identify all HTTP flows where User-Agent indicates rundll32 or related processes
2. Extract and analyze any downloaded DLLs
3. Correlate network activity with host-based alerts
4. Submit suspicious DLLs for analysis
5. Identify parent process chain (explorer.exe → cmd.exe → rundll32.exe is suspicious)

**Automated Rules:**
- Sigma rule: Rundll32 suspicious command line detection
- YARA rule: Suspicious rundll32 network patterns
- YARA rule: DLL with unusual imports (VirtualAlloc, WriteProcessMemory)

**Findings Template:**
```json
{
  "severity": "high",
  "description": "Rundll32 suspicious execution detected",
  "matched_patterns": ["rundll32 network activity", "suspicious DLL download"],
  "source_ips": ["list"],
  "destination_ips": ["list"],
  "indicators": ["DLL hash", "command line if available"],
  "recommended_actions": [
    "Isolate affected host",
    "Analyze downloaded DLL",
    "Review parent process chain",
    "Block associated C2 infrastructure"
  ]
}
```

---

## 4. Integration with CIG

### 4.1 Signature Feedback Loop

Malware analysis results (Phase B) feed directly into hunt playbooks:

```
Malware Analysis (Phase B)
    │
    ├── IOC Extraction ──────────────────────────┐
    │   ├── IP addresses ──────────────────────│──→ ThreatMatcher
    │   ├── Domain names ─────────────────────│──→ DNS Monitor
    │   ├── File hashes ───────────────────────│──→ Alert Enrichment
    │   └── URLs ──────────────────────────────┘
    │
    ├── Signature Generation ───────────────────┐
    │   ├── YARA rules ─────────────────────────│──→ Hunt: YARA Scan
    │   ├── STIX bundle ────────────────────────│──→ Threat Intel Share
    │   └── Sigma rules ────────────────────────│──→ Hunt: Log Analysis
    │
    └── ATT&CK Mapping ─────────────────────────┐
        └── Technique IDs ──────────────────────│──→ Hunt: Hypothesis
```

### 4.2 Hunt to Detection Pipeline

Results from hunts flow back into CIG detection:

```
Hunt Findings
    │
    ├── New IOCs ──────────────────────────────→ CIGFeedUpdater
    │                                                │
    │                                                ↓
    │                                           ThreatMatcher DB
    │
    ├── New/Updated Rules ────────────────────→ CIGSignatureDeliverer
    │                                                │
    │                                                ↓
    │                                           ThreatMatcher Rules
    │
    └── Hunt Alerts ───────────────────────────→ CIG Alert Enrichment
                                                    │
                                                    ↓
                                              Dashboard + Reports
```

### 4.3 Automated Hunt Execution

Sigma rules generated from ATT&CK mappings can be deployed for automated hunting:

1. **Rule Generation** — ATTACKMapper generates Sigma rules from technique mappings
2. **Rule Deployment** — CIGSignatureDeliverer pushes rules to ThreatMatcher
3. **Automated Matching** — ThreatMatcher runs Sigma/YARA rules against incoming data
4. **Alert Generation** — Matches create alerts with hunt reference

---

## 5. Data Sources

### 5.1 PCAP Captures

**Location:** `data/pcaps/`

**Format:** Standard pcap with gzip compression and rotation

**Retention:** 30 days (configurable via `PCAP_RETENTION_DAYS`)

**Search Methods:**
- `tcpdump` for packet-level queries
- Scapy for Python-based analysis
- tshark for protocol-specific extraction

**Hunt-Queriable Fields:**
- Source/destination IP and port
- Protocol (tcp, udp, icmp)
- DNS query names
- HTTP URIs and headers
- Payload content (for YARA scanning)

### 5.2 DNS Query Logs

**Location:** `data/logs/dns/` (created by DNSQueryMonitor)

**Format:** JSON Lines (one JSON object per query)

**Log Entry:**
```json
{
  "timestamp": "YYYY-MM-DDTHH:MM:SS",
  "query": "example.com",
  "response_ip": "1.2.3.4",
  "src_ip": "192.168.1.100",
  "query_type": "A"
}
```

**Retention:** 30 days

**Hunt-Queriable Fields:**
- Query name (domain)
- Response IP
- Source IP
- Timestamp

### 5.3 HTTP Flow Logs

**Location:** `data/logs/http/`

**Format:** JSON Lines (one JSON object per flow)

**Log Entry:**
```json
{
  "timestamp": "YYYY-MM-DDTHH:MM:SS",
  "src_ip": "192.168.1.100",
  "dst_ip": "5.6.7.8",
  "dst_port": 443,
  "method": "POST",
  "uri": "/api/data",
  "user_agent": "Mozilla/5.0",
  "content_type": "application/json",
  "content_length": 1024,
  "host": "malware-c2.example.com"
}
```

**Retention:** 30 days

**Hunt-Queriable Fields:**
- URI, host, user-agent
- Source/destination IP
- Content-type and content-length
- Payload content (when available)

### 5.4 Alert History

**Location:** SQLite database `data/cig.db`, table `alerts`

**Schema:**
```sql
CREATE TABLE alerts (
    id TEXT PRIMARY KEY,
    timestamp TEXT,
    severity TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    indicator TEXT,
    indicator_type TEXT,
    feed_source TEXT,
    rule_id TEXT,
    message TEXT,
    enriched_at TEXT,
    malware_family TEXT,
    attack_techniques TEXT
);
```

**Retention:** 30 days (configurable)

---

## 6. Workflow

### 6.1 Manual Investigation Steps

1. **Select Hunt Playbook**
   - Choose based on current threat landscape or malware analysis results
   - Review hypothesis and expected TTPs

2. **Gather Data**
   - Identify relevant time window
   - Export PCAP or extract logs for suspect period

3. **Execute Hunt Queries**
   - Run data source queries in sequence
   - Document all matches and partial matches

4. **Analyze Findings**
   - Score findings by confidence and severity
   - Identify patterns suggesting specific malware families

5. **Respond to Findings**
   - Create CIG alerts for high-confidence findings
   - Submit suspicious samples to malware analysis
   - Update indicators and rules

### 6.2 Automated Scanning

For each hunt playbook, automated rules can be deployed:

1. **YARA Scanning (PCAP)**
   - Scan PCAP files using yara-python
   - Match against malware-specific rule sets
   - Alert on matches with high priority

2. **Sigma Rule Matching (Logs)**
   - Deploy Sigma rules to CIG log processing
   - Match against DNS and HTTP logs
   - Generate alerts for rule matches

3. **Indicator Lookup**
   - Cross-reference PCAP/log data against CIG indicator database
   - Trigger alerts for known malicious indicators

---

## 7. Hunt API Endpoints

```
# List available hunt playbooks
GET    /api/hunt/playbooks           # List all playbooks
GET    /api/hunt/playbooks/{id}      # Get specific playbook

# Execute hunt
POST   /api/hunt/execute/{playbook_id}   # Execute hunt playbook
GET    /api/hunt/results/{hunt_id}       # Get hunt results

# Hunt data sources
GET    /api/hunt/pcap/search         # Search PCAP captures
GET    /api/hunt/dns/logs            # Query DNS logs
GET    /api/hunt/http/logs           # Query HTTP logs
GET    /api/hunt/alerts              # Query alert history

# Hunt signatures
GET    /api/hunt/signatures          # List hunt-generated signatures
GET    /api/hunt/signatures/yara     # Export YARA rules
GET    /api/hunt/signatures/sigma    # Export Sigma rules

# Integration with malware analysis
GET    /api/hunt/attack-mapping/{sample_id}  # Get ATT&CK mapping for sample
POST   /api/hunt/from-analysis/{sample_id}   # Auto-generate hunt from analysis
```

---

## 8. Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `HUNT_ENABLED` | `true` | Enable threat hunting |
| `PCAP_RETENTION_DAYS` | `30` | PCAP retention period |
| `DNS_LOG_RETENTION_DAYS` | `30` | DNS log retention |
| `HTTP_LOG_RETENTION_DAYS` | `30` | HTTP log retention |
| `ALERT_RETENTION_DAYS` | `30` | Alert retention |
| `AUTO_HUNT_INTERVAL` | `3600` | Seconds between automated hunts |
| `YARA_SCAN_LIMIT_MB` | `100` | Max PCAP size for YARA scanning |
| `SIGMA_RULES_ENABLED` | `true` | Enable Sigma rule matching |
| `HUNT_ALERT_SEVERITY_THRESHOLD` | `medium` | Minimum severity for hunt alerts |

---

## 9. Acceptance Criteria

- [ ] Hunt playbook framework documented in `docs/superpowers/specs/`
- [ ] At least 4 hunt playbooks covering major TTPs (T1059, T1055, T1027, T1218)
- [ ] Playbooks executable via CIG API + manual investigation steps
- [ ] TTPs from malware analysis used in hunt hypothesis generation
- [ ] Hunt findings flow back into CIG detection pipeline
- [ ] YARA/Sigma rules generated from malware analysis can be deployed as hunt rules
- [ ] Hunt results linkable to malware analysis samples
