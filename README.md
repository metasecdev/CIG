# Cyber Intelligence Gateway (CIG)

A real-time cyber threat intelligence platform that aggregates multiple threat feeds, captures network traffic, matches indicators against known threats, and generates security alerts with MITRE ATT&CK mapping.

## Features

### Threat Intelligence Feeds
- **MISP** - Malware Information Sharing Platform integration
- **pfBlockerNG** - DNS blocklists (ads, trackers, malware, phishing)
- **AbuseIPDB** - IP reputation database
- **Abuse.ch** - URLhaus (malware URLs) and ThreatFox (malware indicators)
- **CVE Details** - Vulnerability data from cvedetails.com
- **CISA KEV** - Known Exploited Vulnerabilities catalog
- **Shadowserver** - Network vulnerability reports (requires API key)

### Network Capture
- **PCAP Capture** - Packet capture on LAN/WAN interfaces
- **DNS Query Monitoring** - Real-time DNS query logging and analysis
- **Deep Packet Inspection** - Network traffic analysis

### Threat Matching
- DNS query matching against threat intelligence
- PCAP traffic analysis with IOCs
- Real-time alerting on matches
- Configurable confidence thresholds

### Security Reporting
- MITRE ATT&CK framework mapping
- Trend analysis and visualization
- Security alert generation
- Webhook notifications

### Additional Capabilities
- Multi-tenant support
- OAuth authentication
- Automated response capabilities
- Arkime integration for packet capture analysis
- RESTful API for integrations

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python -m app.main

# Or with custom settings
python -m app.main --host 0.0.0.0 --port 8000 --debug
```

## Configuration

Configure via environment variables or edit `app/core/config.py`:

| Variable | Description | Default |
|----------|-------------|---------|
| `API_HOST` | API server host | `0.0.0.0` |
| `API_PORT` | API server port | `8000` |
| `DATABASE_PATH` | SQLite database path | `data/cig.db` |
| `PCAP_DIR` | PCAP storage directory | `data/pcaps` |
| `MISP_URL` | MISP instance URL | - |
| `MISP_API_KEY` | MISP API key | - |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key | - |
| `WEBHOOK_URL` | Alert webhook URL | - |

## API Endpoints

- `GET /api/alerts` - List security alerts
- `GET /api/feeds` - List configured feeds
- `POST /api/feeds/refresh` - Manually refresh feeds
- `GET /api/indicators` - List threat indicators
- `GET /api/health` - Health check
- `GET /api/trends` - Threat trends

## Architecture

```
app/
├── api/          # FastAPI routes and endpoints
├── capture/      # PCAP and packet capture
├── core/         # Configuration and settings
├── feeds/        # Threat intelligence feeds
├── matching/     # Threat matching engine
├── models/       # Database models
├── mitre/        # MITRE ATT&CK mapping
├── reporting/    # Security reports
├── alerts/       # Notifications and webhooks
├── analysis/     # Trend analysis
├── auth/         # Authentication
├── automation/   # Automated response
└── utils/        # Utilities
```

## Requirements

- Python 3.11+
- FastAPI, Uvicorn
- SQLite (built-in)
- Optional: scapy, dpkt, mitreattack-python, elasticsearch

## Testing

```bash
# Run tests
python -m pytest

# Run specific test
python simple_test.py
```

## Docker

```bash
docker build -t cig .
docker run -p 8000:8000 cig
```