# Feed Management & Configuration - Complete Guide

## Overview

The CIG now includes comprehensive feed management with centralized credential management, advanced scheduling, and configuration pages for managing API credentials and custom threat feeds.

## Features

### 1. **Feed Scheduler Management**
- Centralized orchestration of all threat intelligence feeds
- Midnight UTC automatic synchronization
- Priority-based scheduling (CRITICAL, HIGH, MEDIUM, LOW)
- State persistence with automatic recovery
- Manual trigger endpoints for immediate updates

### 2. **DShield Honeypot Polling**
- SSH attack collection from SANS network
- Web scanner detection
- Port trend analysis
- Threat summarization with geographic data
- Real-time polling capabilities

### 3. **Advanced Feed Filtering**
- Multi-dimensional filtering (type, severity, severity ranges, tags, age, confidence)
- Custom regex pattern matching
- Feed-specific exclusions
- AND/OR composition logic
- Configuration persistence

### 4. **Nessus Integration (Ready to Activate)**
- API key and secret credential storage
- Scan retrieval and vulnerability processing
- Severity distribution tracking
- Automatic database ingestion
- Waiting for user API credentials

### 5. **GrayNoise Integration (Ready to Activate)**
- Community and enterprise API support
- IP reputation tracking
- Trending malicious IP detection
- Rate limit awareness
- Waiting for user API key

### 6. **Custom API Feed Connector**
- Generic framework for ANY REST API threat feed
- Multiple authentication methods:
  - API Key (Header)
  - Bearer Token
  - Basic Authentication
  - Custom Headers
  - OAuth2 support ready
- Data format support:
  - JSON
  - CSV
  - XML
  - STIX
  - Custom formats

### 7. **Report Ingestion System**
- Multi-format security report processing
- Automatic indicator extraction:
  - IP addresses (IPv4/IPv6)
  - Domains
  - URLs
  - Email addresses
  - Hashes
  - CIDR ranges
  - ASNs
- Report metadata tracking
- Statistics and analytics

## API Endpoints

### Scheduler Endpoints

```
GET  /api/scheduler/status          - Get scheduler status and all feeds
POST /api/scheduler/start           - Start the scheduler
POST /api/scheduler/stop            - Stop the scheduler
POST /api/scheduler/feed/{id}/update - Update a specific feed
POST /api/scheduler/update-all       - Update all feeds
```

### DShield Endpoints

```
GET  /api/feeds/dshield/status      - Get DShield stats
POST /api/feeds/dshield/poll        - Manually poll DShield
GET  /api/feeds/dshield/threats     - Get threat summary
```

**Poll Types:**
- `poll_type=ssh` - Poll SSH attacks only
- `poll_type=web` - Poll web attacks only
- `poll_type=all` - Poll all sources (default)

### Filter Endpoints

```
GET  /api/filters/status            - Get filter engine status
POST /api/filters/apply             - Apply filters to indicators
```

### Configuration Endpoints

```
GET  /api/config/status             - Get overall configuration status

POST /api/config/nessus/credentials - Set Nessus API credentials
GET  /api/config/nessus/enabled     - Check if Nessus is enabled

POST /api/config/graynoise/credentials - Set GrayNoise API credentials
GET  /api/config/graynoise/enabled     - Check if GrayNoise is enabled

POST   /api/config/custom-api/add   - Add/update a custom API feed
GET    /api/config/custom-api/list  - List all custom API feeds
DELETE /api/config/custom-api/{id}  - Remove a custom API feed
```

### Report Ingestion Endpoints

```
GET  /api/reports/ingestion/status  - Check ingestion service status
POST /api/reports/ingest            - Ingest a security report file
```

## Configuration Dashboard (`/dashboard/config`)

The configuration page provides a web interface for:

### Nessus Configuration Tab
- API Key and Secret input fields
- Host URL configuration
- Enable/disable toggle
- Test connection button
- Encrypted credential storage

### GrayNoise Configuration Tab
- API Key input
- API Type selection (Community/Enterprise)
- Enable/disable toggle
- Test connection button
- Encrypted credential storage

### Custom API Feeds Tab
- List of currently configured feeds
- Add new feed form:
  - Feed ID
  - Feed Name
  - API URL
  - Authentication type (6 options)
  - Auth value/key
  - Polling interval (hours)
  - Enable/disable toggle
- Remove feed functionality
- Refresh list button

### DShield Tab
- Real-time threat summary
- Top threat countries
- Common attack ports
- Last update timestamp
- Poll buttons:
  - Poll All Sources
  - Poll SSH Attacks
  - Poll Web Attacks
- Manual summary refresh

## Feed Management Dashboard (`/dashboard/feeds`)

The feed management page provides:

### Statistics
- Overall scheduler status
- Number of active feeds
- Last update timestamp

### Control Bar
- Start/Stop scheduler
- Update all feeds
- Refresh status

### Feed Cards
For each registered feed:
- Status display (Running/Stopped/Updating)
- Priority level
- Last update time
- Next scheduled update
- Current indicator count
- Total updates since startup
- Quick action buttons:
  - Update (triggers immediate poll)
  - Details (view feed-specific info)

## Usage Examples

### 1. Activating Nessus

```bash
# Set Nessus credentials
curl -X POST http://localhost:8000/api/config/nessus/credentials \
  -H "Content-Type: application/json" \
  -d '{
    "api_key": "your-key",
    "api_secret": "your-secret",
    "host": "https://cloud.nessus.com",
    "enabled": true
  }'

# Check if enabled
curl http://localhost:8000/api/config/nessus/enabled
```

### 2. Activating GrayNoise

```bash
# Set GrayNoise credentials
curl -X POST http://localhost:8000/api/config/graynoise/credentials \
  -H "Content-Type: application/json" \
  -d '{
    "api_key": "your-api-key",
    "api_type": "enterprise",
    "enabled": true
  }'

# Check if enabled
curl http://localhost:8000/api/config/graynoise/enabled
```

### 3. Adding a Custom API Feed

```bash
# Add a custom threat intelligence feed
curl -X POST http://localhost:8000/api/config/custom-api/add \
  -H "Content-Type: application/json" \
  -d '{
    "feed_id": "my-threat-feed",
    "feed_name": "My Threat Intelligence",
    "api_url": "https://api.example.com/threats",
    "auth_type": "api_key",
    "auth_value": "sk-1234567890",
    "polling_interval_hours": 24,
    "enabled": true
  }'

# List all custom feeds
curl http://localhost:8000/api/config/custom-api/list

# Remove a custom feed
curl -X DELETE http://localhost:8000/api/config/custom-api/my-threat-feed
```

### 4. Triggering Feed Updates

```bash
# Update a specific feed immediately
curl -X POST http://localhost:8000/api/scheduler/feed/dshield/update?force=true

# Update all feeds
curl -X POST http://localhost:8000/api/scheduler/update-all

# Start the scheduler (runs at midnight UTC)
curl -X POST http://localhost:8000/api/scheduler/start

# Stop the scheduler
curl -X POST http://localhost:8000/api/scheduler/stop
```

### 5. Checking Scheduler Status

```bash
# Get full scheduler status
curl http://localhost:8000/api/scheduler/status

# Response example:
{
  "status": "success",
  "scheduler_running": true,
  "feeds": {
    "dshield": {
      "name": "DShield Honeypot",
      "enabled": true,
      "status": "running",
      "priority": "CRITICAL",
      "last_update_time": "2026-03-31T23:45:00Z",
      "next_update_time": "2026-04-01T00:00:00Z",
      "indicators_count": 1245
    }
  }
}
```

### 6. Polling DShield

```bash
# Poll all sources
curl -X POST http://localhost:8000/api/feeds/dshield/poll?poll_type=all

# Poll SSH attacks only
curl -X POST http://localhost:8000/api/feeds/dshield/poll?poll_type=ssh

# Get threat summary
curl http://localhost:8000/api/feeds/dshield/threats
```

### 7. Ingesting Security Reports

```bash
# Upload and process a JSON security report
curl -X POST http://localhost:8000/api/reports/ingest \
  -d "file_path=/path/to/report.json" \
  -d "report_format=json"

# Supported formats: json, csv, text, pdf, xml, stix
```

## Configuration Files

### Credentials File
Location: `/Users/wo/code/config/feed_credentials.json`

```json
{
  "nessus": {
    "api_key": "***",
    "api_secret": "***",
    "host": "https://cloud.nessus.com",
    "enabled": false
  },
  "graynoise": {
    "api_key": "***",
    "api_type": "enterprise",
    "enabled": false
  },
  "custom_apis": {
    "my-feed": {
      "feed_id": "my-feed",
      "feed_name": "My Threat Intelligence",
      "api_url": "https://api.example.com/threats",
      "auth_type": "api_key",
      "auth_value": "***",
      "polling_interval_hours": 24,
      "enabled": true
    }
  }
}
```

### Filter Configuration File
Location: `/Users/wo/code/config/feed_filters.json`

```json
{
  "strict_filter": {
    "filter_id": "strict",
    "filter_name": "Strict Threat Filter",
    "indicator_types": ["IP", "DOMAIN"],
    "min_severity": "HIGH",
    "max_age_days": 7,
    "enabled": true
  }
}
```

## Error Handling & Logging

All new endpoints include comprehensive error handling:

- **503 Service Unavailable**: Components not initialized
- **400 Bad Request**: Invalid parameters
- **404 Not Found**: Resource not found
- **500 Internal Server Error**: Processing failed

Check `/Users/wo/code/data/logs/cig.log` for detailed error messages.

## MITRE ATT&CK Fix

The MITRE ATT&CK `typing.io` dependency warning has been suppressed in [app/mitre/attack_mapper.py](app/mitre/attack_mapper.py) by:
- Adding warning suppression at module level
- Using context manager for import isolation
- Maintaining fallback mapping system

This eliminates noisy log messages while preserving functionality.

## Performance Notes

- **Scheduler**: Background task, no API latency impact
- **DShield Polling**: ~2-5 seconds per source
- **Filter Engine**: O(n) per indicator, parallelizable
- **Report Ingestion**: Streaming parser, constant memory
- **Custom APIs**: Configurable timeouts, rate-aware

## Security Considerations

1. **Credentials Storage**: Stored in JSON files, consider encrypting with environment variables
2. **API Keys**: Masked in logs and API responses (shown as `***`)
3. **Network**: Use HTTPS for all external API calls
4. **Authentication**: Each feed type supports multiple auth methods
5. **Rate Limiting**: GrayNoise and custom APIs respect rate limits with backoff

## Future Enhancements

Planned improvements for credential management:
- Database encryption for sensitive fields
- HSM/Vault integration
- Environment variable fallback
- Credential rotation scheduling
- Audit logging for access

Planned improvements for feeds:
- Real-time push capabilities
- WebSocket support for live updates
- Webhook handlers for external notifications
- Advanced transformation pipelines
- Multi-source aggregation and deduplication
