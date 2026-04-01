# CIG Feed Enhancements - Quick Reference Guide

## Quick Start

### 1. Use the Feed Scheduler
```python
from app.scheduling.feed_scheduler import FeedScheduler, FeedPriority

# Create scheduler
scheduler = FeedScheduler()

# Register a feed
scheduler.register_feed(
    feed_id="my-feed",
    feed_name="My Custom Feed",
    callback=my_update_function,  # async or sync
    update_interval=3600,  # seconds
    priority=FeedPriority.HIGH,
    refresh_at_midnight_utc=True  # Force midnight refresh
)

# Get scheduler status
status = scheduler.get_feed_status()
print(f"Feeds: {status}")

# Manually trigger update
success, error = await scheduler.update_feed("my-feed", force=True)
if success:
    print("Updated successfully")
else:
    print(f"Error: {error}")
```

### 2. Filter Indicators
```python
from app.feeds.filtering import FeedFilterEngine, IndicatorType, SeverityLevel

# Create filter engine
engine = FeedFilterEngine()

# Create a filter rule (only critical/high severity from specific feed)
from app.feeds.filtering import FilterRule

rule = FilterRule(
    id="rule-1",
    name="Critical Threats",
    min_severity=SeverityLevel.HIGH,
    allowed_feeds=["dshield-ssh"],
)

# Register rule
engine.register_rule(rule)

# Apply filters to indicators
indicators = [
    {"value": "1.2.3.4", "type": "ip", "severity": "critical", "tags": ["dshield-ssh"]},
    {"value": "5.6.7.8", "type": "ip", "severity": "low", "tags": ["pfblocker"]},
]

filtered = engine.filter_indicators(indicators)
print(f"Filtered: {len(filtered)} of {len(indicators)}")
```

### 3. Ingest Security Reports
```python
from app.feeds.report_ingestion import ReportIngestionConnector, ReportFormat, ReportType

# Create connector
connector = ReportIngestionConnector(database=my_db)

# Ingest a JSON report
indicators, success = connector.ingest_report(
    "threat_report.json",
    report_format=ReportFormat.JSON,
    report_type=ReportType.THREAT_ANALYSIS,
    source="external-vendor"
)

if success:
    print(f"Extracted {len(indicators)} indicators")
    for ind in indicators:
        print(f"  - {ind.type}: {ind.value} ({ind.severity})")

# Get report statistics
stats = connector.get_report_statistics()
print(f"Total reports ingested: {stats['total_reports']}")
```

### 4. Poll DShield Honeypot
```python
from app.feeds.dshield_polling import get_dshield_poller

# Get poller instance
poller = get_dshield_poller(database=my_db)

# Poll SSH attackers
ssh_attacks, success = poller.poll_ssh_attackers(limit=100)
if success:
    print(f"Found {len(ssh_attacks)} SSH attackers")

# Poll web scanners
web_attacks, success = poller.poll_web_attackers(limit=100)
if success:
    print(f"Found {len(web_attacks)} web scanners")

# Get threat summary
summary = poller.summarize_threats()
print(f"Total unique attacker IPs: {summary['global_unique_ips']}")
print(f"Top countries:")
for country in summary['ssh_attacks']['top_countries']:
    print(f"  {country['country']}: {country['attacks']} attacks")

# Get statistics
stats = poller.get_stats()
print(f"SSH Attacks: {stats['total_ssh_attacks']}")
print(f"Web Attacks: {stats['total_web_attacks']}")
print(f"Unique IPs: {stats['unique_attacker_ips']}")
```

### 5. Use Generic API Connector (Custom Feeds)
```python
from app.feeds.api_connector import (
    GenericAPIFeedConnector,
    APIFeedConfig,
    AuthMethod,
    DataTransformer
)

# Define custom transformer
class MyFeedTransformer(DataTransformer):
    def transform(self, api_response):
        # Convert API response to indicators
        indicators = []
        for item in api_response.get("items", []):
            indicators.append({
                "value": item["ip"],
                "type": "ip",
                "severity": item.get("threat_level", "medium"),
                "tags": item.get("tags", []),
            })
        return indicators
    
    def get_indicator_type(self, record):
        return "ip"
    
    def get_severity(self, record):
        return record.get("severity", "medium")

# Create config
config = APIFeedConfig(
    feed_id="custom-api-feed",
    feed_name="Custom Threat API",
    api_endpoint="https://api.example.com/threats",
    auth_method=AuthMethod.API_KEY,
    auth_credentials={"api_key": "your-api-key", "header_name": "X-API-Key"},
    query_params={"limit": "1000"}
)

# Create connector
transformer = MyFeedTransformer()
connector = GenericAPIFeedConnector(config, transformer=transformer, database=my_db)

# Fetch data
records, success = connector.fetch_data()
if success:
    print(f"Fetched {len(records)} records")

# Get stats
stats = connector.get_stats()
print(f"Average response time: {stats['average_response_time']:.2f}s")
```

### 6. Setup Nessus Integration
```python
from app.feeds.nessus import get_nessus_connector

# Get connector with credentials
connector = get_nessus_connector(
    api_key="your-nessus-api-key",
    api_secret="your-nessus-api-secret",
    database=my_db
)

# Get available scans
scans, success = connector.get_scans()
if success:
    print(f"Found {len(scans)} scans")

# Fetch vulnerabilities from latest scan
vulns, success = connector.fetch_vulnerabilities(limit=1000)
if success:
    print(f"Fetched {len(vulns)} vulnerabilities")

# Get statistics
stats = connector.get_stats()
print(f"Critical: {stats['critical_count']}, High: {stats['high_count']}")
```

### 7. Setup GrayNoise Integration
```python
from app.feeds.greynoise import get_greynoise_connector

# Get connector
connector = get_greynoise_connector(
    api_key="your-greynoise-api-key",
    use_community=False,  # Use commercial API
    database=my_db
)

# Query trending malicious IPs
ips, success = await connector.get_trending_ips_async(limit=100)
if success:
    print(f"Found {len(ips)} trending malicious IPs")

# Check specific IPs
test_ips = ["1.2.3.4", "5.6.7.8"]
results, success = await connector.query_ips_async(test_ips)
if success:
    print(f"Checked {len(results)} IPs")

# Get statistics
stats = connector.get_stats()
print(f"Malicious: {stats['malicious_ips']}, Benign: {stats['benign_ips']}")
```

## Configuration

### Environment Variables
```bash
# Feed scheduling
SCHEDULER_CHECK_INTERVAL=60

# DShield
ENABLE_DSHIELD=true
DSHIELD_POLL_INTERVAL=300

# Nessus
NESSUS_API_KEY=your-key
NESSUS_API_SECRET=your-secret
NESSUS_ENABLED=false

# GrayNoise
GREYNOISE_API_KEY=your-key
GREYNOISE_COMMUNITY_API=false
GREYNOISE_ENABLED=false

# Filtering
ENABLE_FEED_FILTERING=true
FILTER_CONFIG_FILE=config/feed_filters.json
```

### Filter Configuration (config/feed_filters.json)
```json
{
  "filters": {
    "critical-threats": {
      "filter_id": "critical-threats",
      "feed_id": "dshield",
      "name": "Critical Threats Only",
      "enabled": true,
      "rules": [],
      "combine_with": "AND",
      "action": "include"
    }
  },
  "rules": {}
}
```

## Common Patterns

### Register Feed with Scheduler
```python
async def my_feed_update():
    # Your feed update logic
    pass

scheduler.register_feed(
    feed_id="my-feed",
    feed_name="My Feed",
    callback=my_feed_update,
    priority=FeedPriority.HIGH,
    refresh_at_midnight_utc=True
)

# Start scheduler
await scheduler.start_scheduler(check_interval=60)
```

### Monitor Feed Health
```python
def monitor_feeds(scheduler):
    status = scheduler.get_feed_status()
    for feed_id, feed_status in status.items():
        if feed_status["consecutive_failures"] > 3:
            print(f"WARNING: {feed_id} failing - {feed_status['last_error']}")
        else:
            print(f"OK: {feed_id} - updated {feed_status['last_update']}")
```

### Create Multi-Layer Filtering
```python
# Layer 1: High severity only
rule_severity = FilterRule(
    id="rule-1",
    name="High Severity",
    min_severity=SeverityLevel.HIGH
)

# Layer 2: Exclude benign sources
rule_source = FilterRule(
    id="rule-2",
    name="Exclude CDN",
    excluded_feeds=["cloudflare", "akamai"]
)

# Layer 3: Pattern matching
rule_pattern = FilterRule(
    id="rule-3",
    name="C2 Domains",
    value_patterns=[r".*\.(top|xyz|tk)$"]
)

# Combine with AND logic
filter = FeedFilter(
    filter_id="multi-layer",
    feed_id="all",
    name="Multi-Layer Security",
    rules=[rule_severity, rule_source, rule_pattern],
    combine_with="AND",
    action="include"
)
```

## Troubleshooting

### Scheduler Not Updating Feeds
```python
# Check if scheduler is running
if not scheduler.is_running:
    print("Scheduler is not running")
    # Start it
    asyncio.create_task(scheduler.start_scheduler())

# Check feed status
status = scheduler.get_feed_status("my-feed")
print(f"Last update: {status['last_update']}")
print(f"Next update: {status['next_update']}")
print(f"Errors: {status['last_error']}")
```

### Indicators Not Being Filtered
```python
# Check which filters are enabled
filters = filter_engine.get_filter_status()
for filter_id, f in filters.items():
    if not f['enabled']:
        print(f"Filter {filter_id} is disabled")

# Test filter on sample indicators
test_indicators = [...]
filtered = filter_engine.filter_indicators(test_indicators, filter_ids=["my-filter"])
print(f"Filtered {len(test_indicators)} -> {len(filtered)}")
```

### Report Ingestion Issues
```python
# Check report format detection
if filename.endswith('.json'):
    fmt = ReportFormat.JSON
elif filename.endswith('.csv'):
    fmt = ReportFormat.CSV
else:
    print(f"Unsupported format for {filename}")

# Verify parser
indicators, success = connector.ingest_report(path, fmt, source="test")
if not success:
    print("Ingestion failed")

# Check statistics
stats = connector.get_report_statistics()
print(f"Reports: {stats['total_reports']}")
print(f"Indicators: {stats['total_indicators']}")
```

## More Resources
- See ENHANCEMENTS_SUMMARY.md for detailed architecture
- Check docstrings in each module for API details
- Review app/main.py for integration examples
