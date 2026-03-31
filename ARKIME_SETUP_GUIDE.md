# Arkime Installation and Security Onion Integration Guide

## Overview

Arkime is a large-scale, open-source packet capture (PCAP) and session search application that helps users analyze network traffic. This guide covers integrating Arkime with the Cyber Intelligence Gateway (CIG) and Security Onion.

## Features

- **Packet Capture & Analysis**: Full PCAP recording and indexing
- **Session Searching**: Search millions of sessions in real-time
- **PCAP Upload**: Automated PCAP upload from CIG alerts
- **Hunt Creation**: Create hunts for suspicious IPs and indicators
- **Interactive Analysis**: Drill down into network traffic
- **Security Onion Integration**: Seamless integration with SO deployments

## Quick Start

### Standalone Installation

```bash
# Download install script
wget https://raw.githubusercontent.com/aol/arkime/master/etc/config.ini.template

# Run CIG installation script
sudo bash scripts/install_arkime.sh
```

### Security Onion Integration

```bash
# Enable Security Onion mode during installation
export SECURITY_ONION_MODE=true
sudo bash scripts/install_arkime.sh
```

### Docker Installation

```bash
# Using docker-compose
docker-compose -f compose.yaml up arkime elasticsearch

# Access Arkime viewer at http://localhost:8005
```

## Configuration

### Default Paths

**Standalone:**
```
ARKIME_HOME: /opt/arkime
ARKIME_DATA: /opt/arkime/data
PCAP_DIR: /opt/arkime/data/pcap
CONFIG: /opt/arkime/etc/config.ini
```

**Security Onion:**
```
ARKIME_HOME: /opt/so/arkime
ARKIME_DATA: /nsm/arkime
PCAP_DIR: /nsm/arkime/pcap
CONFIG: /opt/so/arkime/etc/config.ini
```

### Configuration File

Key settings in `config.ini`:

```ini
[default]
; Elasticsearch endpoint
elasticsearch=http://localhost:9200

; Viewer password
viewerPassword=yoursecurepassword

; PCAP directory
pcapDir=/var/arkime/pcap

; Data directory
dataDir=/var/arkime/data

; Enable/disable packet inspection
nospi=false

; HTTP port
httpPort=8005
```

## CIG Integration

### API Endpoints

**Check Arkime Status:**
```bash
curl http://localhost:8000/api/arkime/status
```

**Get System Information:**
```bash
curl http://localhost:8000/api/arkime/info
```

**Get Installation Guide:**
```bash
curl http://localhost:8000/api/arkime/installation-guide
```

**Get Security Onion Configuration:**
```bash
curl http://localhost:8000/api/arkime/security-onion
```

### Dashboard

Access Arkime management dashboard at:
```
http://localhost:8000/dashboard/arkime
```

Features:
- Installation status
- Service health (capture, viewer, elasticsearch)
- Directory structure verification
- Security Onion integration status
- Quick installation commands

## Development

### Python API

```python
from app.integrations.arkime import ArkimeConnector, CIGArkimeBridge
from app.integrations.arkime_setup import ArkimeSetupManager

# Initialize connector
connector = ArkimeConnector(
    arkime_url="http://localhost:8005",
    arkime_secret="your_secret",
    arkime_nodes=["node0"]
)

# Test connection
if connector.test_connection():
    print("Connected to Arkime")

# Upload PCAP
connector.upload_pcap("/path/to/pcap/file.pcap")

# Search sessions
sessions = connector.search_sessions("ip.src == 192.168.1.100", limit=50)

# Create hunt
hunt_id = connector.create_hunt("ip.src == 192.168.1.100", "My Hunt")
```

### Setup Management

```python
from app.integrations.arkime_setup import ArkimeSetupManager, SecurityOnionIntegration

# Check installation
setup = ArkimeSetupManager()
status = setup.check_installation()
print(status)

# Validate configuration
validation = setup.validate_configuration()
print(validation)

# Security Onion integration
so = SecurityOnionIntegration()
if so.is_installed():
    print(so.get_deployment_info())
```

## Deployment

### SystemD Services

Services installed:
- `arkime-capture` - Packet capture service
- `arkime-viewer` - Web viewer service

**Start services:**
```bash
sudo systemctl start arkime-capture
sudo systemctl start arkime-viewer
```

**Enable on boot:**
```bash
sudo systemctl enable arkime-capture arkime-viewer
```

**Check status:**
```bash
sudo systemctl status arkime-capture arkime-viewer
```

### Docker Deployment

Use provided `compose.yaml`:
```bash
docker-compose up -d arkime elasticsearch
```

## Troubleshooting

### Connection Issues

```bash
# Check Arkime service
curl http://localhost:8005

# Check Elasticsearch
curl http://localhost:9200/_cluster/health

# Check CIG connectivity
curl http://localhost:8000/api/arkime/status
```

### PCAP Upload Fails

1. Verify disk space on PCAP directory:
   ```bash
   df -h /var/arkime/pcap
   ```

2. Check permissions:
   ```bash
   ls -la /var/arkime/pcap
   chmod 755 /var/arkime/pcap
   ```

3. Review logs:
   ```bash
   tail -f /var/log/arkime/capture.log
   ```

### Sessions Not Indexing

1. Check Elasticsearch cluster:
   ```bash
   curl http://localhost:9200/_cluster/health
   ```

2. Verify network interfaces:
   ```bash
   ip link show
   ifconfig
   ```

3. Check capture logs:
   ```bash
   sudo tail -f /var/log/arkime/capture.log
   ```

## Security Onion Specific

### Installation

Security Onion bundles provide a preconfigured Arkime setup. Simply:

```bash
# Security Onion 2.x
sudo so-update

# Arkime will be automatically configured
```

### Integration Points

1. **Elasticsearch**: Connected to SO's elasticsearch cluster
2. **Network Interfaces**: Uses SO's capture configuration
3. **Dashboard**: Access via SO's navigation
4. **Data Storage**: Uses /nsm/arkime directory

### SO Admin Tasks

```bash
# Check SO services status
sudo so-status

# Manage Arkime via SO
sudo so-allow

# View SO logs
sudo tail -f /var/log/nsm/arkime/capture.log
```

## Best Practices

1. **PCAP Retention**: Set appropriate retention policies
   - Keep hot data for 7-14 days
   - Archive older PCAP files
   - Monitor disk usage

2. **Performance Tuning**:
   - Ensure adequate Elasticsearch cluster resources
   - Configure packet deduplication
   - Use appropriate index management

3. **Security**:
   - Change default viewer password
   - Enable HTTPS/TLS
   - Restrict API access
   - Use authentication tokens

4. **Monitoring**:
   - Monitor disk usage
   - Track capture performance
   - Alert on service failures
   - Archive old PCAP data

## Additional Resources

- [Arkime Official Documentation](https://arkime.com/)
- [Security Onion Wiki](https://github.com/Security-Onion-Solutions/security-onion/wiki)
- [CIG Documentation](../../README.md)

## Support

For issues:
1. Check CIG dashboard health checks
2. Review deployment logs
3. Verify Elasticsearch connectivity
4. Check network interface configuration
5. Review Arkime documentation
