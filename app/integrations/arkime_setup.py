"""Arkime installation and development helpers for CIG"""
import os
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class ArkimeSetupManager:
    """Manage Arkime installation, configuration, and deployment"""

    def __init__(self, arkime_home: str = "/opt/arkime", security_onion: bool = False):
        self.arkime_home = arkime_home
        self.security_onion = security_onion
        self.config_paths = self._resolve_paths()

    def _resolve_paths(self) -> Dict[str, Path]:
        """Resolve Arkime directory paths"""
        if self.security_onion:
            return {
                "home": Path("/opt/so/arkime"),
                "data": Path("/nsm/arkime"),
                "pcap": Path("/nsm/arkime/pcap"),
                "config": Path("/opt/so/arkime/etc"),
                "logs": Path("/var/log/arkime"),
            }
        else:
            return {
                "home": Path(self.arkime_home),
                "data": Path(self.arkime_home) / "data",
                "pcap": Path(self.arkime_home) / "data" / "pcap",
                "config": Path(self.arkime_home) / "etc",
                "logs": Path(self.arkime_home) / "logs",
            }

    def check_installation(self) -> Dict[str, Any]:
        """Check if Arkime is properly installed"""
        status = {
            "installed": False,
            "home_exists": False,
            "config_exists": False,
            "pcap_dir_exists": False,
            "data_dir_exists": False,
            "elasticsearch_connected": False,
            "capture_running": False,
            "viewer_running": False,
            "issues": [],
        }

        # Check paths
        status["home_exists"] = self.config_paths["home"].exists()
        status["config_exists"] = (
            self.config_paths["config"] / "config.ini"
        ).exists()
        status["pcap_dir_exists"] = self.config_paths["pcap"].exists()
        status["data_dir_exists"] = self.config_paths["data"].exists()

        if not status["home_exists"]:
            status["issues"].append(f"Arkime home directory not found: {self.config_paths['home']}")
        if not status["config_exists"]:
            status["issues"].append("Arkime config.ini not found")
        if not status["pcap_dir_exists"]:
            status["issues"].append("PCAP directory does not exist")

        status["installed"] = all(
            [
                status["home_exists"],
                status["config_exists"],
                status["data_dir_exists"],
            ]
        )

        # Check service status
        if self.security_onion:
            status["capture_running"] = self._check_service_status("arkime")
            status["viewer_running"] = False  # SO manages this differently
        else:
            status["capture_running"] = self._check_service_status(
                "arkime-capture"
            )
            status["viewer_running"] = self._check_service_status("arkime-viewer")

        return status

    def _check_service_status(self, service_name: str) -> bool:
        """Check if a systemd service is running"""
        try:
            import subprocess

            result = subprocess.run(
                ["systemctl", "is-active", service_name],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"Error checking service status: {e}")
            return False

    def get_system_info(self) -> Dict[str, Any]:
        """Get system information for Arkime deployment"""
        return {
            "os": "",  # Will be populated from /etc/os-release
            "arkime_home": str(self.config_paths["home"]),
            "arkime_data": str(self.config_paths["data"]),
            "pcap_dir": str(self.config_paths["pcap"]),
            "security_onion_mode": self.security_onion,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def generate_install_script(self) -> str:
        """Generate a customized installation script"""
        base_script = """#!/bin/bash
set -e
echo "Installing Arkime for CIG..."

# Configuration
ARKIME_VERSION="5.0.0"
ARKIME_HOME="{arkime_home}"
ARKIME_DATA="{arkime_data}"
SECURITY_ONION_MODE="{security_onion}"

# Install dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y build-essential libpcap-dev wget curl git libssl-dev zlib1g-dev libmaxminddb-dev

# Create directories
sudo mkdir -p $ARKIME_DATA/pcap
sudo chown -R arkime:arkime $ARKIME_DATA

echo "Arkime installation script generated"
"""
        return base_script.format(
            arkime_home=self.config_paths["home"],
            arkime_data=self.config_paths["data"],
            security_onion="true" if self.security_onion else "false",
        )

    def validate_configuration(self) -> Dict[str, Any]:
        """Validate Arkime configuration"""
        issues = []
        warnings = []

        config_file = self.config_paths["config"] / "config.ini"
        if not config_file.exists():
            issues.append("config.ini not found")
            return {"valid": False, "issues": issues, "warnings": warnings}

        # Read and validate config
        try:
            with open(config_file, "r") as f:
                content = f.read()

            # Check for required settings
            required_settings = [
                "elasticsearch",
                "nodeDataDir",
                "dataDir",
            ]
            missing = [
                s for s in required_settings if s not in content
            ]
            if missing:
                issues.extend([f"Missing setting: {s}" for s in missing])

            # Check for security settings
            if "viewerPassword" not in content:
                warnings.append("viewerPassword not set")
            if "https" not in content:
                warnings.append("HTTPS not configured")

        except Exception as e:
            issues.append(f"Error reading config: {e}")

        return {
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "config_file": str(config_file),
        }

    def get_installation_guide(self) -> str:
        """Get installation guide for deployment"""
        guide = """
# Arkime Installation Guide for CIG

## Quick Start

1. **Standalone Installation:**
   ```bash
   sudo bash scripts/install_arkime.sh
   ```

2. **Security Onion Integration:**
   ```bash
   export SECURITY_ONION_MODE=true
   sudo bash scripts/install_arkime.sh
   ```

## Post-Installation

1. **Start Services:**
   ```bash
   sudo systemctl start arkime-capture
   sudo systemctl start arkime-viewer
   sudo systemctl enable arkime-capture arkime-viewer
   ```

2. **Verify Installation:**
   ```bash
   curl http://localhost:8005
   ```

3. **CIG Integration:**
   - Configure ARKIME_URL in environment
   - Update app/core/config.py with Arkime endpoint
   - Test connection via API: `/api/arkime/health`

## Configuration

Edit `%s/config.ini`:
- Set elasticsearch endpoint
- Configure PCAP directory
- Set viewer password
- Enable/disable packet inspection

## Development

For development with Docker:
```bash
docker-compose -f compose.debug.yaml up arkime
```

## Troubleshooting

1. **Connection refused:**
   - Verify Elasticsearch is running
   - Check ARKIME_URL configuration
   - Verify network connectivity

2. **PCAP upload fails:**
   - Check disk space
   - Verify permissions on PCAP directory
   - Review logs: /var/log/arkime/

3. **Sessions not indexing:**
   - Check Elasticsearch cluster status
   - Verify network interface configuration
   - Check capture node logs
""" % self.config_paths["config"]
        return guide


class SecurityOnionIntegration:
    """Security Onion specific integration helpers"""

    def __init__(self):
        self.so_home = Path("/opt/so")
        self.nsm_dir = Path("/nsm")
        self.so_config = Path("/etc/soconfig")

    def is_installed(self) -> bool:
        """Check if Security Onion is installed"""
        return self.so_home.exists() and (self.so_home / "docker-compose.yml").exists()

    def get_arkime_connection_string(self) -> str:
        """Get Arkime connection string for Security Onion"""
        return "http://127.0.0.1:8005"

    def get_elasticsearch_connection_string(self) -> str:
        """Get Elasticsearch connection string for Security Onion"""
        # Security Onion typically exposes ES on localhost:9200
        return "http://127.0.0.1:9200"

    def get_deployment_info(self) -> Dict[str, Any]:
        """Get deployment information for Security Onion"""
        return {
            "platform": "security_onion",
            "arkime_url": self.get_arkime_connection_string(),
            "elasticsearch_url": self.get_elasticsearch_connection_string(),
            "arkime_home": "/opt/so/arkime",
            "data_dir": "/nsm/arkime",
            "installed": self.is_installed(),
            "integration_ready": self.is_installed(),
        }

    def generate_docker_compose_extension(self) -> str:
        """Generate docker-compose snippet for CIG + Arkime integration"""
        snippet = """
  arkime:
    image: arkime/arkime:5.0.0
    container_name: arkime
    environment:
      - ARKIME_ELASTICSEARCH=elasticsearch:9200
      - ARKIME_VIEWER_PASSWORD=admin
    ports:
      - "8005:8005"
    volumes:
      - arkime_data:/opt/arkime/data
      - /nsm/arkime/pcap:/opt/arkime/pcap
    networks:
      - cig_network
    depends_on:
      - elasticsearch

volumes:
  arkime_data:

networks:
  cig_network:
    driver: bridge
"""
        return snippet
