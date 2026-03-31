#!/bin/bash
# Arkime Installation and Configuration Script for Security Onion
# Supports both standalone and Security Onion integrated deployments

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
ARKIME_VERSION="${ARKIME_VERSION:-5.0.0}"
ARKIME_HOME="${ARKIME_HOME:-/opt/arkime}"
ARKIME_DATADIR="${ARKIME_DATADIR:-/var/arkime}"
ARKIME_USER="${ARKIME_USER:-arkime}"
ARKIME_PASSWORD="${ARKIME_PASSWORD:-admin}"
ELASTICSEARCH_HOST="${ELASTICSEARCH_HOST:-localhost}"
ELASTICSEARCH_PORT="${ELASTICSEARCH_PORT:-9200}"
SECURITY_ONION_MODE="${SECURITY_ONION_MODE:-false}"

echo -e "${GREEN}=== Arkime Installation for CIG ===${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}This script must be run as root${NC}"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo -e "${RED}Cannot detect OS${NC}"
    exit 1
fi

echo -e "${YELLOW}Detected OS: $OS${NC}"

# Install dependencies based on OS
install_dependencies() {
    echo -e "${YELLOW}Installing dependencies...${NC}"
    
    case "$OS" in
        ubuntu|debian)
            apt-get update
            apt-get install -y \
                build-essential \
                libpcap-dev \
                wget \
                curl \
                git \
                libssl-dev \
                zlib1g-dev \
                libmaxminddb-dev
            ;;
        centos|rhel|fedora)
            yum install -y \
                gcc \
                gcc-c++ \
                make \
                libpcap-devel \
                wget \
                curl \
                git \
                openssl-devel \
                zlib-devel \
                libmaxminddb-devel
            ;;
        *)
            echo -e "${RED}Unsupported OS: $OS${NC}"
            exit 1
            ;;
    esac
    echo -e "${GREEN}Dependencies installed${NC}"
}

# Create arkime user
create_arkime_user() {
    echo -e "${YELLOW}Creating arkime user...${NC}"
    
    if ! id -u $ARKIME_USER > /dev/null 2>&1; then
        useradd -m -s /bin/false $ARKIME_USER
        echo -e "${GREEN}User $ARKIME_USER created${NC}"
    else
        echo -e "${YELLOW}User $ARKIME_USER already exists${NC}"
    fi
}

# Install Arkime
install_arkime() {
    echo -e "${YELLOW}Installing Arkime $ARKIME_VERSION...${NC}"
    
    mkdir -p $ARKIME_HOME
    mkdir -p $ARKIME_DATADIR
    
    # Download Arkime
    ARKIME_URL="https://files.molo.com/builds/arkime-centos-7-${ARKIME_VERSION}.tar.gz"
    
    cd /tmp
    wget -q $ARKIME_URL -O arkime.tar.gz
    tar -xzf arkime.tar.gz
    
    # Copy to installation directory
    cp -r arkime-* $ARKIME_HOME
    
    # Set permissions
    chown -R $ARKIME_USER:$ARKIME_USER $ARKIME_HOME $ARKIME_DATADIR
    chmod -R 755 $ARKIME_HOME
    
    echo -e "${GREEN}Arkime installed to $ARKIME_HOME${NC}"
}

# Configure Arkime
configure_arkime() {
    echo -e "${YELLOW}Configuring Arkime...${NC}"
    
    ARKIME_CONFIG="$ARKIME_HOME/etc/config.ini"
    
    # Backup original config
    if [ -f "$ARKIME_CONFIG" ]; then
        cp "$ARKIME_CONFIG" "$ARKIME_CONFIG.backup"
    fi
    
    # Create config
    cat > "$ARKIME_CONFIG" << EOF
[default]
elasticsearch=http://$ELASTICSEARCH_HOST:$ELASTICSEARCH_PORT
esDataDir=$ARKIME_DATADIR
nodeDataDir=$ARKIME_DATADIR
dataDir=$ARKIME_DATADIR
logmsgs=false
debug=false
pcapDir=$ARKIME_DATADIR/pcap
bpfFile=$ARKIME_HOME/etc/iana-ipv4-specialized-address-registry.txt
geoLite2ASN=$ARKIME_HOME/etc/GeoLite2-ASN.mmdb
geoLite2Country=$ARKIME_HOME/etc/GeoLite2-Country.mmdb
maxStreams=1800000
maxPackets=0
maxBytes=0
magicFile=$ARKIME_HOME/etc/magic
showPacketSizes=true
pcapWriteSize=268435456
pcapReadSize=2097152
tcpSaveTimeout=720
udpSaveTimeout=720
icmpSaveTimeout=60
nospi=false
dontSaveSPI=false
maxFileSize=0
viewerPassword=$ARKIME_PASSWORD
dir=$ARKIME_HOME
httpPort=8005
regressionTests=false
EOF

    chown $ARKIME_USER:$ARKIME_USER "$ARKIME_CONFIG"
    chmod 600 "$ARKIME_CONFIG"
    
    echo -e "${GREEN}Arkime configured${NC}"
}

# Install as service
install_service() {
    echo -e "${YELLOW}Installing as systemd service...${NC}"
    
    cat > /etc/systemd/system/arkime-capture.service << EOF
[Unit]
Description=Arkime Packet Capture
After=network.target elasticsearch.service

[Service]
Type=simple
User=$ARKIME_USER
WorkingDirectory=$ARKIME_HOME
ExecStart=$ARKIME_HOME/bin/capture -c $ARKIME_HOME/etc/config.ini
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/arkime-viewer.service << EOF
[Unit]
Description=Arkime Viewer
After=network.target elasticsearch.service

[Service]
Type=simple
User=$ARKIME_USER
WorkingDirectory=$ARKIME_HOME
ExecStart=node $ARKIME_HOME/viewer/viewer.js -c $ARKIME_HOME/etc/config.ini
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    echo -e "${GREEN}Services installed${NC}"
}

# Configure for Security Onion
configure_security_onion() {
    echo -e "${YELLOW}Configuring for Security Onion integration...${NC}"
    
    # Security Onion typically uses specific directories
    export ARKIME_HOME="/opt/so/arkime"
    export ARKIME_DATADIR="/nsm/arkime"
    export ELASTICSEARCH_HOST="127.0.0.1"
    
    # Create SO integration config
    cat > /etc/cig/arkime-so.conf << 'EOF'
# Security Onion + Arkime + CIG Integration

# Elasticsearch connection (Security Onion default)
elasticsearch_host=127.0.0.1
elasticsearch_port=9200

# Arkime paths for SO
arkime_home=/opt/so/arkime
arkime_data=/nsm/arkime
arkime_pcap=/nsm/arkime/pcap

# Integration settings
cig_arkime_url=http://127.0.0.1:8005
cig_arkime_user=admin
cig_arkime_secret=so_integration_secret

# Automatic PCAP upload on alert
auto_upload_pcap=true
auto_create_hunt=true
auto_tag_sessions=true

# PCAP retention
pcap_retention_days=30
EOF
    
    chmod 600 /etc/cig/arkime-so.conf
    echo -e "${GREEN}Security Onion integration configured${NC}"
}

# Main installation flow
main() {
    install_dependencies
    create_arkime_user
    install_arkime
    configure_arkime
    install_service
    
    if [ "$SECURITY_ONION_MODE" = "true" ]; then
        configure_security_onion
    fi
    
    echo -e "${GREEN}=== Installation Complete ===${NC}"
    echo "Arkime installed to: $ARKIME_HOME"
    echo "Data directory: $ARKIME_DATADIR"
    echo "Web interface: http://localhost:8005"
    echo ""
    echo "To start Arkime capture:"
    echo "  sudo systemctl start arkime-capture"
    echo ""
    echo "To start Arkime viewer:"
    echo "  sudo systemctl start arkime-viewer"
    echo ""
    echo "To enable on boot:"
    echo "  sudo systemctl enable arkime-capture arkime-viewer"
}

main "$@"
