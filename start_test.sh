#!/bin/bash
# Startup script for CIG with testing configuration

export SKIP_FEED_UPDATES=true
export SKIP_DNS_MONITORING=true

echo "Starting CIG with feed updates and DNS monitoring disabled..."
python3 app/main.py "$@"