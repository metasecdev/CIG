FROM python:3.11-slim-bookworm

LABEL maintainer="CIG Security Team" \
      description="Cyber Intelligence Gateway - Network Security Monitoring"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Network tools
    tcpdump \
    tshark \
    iputils-ping \
    # libpcap for packet capture
    libpcap-dev \
    # Compression
    gzip \
    # Build tools
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create directories
RUN mkdir -p /data/pcaps /data/logs /config

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/

# Create non-root user for security
RUN useradd -m -u 1000 cig && \
    chown -R cig:cig /app /data /config

# Switch to non-root user
USER cig

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/api/health')" || exit 1

# Run the application
ENTRYPOINT ["python", "app/main.py"]
CMD ["--host", "0.0.0.0", "--port", "8000"]
