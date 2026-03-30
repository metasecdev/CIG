FROM python:3.11-slim-bookworm

LABEL maintainer="CIG Security Team" \
      description="Arkime Connector for Cyber Intelligence Gateway"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/integrations/arkime.py /app/
COPY app/utils/ /app/utils/

ENV ARKIME_URL=http://arkime:8005 \
    ARKIME_SECRET=secret

EXPOSE 8080

CMD ["python", "-c", "
from app.integrations.arkime import ArkimeConnector, CIGArkimeBridge
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

connector = ArkimeConnector(
    arkime_url=os.getenv('ARKIME_URL', 'http://arkime:8005'),
    arkime_secret=os.getenv('ARKIME_SECRET', 'secret')
)

if connector.test_connection():
    logger.info('Connected to Arkime successfully')
else:
    logger.warning('Could not connect to Arkime')

logger.info('Arkime connector service started')
"]
