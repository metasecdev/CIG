"""
Real-time Webhook Alerting
Sends alerts to webhook endpoints in real-time
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime
from dataclasses import dataclass
import hashlib
import hmac
import json

try:
    import aiohttp

    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

logger = logging.getLogger(__name__)


@dataclass
class AlertPayload:
    """Alert data structure for webhooks"""

    id: str
    timestamp: str
    severity: str
    source_ip: str
    destination_ip: str
    indicator: str
    indicator_type: str
    feed_source: str
    rule_id: str
    metadata: Dict[str, Any]


class WebhookConfig:
    """Configuration for a webhook endpoint"""

    def __init__(
        self,
        name: str,
        url: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        secret: Optional[str] = None,
        enabled: bool = True,
        timeout: int = 10,
        retry_count: int = 3,
    ):
        self.name = name
        self.url = url
        self.method = method
        self.headers = headers or {"Content-Type": "application/json"}
        self.secret = secret
        self.enabled = enabled
        self.timeout = timeout
        self.retry_count = retry_count


class WebhookSender:
    """Handles sending alerts to webhook endpoints"""

    def __init__(self):
        if not HAS_AIOHTTP:
            logger.warning("aiohttp not available. Webhook alerts will be disabled.")
        self.session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> Optional[aiohttp.ClientSession]:
        """Get or create aiohttp session"""
        if not HAS_AIOHTTP:
            return None

        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
        return self.session

    async def send_alert(self, config: WebhookConfig, payload: AlertPayload) -> bool:
        """Send alert to webhook endpoint"""
        if not config.enabled:
            return True

        session = await self._get_session()
        if session is None:
            logger.error("Cannot send webhook: aiohttp not available")
            return False

        data = self._build_payload(payload)

        if config.secret:
            signature = self._generate_signature(data, config.secret)
            headers = {**config.headers, "X-Signature": signature}
        else:
            headers = config.headers

        for attempt in range(config.retry_count + 1):
            try:
                async with session.request(
                    config.method,
                    config.url,
                    json=data,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=config.timeout),
                ) as response:
                    if response.status < 400:
                        logger.info(f"Webhook '{config.name}' sent successfully")
                        return True
                    else:
                        logger.warning(
                            f"Webhook '{config.name}' returned {response.status}"
                        )
            except asyncio.TimeoutError:
                logger.warning(
                    f"Webhook '{config.name}' timed out (attempt {attempt + 1})"
                )
            except Exception as e:
                logger.error(f"Webhook '{config.name}' error: {e}")

            if attempt < config.retry_count:
                await asyncio.sleep(2**attempt)

        logger.error(
            f"Webhook '{config.name}' failed after {config.retry_count + 1} attempts"
        )
        return False

    def _build_payload(self, alert: AlertPayload) -> Dict[str, Any]:
        """Build webhook payload from alert"""
        return {
            "id": alert.id,
            "timestamp": alert.timestamp,
            "alert": {
                "severity": alert.severity,
                "source_ip": alert.source_ip,
                "destination_ip": alert.destination_ip,
                "indicator": alert.indicator,
                "indicator_type": alert.indicator_type,
                "feed_source": alert.feed_source,
                "rule_id": alert.rule_id,
            },
            "metadata": alert.metadata,
            "cig_version": "1.0.0",
        }

    def _generate_signature(self, data: Dict[str, Any], secret: str) -> str:
        """Generate HMAC signature for payload"""
        payload = json.dumps(data, sort_keys=True)
        signature = hmac.new(
            secret.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        return f"sha256={signature}"

    async def close(self):
        """Close the aiohttp session"""
        if self.session and not self.session.closed:
            await self.session.close()


class WebhookAlertManager:
    """Manages webhook endpoints and alert routing"""

    def __init__(self, db=None):
        self.db = db
        self.webhooks: Dict[str, WebhookConfig] = {}
        self.sender = WebhookSender()
        self.filters: List[Callable[[AlertPayload], bool]] = []
        self.rate_limiter = RateLimiter(max_alerts=100, window_seconds=60)

    def register_webhook(
        self,
        name: str,
        url: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        secret: Optional[str] = None,
        enabled: bool = True,
    ) -> bool:
        """Register a new webhook endpoint"""
        if not HAS_AIOHTTP:
            logger.warning("Cannot register webhook: aiohttp not available")
            return False

        try:
            webhook = WebhookConfig(
                name=name,
                url=url,
                method=method,
                headers=headers,
                secret=secret,
                enabled=enabled,
            )
            self.webhooks[name] = webhook
            logger.info(f"Registered webhook: {name} -> {url}")
            return True
        except Exception as e:
            logger.error(f"Failed to register webhook '{name}': {e}")
            return False

    def add_filter(self, filter_func: Callable[[AlertPayload], bool]) -> None:
        """Add a filter function to control which alerts get sent"""
        self.filters.append(filter_func)

    async def send_alert(self, alert_data: Dict[str, Any]) -> Dict[str, bool]:
        """Send alert to all enabled webhooks"""
        payload = AlertPayload(
            id=alert_data.get("id", ""),
            timestamp=alert_data.get("timestamp", datetime.now().isoformat()),
            severity=alert_data.get("severity", "info"),
            source_ip=alert_data.get("source_ip", ""),
            destination_ip=alert_data.get("destination_ip", ""),
            indicator=alert_data.get("indicator", ""),
            indicator_type=alert_data.get("indicator_type", "unknown"),
            feed_source=alert_data.get("feed_source", "unknown"),
            rule_id=alert_data.get("rule_id", ""),
            metadata=alert_data.get("metadata", {}),
        )

        if self.filters and not all(f(payload) for f in self.filters):
            logger.debug("Alert filtered out by webhook filters")
            return {}

        if not self.rate_limiter.can_send():
            logger.warning("Webhook rate limit exceeded, dropping alert")
            return {}

        results = {}
        for name, webhook in self.webhooks.items():
            if webhook.enabled:
                success = await self.sender.send_alert(webhook, payload)
                results[name] = success
                if success:
                    self.rate_limiter.record_alert()

        return results

    def remove_webhook(self, name: str) -> bool:
        """Remove a webhook endpoint"""
        if name in self.webhooks:
            del self.webhooks[name]
            return True
        return False

    def enable_webhook(self, name: str) -> bool:
        """Enable a webhook"""
        if name in self.webhooks:
            self.webhooks[name].enabled = True
            return True
        return False

    def disable_webhook(self, name: str) -> bool:
        """Disable a webhook"""
        if name in self.webhooks:
            self.webhooks[name].enabled = False
            return True
        return False

    def get_webhook_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all webhooks"""
        return {
            name: {
                "url": webhook.url,
                "method": webhook.method,
                "enabled": webhook.enabled,
                "timeout": webhook.timeout,
            }
            for name, webhook in self.webhooks.items()
        }

    async def close(self):
        """Clean up resources"""
        await self.sender.close()


class RateLimiter:
    """Rate limiter for webhook alerts"""

    def __init__(self, max_alerts: int = 100, window_seconds: int = 60):
        self.max_alerts = max_alerts
        self.window_seconds = window_seconds
        self.alerts: List[datetime] = []

    def can_send(self) -> bool:
        """Check if alert can be sent within rate limits"""
        self._cleanup()
        return len(self.alerts) < self.max_alerts

    def record_alert(self):
        """Record an alert"""
        self.alerts.append(datetime.now())

    def _cleanup(self):
        """Remove alerts outside the time window"""
        from datetime import timedelta

        cutoff = datetime.now() - timedelta(seconds=self.window_seconds)
        self.alerts = [ts for ts in self.alerts if ts > cutoff]
