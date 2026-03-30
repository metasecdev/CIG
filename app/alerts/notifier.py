"""
Real-time alert notification system
"""

import json
import asyncio
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, asdict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class AlertNotification:
    """Alert notification data"""
    alert_id: str
    timestamp: str
    severity: str
    source_ip: str
    destination_ip: str
    indicator: str
    indicator_type: str
    feed_source: str
    message: str
    protocol: str = ""
    source_port: int = 0
    destination_port: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class NotificationHandler:
    """Base class for notification handlers"""

    async def send(self, notification: AlertNotification) -> bool:
        """Send notification. Return True if successful."""
        raise NotImplementedError


class WebhookHandler(NotificationHandler):
    """Send alerts to webhook URL"""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    async def send(self, notification: AlertNotification) -> bool:
        """Send alert to webhook"""
        try:
            import aiohttp
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=notification.to_dict(),
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    return response.status == 200
        except Exception as e:
            logger.error(f"Webhook notification failed: {e}")
            return False


class EmailHandler(NotificationHandler):
    """Send critical alerts via email"""

    def __init__(self, recipients: List[str], smtp_server: str = "localhost",
                 smtp_port: int = 587):
        self.recipients = recipients
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port

    async def send(self, notification: AlertNotification) -> bool:
        """Send alert via email"""
        if notification.severity not in ["critical", "high"]:
            return True  # Only email critical/high severity

        try:
            import aiosmtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            msg = MIMEMultipart()
            msg["Subject"] = f"CIG Alert [{notification.severity.upper()}] {notification.indicator}"
            msg["From"] = "cig-alerts@localhost"
            msg["To"] = ", ".join(self.recipients)

            body = f"""
CIG Threat Alert
================

Severity: {notification.severity.upper()}
Timestamp: {notification.timestamp}
Indicator: {notification.indicator} ({notification.indicator_type})
Feed Source: {notification.feed_source}

Source IP: {notification.source_ip}:{notification.source_port}
Destination IP: {notification.destination_ip}:{notification.destination_port}
Protocol: {notification.protocol}

Message: {notification.message}

Alert ID: {notification.alert_id}
"""

            msg.attach(MIMEText(body, "plain"))

            async with aiosmtplib.SMTP(hostname=self.smtp_server, port=self.smtp_port) as smtp:
                await smtp.send_message(msg)
            return True
        except Exception as e:
            logger.error(f"Email notification failed: {e}")
            return False


class SyslogHandler(NotificationHandler):
    """Send alerts to syslog"""

    def __init__(self, host: str = "localhost", port: int = 514):
        self.host = host
        self.port = port

    async def send(self, notification: AlertNotification) -> bool:
        """Send alert to syslog"""
        try:
            import aioudp
            
            message = (
                f"CIG[{notification.severity}]: {notification.indicator} from "
                f"{notification.source_ip} - {notification.message}"
            )

            sock = await aioudp.open_local_endpoint()
            sock.sendto(message.encode(), (self.host, self.port))
            return True
        except Exception as e:
            logger.error(f"Syslog notification failed: {e}")
            return False


class AlertNotifier:
    """Sends alerts through multiple notification channels"""

    def __init__(self, handlers: Optional[List[NotificationHandler]] = None):
        """
        Initialize notifier with handlers.
        
        Args:
            handlers: List of notification handlers
        """
        self.handlers = handlers or []
        self._callbacks: List[Callable[[AlertNotification], None]] = []

    def add_handler(self, handler: NotificationHandler) -> None:
        """Add a notification handler"""
        self.handlers.append(handler)

    def add_callback(self, callback: Callable[[AlertNotification], None]) -> None:
        """Add a synchronous callback"""
        self._callbacks.append(callback)

    async def notify(self, notification: AlertNotification) -> Dict[str, bool]:
        """
        Send notification to all handlers.
        
        Returns:
            Dict mapping handler class names to success status
        """
        results = {}

        # Send through async handlers
        tasks = [
            self._send_with_error_handling(handler, notification)
            for handler in self.handlers
        ]

        if tasks:
            handler_results = await asyncio.gather(*tasks, return_exceptions=False)
            for handler, success in zip(self.handlers, handler_results):
                results[handler.__class__.__name__] = success

        # Call synchronous callbacks
        for callback in self._callbacks:
            try:
                callback(notification)
            except Exception as e:
                logger.error(f"Callback error: {e}")

        # Also log the alert
        logger.warning(
            f"Alert: [{notification.severity}] {notification.indicator} from "
            f"{notification.source_ip} (Feed: {notification.feed_source})"
        )

        return results

    async def _send_with_error_handling(self, handler: NotificationHandler,
                                       notification: AlertNotification) -> bool:
        """Send notification with error handling"""
        try:
            return await handler.send(notification)
        except Exception as e:
            logger.error(f"Notification error ({handler.__class__.__name__}): {e}")
            return False

    def notify_sync(self, notification: AlertNotification) -> None:
        """
        Send notification synchronously (for use in non-async contexts).
        Note: Async handlers will be scheduled but execution may not complete.
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Can't use run_until_complete in running loop
                asyncio.create_task(self.notify(notification))
            else:
                loop.run_until_complete(self.notify(notification))
        except RuntimeError:
            # No event loop, create one
            asyncio.run(self.notify(notification))


class AlertNotificationManager:
    """Manages alert notifications with configuration"""

    def __init__(self, webhook_url: Optional[str] = None,
                 email_recipients: Optional[List[str]] = None,
                 syslog_host: Optional[str] = None):
        """
        Initialize notification manager.
        
        Args:
            webhook_url: Webhook URL for notifications
            email_recipients: List of email addresses for critical alerts
            syslog_host: Syslog server hostname
        """
        handlers = []

        if webhook_url:
            handlers.append(WebhookHandler(webhook_url))

        if email_recipients:
            handlers.append(EmailHandler(email_recipients))

        if syslog_host:
            handlers.append(SyslogHandler(syslog_host))

        self.notifier = AlertNotifier(handlers)

    def notify_alert(self, alert: Dict[str, Any]) -> None:
        """Send notification for an alert"""
        notification = AlertNotification(
            alert_id=alert.get("id", ""),
            timestamp=alert.get("timestamp", datetime.utcnow().isoformat()),
            severity=alert.get("severity", "info"),
            source_ip=alert.get("source_ip", ""),
            destination_ip=alert.get("destination_ip", ""),
            indicator=alert.get("indicator", ""),
            indicator_type=alert.get("indicator_type", ""),
            feed_source=alert.get("feed_source", ""),
            message=alert.get("message", ""),
            protocol=alert.get("protocol", ""),
            source_port=alert.get("source_port", 0),
            destination_port=alert.get("destination_port", 0),
        )

        self.notifier.notify_sync(notification)
