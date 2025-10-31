"""
Notification Service for Webhooks and Alerts
"""
import aiohttp
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from config.settings import settings

logger = logging.getLogger(__name__)


class NotificationService:
    """Handle notifications via webhooks and other channels"""

    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession()
        return self.session

    async def close(self):
        """Close aiohttp session"""
        if self.session and not self.session.closed:
            await self.session.close()

    async def notify_scan_completed(
        self,
        scan_id: str,
        user_id: str,
        results: Dict[str, Any]
    ):
        """Send notification when scan completes"""
        try:
            # Get user's webhooks from database
            from db.database import get_async_session_context
            from db.models import Webhook
            from sqlalchemy import select

            async with get_async_session_context() as session:
                query = select(Webhook).where(
                    Webhook.user_id == user_id,
                    Webhook.is_active == True
                )
                result = await session.execute(query)
                webhooks = result.scalars().all()

                # Send to each webhook
                for webhook in webhooks:
                    if "scan.completed" in webhook.events:
                        await self._send_webhook(
                            webhook,
                            event_type="scan.completed",
                            payload={
                                "scan_id": scan_id,
                                "event": "scan.completed",
                                "timestamp": datetime.utcnow().isoformat(),
                                "data": {
                                    "domain": results.get('domain'),
                                    "total_subdomains": results.get('statistics', {}).get('total_subdomains'),
                                    "active_subdomains": results.get('statistics', {}).get('active_subdomains'),
                                    "duration_seconds": results.get('duration_seconds'),
                                }
                            }
                        )

            # Send to Slack if configured
            if settings.notifications.slack_webhook_url:
                await self._send_slack_notification(
                    "Scan Completed",
                    f"Scan for {results.get('domain')} completed successfully!\n"
                    f"• Total subdomains: {results.get('statistics', {}).get('total_subdomains')}\n"
                    f"• Active subdomains: {results.get('statistics', {}).get('active_subdomains')}\n"
                    f"• Duration: {results.get('duration_seconds')}s"
                )

            # Send to Discord if configured
            if settings.notifications.discord_webhook_url:
                await self._send_discord_notification(
                    "Scan Completed",
                    f"Scan for {results.get('domain')} completed successfully!\n"
                    f"Total subdomains: {results.get('statistics', {}).get('total_subdomains')}\n"
                    f"Active: {results.get('statistics', {}).get('active_subdomains')}"
                )

        except Exception as e:
            logger.error(f"Failed to send scan completed notification: {e}")

    async def notify_scan_failed(
        self,
        scan_id: str,
        user_id: str,
        error: str
    ):
        """Send notification when scan fails"""
        try:
            from db.database import get_async_session_context
            from db.models import Webhook
            from sqlalchemy import select

            async with get_async_session_context() as session:
                query = select(Webhook).where(
                    Webhook.user_id == user_id,
                    Webhook.is_active == True
                )
                result = await session.execute(query)
                webhooks = result.scalars().all()

                for webhook in webhooks:
                    if "scan.failed" in webhook.events:
                        await self._send_webhook(
                            webhook,
                            event_type="scan.failed",
                            payload={
                                "scan_id": scan_id,
                                "event": "scan.failed",
                                "timestamp": datetime.utcnow().isoformat(),
                                "error": error
                            }
                        )

            # Send to Slack
            if settings.notifications.slack_webhook_url:
                await self._send_slack_notification(
                    "Scan Failed",
                    f"Scan {scan_id} failed!\nError: {error}",
                    color="danger"
                )

        except Exception as e:
            logger.error(f"Failed to send scan failed notification: {e}")

    async def _send_webhook(
        self,
        webhook,
        event_type: str,
        payload: Dict[str, Any]
    ):
        """Send webhook notification"""
        try:
            session = await self._get_session()

            headers = {"Content-Type": "application/json"}

            # Add authentication if configured
            if webhook.auth_type == "bearer" and webhook.auth_value:
                headers["Authorization"] = f"Bearer {webhook.auth_value}"
            elif webhook.auth_type == "custom" and webhook.auth_header and webhook.auth_value:
                headers[webhook.auth_header] = webhook.auth_value

            async with session.post(
                webhook.url,
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status >= 200 and response.status < 300:
                    logger.info(f"Webhook {webhook.name} sent successfully")

                    # Update webhook statistics
                    from db.database import get_async_session_context
                    async with get_async_session_context() as db:
                        webhook.total_calls += 1
                        webhook.last_called = datetime.utcnow()
                        await db.commit()

                else:
                    logger.warning(
                        f"Webhook {webhook.name} failed with status {response.status}"
                    )
                    # Update failed calls
                    from db.database import get_async_session_context
                    async with get_async_session_context() as db:
                        webhook.failed_calls += 1
                        webhook.last_error = f"HTTP {response.status}"
                        await db.commit()

        except Exception as e:
            logger.error(f"Failed to send webhook {webhook.name}: {e}")

    async def _send_slack_notification(
        self,
        title: str,
        message: str,
        color: str = "good"
    ):
        """Send notification to Slack"""
        if not settings.notifications.slack_webhook_url:
            return

        try:
            session = await self._get_session()

            payload = {
                "attachments": [
                    {
                        "title": title,
                        "text": message,
                        "color": color,
                        "footer": "Orizon Enterprise",
                        "ts": int(datetime.utcnow().timestamp())
                    }
                ]
            }

            async with session.post(
                settings.notifications.slack_webhook_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 200:
                    logger.info("Slack notification sent successfully")
                else:
                    logger.warning(f"Slack notification failed: {response.status}")

        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")

    async def _send_discord_notification(
        self,
        title: str,
        message: str,
        color: int = 0x00FF00
    ):
        """Send notification to Discord"""
        if not settings.notifications.discord_webhook_url:
            return

        try:
            session = await self._get_session()

            payload = {
                "embeds": [
                    {
                        "title": title,
                        "description": message,
                        "color": color,
                        "footer": {
                            "text": "Orizon Enterprise"
                        },
                        "timestamp": datetime.utcnow().isoformat()
                    }
                ]
            }

            async with session.post(
                settings.notifications.discord_webhook_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                if response.status == 204:
                    logger.info("Discord notification sent successfully")
                else:
                    logger.warning(f"Discord notification failed: {response.status}")

        except Exception as e:
            logger.error(f"Failed to send Discord notification: {e}")

    async def send_email_notification(
        self,
        to_email: str,
        subject: str,
        body: str,
        html: Optional[str] = None
    ):
        """Send email notification"""
        if not settings.notifications.enable_email_notifications:
            return

        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = settings.notifications.smtp_from_email
            msg['To'] = to_email

            # Text part
            text_part = MIMEText(body, 'plain')
            msg.attach(text_part)

            # HTML part
            if html:
                html_part = MIMEText(html, 'html')
                msg.attach(html_part)

            # Send email
            with smtplib.SMTP(
                settings.notifications.smtp_host,
                settings.notifications.smtp_port
            ) as server:
                server.starttls()
                server.login(
                    settings.notifications.smtp_user,
                    settings.notifications.smtp_password
                )
                server.send_message(msg)

            logger.info(f"Email sent to {to_email}")

        except Exception as e:
            logger.error(f"Failed to send email: {e}")
