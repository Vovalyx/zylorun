"""Minimal SMTP sender used for password-reset links."""
import asyncio
import logging
import smtplib
from email.message import EmailMessage

from app.config import settings

logger = logging.getLogger(__name__)


def smtp_configured() -> bool:
    return bool(settings.SMTP_HOST and (settings.SMTP_FROM or settings.SMTP_USERNAME))


def _send_sync(to_address: str, subject: str, body: str) -> None:
    message = EmailMessage()
    message["From"] = settings.SMTP_FROM or settings.SMTP_USERNAME
    message["To"] = to_address
    message["Subject"] = subject
    message.set_content(body)
    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=15) as client:
        client.starttls()
        if settings.SMTP_USERNAME:
            client.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        client.send_message(message)


async def send_email(to_address: str, subject: str, body: str) -> bool:
    """Send an e-mail off the event loop. Returns False when it could not be sent."""
    if not smtp_configured():
        return False
    try:
        await asyncio.to_thread(_send_sync, to_address, subject, body)
        return True
    except Exception as exc:
        logger.error("Could not send e-mail to the requested address: %s", exc.__class__.__name__)
        return False
