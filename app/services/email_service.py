import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from app.config import settings

logger = logging.getLogger(__name__)


def send_email(to: str, subject: str, body: str) -> None:
    """Send a plain-text email via SMTP.

    Args:
        to: Recipient email address.
        subject: Email subject line.
        body: Plain-text email body.

    Raises:
        smtplib.SMTPException: If sending fails (callers should catch and log).
    """
    msg = MIMEMultipart("alternative")
    msg["From"] = settings.FROM_EMAIL
    msg["To"] = to
    msg["Subject"] = subject

    part = MIMEText(body, "plain")
    msg.attach(part)

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
        if settings.SMTP_PORT == 587:
            server.starttls()
        if settings.SMTP_USER and settings.SMTP_PASSWORD:
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.sendmail(settings.FROM_EMAIL, [to], msg.as_string())


def send_verification_email(to: str, token: str) -> None:
    """Send an email verification link to the user.

    Args:
        to: Recipient email address.
        token: JWT email-verification token.
    """
    link = f"{settings.FRONTEND_URL}/verify?token={token}"
    subject = "PentestAI - Verify Your Email"
    body = (
        f"Hello,\n\n"
        f"Thank you for creating a PentestAI account. Please verify your email address by clicking the link below:\n\n"
        f"{link}\n\n"
        f"This link is valid for 24 hours.\n\n"
        f"If you did not create this account, please ignore this message.\n\n"
        f"Best regards,\nThe PentestAI Team"
    )
    send_email(to=to, subject=subject, body=body)


def send_password_reset_email(to: str, token: str) -> None:
    """Send a password reset link to the user.

    Args:
        to: Recipient email address.
        token: JWT password-reset token.
    """
    link = f"{settings.FRONTEND_URL}/reset-password?token={token}"
    subject = "PentestAI - Reset Your Password"
    body = (
        f"Hello,\n\n"
        f"Click the link below to reset your password:\n\n"
        f"{link}\n\n"
        f"This link is valid for 1 hour.\n\n"
        f"If you did not request a password reset, please ignore this message.\n\n"
        f"Best regards,\nThe PentestAI Team"
    )
    send_email(to=to, subject=subject, body=body)


def send_scan_completed_email(to: str, scan_id: str) -> None:
    """Notify the user that a security scan has completed.

    Args:
        to: Recipient email address.
        scan_id: UUID string of the completed scan.
    """
    link = f"{settings.FRONTEND_URL}/scans/{scan_id}"
    subject = "PentestAI - Scan Completed"
    body = (
        f"Hello,\n\n"
        f"Your PentestAI scan ({scan_id}) has been completed successfully.\n\n"
        f"Click the link below to view the results:\n\n"
        f"{link}\n\n"
        f"Best regards,\nThe PentestAI Team"
    )
    send_email(to=to, subject=subject, body=body)
