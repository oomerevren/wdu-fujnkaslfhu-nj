"""Email service for PentestAI — production SMTP integration."""
from typing import Optional
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from app.core.logging import logger
from app.config import settings


class EmailService:
    def __init__(self):
        self.smtp_server = settings.SMTP_HOST
        self.smtp_port = settings.SMTP_PORT
        self.from_email = settings.FROM_EMAIL
        self.smtp_user = settings.SMTP_USER
        self.smtp_password = settings.SMTP_PASSWORD

    def _connect(self) -> Optional[smtplib.SMTP]:
        try:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            if self.smtp_user and self.smtp_password:
                server.login(self.smtp_user, self.smtp_password)
            return server
        except Exception as exc:
            logger.warning("SMTP connection failed — email not sent", extra={"error": str(exc)})
            return None

    def send_email(self, to_email: str, subject: str, body: str, html_body: Optional[str] = None) -> bool:
        server = self._connect()
        if not server:
            logger.info("Email skipped (SMTP unavailable)", extra={"to": to_email, "subject": subject})
            return False
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.from_email
            msg["To"] = to_email

            msg.attach(MIMEText(body, "plain"))
            if html_body:
                msg.attach(MIMEText(html_body, "html"))

            server.sendmail(self.from_email, to_email, msg.as_string())
            server.quit()
            logger.info("Email sent", extra={"to": to_email, "subject": subject})
            return True
        except Exception as exc:
            logger.error("Email send failed", extra={"to": to_email, "subject": subject, "error": str(exc)})
            return False

    async def send_scan_completion_email(self, user_email: str, scan_id: str, summary: dict) -> bool:
        subject = f"PentestAI: Scan {scan_id} Completed"
        body = (
            f"Your PentestAI scan has completed.\n"
            f"Scan ID: {scan_id}\n"
            f"Total Findings: {summary.get('total', 0)}\n"
            f"Critical: {summary.get('critical', 0)}\n"
            f"High: {summary.get('high', 0)}\n"
            f"Medium: {summary.get('medium', 0)}\n"
            f"Low: {summary.get('low', 0)}\n"
            f"\nLog in to your dashboard to view the full report."
        )
        return self.send_email(user_email, subject, body)

    async def send_subscription_alert(self, user_email: str, status: str) -> bool:
        subject = f"PentestAI: Subscription {status}"
        body = f"Your PentestAI subscription status has changed to: {status.upper()}.\nPlease review your billing dashboard."
        return self.send_email(user_email, subject, body)

    async def send_verification_email(self, to: str, token: str) -> bool:
        verification_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"
        subject = "PentestAI: Verify Your Email"
        body = (
            f"Welcome to PentestAI!\n\n"
            f"Please verify your email by clicking the link below:\n"
            f"{verification_url}\n\n"
            f"If you did not create an account, please ignore this email."
        )
        html_body = f"""
        <html><body>
        <h2>Welcome to PentestAI</h2>
        <p>Please verify your email by clicking <a href="{verification_url}">here</a>.</p>
        </body></html>
        """
        return self.send_email(to, subject, body, html_body)

    async def send_password_reset_email(self, to: str, token: str) -> bool:
        reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"
        subject = "PentestAI: Password Reset Request"
        body = (
            f"You requested a password reset for your PentestAI account.\n\n"
            f"Click the link below to reset your password:\n{reset_url}\n\n"
            f"This link will expire in 1 hour."
        )
        html_body = f"""
        <html><body>
        <h2>Reset Your PentestAI Password</h2>
        <p>Click <a href="{reset_url}">here</a> to reset your password.</p>
        <p>This link expires in 1 hour.</p>
        </body></html>
        """
        return self.send_email(to, subject, body, html_body)


email_service = EmailService()

# Wrapper functions for direct import (used by auth_service, etc.)
async def send_verification_email(to: str, token: str) -> bool:
    return await email_service.send_verification_email(to, token)

async def send_password_reset_email(to: str, token: str) -> bool:
    return await email_service.send_password_reset_email(to, token)

async def send_scan_completion_email(user_email: str, scan_id: str, summary: dict) -> bool:
    return await email_service.send_scan_completion_email(user_email, scan_id, summary)

async def send_subscription_alert(user_email: str, status: str) -> bool:
    return await email_service.send_subscription_alert(user_email, status)
