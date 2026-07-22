from typing import List, Dict, Any
from app.core.logging import logger
from app.config import settings

class EmailService:
    def __init__(self):
        self.smtp_server = settings.SMTP_HOST
        self.from_email = settings.EMAILS_FROM_EMAIL

    async def send_scan_completion_email(self, user_email: str, scan_id: str, summary: Dict[str, Any]):
        """"Sends an email notification when a scan is finished."""
        logger.info(f"Sending scan completion email to {user_email} for scan {scan_id}")
        # Mock SMTP logic
        subject = f"PentestAI: Scan {scan_id} Completed"
        body = f"Total Findings: {summary.get('total', 0)}
Critical: {summary.get('critical', 0)}"
        return True

    async def send_subscription_alert(self, user_email: str, status: str):
        """"Sends subscription status updates (e.g., payment success/fail)."""
        logger.info(f"Sending subscription {status} email to {user_email}")
        return True