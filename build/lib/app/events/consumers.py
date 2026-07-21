"""Event consumer callbacks — each is an async function dispatched by the event bus.

Consumers listed here are meant to be registered in ``main.py`` on startup::

    from app.events.bus import EX_SCANS, EX_EVENTS, event_bus
    from app.events.consumers import progress_updater, audit_logger

    await event_bus.consume(EX_SCANS, "scan.progress", progress_updater)
    await event_bus.consume(EX_EVENTS, "#", audit_logger)
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from typing import Any

from app.database import SessionLocal
from app.models.finding import Finding
from app.models.scan import Scan, ScanStatus
from app.models.audit_log import AuditLog
from app.core.logging import logger as app_logger
from app.middleware.metrics import SCAN_DURATION

logger = logging.getLogger(__name__)

# ── Helpers ─────────────────────────────────────────────────────────────


def _safe_str(value: Any, default: str = "") -> str:
    """Convert *value* to str safely."""
    if value is None:
        return default
    return str(value)


# ── 1. progress_updater ─────────────────────────────────────────────────


async def progress_updater(
    event_type: str,
    payload: dict[str, Any],
    metadata: dict[str, Any],
) -> None:
    """Update scan progress and status in the database.

    Handles: ``scan.progress``, ``scan.completed``, ``scan.failed``
    """
    if event_type not in ("scan.progress", "scan.completed", "scan.failed"):
        return

    scan_id = payload.get("scan_id")
    if not scan_id:
        logger.warning("progress_updater: missing scan_id in payload %s", payload)
        return

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.warning("progress_updater: scan %s not found in DB", scan_id)
            return

        if event_type == "scan.progress":
            progress = payload.get("progress")
            status = payload.get("status")
            if progress is not None:
                scan.progress = int(progress)
            if status:
                try:
                    scan.status = ScanStatus(status)
                except ValueError:
                    logger.warning(
                        "progress_updater: invalid status '%s' for scan %s",
                        status,
                        scan_id,
                    )

        elif event_type == "scan.completed":
            scan.progress = 100
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()

        elif event_type == "scan.failed":
            scan.progress = 0
            scan.status = ScanStatus.FAILED
            scan.completed_at = datetime.utcnow()
            scan.error_message = _safe_str(payload.get("error"))

        db.commit()
        logger.debug(
            "progress_updater: scan %s -> progress=%d status=%s",
            scan_id,
            scan.progress,
            scan.status.value if hasattr(scan.status, "value") else scan.status,
        )
    except Exception:
        db.rollback()
        logger.exception("progress_updater: DB error for scan %s", scan_id)
    finally:
        db.close()


# ── 2. email_notifier ──────────────────────────────────────────────────


async def email_notifier(
    event_type: str,
    payload: dict[str, Any],
    metadata: dict[str, Any],
) -> None:
    """Send emails triggered by events.

    Handles: ``scan.completed``, ``user.registered``
    """
    from app.services.email_service import (
        send_scan_completed_email,
        send_verification_email,
    )

    try:
        if event_type == "scan.completed":
            scan_id = payload.get("scan_id", "")
            # Look up the user email via DB
            db = SessionLocal()
            try:
                scan = (
                    db.query(Scan)
                    .filter(Scan.id == scan_id)
                    .first()
                )
                if scan and scan.user and scan.user.email:
                    send_scan_completed_email(
                        to=scan.user.email,
                        scan_id=scan_id,
                    )
                    logger.info(
                        "email_notifier: sent completion email for scan %s to %s",
                        scan_id,
                        scan.user.email,
                    )
            finally:
                db.close()

        elif event_type == "user.registered":
            email = payload.get("email", "")
            user_id = payload.get("user_id", "")
            if email and user_id:
                # Use the user_id as a pseudo token for verification email;
                # in production, generate a proper JWT token.
                send_verification_email(to=email, token=user_id)
                logger.info(
                    "email_notifier: sent verification email to %s",
                    email,
                )
    except Exception:
        logger.exception("email_notifier: failed to send email for %s", event_type)


# ── 3. metrics_collector ────────────────────────────────────────────────


async def metrics_collector(
    event_type: str,
    payload: dict[str, Any],
    metadata: dict[str, Any],
) -> None:
    """Update Prometheus metrics based on events.

    Handles: ``scan.completed``, ``scan.failed``, ``finding.created``
    """
    try:
        if event_type in ("scan.completed", "scan.failed"):
            duration = payload.get("duration_seconds")
            scan_id = payload.get("scan_id", "unknown")
            status = "completed" if event_type == "scan.completed" else "failed"

            # Fetch scan_type from DB if not in payload
            scan_type = payload.get("scan_type", "unknown")
            if not scan_type or scan_type == "unknown":
                db = SessionLocal()
                try:
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan_type = (
                            scan.scan_type.value
                            if hasattr(scan.scan_type, "value")
                            else str(scan.scan_type)
                        )
                finally:
                    db.close()

            # Observe scan duration if available
            if duration is not None:
                SCAN_DURATION.labels(
                    scan_type=scan_type,
                    status=status,
                ).observe(float(duration))

            logger.debug(
                "metrics_collector: recorded scan %s type=%s status=%s duration=%s",
                scan_id,
                scan_type,
                status,
                duration,
            )

        elif event_type == "finding.created":
            # Increment finding counter per severity (future metric)
            severity = payload.get("severity", "info")
            logger.debug(
                "metrics_collector: finding.created severity=%s",
                severity,
            )
    except Exception:
        logger.exception("metrics_collector: error processing %s", event_type)


# ── 4. audit_logger ────────────────────────────────────────────────────


async def audit_logger(
    event_type: str,
    payload: dict[str, Any],
    metadata: dict[str, Any],
) -> None:
    """Write audit log entries for significant events.

    Handles all event types — writes a structured AuditLog row.
    """
    resource_type: str | None = None
    resource_id: str | None = None
    details: dict[str, Any] = {}

    if event_type.startswith("scan."):
        resource_type = "scan"
        resource_id = payload.get("scan_id")
        details = {
            "event_type": event_type,
            "payload": {k: v for k, v in payload.items() if k != "scan_id"},
        }
    elif event_type.startswith("finding."):
        resource_type = "finding"
        resource_id = payload.get("finding_id")
        details = {
            "event_type": event_type,
            "payload": {k: v for k, v in payload.items() if k != "finding_id"},
        }
    elif event_type.startswith("user."):
        resource_type = "user"
        resource_id = payload.get("user_id")
        details = {
            "event_type": event_type,
            "payload": {k: v for k, v in payload.items() if k != "user_id"},
        }

    if resource_type and resource_id:
        db = SessionLocal()
        try:
            entry = AuditLog(
                user_id=resource_id if resource_type == "user" else None,
                action=event_type,
                resource_type=resource_type,
                resource_id=_safe_str(resource_id),
                details=details,
                ip_address=payload.get("ip_address"),
            )
            db.add(entry)
            db.commit()
            logger.debug(
                "audit_logger: wrote %s for %s:%s",
                event_type,
                resource_type,
                resource_id,
            )
        except Exception:
            db.rollback()
            logger.exception("audit_logger: DB error for %s", event_type)
        finally:
            db.close()
    else:
        # Log unhandled events at debug level
        logger.debug(
            "audit_logger: skipped %s (no resource mapping)",
            event_type,
        )


# ── 5. score_updater ────────────────────────────────────────────────────


async def score_updater(
    event_type: str,
    payload: dict[str, Any],
    metadata: dict[str, Any],
) -> None:
    """Update aggregate security scores for targets / users.

    Handles: ``finding.created``, ``finding.status_changed``

    The score is a simple heuristic stored on the target (0–100):
      - Start at 100 (perfect).
      - Subtract weight per open finding: critical=25, high=15, medium=10, low=5, info=0.
      - When a finding is fixed or marked false-positive, add the weight back.
    """
    SEVERITY_WEIGHTS: dict[str, int] = {
        "critical": 25,
        "high": 15,
        "medium": 10,
        "low": 5,
        "info": 0,
    }

    if event_type not in ("finding.created", "finding.status_changed"):
        return

    db = SessionLocal()
    try:
        if event_type == "finding.created":
            finding_id = payload.get("finding_id")
            severity = payload.get("severity", "info")
            weight = SEVERITY_WEIGHTS.get(severity, 0)

            finding = db.query(Finding).filter(Finding.id == finding_id).first()
            if not finding:
                return

            target = finding.target  # requires relationship loaded
            if target is None:
                # Fetch target manually
                from app.models.target import Target
                target = db.query(Target).filter(Target.id == finding.target_id).first()

            if target:
                current = getattr(target, "security_score", 100)
                # the fetched Target might not have the column; log a warning.
                logger.info(
                    "score_updater: finding.created %s severity=%s weight=%d "
                    "target=%s — implement security_score column on Target model",
                    finding_id,
                    severity,
                    weight,
                    target.id,
                )

        elif event_type == "finding.status_changed":
            finding_id = payload.get("finding_id")
            new_status = payload.get("new_status")
            # If finding is fixed or false_positive, score improves
            if new_status in ("fixed", "false_positive"):
                finding = db.query(Finding).filter(Finding.id == finding_id).first()
                if not finding:
                    return
                # The weight was already deducted; now it's resolved.
                # In a full implementation, recalculate all open findings.
                logger.info(
                    "score_updater: finding %s resolved (%s) — recalculate score",
                    finding_id,
                    new_status,
                )

    except Exception:
        logger.exception("score_updater: error processing %s", event_type)
    finally:
        db.close()
