"""Event producer functions — convenience wrappers around ``event_bus.publish()``.

Every function validates the payload against the registered JSON Schema before
publishing.  Producers are async and should be awaited from async contexts or
wrapped in ``asyncio.run()`` from sync contexts (e.g. Celery tasks).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.events.bus import (
    Event,
    EX_SCANS,
    EX_FINDINGS,
    EX_USERS,
    RK_SCAN_CREATED,
    RK_SCAN_PROGRESS,
    RK_SCAN_COMPLETED,
    RK_SCAN_FAILED,
    RK_FINDING_CREATED,
    RK_FINDING_STATUS_CHANGED,
    RK_USER_REGISTERED,
    RK_USER_LOGIN,
    event_bus,
)
from app.events.schema import event_catalog, validate_event

logger = logging.getLogger(__name__)


def _validate_or_warn(event_type: str, payload: dict[str, Any]) -> None:
    """Validate *payload* and log a warning if it doesn't match the schema."""
    errors = validate_event(event_type, payload)
    if errors:
        logger.warning(
            "Event payload validation failed for %s: %s",
            event_type,
            "; ".join(errors),
        )


# ── Scan events ─────────────────────────────────────────────────────────


async def publish_scan_created(
    scan_id: str,
    target_id: str,
    scan_type: str,
    user_id: str,
) -> None:
    """Publish a scan.created event.

    Args:
        scan_id:   UUID of the created scan.
        target_id: UUID of the target being scanned.
        scan_type: Scanner type (nuclei, zap, promptfoo).
        user_id:   UUID of the user who owns the scan.
    """
    payload = {
        "scan_id": str(scan_id),
        "target_id": str(target_id),
        "scan_type": scan_type,
        "user_id": str(user_id),
    }
    _validate_or_warn("scan.created", payload)
    event = Event(type="scan.created", payload=payload)
    await event_bus.publish(EX_SCANS, RK_SCAN_CREATED, event)
    logger.info("Published scan.created for scan=%s type=%s", scan_id, scan_type)


async def publish_scan_progress(
    scan_id: str,
    progress: int,
    status: str,
) -> None:
    """Publish a scan.progress event.

    Args:
        scan_id:  UUID of the scan.
        progress: Progress percentage (0–100).
        status:   Current status (queued, running, completed, failed).
    """
    payload = {
        "scan_id": str(scan_id),
        "progress": progress,
        "status": status,
    }
    _validate_or_warn("scan.progress", payload)
    event = Event(type="scan.progress", payload=payload)
    await event_bus.publish(EX_SCANS, RK_SCAN_PROGRESS, event)
    logger.debug("Published scan.progress for scan=%s progress=%d", scan_id, progress)


async def publish_scan_completed(
    scan_id: str,
    findings_count: int,
    duration_seconds: float | None = None,
) -> None:
    """Publish a scan.completed event.

    Args:
        scan_id:         UUID of the completed scan.
        findings_count:  Number of findings discovered.
        duration_seconds: Total scan duration in seconds (optional).
    """
    payload: dict[str, Any] = {
        "scan_id": str(scan_id),
        "findings_count": findings_count,
    }
    if duration_seconds is not None:
        payload["duration_seconds"] = duration_seconds
    _validate_or_warn("scan.completed", payload)
    event = Event(type="scan.completed", payload=payload)
    await event_bus.publish(EX_SCANS, RK_SCAN_COMPLETED, event)
    logger.info(
        "Published scan.completed for scan=%s findings=%d",
        scan_id,
        findings_count,
    )


async def publish_scan_failed(
    scan_id: str,
    error: str,
) -> None:
    """Publish a scan.failed event.

    Args:
        scan_id: UUID of the failed scan.
        error:   Error message describing the failure.
    """
    payload = {
        "scan_id": str(scan_id),
        "error": str(error),
    }
    _validate_or_warn("scan.failed", payload)
    event = Event(type="scan.failed", payload=payload)
    await event_bus.publish(EX_SCANS, RK_SCAN_FAILED, event)
    logger.error("Published scan.failed for scan=%s error=%s", scan_id, error)


# ── Finding events ──────────────────────────────────────────────────────


async def publish_finding_created(
    finding_id: str,
    scan_id: str,
    severity: str,
    name: str | None = None,
    cve_id: str | None = None,
) -> None:
    """Publish a finding.created event.

    Args:
        finding_id: UUID of the created finding.
        scan_id:    UUID of the scan that discovered this finding.
        severity:   Severity level (critical, high, medium, low, info).
        name:       Short finding name (optional).
        cve_id:     Associated CVE identifier (optional).
    """
    payload: dict[str, Any] = {
        "finding_id": str(finding_id),
        "scan_id": str(scan_id),
        "severity": severity,
    }
    if name is not None:
        payload["name"] = name
    if cve_id is not None:
        payload["cve_id"] = cve_id
    _validate_or_warn("finding.created", payload)
    event = Event(type="finding.created", payload=payload)
    await event_bus.publish(EX_FINDINGS, RK_FINDING_CREATED, event)
    logger.info(
        "Published finding.created for finding=%s severity=%s",
        finding_id,
        severity,
    )


async def publish_finding_status_changed(
    finding_id: str,
    old_status: str,
    new_status: str,
) -> None:
    """Publish a finding.status_changed event.

    Args:
        finding_id: UUID of the finding.
        old_status: Previous triage status.
        new_status: New triage status.
    """
    payload = {
        "finding_id": str(finding_id),
        "old_status": old_status,
        "new_status": new_status,
    }
    _validate_or_warn("finding.status_changed", payload)
    event = Event(type="finding.status_changed", payload=payload)
    await event_bus.publish(EX_FINDINGS, RK_FINDING_STATUS_CHANGED, event)
    logger.info(
        "Published finding.status_changed for finding=%s %s -> %s",
        finding_id,
        old_status,
        new_status,
    )


# ── User events ─────────────────────────────────────────────────────────


async def publish_user_registered(
    user_id: str,
    email: str,
) -> None:
    """Publish a user.registered event.

    Args:
        user_id: UUID of the newly registered user.
        email:   Email address of the user.
    """
    payload = {
        "user_id": str(user_id),
        "email": email,
    }
    _validate_or_warn("user.registered", payload)
    event = Event(type="user.registered", payload=payload)
    await event_bus.publish(EX_USERS, RK_USER_REGISTERED, event)
    logger.info("Published user.registered for user=%s email=%s", user_id, email)


async def publish_user_login(
    user_id: str,
    ip_address: str,
) -> None:
    """Publish a user.login event.

    Args:
        user_id:    UUID of the user who logged in.
        ip_address: Source IP address of the login request.
    """
    payload = {
        "user_id": str(user_id),
        "ip_address": ip_address,
    }
    _validate_or_warn("user.login", payload)
    event = Event(type="user.login", payload=payload)
    await event_bus.publish(EX_USERS, RK_USER_LOGIN, event)
    logger.info("Published user.login for user=%s ip=%s", user_id, ip_address)


# ── Sync helpers (for use in Celery tasks / non-async code) ─────────────


def _run_async(coro: Any) -> Any:
    """Run an async coroutine from a synchronous context.

    Uses ``asyncio.run()`` in a new event loop if one isn't already running.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    # An event loop is already running — create a new task and wait.
    task = loop.create_task(coro)
    return asyncio.get_event_loop().run_until_complete(task)


def publish_scan_created_sync(
    scan_id: str,
    target_id: str,
    scan_type: str,
    user_id: str,
) -> None:
    """Synchronous wrapper for :func:`publish_scan_created`."""
    _run_async(publish_scan_created(scan_id, target_id, scan_type, user_id))


def publish_scan_progress_sync(
    scan_id: str,
    progress: int,
    status: str,
) -> None:
    """Synchronous wrapper for :func:`publish_scan_progress`."""
    _run_async(publish_scan_progress(scan_id, progress, status))


def publish_scan_completed_sync(
    scan_id: str,
    findings_count: int,
    duration_seconds: float | None = None,
) -> None:
    """Synchronous wrapper for :func:`publish_scan_completed`."""
    _run_async(publish_scan_completed(scan_id, findings_count, duration_seconds))


def publish_scan_failed_sync(
    scan_id: str,
    error: str,
) -> None:
    """Synchronous wrapper for :func:`publish_scan_failed`."""
    _run_async(publish_scan_failed(scan_id, error))


def publish_finding_created_sync(
    finding_id: str,
    scan_id: str,
    severity: str,
    name: str | None = None,
    cve_id: str | None = None,
) -> None:
    """Synchronous wrapper for :func:`publish_finding_created`."""
    _run_async(publish_finding_created(finding_id, scan_id, severity, name, cve_id))


def publish_finding_status_changed_sync(
    finding_id: str,
    old_status: str,
    new_status: str,
) -> None:
    """Synchronous wrapper for :func:`publish_finding_status_changed`."""
    _run_async(publish_finding_status_changed(finding_id, old_status, new_status))


def publish_user_registered_sync(
    user_id: str,
    email: str,
) -> None:
    """Synchronous wrapper for :func:`publish_user_registered`."""
    _run_async(publish_user_registered(user_id, email))


def publish_user_login_sync(
    user_id: str,
    ip_address: str,
) -> None:
    """Synchronous wrapper for :func:`publish_user_login`."""
    _run_async(publish_user_login(user_id, ip_address))
