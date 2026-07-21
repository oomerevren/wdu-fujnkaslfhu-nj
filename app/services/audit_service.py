import hmac
import hashlib
import json
import logging
from uuid import UUID
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.audit_log import AuditLog
from app.config import settings

logger = logging.getLogger(__name__)

_AUDIT_HMAC_KEY = settings.JWT_SECRET_KEY.encode()


def _compute_signature(payload: dict) -> str:
    raw = json.dumps(payload, sort_keys=True, default=str).encode()
    return hmac.new(_AUDIT_HMAC_KEY, raw, hashlib.sha256).hexdigest()


def log_event(
    db: Session,
    user_id: str | UUID | None,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    request_fingerprint: str | None = None,
) -> AuditLog:
    payload = {
        "user_id": str(user_id) if user_id else None,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "details": details or {},
        "ip_address": ip_address,
        "user_agent": user_agent,
        "request_fingerprint": request_fingerprint,
    }
    signature = _compute_signature(payload)

    entry = AuditLog(
        user_id=UUID(str(user_id)) if user_id else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
        ip_address=ip_address,
        user_agent=user_agent,
        request_fingerprint=request_fingerprint,
        hmac_signature=signature,
    )
    db.add(entry)
    db.flush()
    db.refresh(entry)
    logger.info(f"Audit: {action} - {resource_type}:{resource_id} by user:{user_id}")
    return entry


def verify_audit_entry(entry: AuditLog) -> bool:
    payload = {
        "user_id": str(entry.user_id) if entry.user_id else None,
        "action": entry.action,
        "resource_type": entry.resource_type,
        "resource_id": entry.resource_id,
        "details": entry.details or {},
        "ip_address": entry.ip_address,
        "user_agent": entry.user_agent,
        "request_fingerprint": entry.request_fingerprint,
    }
    expected = _compute_signature(payload)
    return hmac.compare_digest(expected, entry.hmac_signature or "")


def get_audit_trail(
    db: Session,
    user_id: Optional[str | UUID] = None,
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[AuditLog]:
    query = db.query(AuditLog)
    if user_id:
        query = query.filter(AuditLog.user_id == str(user_id))
    if action:
        query = query.filter(AuditLog.action == action)
    if resource_type:
        query = query.filter(AuditLog.resource_type == resource_type)
    return query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()


async def log_event_async(
    db: AsyncSession,
    user_id: str | UUID | None,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    request_fingerprint: str | None = None,
) -> AuditLog:
    payload = {
        "user_id": str(user_id) if user_id else None,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "details": details or {},
        "ip_address": ip_address,
        "user_agent": user_agent,
        "request_fingerprint": request_fingerprint,
    }
    signature = _compute_signature(payload)

    entry = AuditLog(
        user_id=UUID(str(user_id)) if user_id else None,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
        ip_address=ip_address,
        user_agent=user_agent,
        request_fingerprint=request_fingerprint,
        hmac_signature=signature,
    )
    db.add(entry)
    await db.flush()
    await db.refresh(entry)
    logger.info(f"Audit: {action} - {resource_type}:{resource_id} by user:{user_id}")
    return entry
