from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID
from sqlalchemy.orm import Session
from app.models.api_key import ApiKey
from app.models.user import User
from app.config import settings
from app.core.logging import logger


def create_api_key(
    db: Session,
    user_id: UUID,
    name: str,
    expires_in_days: Optional[int] = None,
) -> str:
    if expires_in_days is None:
        expires_in_days = settings.API_KEY_ROTATION_DAYS

    full_key, key_hash, key_prefix = ApiKey.generate_key()

    entry = ApiKey(
        user_id=user_id,
        name=name,
        key_prefix=key_prefix,
        key_hash=key_hash,
        expires_at=datetime.utcnow() + timedelta(days=expires_in_days),
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)

    logger.info(
        "API key created",
        extra={"user_id": str(user_id), "key_id": str(entry.id), "key_prefix": key_prefix},
    )
    return full_key


def revoke_api_key(db: Session, key_id: UUID) -> bool:
    entry = db.query(ApiKey).filter(ApiKey.id == key_id).first()
    if not entry:
        return False
    entry.is_active = False
    db.commit()
    logger.info("API key revoked", extra={"key_id": str(key_id)})
    return True


def list_api_keys(db: Session, user_id: UUID) -> list[dict]:
    keys = (
        db.query(ApiKey)
        .filter(ApiKey.user_id == user_id)
        .order_by(ApiKey.created_at.desc())
        .all()
    )
    return [
        {
            "id": str(k.id),
            "name": k.name,
            "key_prefix": k.key_prefix,
            "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
            "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            "is_active": k.is_active,
            "created_at": k.created_at.isoformat() if k.created_at else None,
        }
        for k in keys
    ]


def verify_api_key(db: Session, key: str) -> Optional[User]:
    key_hash = ApiKey.hash_key(key)
    entry = db.query(ApiKey).filter(ApiKey.key_hash == key_hash).first()
    if not entry:
        return None
    if not entry.is_active:
        return None
    if entry.expires_at and datetime.utcnow() > entry.expires_at:
        return None

    entry.last_used_at = datetime.utcnow()
    db.commit()

    user = db.query(User).filter(User.id == entry.user_id).first()
    return user


def rotate_expired_keys(db: Session) -> int:
    cutoff = datetime.utcnow()
    expired = (
        db.query(ApiKey)
        .filter(ApiKey.expires_at < cutoff, ApiKey.is_active == True)
        .all()
    )
    count = 0
    for key in expired:
        key.is_active = False
        count += 1
    if count:
        db.commit()
        logger.info("Expired API keys rotated", extra={"count": count})
    return count
