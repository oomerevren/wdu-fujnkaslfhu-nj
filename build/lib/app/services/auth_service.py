from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID, uuid4

from jose import jwt, JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.schemas.user import TokenResponse, UserResponse
from app.services.email_service import send_verification_email
from app.core.logging import logger
from app.utils.rate_limiter import auth_limiter
from app.utils.security import validate_password
from app.utils.token_blacklist import token_blacklist

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# ── Sync helpers ─────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(user_id: UUID, jti: Optional[str] = None) -> str:
    """Create a short-lived access token with a unique JWT ID."""
    if jti is None:
        jti = str(uuid4())
    expire = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRATION_MINUTES)
    to_encode = {
        "sub": str(user_id),
        "exp": expire,
        "type": "access",
        "jti": jti,
    }
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(user_id: UUID, jti: Optional[str] = None) -> str:
    """Create a long-lived refresh token (30 days) with a unique JWT ID.

    Args:
        user_id: The user this token belongs to.
        jti: Optional explicit JWT ID. Generated automatically if not provided.

    Returns:
        The encoded JWT string.
    """
    if jti is None:
        jti = str(uuid4())
    expire = datetime.utcnow() + timedelta(days=30)
    to_encode = {
        "sub": str(user_id),
        "exp": expire,
        "type": "refresh",
        "jti": jti,
    }
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_email_verification_token(user_id: UUID) -> str:
    expire = datetime.utcnow() + timedelta(hours=24)
    to_encode = {"sub": str(user_id), "exp": expire, "type": "email_verify"}
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_password_reset_token(email: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=1)
    to_encode = {"sub": email, "exp": expire, "type": "password_reset"}
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


# ── Sync auth functions ──────────────────────────────────────────────────────

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        jti: str = payload.get("jti")
        if user_id is None:
            raise credentials_exception
        # Blacklist check: if the token has a jti, verify it's not blacklisted
        if jti and token_blacklist.is_token_blacklisted(jti):
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None or not user.is_active:
        raise credentials_exception
    return user


def get_current_user_or_api_key(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    # Try JWT first
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        jti: str = payload.get("jti")
        if user_id:
            # Blacklist check
            if jti and token_blacklist.is_token_blacklisted(jti):
                raise credentials_exception
            user = db.query(User).filter(User.id == user_id).first()
            if user and user.is_active:
                return user
    except JWTError:
        pass

    # Fallback: try API key
    from app.services.key_service import verify_api_key
    user = verify_api_key(db, token)
    if user:
        return user

    raise credentials_exception


def refresh_access_token(refresh_token: str, db: Session) -> TokenResponse:
    """Validate refresh token and issue new access + refresh tokens.

    Implements refresh-token rotation: the old refresh token is marked as
    *used* immediately so it cannot be reused.  The new refresh token gets
    its own unique ``jti`` stored as *active*.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            refresh_token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_jti": False},  # jti is not a standard verify option
        )
        if payload.get("type") != "refresh":
            raise credentials_exception
        user_id: str = payload.get("sub")
        jti: str = payload.get("jti")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    # ── Blacklist / rotation check ──────────────────────────────────────
    if jti:
        status = token_blacklist.get_refresh_token_status(jti)
        if status is None:
            # Token unknown to Redis — could be from before the feature was
            # deployed.  We allow it once but will force a re-store.
            pass
        elif status in ("used", "revoked"):
            # Token reuse detected — potential leak!
            logger.warning(
                "Refresh token reuse detected — jti=%s user_id=%s status=%s",
                jti, user_id, status,
            )
            raise credentials_exception

    user = db.query(User).filter(User.id == user_id).first()
    if user is None or not user.is_active:
        raise credentials_exception

    # ── Rotate: mark old token as used ──────────────────────────────────
    if jti:
        token_blacklist.mark_refresh_token_used(jti)

    new_jti = str(uuid4())
    new_access_token = create_access_token(user.id)
    new_refresh_token = create_refresh_token(user.id, jti=new_jti)

    # Store the new refresh token in Redis
    token_blacklist.store_refresh_token(
        jti=new_jti,
        user_id=str(user.id),
        ttl=30 * 24 * 3600,  # 30 days
    )

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        user=UserResponse.model_validate(user),
    )


def register_user(db: Session, email: str, password: str, full_name: Optional[str] = None) -> User:
    # Password policy kontrolü
    is_valid, error_message = validate_password(password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message
        )

    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This email address is already registered"
        )

    user = User(
        email=email,
        hashed_password=hash_password(password),
        full_name=full_name,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Email doğrulama token'ı oluştur ve gönder
    try:
        token = create_email_verification_token(user.id)
        send_verification_email(to=user.email, token=token)
    except Exception:
        logger.warning("Doğrulama emaili gönderilemedi", exc_info=True)

    return user


def authenticate_user(
    db: Session,
    email: str,
    password: str,
    ip_address: Optional[str] = None,
) -> User:
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.hashed_password:
        if ip_address:
            auth_limiter.increment(ip_address, "login", 900)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Hesap kilitli mi kontrol et
    if user.locked_until and datetime.utcnow() < user.locked_until:
        remaining_minutes = int((user.locked_until - datetime.utcnow()).total_seconds() / 60)
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Your account has been temporarily locked. Please try again in {remaining_minutes} minutes."
        )

    if not verify_password(password, user.hashed_password):
        # Başarısız giriş — sayaç artır
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1

        # 5 başarısız deneme → 30 dakika kilit
        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.utcnow() + timedelta(minutes=30)
            user.failed_login_attempts = 0

        db.commit()

        if ip_address:
            auth_limiter.increment(ip_address, "login", 900)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Başarılı giriş — sayaçları sıfırla
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    if ip_address:
        auth_limiter.reset(ip_address, "login")
    return user


# ── Async auth functions ─────────────────────────────────────────────────────

async def get_current_user_async(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends("app.database.get_async_db"),
) -> User:
    """Async version of get_current_user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        jti: str = payload.get("jti")
        if user_id is None:
            raise credentials_exception
        # Blacklist check
        if jti and token_blacklist.is_token_blacklisted(jti):
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise credentials_exception
    return user


async def register_user_async(
    db: AsyncSession,
    email: str,
    password: str,
    full_name: Optional[str] = None,
) -> User:
    """Async version of register_user."""
    # Password policy kontrolü
    is_valid, error_message = validate_password(password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message
        )

    result = await db.execute(select(User).where(User.email == email))
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This email address is already registered"
        )

    user = User(
        email=email,
        hashed_password=hash_password(password),
        full_name=full_name,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    # Email doğrulama token'ı oluştur ve gönder
    try:
        token = create_email_verification_token(user.id)
        send_verification_email(to=user.email, token=token)
    except Exception:
        logger.warning("Doğrulama emaili gönderilemedi", exc_info=True)

    return user


async def authenticate_user_async(
    db: AsyncSession,
    email: str,
    password: str,
    ip_address: Optional[str] = None,
) -> User:
    """Async version of authenticate_user."""
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if not user or not user.hashed_password:
        if ip_address:
            auth_limiter.increment(ip_address, "login", 900)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Hesap kilitli mi kontrol et
    if user.locked_until and datetime.utcnow() < user.locked_until:
        remaining_minutes = int((user.locked_until - datetime.utcnow()).total_seconds() / 60)
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Your account has been temporarily locked. Please try again in {remaining_minutes} minutes."
        )

    if not verify_password(password, user.hashed_password):
        # Başarısız giriş — sayaç artır
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1

        # 5 başarısız deneme → 30 dakika kilit
        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.utcnow() + timedelta(minutes=30)
            user.failed_login_attempts = 0

        await db.commit()

        if ip_address:
            auth_limiter.increment(ip_address, "login", 900)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Başarılı giriş — sayaçları sıfırla
    user.failed_login_attempts = 0
    user.locked_until = None
    await db.commit()

    if ip_address:
        auth_limiter.reset(ip_address, "login")
    return user


async def refresh_access_token_async(refresh_token: str, db: AsyncSession) -> TokenResponse:
    """Async version of refresh_access_token with rotation support."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            refresh_token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_jti": False},
        )
        if payload.get("type") != "refresh":
            raise credentials_exception
        user_id: str = payload.get("sub")
        jti: str = payload.get("jti")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    # ── Blacklist / rotation check ──────────────────────────────────────
    if jti:
        status = token_blacklist.get_refresh_token_status(jti)
        if status is None:
            pass  # Pre-rotation token, allow it
        elif status in ("used", "revoked"):
            logger.warning(
                "Refresh token reuse detected — jti=%s user_id=%s status=%s",
                jti, user_id, status,
            )
            raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise credentials_exception

    # ── Rotate ──────────────────────────────────────────────────────────
    if jti:
        token_blacklist.mark_refresh_token_used(jti)

    new_jti = str(uuid4())
    new_access_token = create_access_token(user.id)
    new_refresh_token = create_refresh_token(user.id, jti=new_jti)

    token_blacklist.store_refresh_token(
        jti=new_jti,
        user_id=str(user.id),
        ttl=30 * 24 * 3600,
    )

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        user=UserResponse.model_validate(user),
    )


# ── Logout / Revocation helpers ─────────────────────────────────────────────


def get_token_jti(token: str) -> Optional[str]:
    """Extract the ``jti`` claim from a JWT without verifying expiry.

    Returns ``None`` if the token is malformed.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_exp": False},
        )
        return payload.get("jti")
    except JWTError:
        return None


def get_token_expires_in(token: str) -> int:
    """Return the number of seconds until the token expires (clamped to 0)."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_exp": False},
        )
        exp = payload.get("exp", 0)
        return max(0, int(exp - datetime.utcnow().timestamp()))
    except JWTError:
        return 0


def blacklist_access_token(access_token: str) -> bool:
    """Add an access token to the blacklist so it can no longer be used.

    Returns ``True`` if the token was successfully blacklisted.
    """
    jti = get_token_jti(access_token)
    if not jti:
        # Token without jti — get a surrogate from the token hash
        import hashlib
        jti = hashlib.sha256(access_token.encode()).hexdigest()
    expires_in = get_token_expires_in(access_token)
    if expires_in <= 0:
        return False  # Already expired
    token_blacklist.blacklist_token(jti, expires_in)
    return True


def revoke_all_user_refresh_tokens(user_id: UUID) -> int:
    """Revoke every active refresh token for the given user.

    Returns the number of tokens revoked.
    """
    return token_blacklist.revoke_all_user_tokens(str(user_id))
