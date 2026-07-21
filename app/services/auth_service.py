"""
Authentication service — JWT token creation, verification, user lifecycle.

Security upgrades applied:
  • HS256 → HS512 algorithm migration (stronger hashing, 512-bit key)
  • Key rotation with ``KeyManager`` (active + previous key support)
  • ``iss`` (issuer) and ``jti`` (JWT ID) claims on every token
  • Issuer verification on token decode
  • All verification keys + both HS256/HS512 tried during decode for
    backward compatibility with tokens signed before the migration.
"""

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
from app.utils.key_rotation import key_manager

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


# ── Internal helpers ─────────────────────────────────────────────────────────


def _decode_token(
    token: str,
    options: Optional[dict] = None,
    verify_iss: bool = True,
) -> dict:
    """Decode and verify a JWT against all known keys and algorithms.

    Tries **every** verification key (active + previous) with **both**
    ``HS512`` and ``HS256`` algorithms.  This guarantees backward
    compatibility with tokens signed before the HS256→HS512 migration
    and after any key rotation.

    Args:
        token: The encoded JWT string.
        options: Optional dict of verification options passed to
            ``jwt.decode`` (e.g. ``{"verify_exp": False}``).
        verify_iss: When ``True`` (default), rejects tokens whose ``iss``
            claim does not match ``settings.JWT_ISSUER``.

    Returns:
        The decoded payload dict.

    Raises:
        HTTPException 401: If the token is invalid, expired, or issuer
            doesn't match.
    """
    if options is None:
        options = {}
    full_options: dict = {"verify_exp": True, **options}

    verification_keys = key_manager.get_verification_keys()
    # Try HS512 first (current), then HS256 (legacy)
    algorithms = ["HS512", "HS256"]

    last_error: Optional[Exception] = None
    for key in verification_keys:
        for alg in algorithms:
            try:
                payload = jwt.decode(
                    token, key, algorithms=[alg], options=full_options,
                )

                # Issuer verification
                if verify_iss:
                    iss = payload.get("iss")
                    if iss is None:
                        # Tokens created before the iss claim was added
                        # are still accepted (backward compat).
                        pass
                    elif iss != settings.JWT_ISSUER:
                        raise JWTError(
                            f"Invalid issuer: expected {settings.JWT_ISSUER!r}, "
                            f"got {iss!r}"
                        )

                return payload
            except JWTError as e:
                last_error = e
                continue

    # None of the key+algorithm combinations worked
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )


# ── Sync helpers ─────────────────────────────────────────────────────────────


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    user_id: UUID,
    jti: Optional[str] = None,
    *,
    iss: Optional[str] = None,
) -> str:
    """Create a short-lived access token.

    Security improvements:
      • Signed with the **active** key from ``KeyManager`` (supports rotation)
      • Uses ``HS512`` algorithm for stronger hashing
      • Includes ``iss`` (issuer) and ``jti`` (unique token ID) claims
      • Shorter expiry (30 min instead of former 60 min)

    Args:
        user_id: The user this token belongs to.
        jti: Optional explicit JWT ID. Generated automatically if not provided.
        iss: Override the issuer claim (defaults to ``settings.JWT_ISSUER``).

    Returns:
        The encoded JWT string.
    """
    if jti is None:
        jti = str(uuid4())
    expire = datetime.utcnow() + timedelta(minutes=settings.JWT_ACCESS_EXPIRATION_MINUTES)
    to_encode = {
        "sub": str(user_id),
        "exp": expire,
        "type": "access",
        "jti": jti,
        "iss": iss or settings.JWT_ISSUER,
    }
    return jwt.encode(
        to_encode,
        key_manager.get_signing_key(),
        algorithm=settings.JWT_ALGORITHM,
    )


def create_refresh_token(
    user_id: UUID,
    jti: Optional[str] = None,
    *,
    iss: Optional[str] = None,
) -> str:
    """Create a long-lived refresh token.

    Security improvements:
      • Signed with the **active** key from ``KeyManager``
      • Uses ``HS512`` algorithm
      • Includes ``iss`` and ``jti`` claims

    Args:
        user_id: The user this token belongs to.
        jti: Optional explicit JWT ID. Generated automatically if not provided.
        iss: Override the issuer claim (defaults to ``settings.JWT_ISSUER``).

    Returns:
        The encoded JWT string.
    """
    if jti is None:
        jti = str(uuid4())
    expire = datetime.utcnow() + timedelta(days=settings.JWT_REFRESH_EXPIRATION_DAYS)
    to_encode = {
        "sub": str(user_id),
        "exp": expire,
        "type": "refresh",
        "jti": jti,
        "iss": iss or settings.JWT_ISSUER,
    }
    return jwt.encode(
        to_encode,
        key_manager.get_signing_key(),
        algorithm=settings.JWT_ALGORITHM,
    )


def create_email_verification_token(user_id: UUID) -> str:
    expire = datetime.utcnow() + timedelta(hours=24)
    to_encode = {
        "sub": str(user_id),
        "exp": expire,
        "type": "email_verify",
        "iss": settings.JWT_ISSUER,
    }
    return jwt.encode(
        to_encode,
        key_manager.get_signing_key(),
        algorithm=settings.JWT_ALGORITHM,
    )


def create_password_reset_token(email: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=1)
    to_encode = {
        "sub": email,
        "exp": expire,
        "type": "password_reset",
        "iss": settings.JWT_ISSUER,
    }
    return jwt.encode(
        to_encode,
        key_manager.get_signing_key(),
        algorithm=settings.JWT_ALGORITHM,
    )


# ── Sync auth functions ──────────────────────────────────────────────────────


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Dependency — extract and verify the current user from a JWT access token.

    Verifies:
      1. Token is valid (signature, expiry, issuer)
      2. ``jti`` is not blacklisted
      3. User exists and is active
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = _decode_token(token)
        user_id: str = payload.get("sub")
        jti: str = payload.get("jti")
        if user_id is None:
            raise credentials_exception
        # Blacklist check
        if jti and token_blacklist.is_token_blacklisted(jti):
            raise credentials_exception
    except HTTPException:
        raise
    except Exception:
        raise credentials_exception

    user = db.query(User).filter(User.id == UUID(user_id)).first()
    if user is None or not user.is_active:
        raise credentials_exception
    return user


def get_current_user_or_api_key(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Like ``get_current_user`` but falls back to API key authentication.

    Order:
      1. Try JWT decode (with all keys + both algorithms)
      2. If JWT fails, try API key lookup
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # ── Attempt 1: JWT ───────────────────────────────────────────────────
    try:
        payload = _decode_token(token)
        user_id: str = payload.get("sub")
        jti: str = payload.get("jti")
        if user_id:
            if jti and token_blacklist.is_token_blacklisted(jti):
                raise credentials_exception
            user = db.query(User).filter(User.id == UUID(user_id)).first()
            if user and user.is_active:
                return user
    except HTTPException:
        # Don't fall through to API key if JWT was explicitly rejected
        raise
    except Exception:
        pass

    # ── Attempt 2: API key ───────────────────────────────────────────────
    from app.services.key_service import verify_api_key

    user = verify_api_key(db, token)
    if user:
        return user

    raise credentials_exception


def refresh_access_token(refresh_token: str, db: Session) -> TokenResponse:
    """Validate refresh token and issue new access + refresh tokens.

    Implements refresh-token rotation: the old refresh token is marked
    as *used* so it cannot be reused if stolen.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = _decode_token(
            refresh_token,
            options={"verify_jti": False},  # jti is not a standard verify option
        )
        if payload.get("type") != "refresh":
            raise credentials_exception
        user_id: str = payload.get("sub")
        jti: str = payload.get("jti")
        if user_id is None:
            raise credentials_exception
    except HTTPException:
        raise
    except Exception:
        raise credentials_exception

    # ── Blacklist / rotation check ──────────────────────────────────────
    if jti:
        token_status = token_blacklist.get_refresh_token_status(jti)
        if token_status is None:
            # Token unknown to Redis — could be from before the feature was
            # deployed.  We allow it once but will force a re-store.
            pass
        elif token_status in ("used", "revoked"):
            # Token reuse detected — potential leak!
            logger.warning(
                "Refresh token reuse detected — jti=%s user_id=%s status=%s",
                jti, user_id, token_status,
            )
            try:
                revoke_all_user_refresh_tokens(UUID(user_id))
            except Exception:
                logger.exception("Failed to revoke user tokens on reuse detection")
            raise credentials_exception

    user = db.query(User).filter(User.id == UUID(user_id)).first()
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
        ttl=settings.JWT_REFRESH_EXPIRATION_DAYS * 24 * 3600,
    )

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        user=UserResponse.model_validate(user),
    )


def register_user(
    db: Session,
    email: str,
    password: str,
    full_name: Optional[str] = None,
) -> User:
    # Password policy kontrolü
    is_valid, error_message = validate_password(password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message,
        )

    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This email address is already registered",
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
            detail="Invalid email or password",
        )

    # Hesap kilitli mi kontrol et
    if user.locked_until and datetime.utcnow() < user.locked_until:
        remaining_minutes = int(
            (user.locked_until - datetime.utcnow()).total_seconds() / 60
        )
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Your account has been temporarily locked. "
            f"Please try again in {remaining_minutes} minutes.",
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
            detail="Invalid email or password",
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
    """Async version of ``get_current_user``."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = _decode_token(token)
        user_id: str = payload.get("sub")
        jti: str = payload.get("jti")
        if user_id is None:
            raise credentials_exception
        # Blacklist check
        if jti and token_blacklist.is_token_blacklisted(jti):
            raise credentials_exception
    except HTTPException:
        raise
    except Exception:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == UUID(user_id)))
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
    is_valid, error_message = validate_password(password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message,
        )

    result = await db.execute(select(User).where(User.email == email))
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This email address is already registered",
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
            detail="Invalid email or password",
        )

    # Hesap kilitli mi kontrol et
    if user.locked_until and datetime.utcnow() < user.locked_until:
        remaining_minutes = int(
            (user.locked_until - datetime.utcnow()).total_seconds() / 60
        )
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Your account has been temporarily locked. "
            f"Please try again in {remaining_minutes} minutes.",
        )

    if not verify_password(password, user.hashed_password):
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1

        if user.failed_login_attempts >= 5:
            user.locked_until = datetime.utcnow() + timedelta(minutes=30)
            user.failed_login_attempts = 0

        await db.commit()

        if ip_address:
            auth_limiter.increment(ip_address, "login", 900)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    user.failed_login_attempts = 0
    user.locked_until = None
    await db.commit()

    if ip_address:
        auth_limiter.reset(ip_address, "login")
    return user


async def refresh_access_token_async(
    refresh_token: str,
    db: AsyncSession,
) -> TokenResponse:
    """Async version of refresh_access_token with rotation support."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = _decode_token(
            refresh_token,
            options={"verify_jti": False},
        )
        if payload.get("type") != "refresh":
            raise credentials_exception
        user_id: str = payload.get("sub")
        jti: str = payload.get("jti")
        if user_id is None:
            raise credentials_exception
    except HTTPException:
        raise
    except Exception:
        raise credentials_exception

    # ── Blacklist / rotation check ──────────────────────────────────────
    if jti:
        token_status = token_blacklist.get_refresh_token_status(jti)
        if token_status is None:
            pass  # Pre-rotation token, allow it
        elif token_status in ("used", "revoked"):
            logger.warning(
                "Refresh token reuse detected — jti=%s user_id=%s status=%s",
                jti, user_id, token_status,
            )
            try:
                revoke_all_user_refresh_tokens(UUID(user_id))
            except Exception:
                logger.exception("Failed to revoke user tokens on reuse detection")
            raise credentials_exception

    result = await db.execute(select(User).where(User.id == UUID(user_id)))
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
        ttl=settings.JWT_REFRESH_EXPIRATION_DAYS * 24 * 3600,
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
        payload = _decode_token(
            token,
            options={"verify_exp": False},
            verify_iss=False,
        )
        return payload.get("jti")
    except Exception:
        return None


def get_token_expires_in(token: str) -> int:
    """Return the number of seconds until the token expires (clamped to 0)."""
    try:
        payload = _decode_token(
            token,
            options={"verify_exp": False},
            verify_iss=False,
        )
        exp = payload.get("exp", 0)
        return max(0, int(exp - datetime.utcnow().timestamp()))
    except Exception:
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
