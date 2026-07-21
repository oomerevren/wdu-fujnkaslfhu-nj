import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.config import settings
from app.schemas.user import (
    UserCreate, UserLogin, TokenResponse, UserResponse,
    ForgotPasswordRequest, ResetPasswordRequest, OnboardingCompanyRequest,
    LogoutResponse, RevokeAllResponse, RefreshTokenRequest,
)
from app.services.auth_service import (
    register_user, authenticate_user, create_access_token,
    create_refresh_token, refresh_access_token,
    get_current_user, create_email_verification_token,
    create_password_reset_token, blacklist_access_token,
    revoke_all_user_refresh_tokens,
)
from app.models.user import User
from app.utils.rate_limiter import auth_limiter
from app.utils.token_blacklist import token_blacklist
from app.services.audit_service import log_event
from jose import jwt, JWTError

router = APIRouter()


def _build_token_response(user: User) -> TokenResponse:
    """Create a TokenResponse with the refresh token stored in Redis."""
    rt_jti = str(uuid.uuid4())
    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id, jti=rt_jti)

    # Store refresh token in Redis for rotation tracking
    token_blacklist.store_refresh_token(
        jti=rt_jti,
        user_id=str(user.id),
        ttl=30 * 24 * 3600,  # 30 days
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserResponse.model_validate(user),
    )


@router.post("/register", response_model=TokenResponse)
def register(
    data: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
):
    client_ip = request.client.host

    # Rate limit: IP başına en fazla 3 kayıt / saat
    if auth_limiter.is_rate_limited(client_ip, "register", max_attempts=3, window=3600):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts. Please wait 1 hour.",
        )

    user = register_user(db, data.email, data.password, data.full_name)
    auth_limiter.increment(client_ip, "register", window=3600)
    log_event(db, user.id, "user.registered", "user", str(user.id), ip_address=client_ip)
    db.commit()
    return _build_token_response(user)

@router.get("/verify-email")
def verify_email(
    token: str,
    db: Session = Depends(get_db),
):
    """Email doğrulama token'ını doğrula."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != "email_verify":
            raise HTTPException(status_code=400, detail="Invalid token type")
        user_id = payload.get("sub")
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user.is_verified:
            return {"message": "Email already verified"}
        user.is_verified = True
        user.is_active = True
        db.commit()
        return {"message": "Email verified successfully. Your account is now active."}
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

@router.post("/login", response_model=TokenResponse)
def login(
    data: UserLogin,
    request: Request,
    db: Session = Depends(get_db),
):
    client_ip = request.client.host

    # Rate limit: IP başına en fazla 5 başarısız deneme / 15 dk
    if auth_limiter.is_rate_limited(client_ip, "login", max_attempts=5, window=900):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please wait 15 minutes.",
        )

    user = authenticate_user(db, data.email, data.password, ip_address=client_ip)
    log_event(db, user.id, "user.login", "user", str(user.id), ip_address=client_ip)
    db.commit()
    return _build_token_response(user)

@router.post("/refresh", response_model=TokenResponse)
def refresh(
    data: RefreshTokenRequest,
    db: Session = Depends(get_db),
):
    """Exchange a refresh token for a new access token + new refresh token.

    Implements refresh-token rotation: the old token is marked as *used*
    and cannot be reused.
    """
    return refresh_access_token(data.refresh_token, db)

@router.post("/logout", response_model=LogoutResponse)
def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Logout by blacklisting the current access token.

    The access token is added to the blacklist for its remaining lifetime,
    making it unusable even if stolen after logout.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing Authorization header",
        )
    token = auth_header.removeprefix("Bearer ")

    success = blacklist_access_token(token)
    if success:
        log_event(db, current_user.id, "user.logout", "user", str(current_user.id))
        db.commit()
        return LogoutResponse()
    # Token already expired
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Token is already expired",
    )


@router.post("/revoke-all", response_model=RevokeAllResponse)
def revoke_all(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke all active refresh tokens for the current user.

    Use this after a password change or when a device is compromised.
    The user will need to log in again on all devices.
    """
    count = revoke_all_user_refresh_tokens(current_user.id)
    log_event(db, current_user.id, "user.tokens_revoked", "user", str(current_user.id))
    db.commit()
    return RevokeAllResponse(
        message="All refresh tokens have been revoked. Please log in again.",
        tokens_revoked=count,
    )


@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return UserResponse.model_validate(current_user)

@router.post("/forgot-password")
def forgot_password(
    data: ForgotPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    client_ip = request.client.host

    # Rate limit: IP başına en fazla 3 şifre sıfırlama talebi / saat
    if auth_limiter.is_rate_limited(client_ip, "forgot_password", max_attempts=3, window=3600):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password reset requests. Please wait 1 hour.",
        )

    # Email bazlı rate limit (email enumeration'ı önler)
    email_key = f"email:{data.email}"
    if auth_limiter.is_rate_limited(email_key, "forgot_password", max_attempts=3, window=3600):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password reset requests for this email. Please wait 1 hour.",
        )

    user = db.query(User).filter(User.email == data.email).first()
    if user:
        token = create_password_reset_token(user.email)
        auth_limiter.increment(client_ip, "forgot_password", window=3600)
        auth_limiter.increment(email_key, "forgot_password", window=3600)
        # TODO: Email gönderme servisi çağrılacak
    # Always return same message to prevent email enumeration
    return {"message": "If the email exists, a password reset link has been sent."}

@router.post("/reset-password")
def reset_password(
    data: ResetPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    client_ip = request.client.host

    # Rate limit: IP başına en fazla 5 şifre sıfırlama / 15 dk
    if auth_limiter.is_rate_limited(client_ip, "reset_password", max_attempts=5, window=900):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password reset attempts. Please wait 15 minutes.",
        )

    from app.services.auth_service import hash_password
    try:
        payload = jwt.decode(data.token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != "password_reset":
            raise HTTPException(status_code=400, detail="Invalid token")
        email = payload.get("sub")
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user.hashed_password = hash_password(data.new_password)
        db.commit()
        return {"message": "Password has been reset successfully"}
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

# Onboarding Endpoints (Task 3)
@router.post("/onboarding/company")
def onboarding_company(
    data: OnboardingCompanyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    current_user.company_name = data.company_name
    current_user.onboarding_step = "target"
    db.commit()
    return {"onboarding_step": "target", "message": "Company info saved. Now add a target."}

@router.get("/onboarding/status")
def onboarding_status(
    current_user: User = Depends(get_current_user)
):
    return {"onboarding_step": current_user.onboarding_step}
