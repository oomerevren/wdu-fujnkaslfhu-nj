from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional
from datetime import datetime
from uuid import UUID

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v):
        from app.utils.security import validate_password
        is_valid, message = validate_password(v)
        if not is_valid:
            raise ValueError(message)
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: UUID
    email: str
    full_name: Optional[str]
    company_name: Optional[str]
    avatar_url: Optional[str]
    is_active: bool
    is_verified: bool
    onboarding_step: str
    created_at: datetime

    class Config:
        from_attributes = True

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserResponse

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class OnboardingCompanyRequest(BaseModel):
    company_name: str

class OnboardingCompleteResponse(BaseModel):
    onboarding_step: str
    message: str


class LogoutResponse(BaseModel):
    message: str = "Successfully logged out"


class RevokeAllResponse(BaseModel):
    message: str
    tokens_revoked: int


class RefreshTokenRequest(BaseModel):
    refresh_token: str
