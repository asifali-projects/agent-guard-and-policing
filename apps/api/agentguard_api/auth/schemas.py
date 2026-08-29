"""Request/response models for the auth endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from ..models.enums import MembershipRole


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=256)
    full_name: str | None = Field(default=None, max_length=200)
    organization_name: str = Field(min_length=2, max_length=200)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    organization_id: uuid.UUID | None = None


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str | None = None
    all_sessions: bool = False


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth response field name, not a secret
    expires_in: int
    organization_id: uuid.UUID | None


class MfaChallengeResponse(BaseModel):
    mfa_required: bool = True
    mfa_token: str


class MfaEnrollResponse(BaseModel):
    secret: str
    otpauth_uri: str


class MfaCodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=10)


class MfaVerifyRequest(BaseModel):
    mfa_token: str
    code: str = Field(min_length=6, max_length=10)


class MembershipOut(BaseModel):
    organization_id: uuid.UUID
    organization_name: str
    role: MembershipRole


class MeResponse(BaseModel):
    id: uuid.UUID
    email: EmailStr
    full_name: str | None
    mfa_enabled: bool
    is_superuser: bool
    active_organization_id: uuid.UUID | None
    permissions: list[str]
    memberships: list[MembershipOut]


class SessionOut(BaseModel):
    id: uuid.UUID
    user_agent: str | None
    ip_address: str | None
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    current: bool
