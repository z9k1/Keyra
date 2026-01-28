from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class MagicLinkRequest(BaseModel):
    email: EmailStr = Field(..., max_length=320)


class MagicLinkResponse(BaseModel):
    status: str = "ok"


class MagicLinkVerifyRequest(BaseModel):
    token: str = Field(..., min_length=10, max_length=512)


class UserMeResponse(BaseModel):
    id: str
    email: EmailStr
    email_verified_at: datetime | None
    created_at: datetime
