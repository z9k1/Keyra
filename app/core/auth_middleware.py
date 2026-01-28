import logging

import jwt
from fastapi import Request

from app.core.config import get_settings


logger = logging.getLogger("app.auth")
settings = get_settings()


def decode_access_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        return payload.get("sub")
    except jwt.PyJWTError:
        return None


def get_token_from_cookie(request: Request) -> str | None:
    return request.cookies.get("access_token")


async def jwt_auth_middleware(request: Request, call_next):
    token = get_token_from_cookie(request)
    if token:
        user_id = decode_access_token(token)
        request.state.user_id = user_id
    else:
        request.state.user_id = None
    return await call_next(request)
