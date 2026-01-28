import logging

from fastapi import APIRouter, Depends, Request, Response, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.postgres import get_db_session
from app.db.redis import redis_client
from app.modules.auth.schemas import MagicLinkRequest, MagicLinkResponse, MagicLinkVerifyRequest, UserMeResponse
from app.modules.auth.service import (
    check_rate_limit,
    create_login_challenge,
    get_user_by_id,
    log_magic_link,
    normalize_email,
    revoke_all_sessions_for_user,
    revoke_session_by_refresh_token,
    rotate_refresh_token,
    verify_magic_token_and_create_session,
)


router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger("app.auth")
settings = get_settings()


def _get_user_id_from_request(request: Request) -> str:
    user_id = getattr(request.state, "user_id", None)
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")
    return user_id


@router.post("/magic/request", response_model=MagicLinkResponse)
async def request_magic_link(
    payload: MagicLinkRequest,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
):
    email = normalize_email(payload.email)
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    allowed = await check_rate_limit(redis_client, email=email, ip=client_ip)
    if not allowed:
        logger.warning("Rate limit hit for email=%s ip=%s", email, client_ip)
        return MagicLinkResponse()

    token = await create_login_challenge(
        session=session,
        email=email,
        request_ip=client_ip,
        request_user_agent=user_agent,
    )

    # Simulate email send with log
    log_magic_link(email, token)

    return MagicLinkResponse()


@router.post("/magic/verify", response_model=MagicLinkResponse)
async def verify_magic_link(
    payload: MagicLinkVerifyRequest,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_db_session),
):
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        async with session.begin():
            access_token, refresh_token = await verify_magic_token_and_create_session(
                session=session,
                token=payload.token,
                request_ip=client_ip,
                request_user_agent=user_agent,
            )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="invalid_or_expired_token",
        )

    response.set_cookie(
        "access_token",
        access_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        domain=settings.cookie_domain,
        max_age=settings.access_token_ttl_minutes * 60,
    )
    response.set_cookie(
        "refresh_token",
        refresh_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        domain=settings.cookie_domain,
        max_age=settings.refresh_token_ttl_days * 24 * 60 * 60,
    )

    return MagicLinkResponse()


@router.post("/refresh", response_model=MagicLinkResponse)
async def refresh_session(
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_db_session),
):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing_refresh_token")

    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        async with session.begin():
            access_token, new_refresh_token = await rotate_refresh_token(
                session=session,
                refresh_token=refresh_token,
                request_ip=client_ip,
                request_user_agent=user_agent,
            )
    except ValueError as exc:
        if str(exc) in {"refresh_token_reuse", "session_hijacking", "refresh_token_expired"}:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_refresh_token")

    response.set_cookie(
        "access_token",
        access_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        domain=settings.cookie_domain,
        max_age=settings.access_token_ttl_minutes * 60,
    )
    response.set_cookie(
        "refresh_token",
        new_refresh_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        domain=settings.cookie_domain,
        max_age=settings.refresh_token_ttl_days * 24 * 60 * 60,
    )

    return MagicLinkResponse()


@router.post("/logout", response_model=MagicLinkResponse)
async def logout(
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_db_session),
):
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing_refresh_token")

    async with session.begin():
        ok = await revoke_session_by_refresh_token(session, refresh_token)
        if not ok:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_refresh_token")

    response.delete_cookie("access_token", domain=settings.cookie_domain)
    response.delete_cookie("refresh_token", domain=settings.cookie_domain)
    return MagicLinkResponse()


@router.post("/logout-all", response_model=MagicLinkResponse)
async def logout_all(
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_db_session),
):
    user_id = _get_user_id_from_request(request)

    async with session.begin():
        await revoke_all_sessions_for_user(session, user_id)

    response.delete_cookie("access_token", domain=settings.cookie_domain)
    response.delete_cookie("refresh_token", domain=settings.cookie_domain)
    return MagicLinkResponse()


@router.get("/me", response_model=UserMeResponse)
async def me(
    request: Request,
    session: AsyncSession = Depends(get_db_session),
):
    user_id = _get_user_id_from_request(request)
    user = await get_user_by_id(session, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unauthorized")

    return UserMeResponse(
        id=str(user.id),
        email=user.email,
        email_verified_at=user.email_verified_at,
        created_at=user.created_at,
    )
