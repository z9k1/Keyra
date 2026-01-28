import logging
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.models import LoginChallenge, Session as UserSession, User


logger = logging.getLogger("app.auth")

MAGIC_LINK_TTL_MINUTES = 10
RATE_LIMIT_WINDOW_SECONDS = 600
RATE_LIMIT_MAX = 5

settings = get_settings()


def normalize_email(email: str) -> str:
    return email.strip().lower()


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _generate_token() -> str:
    return secrets.token_urlsafe(32)


def _generate_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def create_access_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.access_token_ttl_minutes)).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


async def check_rate_limit(redis_client, email: str, ip: str | None) -> bool:
    if not ip:
        ip = "unknown"

    key_email = f"rl:magic:email:{email}"
    key_ip = f"rl:magic:ip:{ip}"

    pipe = redis_client.pipeline()
    pipe.incr(key_email)
    pipe.expire(key_email, RATE_LIMIT_WINDOW_SECONDS)
    pipe.incr(key_ip)
    pipe.expire(key_ip, RATE_LIMIT_WINDOW_SECONDS)
    results = await pipe.execute()

    email_count = results[0]
    ip_count = results[2]

    if email_count > RATE_LIMIT_MAX or ip_count > RATE_LIMIT_MAX:
        return False

    return True


async def create_login_challenge(
    session: AsyncSession,
    email: str,
    request_ip: str | None,
    request_user_agent: str | None,
) -> str:
    token = _generate_token()
    token_hash = _hash_token(token)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=MAGIC_LINK_TTL_MINUTES)

    challenge = LoginChallenge(
        email=email,
        token_hash=token_hash,
        expires_at=expires_at,
        request_ip=request_ip,
        request_user_agent=request_user_agent,
    )

    session.add(challenge)
    await session.commit()

    return token


def log_magic_link(email: str, token: str) -> None:
    logger.info("Magic link generated for %s: token=%s", email, token)


async def verify_magic_token_and_create_session(
    session: AsyncSession,
    token: str,
    request_ip: str | None,
    request_user_agent: str | None,
) -> tuple[str, str]:
    token_hash = _hash_token(token)
    now = datetime.now(timezone.utc)

    stmt = (
        select(LoginChallenge)
        .where(
            LoginChallenge.token_hash == token_hash,
            LoginChallenge.used_at.is_(None),
            LoginChallenge.expires_at > now,
        )
        .with_for_update()
    )
    result = await session.execute(stmt)
    challenge = result.scalar_one_or_none()
    if not challenge:
        raise ValueError("invalid_or_expired_token")

    challenge.used_at = now

    user_stmt = select(User).where(User.email == challenge.email)
    user_result = await session.execute(user_stmt)
    user = user_result.scalar_one_or_none()
    if not user:
        user = User(email=challenge.email)
        session.add(user)
        await session.flush()

    refresh_token = _generate_refresh_token()
    refresh_token_hash = _hash_token(refresh_token)
    refresh_expires_at = now + timedelta(days=settings.refresh_token_ttl_days)

    user_session = UserSession(
        user_id=user.id,
        refresh_token_hash=refresh_token_hash,
        refresh_expires_at=refresh_expires_at,
        ip=request_ip,
        user_agent=request_user_agent,
        last_seen_at=now,
    )
    session.add(user_session)
    await session.flush()

    access_token = create_access_token(str(user.id))
    return access_token, refresh_token


async def _collect_session_chain_ids(
    session: AsyncSession,
    root_session_id,
) -> list:
    ids = [root_session_id]
    idx = 0
    while idx < len(ids):
        current_id = ids[idx]
        stmt = select(UserSession.id).where(UserSession.rotated_from_session_id == current_id)
        result = await session.execute(stmt)
        child_ids = [row[0] for row in result.all()]
        for child_id in child_ids:
            if child_id not in ids:
                ids.append(child_id)
        idx += 1
    return ids


async def revoke_session_chain(session: AsyncSession, root_session_id) -> None:
    now = datetime.now(timezone.utc)
    ids = await _collect_session_chain_ids(session, root_session_id)
    await session.execute(
        update(UserSession)
        .where(UserSession.id.in_(ids))
        .values(revoked_at=now)
    )


async def rotate_refresh_token(
    session: AsyncSession,
    refresh_token: str,
    request_ip: str | None,
    request_user_agent: str | None,
) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    token_hash = _hash_token(refresh_token)

    stmt = select(UserSession).where(UserSession.refresh_token_hash == token_hash).with_for_update()
    result = await session.execute(stmt)
    current_session = result.scalar_one_or_none()

    if not current_session:
        raise ValueError("invalid_refresh_token")

    if current_session.revoked_at is not None:
        await revoke_session_chain(session, current_session.id)
        raise ValueError("refresh_token_reuse")

    if current_session.refresh_expires_at <= now:
        await revoke_session_chain(session, current_session.id)
        raise ValueError("refresh_token_expired")

    if current_session.ip and request_ip and current_session.ip != request_ip:
        await revoke_session_chain(session, current_session.id)
        raise ValueError("session_hijacking")

    if current_session.user_agent and request_user_agent and current_session.user_agent != request_user_agent:
        await revoke_session_chain(session, current_session.id)
        raise ValueError("session_hijacking")

    new_refresh_token = _generate_refresh_token()
    new_refresh_token_hash = _hash_token(new_refresh_token)
    refresh_expires_at = now + timedelta(days=settings.refresh_token_ttl_days)

    new_session = UserSession(
        user_id=current_session.user_id,
        refresh_token_hash=new_refresh_token_hash,
        refresh_expires_at=refresh_expires_at,
        rotated_from_session_id=current_session.id,
        ip=request_ip,
        user_agent=request_user_agent,
        last_seen_at=now,
    )
    session.add(new_session)

    current_session.revoked_at = now

    access_token = create_access_token(str(current_session.user_id))
    return access_token, new_refresh_token


async def revoke_session_by_refresh_token(session: AsyncSession, refresh_token: str) -> bool:
    now = datetime.now(timezone.utc)
    token_hash = _hash_token(refresh_token)
    stmt = select(UserSession).where(UserSession.refresh_token_hash == token_hash).with_for_update()
    result = await session.execute(stmt)
    current_session = result.scalar_one_or_none()
    if not current_session:
        return False
    current_session.revoked_at = now
    return True


async def revoke_all_sessions_for_user(session: AsyncSession, user_id: str) -> None:
    now = datetime.now(timezone.utc)
    await session.execute(
        update(UserSession)
        .where(UserSession.user_id == user_id)
        .values(revoked_at=now)
    )


async def get_user_by_id(session: AsyncSession, user_id: str):
    stmt = select(User).where(User.id == user_id)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()
