from fastapi import Depends, Request, Form, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import select
from app.models.Users import User
from app.core.auth.jwt import (
    verify_password,
    create_token,
    decode_token,
    is_refresh_valid,
    revoke_refresh,
    store_refresh_token,
    revoke_all_user_sessions,
    get_password_hash
)
from app.core.logger import get_logger
import time
from app.core.db import db_session
from app.services.users import get_user_by_username, get_user_by_email
from app.core.redis import redis_client
from app.models.Tokens import Token, TokenTypes
from app.services.users import owner_or_admin, get_user_by_id
import pyotp
from enum import Enum
from app.core.config import settings
from datetime import timedelta
from app.services.email_service import send_password_reset_email

logger = get_logger(__name__)
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS = settings.REFRESH_TOKEN_EXPIRE_DAYS
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES = settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES


class LoginTokenResult(Enum):
    SUCCESS = "success"
    INVALID_CREDENTIALS = "invalid_credentials"
    REQUIRED_2FA_CODE = "required_2fa_code"
    INVALID_2FA_CODE = "invalid_2fa_code"

class RefreshTokenResult(Enum):
    SUCCESS = "success"
    INVALID_TOKEN = "invalid_token"
    WRONG_TOKEN_TYPE = "wrong_token_type"
    REFRESH_TOKEN_REUSE = "refresh_token_reuse"
    REFRESH_REVOKE_OR_EXPIRED = "refresh_revoke_or_expired"

class DeleteSessionResult(Enum):
    SUCCESS = "success"
    SESSION_NOT_FOUND = "session_not_found"

class ActivateTokenResult(Enum):
    SUCCESS = "success"
    INVALID_TOKEN = "invalid_token"
    WRONG_TOKEN_TYPE = "wrong_token_type"
    USER_NOT_FOUND = "user_not_found"

class ChangeSuperuserStatusResult(Enum):
    SUCCESS = "success"
    USER_NOT_FOUND = "user_not_found"


class SendChangePasswordMailResult(Enum):
    SUCCESS = "success"
    USER_NOT_FOUND = "user_not_found"

class ChangePasswordResult(Enum):
    SUCCESS = "success"
    INVALID_TOKEN = "invalid_token"
    WRONG_TOKEN_TYPE = "wrong_token_type"
    USER_NOT_FOUND = "user_not_found"

async def login_token(
    request: Request,
    redis: redis_client,
    session: db_session,
    form_data: OAuth2PasswordRequestForm = Depends(),
    mfa_code: str | None = Form(default=None)):

    user = await get_user_by_username(session, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        logger.warning("invalid_credentials_attempt", username=form_data.username)
        return LoginTokenResult.INVALID_CREDENTIALS

    if user.is_totp_enabled:
        if not mfa_code:
            logger.info("2fa_code_missing", username=user.username)
            return LoginTokenResult.REQUIRED_2FA_CODE

        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(mfa_code):
            if user.backup_codes and mfa_code in user.backup_codes:
                user.backup_codes.remove(mfa_code)
                session.add(user)
                await session.commit()
                logger.info("backup_code_used", username=user.username, user_id=str(user.id))
            else:
                logger.warning("invalid_2fa_code_attempt", username=user.username)
                return LoginTokenResult.INVALID_2FA_CODE

    access_token = create_token(user.id, user.username, TokenTypes.ACCESS, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh_token = create_token(user.id, user.username, TokenTypes.REFRESH, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))


    payload = decode_token(refresh_token)
    jti = payload.get("jti")
    exp = payload.get("exp")

    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
    else:
        ip = request.client.host if request.client else None
    device = request.headers.get("user-agent", "unknown")
    await store_refresh_token(redis, jti, user.id, exp, device=device, ip=ip)

    logger.info("user_logged_in", user_id=str(user.id), device=device, ip=ip, jti=jti)
    return Token(access_token=access_token, token_type="bearer", refresh_token=refresh_token)

async def refresh_token(redis: redis_client, refresh_token: str):
    
    try:
        payload = decode_token(refresh_token)
    except Exception as e:
        logger.warning("token_decode_failed", error=str(e))
        return RefreshTokenResult.INVALID_TOKEN

    if payload.get("typ") != TokenTypes.REFRESH:
        logger.warning("wrong_token_type_presented", typ=payload.get("typ"))
        return RefreshTokenResult.WRONG_TOKEN_TYPE

    jti = payload.get("jti")
    if not jti:
        logger.warning("token_missing_jti")
        return RefreshTokenResult.INVALID_TOKEN

    valid = await is_refresh_valid(redis, jti)
    if not valid:
        exp = payload.get("exp")
        now_ts = int(time.time())
        if exp and int(exp) > now_ts:
            user_id = payload.get("id") or payload.get("sub")
            await revoke_all_user_sessions(redis, str(user_id))
            logger.error("refresh_token_reuse_detected", user_id=str(user_id), jti=jti)
            return RefreshTokenResult.REFRESH_TOKEN_REUSE
        return RefreshTokenResult.REFRESH_REVOKE_OR_EXPIRED

    await revoke_refresh(redis, jti)

    username = payload.get("sub")
    id = payload.get("id")

    access_token = create_token(id, username, TokenTypes.ACCESS, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    new_refresh_token = create_token(id, username, TokenTypes.REFRESH, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))

    new_payload = decode_token(new_refresh_token)
    new_jti = new_payload.get("jti")
    new_exp = new_payload.get("exp")
    await store_refresh_token(redis, new_jti, id, new_exp)

    logger.info("token_refreshed", user_id=str(id), old_jti=jti, new_jti=new_jti)
    return Token(access_token=access_token, token_type="bearer", refresh_token=new_refresh_token)

async def revoke_refresh_token(redis: redis_client, refresh_token: str):
    try:
        payload = decode_token(refresh_token)
        if payload.get("typ") != TokenTypes.REFRESH:
            return {"message": "No-op"}
        jti = payload.get("jti")
        if jti:
            from app.core.auth.jwt import revoke_refresh as jwt_revoke_refresh
            await jwt_revoke_refresh(redis, jti)
            logger.info("refresh_token_revoked", jti=jti, user_id=str(payload.get("id")))
    except Exception as e:
        logger.warning("refresh_token_revoke_failed", error=str(e))

    return {"message": "Logged out"}

async def fetch_auth_sessions(redis: redis_client, user: owner_or_admin):
    sids = list(await redis.smembers(f"user_sessions:{user.id}"))
    results = []
    for sid in sids:
        index_key = f"user_session_index:{user.id}:{sid}"
        refresh_key = await redis.get(index_key)
        if not refresh_key:
            await redis.srem(f"user_sessions:{user.id}", sid)
            continue
        meta = await redis.hgetall(refresh_key)
        ttl = await redis.ttl(refresh_key)
        results.append({
            "sid": sid,
            "device": meta.get("device"),
            "ip": meta.get("ip"),
            "created_at": meta.get("created_at"),
            "last_seen": meta.get("last_seen"),
            "expires_in": ttl,
        })
    return results

async def delete_session(redis: redis_client, user: owner_or_admin, sid: str):
    if not await redis.sismember(f"user_sessions:{user.id}", sid):
        logger.warning("delete_session_not_found", user_id=str(user.id), sid=sid)
        return DeleteSessionResult.SESSION_NOT_FOUND

    index_key = f"user_session_index:{user.id}:{sid}"
    refresh_key = await redis.get(index_key)
    pipe = redis.pipeline()
    pipe.srem(f"user_sessions:{user.id}", sid)
    if refresh_key:
        pipe.delete(refresh_key)
    pipe.delete(index_key)
    await pipe.execute()
    
    logger.info("session_deleted", user_id=str(user.id), sid=sid)
    return {"message": "session revoked"}

async def change_account_status(session: db_session, activate_token:str):

    try:
        payload = decode_token(activate_token)
    except Exception as e:
        logger.warning("token_decode_failed", error=str(e))
        return ActivateTokenResult.INVALID_TOKEN

    if payload.get("typ") != TokenTypes.ACTIVATE:
        logger.warning("wrong_token_type_presented", typ=payload.get("typ"))
        return ActivateTokenResult.WRONG_TOKEN_TYPE

    jti = payload.get("jti")
    if not jti:
        logger.warning("token_missing_jti")
        return ActivateTokenResult.INVALID_TOKEN
    
    user_id = payload.get("id")
    user = await get_user_by_id(session, user_id)
    if not user:
        logger.warning("user_not_found")
        return ActivateTokenResult.USER_NOT_FOUND

    user.is_activated = True
    session.add(user)
    await session.commit()
    await session.refresh(user)
    
    logger.info("account_activated", user_id=str(user.id))

    return user

async def change_superuser_status(session: db_session, user_id: int):

    result = await session.exec(select(User).where(User.id == user_id))
    db_user = result.one_or_none()

    if not db_user:
        logger.warning("user_not_found")
        return ChangeSuperuserStatusResult.USER_NOT_FOUND
    
    db_user.is_superuser = True
    session.add(db_user)
    await session.commit()
    await session.refresh(db_user)

    logger.warning("new_admin", user_id=str(db_user.id))

    return db_user

async def send_change_password_mail(session: db_session, email: str, background_tasks: BackgroundTasks):

    user = await get_user_by_email(session, email)
    
    if not user:
        return SendChangePasswordMailResult.USER_NOT_FOUND
    
    token = create_token(user.id, user.username, TokenTypes.CHANGE_PASSWORD, timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRE_MINUTES))

    background_tasks.add_task(send_password_reset_email, user.email, token)

    logger.info("password_change_mail_sent", user_id=str(user.id))

    return SendChangePasswordMailResult.SUCCESS

async def change_password(session: db_session, password_change_token: str, plain_password: str):

    try:
        payload = decode_token(password_change_token)
    except Exception as e:
        logger.warning("token_decode_failed", error=str(e))
        return ChangePasswordResult.INVALID_TOKEN

    if payload.get("typ") != TokenTypes.CHANGE_PASSWORD:
        logger.warning("wrong_token_type_presented", typ=payload.get("typ"))
        return ChangePasswordResult.WRONG_TOKEN_TYPE

    jti = payload.get("jti")
    if not jti:
        logger.warning("token_missing_jti")
        return ChangePasswordResult.INVALID_TOKEN
    
    user_id = payload.get("id")
    user = await get_user_by_id(session, user_id)
    if not user:
        logger.warning("user_not_found")
        return ChangePasswordResult.USER_NOT_FOUND

    hashed = get_password_hash(plain_password)
    user.hashed_password = hashed

    session.add(user)
    await session.commit()
    await session.refresh(user)
    
    logger.info("password_changed", user_id=str(user.id))

    return user
    
