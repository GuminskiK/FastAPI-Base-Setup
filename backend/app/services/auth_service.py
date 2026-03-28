from fastapi import APIRouter, Depends, HTTPException, status, Body, Request, Form
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from app.core.auth.jwt import (
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    is_refresh_valid,
    revoke_refresh,
    store_refresh_token,
    revoke_all_user_sessions,
)
import logging
import time
from app.core.db import db_session
from app.services.users import get_user_by_username
from app.core.redis import redis_client
from app.models.Tokens import Token
from app.services.users import current_user, owner_or_admin
import pyotp
from enum import Enum

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

async def login_token(
    request: Request,
    redis: redis_client,
    session: db_session,
    form_data: OAuth2PasswordRequestForm = Depends(),
    mfa_code: str | None = Form(default=None)):

    user = await get_user_by_username(session, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        return LoginTokenResult.INVALID_CREDENTIALS

    if user.is_totp_enabled:
        if not mfa_code:
            return LoginTokenResult.REQUIRED_2FA_CODE

        totp = pyotp.TOTP(user.totp_secret)
        if not totp.verify(mfa_code):
            if user.backup_codes and mfa_code in user.backup_codes:
                user.backup_codes.remove(mfa_code)
                session.add(user)
                await session.commit()
            else:
                return LoginTokenResult.INVALID_2FA_CODE

    access_token = create_access_token(user.username, user.id)
    refresh_token = create_refresh_token(user.username, user.id)


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

    return Token(access_token=access_token, token_type="bearer", refresh_token=refresh_token)

async def refresh_token(redis: redis_client, refresh_token: str):
    
    try:
        payload = decode_token(refresh_token)
    except Exception:
        return RefreshTokenResult.INVALID_TOKEN

    if payload.get("typ") != "refresh":
        return RefreshTokenResult.WRONG_TOKEN_TYPE

    jti = payload.get("jti")
    if not jti:
        return RefreshTokenResult.INVALID_TOKEN

    valid = await is_refresh_valid(redis, jti)
    if not valid:
        exp = payload.get("exp")
        now_ts = int(time.time())
        if exp and int(exp) > now_ts:
            user_id = payload.get("id") or payload.get("sub")
            await revoke_all_user_sessions(redis, str(user_id))
            logging.warning("Refresh token reuse detected for user %s", user_id)
            return RefreshTokenResult.REFRESH_TOKEN_REUSE
        return RefreshTokenResult.REFRESH_REVOKE_OR_EXPIRED

    await revoke_refresh(redis, jti)

    username = payload.get("sub")
    id = payload.get("id")

    access_token = create_access_token(username, id)
    new_refresh_token = create_refresh_token(username, id)

    new_payload = decode_token(new_refresh_token)
    new_jti = new_payload.get("jti")
    new_exp = new_payload.get("exp")
    await store_refresh_token(redis, new_jti, id, new_exp)

    return Token(access_token=access_token, token_type="bearer", refresh_token=new_refresh_token)

async def revoke_refresh_token(redis: redis_client, refresh_token: str):
    try:
        payload = decode_token(refresh_token)
        if payload.get("typ") != "refresh":
            return {"message": "No-op"}
        jti = payload.get("jti")
        if jti:
            from app.core.auth.jwt import revoke_refresh as jwt_revoke_refresh
            await jwt_revoke_refresh(redis, jti)
    except Exception:
        pass

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
        return DeleteSessionResult.SESSION_NOT_FOUND

    index_key = f"user_session_index:{user.id}:{sid}"
    refresh_key = await redis.get(index_key)
    pipe = redis.pipeline()
    pipe.srem(f"user_sessions:{user.id}", sid)
    if refresh_key:
        pipe.delete(refresh_key)
    pipe.delete(index_key)
    await pipe.execute()
    return {"message": "session revoked"}