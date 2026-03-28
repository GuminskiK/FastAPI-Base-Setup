from fastapi import APIRouter, Depends, HTTPException, status, Body, Request, Form
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from app.core.db import db_session
from app.core.redis import redis_client
from app.models.Tokens import Token
from app.services.users import owner_or_admin
from app.services.auth_service import (
    login_token,
    refresh_token as refresh_token_service,
    revoke_refresh_token as logout_service,
    fetch_auth_sessions,
    delete_session,
    LoginTokenResult,
    RefreshTokenResult,
    DeleteSessionResult,
)


router = APIRouter(prefix="/auth", tags=["auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@router.post("/token", response_model=Token)
async def post_token(
    request: Request,
    redis: redis_client,
    session: db_session,
    form_data: OAuth2PasswordRequestForm = Depends(),
    mfa_code: str | None = Form(default=None)
):
    result = await login_token(request, redis, session, form_data, mfa_code)

    if result == LoginTokenResult.INVALID_CREDENTIALS:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if result == LoginTokenResult.REQUIRED_2FA_CODE:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="2FA required")

    if result == LoginTokenResult.INVALID_2FA_CODE:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 2FA code")

    return result


@router.post("/refresh", response_model=Token)
async def post_refresh_token(redis: redis_client, refresh_token: str = Body(..., embed=True)):
    
    result = await refresh_token_service(redis, refresh_token)

    if result == RefreshTokenResult.INVALID_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if result == RefreshTokenResult.WRONG_TOKEN_TYPE:
        raise HTTPException(status_code=401, detail="Wrong token type")
    
    if result == RefreshTokenResult.INVALID_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")

    if result == RefreshTokenResult.REFRESH_TOKEN_REUSE:
        raise HTTPException(status_code=401, detail="Refresh token reuse detected; all sessions revoked")

    if result == RefreshTokenResult.REFRESH_REVOKE_OR_EXPIRED:
        raise HTTPException(status_code=401, detail="Refresh revoked or expired")

    return result

@router.post("/logout")
async def logout(redis: redis_client, refresh_token: str = Body(..., embed=True)):
    
    result = await logout_service(redis, refresh_token)

    return result

@router.get("/sessions")
async def get_auth_sessions(redis: redis_client, user: owner_or_admin):
    
    result = await fetch_auth_sessions(redis, user)

    return result

@router.post("/logout/{sid}")
async def logout_with_session_id(redis: redis_client, user: owner_or_admin, sid: str):
    
    result = await delete_session(redis, user, sid)

    if result == DeleteSessionResult.SESSION_NOT_FOUND:
        raise HTTPException(status_code=404, detail="session not found")