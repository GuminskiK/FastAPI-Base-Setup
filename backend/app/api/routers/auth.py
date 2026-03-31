from fastapi import APIRouter, Depends, HTTPException, status, Body, Request, Form, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from app.core.db import db_session
from app.core.redis import redis_client
from app.models.Tokens import Token
from app.services.users import owner_or_admin, current_admin_user
from app.services.auth_service import (
    login_token,
    refresh_token as refresh_token_service,
    revoke_refresh_token as logout_service,
    fetch_auth_sessions,
    delete_session,
    change_account_status,
    LoginTokenResult,
    RefreshTokenResult,
    DeleteSessionResult,
    change_superuser_status, ChangeSuperuserStatusResult,
    change_account_status, ActivateTokenResult,
    send_change_password_mail,
    change_password, ChangePasswordResult
)
from app.models.Users import UserRead

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

    return result

@router.patch("/activate/{activate_token}", response_model=UserRead)
async def activate_account(session: db_session, activate_token: str):

    result = await change_account_status(session, activate_token)

    if result == ActivateTokenResult.INVALID_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if result == ActivateTokenResult.WRONG_TOKEN_TYPE:
        raise HTTPException(status_code=401, detail="Wrong token type")

    if result == ActivateTokenResult.USER_NOT_FOUND:
        raise HTTPException(status_code=404, detail="User not found")

    return result

@router.patch("/change_superuser_status/{user_id}", response_model=UserRead)
async def patch_superuser_status(session: db_session, user_id: int, admin: current_admin_user):

    result = await change_superuser_status(session, user_id)

    if result == ChangeSuperuserStatusResult.USER_NOT_FOUND:
        raise HTTPException(status_code=404, detail="User not found")
    
    return result

@router.post("/forgot_password")
async def forgot_password(session: db_session, background_tasks: BackgroundTasks, email: str = Body(..., embed=True)):

    await send_change_password_mail(session, email, background_tasks)

    return {"message": "Jeśli to konto instnieje, wysłaliśmy instrukcje resetu hasła na wskazany adres e-mail."}

@router.patch("/change_password/{password_change_token}")
async def patch_password(session: db_session, password_change_token: str, plain_password: str = Body(..., embed=True)):

    result = await change_password(session, password_change_token, plain_password)
    
    if result == ChangePasswordResult.INVALID_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if result == ChangePasswordResult.WRONG_TOKEN_TYPE:
        raise HTTPException(status_code=401, detail="Wrong token type")

    if result == ChangePasswordResult.USER_NOT_FOUND:
        raise HTTPException(status_code=404, detail="User not found")

    return {"message": "Hasło zostało pomyślnie zmienione."}

@router.patch("/activate/{activate_token}", response_model=UserRead)
async def activate_account(session: db_session, activate_token: str):

    result = await change_account_status(session, activate_token)

    if result == ActivateTokenResult.INVALID_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if result == ActivateTokenResult.WRONG_TOKEN_TYPE:
        raise HTTPException(status_code=401, detail="Wrong token type")

    if result == ActivateTokenResult.USER_NOT_FOUND:
        raise HTTPException(status_code=404, detail="User not found")

    return result