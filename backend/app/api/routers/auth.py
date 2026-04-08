from fastapi import APIRouter, Depends, Body, Request, Form, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from backend.app.api.deps.db import db_session
from backend.app.api.deps.redis import redis_client
from app.models.Tokens import Token
from app.api.deps.users import owner_or_admin, current_admin_user
from app.services.auth_service import (
    login_token,
    refresh_token as refresh_token_service,
    revoke_refresh_token as logout_service,
    fetch_auth_sessions,
    delete_session,
    change_superuser_status,
    change_account_status,
    send_change_password_mail,
    change_password
)
from app.models.Users import UserRead, NewPasswordModel
from app.core.rate_limiting import limiter

router = APIRouter(prefix="/auth", tags=["auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@router.post("/token", response_model=Token)
@limiter.limit("20/hour")
async def post_token(
    request: Request,
    redis: redis_client,
    session: db_session,
    form_data: OAuth2PasswordRequestForm = Depends(),
    mfa_code: str | None = Form(default=None)
):
    return await login_token(request, redis, session, form_data, mfa_code)



@router.post("/refresh", response_model=Token)
async def post_refresh_token(redis: redis_client, refresh_token: str = Body(..., embed=True)):
    
    return await refresh_token_service(redis, refresh_token)

@router.post("/logout")
async def logout(redis: redis_client, refresh_token: str = Body(..., embed=True)):
    
    return await logout_service(redis, refresh_token)

@router.get("/sessions")
async def get_auth_sessions(redis: redis_client, user: owner_or_admin):
    
    return await fetch_auth_sessions(redis, user)

@router.post("/logout/{sid}")
async def logout_with_session_id(redis: redis_client, user: owner_or_admin, sid: str):
    
    return await delete_session(redis, user, sid)

@router.patch("/activate/{activate_token}", response_model=UserRead)
async def activate_account(session: db_session, activate_token: str):

    return await change_account_status(session, activate_token)

@router.patch("/change_superuser_status/{user_id}", response_model=UserRead)
async def patch_superuser_status(session: db_session, user_id: int, admin: current_admin_user):

    return await change_superuser_status(session, user_id)


@router.post("/forgot_password")
async def forgot_password(session: db_session, background_tasks: BackgroundTasks, email: str = Body(..., embed=True)):

    await send_change_password_mail(session, email, background_tasks)

    return {"message": "Jeśli to konto instnieje, wysłaliśmy instrukcje resetu hasła na wskazany adres e-mail."}

@router.patch("/change_password/{password_change_token}")
async def patch_password(session: db_session, password_change_token: str, payload: NewPasswordModel):

    await change_password(session, password_change_token, payload.plain_password)

    return {"message": "Hasło zostało pomyślnie zmienione."}