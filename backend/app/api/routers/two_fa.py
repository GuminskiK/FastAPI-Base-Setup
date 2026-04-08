from fastapi import APIRouter, HTTPException, status, Body
from app.services.users import current_active_user
from backend.app.api.deps.db import db_session
from app.core.config import settings
from app.services.two_fa_service import generate_setup_data, Setup2FAResult, verify_and_enable, verify_and_disable, Enable2FAResult, Disable2FAResult


router = APIRouter(prefix="/2fa", tags=["2fa"])

APP_NAME = settings.APP_NAME

@router.post("/setup")
async def setup_2fa(user: current_active_user, session: db_session):
    
    return await generate_setup_data(user, session)
    
@router.post("/enable")
async def enable_2fa(user: current_active_user, session: db_session, code: str = Body(..., embed=True)):

    await verify_and_enable(user, session, code)

    return {"message": "2FA successfully enabled"}

@router.post("/disable")
async def disable_2fa(user: current_active_user, session: db_session, code: str = Body(..., embed=True)):
    
    return await verify_and_disable(user, session, code)  