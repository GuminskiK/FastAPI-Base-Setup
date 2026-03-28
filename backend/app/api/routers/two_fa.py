from fastapi import APIRouter, Depends, HTTPException, status, Body, Request, Form
from app.services.users import current_active_user
from app.core.db import db_session
from app.core.config import settings
from app.services.two_fa_service import *
import pyotp


router = APIRouter(prefix="/2fa", tags=["2fa"])

APP_NAME = settings.APP_NAME

@router.post("/setup")
async def setup_2fa(user: current_active_user, session: db_session):
    
    result = await generate_setup_data(user, session)
    
    if result == Setup2FAResult.ALREADY_ENABLED:
        raise HTTPException(status_code=400, detail="2FA is already enabled")
    
    return result

    
@router.post("/enable")
async def enable_2fa(user: current_active_user, session: db_session, code: str = Body(..., embed=True)):

    result = await verify_and_enable(user, session, code)
    
    if result == Enable2FAResult.ALREADY_ENABLED:
        raise HTTPException(status_code=400, detail="2FA is already enabled")
        
    elif result == Enable2FAResult.NOT_INITIATED:
        raise HTTPException(status_code=400, detail="2FA setup not initiated")
        
    elif result == Enable2FAResult.INVALID_CODE:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 2FA code")
        
    return {"message": "2FA successfully enabled"}

@router.post("/disable")
async def disable_2fa(user: current_active_user, session: db_session, code: str = Body(..., embed=True)):
    
    result = await verify_and_disable(user, session, code)
    
    if result == Disable2FAResult.NOT_ENABLED:
        raise HTTPException(status_code=400, detail="2FA is not enabled")
        
    if result == Disable2FAResult.INVALID_CODE:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 2FA code")
        
    return result