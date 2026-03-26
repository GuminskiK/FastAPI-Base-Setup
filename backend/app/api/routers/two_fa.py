from fastapi import APIRouter, Depends, HTTPException, status, Body, Request, Form
from app.services.users import current_active_user
from app.core.db import db_session
from app.core.config import settings
import secrets
import pyotp
import qrcode
import base64
import io

router = APIRouter(prefix="/2fa", tags=["2fa"])

APP_NAME = settings.APP_NAME

@router.post("/setup")
async def setup_2fa(user: current_active_user, session: db_session):
    if user.is_totp_enabled:
        raise HTTPException(status_code=400, detail="2FA is already enabled")
        
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user.username, issuer_name=APP_NAME)
    
    qr = qrcode.make(provisioning_uri)
    img_byte_arr = io.BytesIO()
    qr.save(img_byte_arr, format='PNG')
    qr_b64 = base64.b64encode(img_byte_arr.getvalue()).decode('utf-8')
    
    backup_codes = [secrets.token_hex(4) for _ in range(8)]
    
    user.totp_secret = secret
    user.backup_codes = backup_codes
    session.add(user)
    await session.commit()
    
    return {
        "secret": secret,
        "qr_code_base64": f"data:image/png;base64,{qr_b64}",
        "backup_codes": backup_codes
    }

@router.post("/enable")
async def enable_2fa(user: current_active_user, session: db_session, code: str = Body(..., embed=True)):
    if user.is_totp_enabled:
        raise HTTPException(status_code=400, detail="2FA is already enabled")
        
    if not user.totp_secret:
        raise HTTPException(status_code=400, detail="2FA setup not initiated")
        
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 2FA code")
        
    user.is_totp_enabled = True
    session.add(user)
    await session.commit()
    
    return {"message": "2FA successfully enabled"}

@router.post("/disable")
async def disable_2fa(user: current_active_user, session: db_session, code: str = Body(..., embed=True)):
    if not user.is_totp_enabled:
        raise HTTPException(status_code=400, detail="2FA is not enabled")
        
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 2FA code")
        
    user.is_totp_enabled = False
    user.totp_secret = None
    user.backup_codes = None
    session.add(user)
    await session.commit()
    
    return {"message": "2FA successfully disabled"}