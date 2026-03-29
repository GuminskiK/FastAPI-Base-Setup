import pyotp
import qrcode
import base64
import io
import secrets
from enum import Enum
from app.models.Users import User
from app.core.db import db_session 
from app.core.config import settings
from app.core.logger import get_logger

class Setup2FAResult(Enum):
    SUCCESS = "success"
    ALREADY_ENABLED = "already_enabled"

class Enable2FAResult(Enum):
    SUCCESS = "success"
    ALREADY_ENABLED = "already_enabled"
    NOT_INITIATED = "not_initiated"
    INVALID_CODE = "invalid_code"

class Disable2FAResult(Enum):
    SUCCESS = "success"
    NOT_ENABLED = "not_enabled"
    INVALID_CODE = "invalid_code"

logger = get_logger(__name__)

async def generate_setup_data(user: User, session: db_session) -> dict | Setup2FAResult:
    if user.is_totp_enabled:
        logger.info("2fa_setup_already_enabled", user_id=str(user.id))
        return Setup2FAResult.ALREADY_ENABLED
        
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user.username, issuer_name=settings.APP_NAME)
    
    qr = qrcode.make(provisioning_uri)
    img_byte_arr = io.BytesIO()
    qr.save(img_byte_arr, format='PNG')
    qr_b64 = base64.b64encode(img_byte_arr.getvalue()).decode('utf-8')
    
    backup_codes = [secrets.token_hex(4) for _ in range(8)]
    
    user.totp_secret = secret
    user.backup_codes = backup_codes
    session.add(user)
    await session.commit()
    
    logger.info("2fa_setup_data_generated", user_id=str(user.id))
    return {
        "secret": secret,
        "qr_code_base64": f"data:image/png;base64,{qr_b64}",
        "backup_codes": backup_codes
    }

async def verify_and_enable(user: User, session: db_session, code: str) -> Enable2FAResult:
    
    if user.is_totp_enabled:
        return Enable2FAResult.ALREADY_ENABLED
        
    if not user.totp_secret:
        return Enable2FAResult.NOT_INITIATED
        
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(code):
        return Enable2FAResult.INVALID_CODE
        
    user.is_totp_enabled = True
    session.add(user)
    await session.commit()
    
    return Enable2FAResult.SUCCESS

async def verify_and_disable(user: User, session: db_session, code: str):

    if not user.is_totp_enabled:
        return Disable2FAResult.NOT_ENABLED
        
    totp = pyotp.TOTP(user.totp_secret)

    if not totp.verify(code):
        return Disable2FAResult.INVALID_CODE
    
    user.is_totp_enabled = False
    user.totp_secret = None
    user.backup_codes = None
    session.add(user)
    await session.commit()

    return {"message": "2FA successfully disabled"}