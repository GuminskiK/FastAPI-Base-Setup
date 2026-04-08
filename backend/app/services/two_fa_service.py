import base64
import io
import secrets

import pyotp
import qrcode

from app.core.config import settings
from app.core.exceptions.exceptions import (Invalid2FACodeException,
                                            TwoFaAlreadyEnabledException,
                                            TwoFaNotEnabledException,
                                            TwoFaNotInitiatedException)
from app.models.Users import User
from app.api.deps.db import db_session
from app.core.logger.logger import get_logger

logger = get_logger(__name__)

async def generate_setup_data(user: User, session: db_session):
    if user.is_totp_enabled:
        logger.info("2fa_setup_already_enabled", user_id=str(user.id))
        raise TwoFaAlreadyEnabledException()
        
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

async def verify_and_enable(user: User, session: db_session, code: str):
    
    if user.is_totp_enabled:
        raise TwoFaAlreadyEnabledException()
        
    if not user.totp_secret:
        raise TwoFaNotInitiatedException()
        
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(code):
        raise Invalid2FACodeException()
        
    user.is_totp_enabled = True
    session.add(user)
    await session.commit()
    
    return {"message": "ok"}

async def verify_and_disable(user: User, session: db_session, code: str):

    if not user.is_totp_enabled:
       raise TwoFaNotEnabledException()
        
    totp = pyotp.TOTP(user.totp_secret)

    if not totp.verify(code):
       raise Invalid2FACodeException()
    
    user.is_totp_enabled = False
    user.totp_secret = None
    user.backup_codes = None
    session.add(user)
    await session.commit()

    return {"message": "2FA successfully disabled"}