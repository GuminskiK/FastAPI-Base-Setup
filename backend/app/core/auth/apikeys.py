from fastapi import HTTPException
from app.core.config import settings
from app.core.db import db_session
from app.models.Users import User
from app.models.APIKeys import APIKey
from sqlmodel import select
import hashlib
import secrets
import hmac
from app.core.logger import get_logger

logger = get_logger(__name__)

def _hash_api_key(api_key: str) -> str:
    key = settings.SECRET_KEY.encode()
    return hmac.new(key, api_key.encode(), hashlib.sha256).hexdigest()

async def generate_api_key_for_user(session: db_session, user_id: int, name: str) -> str:
    key = secrets.token_urlsafe(32)
    hashed = _hash_api_key(key)
    statement = select(User).where(User.id == user_id)
    result = await session.exec(statement)
    user = result.one_or_none()
    if not user:
        logger.warning("api_key_generation_failed_user_not_found", user_id=user_id)
        raise HTTPException(status_code=404, detail="User not found")
    apikey = APIKey(name = name, hashed_key=hashed, key_hint= hashed[:4] + hashed[-4:], user_id=user_id)    
    session.add(apikey)
    await session.commit()
    logger.info("api_key_saved_to_db", user_id=user_id)
    return key

async def revoke_user_api_key(session: db_session, user_id: int, key_id: int) -> None:
    result = await session.exec(select(APIKey).where(APIKey.user_id == user_id, APIKey.id == key_id))
    apikey = result.one_or_none()
    if not apikey:
        logger.warning("api_key_revoke_failed_not_found", user_id=user_id, key_id=key_id)
        raise HTTPException(status_code=404, detail="APIKey not found")
    await session.delete(apikey)
    await session.commit()
    logger.info("api_key_deleted_from_db", user_id=user_id, key_id=key_id)

async def get_user_by_api_key(session: db_session, api_key: str) -> User | None:
    hashed = _hash_api_key(api_key)
    result = await session.exec(select(APIKey).where(APIKey.hashed_key == hashed))
    apikey = result.one_or_none()
    if not apikey:
        return None
    user_result = await session.exec(select(User).where(User.id == apikey.user_id))
    user = user_result.one_or_none()
    if not user:
        return None
    return user