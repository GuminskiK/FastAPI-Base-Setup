from enum import Enum
from app.core.db import db_session
from app.models.Users import User
from app.core.auth.apikeys import generate_api_key_for_user, revoke_user_api_key
from sqlmodel import select
from app.models.APIKeys import APIKey

from app.core.logger import get_logger
logger = get_logger(__name__)

class CreateApikeyResult(Enum):
    SUCCESS = "sucess",
    ADMIN = "admin"

async def validate_and_create_apikey(user: User, session: db_session, name: str):

    if user.is_superuser:
        logger.warning("api_key_creation_attempted_by_admin", user_id=str(user.id))
        return CreateApikeyResult

    key = await generate_api_key_for_user(session, user.id, name)
    logger.info("api_key_created", user_id=str(user.id), key_name=name)
    return {"api_key": key}

async def revoke_apikey(key_id: int, user: User, session: db_session):

    await revoke_user_api_key(session, user.id, key_id)
    logger.info("api_key_revoked", user_id=str(user.id), key_id=key_id)
    return {"message": "api key revoked"}

async def fetch_user_apikeys(user: User, session: db_session):
    
    result = await session.exec(select(APIKey).where(APIKey.user_id == user.id))
    apikeys = result.all()
    logger.info("user_apikeys_fetched", user_id=str(user.id), key_count=len(apikeys))
    return [{"id": k.id, "name": k.name, "key_hint": k.key_hint, "created_at": k.created_at} for k in apikeys]
    