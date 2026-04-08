from sqlmodel import select
from structlog.contextvars import bind_contextvars

from app.core.auth.apikeys import (generate_api_key_for_user,
                                   revoke_user_api_key)
from app.core.exceptions.exceptions import \
    AdminForibiddenFromCreatingApiKeyException
from app.models.APIKeys import APIKey
from app.models.Users import User
from backend.app.api.deps.db import db_session
from backend.app.core.logger.logger import get_logger

logger = get_logger(__name__)

async def validate_and_create_apikey(user: User, session: db_session, name: str):

    if user.is_superuser:
        logger.warning("api_key_creation_attempted_by_admin", user_id=str(user.id))
        raise AdminForibiddenFromCreatingApiKeyException()

    key = await generate_api_key_for_user(session, user.id, name)
    logger.info("api_key_created", user_id=str(user.id), key_name=name)
    return {"api_key": key}

async def revoke_apikey(key_id: int, user: User, session: db_session):

    bind_contextvars(
        target_key = key_id
    )

    await revoke_user_api_key(session, user.id, key_id)
    logger.info("api_key_revoked", user_id=str(user.id), key_id=key_id)
    return {"message": "api key revoked"}

async def fetch_user_apikeys(user: User, session: db_session):
    
    result = await session.exec(select(APIKey).where(APIKey.user_id == user.id))
    apikeys = result.all()
    logger.info("user_apikeys_fetched", user_id=str(user.id), key_count=len(apikeys))
    return [{"id": k.id, "name": k.name, "key_hint": k.key_hint, "created_at": k.created_at} for k in apikeys]
    