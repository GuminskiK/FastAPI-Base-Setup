from backend.app.api.deps.db import db_session
from sqlmodel import select
from app.models.Users import User, UserUpdate, UserCreate
from app.core.auth.utils import get_blind_index
from app.core.auth.jwt import get_password_hash, create_token
from app.models.Tokens import TokenTypes
from backend.app.core.logger.logger import get_logger
from app.services.users import get_user_by_username, get_user_by_email
from app.core.config import settings
from app.services.email_service import send_activation_email
from fastapi import BackgroundTasks
from app.core.exceptions.exceptions import (
    UsernameTakenException, EmailTakenException, UserNotFoundException

)
from structlog.contextvars import bind_contextvars
from datetime import timedelta
logger = get_logger(__name__)
ACTIVATE_TOKEN_EXPIRE_DAYS = settings.ACTIVATE_TOKEN_EXPIRE_DAYS
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES= settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES

async def create_user(session: db_session, user: UserCreate, background_tasks: BackgroundTasks):

    if await get_user_by_username(session, user.username):
        logger.warning("user_create_failed_username_taken")
        raise UsernameTakenException()
    
    if await get_user_by_email(session, user.email):
        logger.warning("user_create_failed_email_taken")
        raise EmailTakenException()
    
    hashed = get_password_hash(user.plain_password)
    
    user_data = user.model_dump(exclude={"plain_password"})
    email_blind_index = get_blind_index(user_data["email"])
    
    db_user = User(
        **user_data, 
        hashed_password=hashed,
        email_blind_index=email_blind_index
    )
    session.add(db_user)
    await session.commit()
    await session.refresh(db_user)

    logger.info("user_created_successfully", user_id=db_user.id)

    token = create_token(db_user.id, db_user.username, TokenTypes.ACTIVATE, timedelta(days=ACTIVATE_TOKEN_EXPIRE_DAYS))

    background_tasks.add_task(send_activation_email, db_user.email, token)

    return db_user

async def fetch_user(session: db_session, user_id: int):
    
    result = await session.exec(select(User).where(User.id == user_id))
    user = result.one_or_none()

    if not user:
        raise UserNotFoundException()

    return user

async def fetch_all_users(session: db_session):

    result = await session.exec(select(User))
    users = result.all()

    if not users:
        raise UserNotFoundException()
    
    return users


async def update_user(session: db_session, user: UserUpdate, user_id: int):
    
    bind_contextvars(
        target_user = user_id
    )

    result = await session.exec(select(User).where(User.id == user_id))
    db_user = result.one_or_none()

    if not db_user:
        logger.warning("user_patch_failed_user_not_found", user_id=user_id)
        raise UserNotFoundException()
    
    user_data = user.model_dump(exclude_unset=True)
    
    if "plain_password" in user_data:
        user_data.hashed_password = get_password_hash(user_data.pop("plain_password"))

    if "email" in user_data:
        existing_user = get_user_by_email(session, user_data["email"])
        if existing_user and existing_user.id != user_id:
            logger.warning("user_patch_failed_email_taken", user_id=user_id)
            raise EmailTakenException()
        user.email_blind_index = get_blind_index(user_data["email"])

    db_user.sqlmodel_update(user_data)
    session.add(db_user)
    await session.commit()
    await session.refresh(db_user)

    logger.info("user_patched_successfully", user_id=user_id, updated_fields=list(user_data.keys()))
    return db_user

async def remove_user(session: db_session, user_id: int):

    bind_contextvars(
        target_user = user_id
    )

    result = await session.exec(select(User).where(User.id == user_id))
    db_user = result.one_or_none()

    if not db_user:
        logger.warning("user_delete_failed_not_found", user_id=user_id)
        raise UserNotFoundException()
    
    await session.delete(db_user)
    await session.commit()

    logger.info("user_deleted_successfully", user_id=user_id)
    return db_user
    