from app.core.db import db_session
from sqlmodel import select
from app.models.Users import User, UserUpdate
from fastapi import HTTPException
from app.services.users import get_user_by_email
from app.core.auth.utils import get_blind_index
from app.core.auth.jwt import get_password_hash
from app.core.logger import get_logger

logger = get_logger(__name__)

async def patch_user_db(session: db_session, user: UserUpdate, user_id: int):
    
    result = await session.exec(select(User).where(User.id == user_id))
    db_user = result.one_or_none()

    if not db_user:
        logger.warning("user_patch_failed_not_found", user_id=user_id)
        raise HTTPException(status_code=404, detail="User not found")
    
    user_data = user.model_dump(exclude_unset=True)
    
    if "plain_password" in user_data:
        user_data.hashed_password = get_password_hash(user_data.pop("plain_password"))

    if "email" in user_data:
        existing_user = get_user_by_email(session, user_data["email"])
        if existing_user and existing_user.id != user_id:
             logger.warning("user_patch_failed_email_taken", user_id=user_id)
             raise HTTPException(
                status_code = 400,
                detail = "Email already registered"
            )
        user.email_blind_index = get_blind_index(user_data["email"])

    db_user.sqlmodel_update(user_data)
    session.add(db_user)
    await session.commit()
    await session.refresh(db_user)

    logger.info("user_patched_successfully", user_id=user_id, updated_fields=list(user_data.keys()))
    return db_user

async def delete_user_db(session: db_session, user_id: int):

    result = await session.exec(select(User).where(User.id == user_id))
    db_user = result.one_or_none()

    if not db_user:
        logger.warning("user_delete_failed_not_found", user_id=user_id)
        raise HTTPException(status_code=404, detail="User not found")
    
    await session.delete(db_user)
    await session.commit()

    logger.info("user_deleted_successfully", user_id=user_id)
    return db_user