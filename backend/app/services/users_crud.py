from app.core.db import db_session
from sqlmodel import select
from app.models.Users import User, UserUpdate
from fastapi import HTTPException
from app.services.users import get_user_by_username, get_user_by_email
from app.core.auth.utils import get_blind_index
from app.core.auth.jwt import get_password_hash

async def patch_user_db(session: db_session, user: UserUpdate, user_id: int):
    
    result = await session.exec(select(User).where(User.id == user_id))
    db_user = result.one_or_none()

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user_data = user.model_dump(exclude_unset=True)
    
    if "plain_password" in user_data:
        user_data.hashed_password = get_password_hash(user_data.pop("plain_password"))

    if "email" in user_data:
        existing_user = get_user_by_email(session, user_data["email"])
        if existing_user and existing_user.id != user_id:
             raise HTTPException(
                status_code = 400,
                detail = "Email already registered"
            )
        user.email_blind_index = get_blind_index(user_data["email"])

    db_user.sqlmodel_update(user_data)
    session.add(db_user)
    await session.commit()
    await session.refresh(db_user)

    return db_user

async def delete_user_db(session: db_session, user_id: int):

    result = await session.exec(select(User).where(User.id == user_id))
    db_user = result.one_or_none()

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    await session.delete(db_user)
    await session.commit()

    return db_user