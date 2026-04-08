from typing import Optional

from sqlmodel import select

from app.core.auth.utils import get_blind_index
from app.models.Users import User
from app.api.deps.db import db_session


async def get_user_by_id(session: db_session, id: int) -> User | None:
    result = await session.exec(select(User).where(User.id == id))
    user = result.one_or_none()
    return user

async def get_user_by_username(session: db_session, username: str) -> User | None:
    result = await session.exec(select(User).where(User.username == username))
    user = result.one_or_none()
    return user

async def get_user_by_email(session: db_session, email: str) -> Optional[User]:
    blind_index = get_blind_index(email)
    result = await session.exec(select(User).where(User.email_blind_index == blind_index))
    return result.one_or_none()