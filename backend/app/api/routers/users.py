from fastapi import APIRouter, HTTPException
from sqlmodel import select
from app.core.db import db_session
from app.models.Users import User, UserRead, UserUpdate, UserCreate
from app.core.auth.jwt import get_password_hash
from app.services.users import get_user_by_username, get_user_by_email
from app.core.auth.utils import get_blind_index
from typing import List

router = APIRouter(prefix="/users", tags=["users"])

@router.post("", response_model=UserRead, status_code=201)
async def post_user(session: db_session, user: UserCreate):

    if await get_user_by_username(session, user.username):
        raise HTTPException(
            status_code = 400,
            detail = "Username already registered"
        )
    
    if await get_user_by_email(session, user.email):
        raise HTTPException(
            status_code = 400,
            detail = "Email already registered"
        )
        
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

    return db_user

@router.get("/{user_id}", response_model=UserRead)
async def get_user(session: db_session, user_id: int):

    result = await session.exec(select(User).where(User.id == user_id))
    user = result.one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return user

@router.get("", response_model=List[UserRead])
async def get_all_users(session: db_session):

    result = await session.exec(select(User))
    users = result.all()

    if not users:
        raise HTTPException(status_code=404, detail="Users not found")
    
    return users

@router.patch("/{user_id}", response_model=UserRead)
async def patch_user(session: db_session, user: UserUpdate, user_id: int):

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

@router.delete("/{user_id}", response_model=UserRead)
async def delete_user(session: db_session, user_id: int):

    result = await session.exec(select(User).where(User.id == user_id))
    db_user = result.one_or_none()

    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    await session.delete(db_user)
    await session.commit()

    return db_user