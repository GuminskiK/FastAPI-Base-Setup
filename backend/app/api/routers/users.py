from typing import List

from fastapi import APIRouter, BackgroundTasks

from app.api.deps.users import current_active_user, current_admin_user
from app.models.Users import UserCreate, UserRead, UserUpdate
from app.services.users_crud import (create_user, fetch_all_users, fetch_user,
                                     remove_user, update_user)
from app.api.deps.db import db_session

router = APIRouter(prefix="/users", tags=["users"])

@router.post("", response_model=UserRead, status_code=201)
async def post_user(session: db_session, user: UserCreate, background_tasks: BackgroundTasks):

    return await create_user(session, user, background_tasks)


@router.get("/{user_id}", response_model=UserRead)
async def get_user(session: db_session, user_id: int, admin: current_admin_user):

    return await fetch_user(session, user_id)

@router.get("", response_model=List[UserRead])
async def get_all_users(session: db_session, admin: current_admin_user):

    return await fetch_all_users(session)

@router.patch("/{user_id}", response_model=UserRead)
async def patch_user_admin(session: db_session, user: UserUpdate, user_id: int, admin: current_admin_user):

    return await update_user(session, user, user_id)

@router.patch("/me", response_model=UserRead)
async def patch_user(session: db_session, user: UserUpdate, current_user: current_active_user):
    
    return await update_user(session, user, current_user.id)

@router.delete("/{user_id}", response_model=UserRead)
async def delete_user_admin(session: db_session, user_id: int, admin: current_admin_user):

    return await remove_user(session, user_id)

@router.delete("/me", response_model=UserRead)
async def delete_user(session: db_session, user: current_active_user):

    return await remove_user(session, user.id)
