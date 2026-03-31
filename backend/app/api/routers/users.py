from fastapi import APIRouter, HTTPException, BackgroundTasks
from app.core.db import db_session
from app.models.Users import UserRead, UserUpdate, UserCreate
from typing import List
from app.services.users import current_admin_user, current_active_user
from app.services.users_crud import (
    remove_user, RemoveUserResult,
    update_user, UpdateUserResult,
    fetch_user, FetchUserResult,
    fetch_all_users,
    create_user, CreateUserResult)

router = APIRouter(prefix="/users", tags=["users"])

@router.post("", response_model=UserRead, status_code=201)
async def post_user(session: db_session, user: UserCreate, background_tasks: BackgroundTasks):

    result = await create_user(session, user, background_tasks)

    if result == CreateUserResult.USERNAME_TAKEN:
        raise HTTPException(
            status_code = 400,
            detail = "Username already registered"
        )
    
    if result == CreateUserResult.EMAIL_ALREADY_REGISTERED:
        raise HTTPException(
            status_code = 400,
            detail = "Email already registered"
        )

    return result

@router.get("/{user_id}", response_model=UserRead)
async def get_user(session: db_session, user_id: int, admin: current_admin_user):

    result = await fetch_user(session, user_id)

    if result == FetchUserResult.USER_NOT_FOUND:
        raise HTTPException(status_code=404, detail="User not found")

    return result

@router.get("", response_model=List[UserRead])
async def get_all_users(session: db_session, admin: current_admin_user):

    result = await fetch_all_users(session)

    if result == FetchUserResult.USER_NOT_FOUND:
        raise HTTPException(status_code=404, detail="Users not found")
    
    return result

@router.patch("/{user_id}", response_model=UserRead)
async def patch_user_admin(session: db_session, user: UserUpdate, user_id: int, admin: current_admin_user):

    result = await update_user(session, user, user_id)

    if result == UpdateUserResult.USER_NOT_FOUND:
        raise HTTPException(status_code=404, detail="User not found")
    
    if result == UpdateUserResult.EMAIL_ALREADY_REGISTERED:
        raise HTTPException(status_code = 400, detail = "Email already registered")

    return result

@router.patch("/me", response_model=UserRead)
async def patch_user(session: db_session, user: UserUpdate, current_user: current_active_user):
    
    result = await update_user(session, user, current_user.id)

    if result == UpdateUserResult.USER_NOT_FOUND:
        raise HTTPException(status_code=404, detail="User not found")
    
    if result == UpdateUserResult.EMAIL_ALREADY_REGISTERED:
        raise HTTPException(status_code = 400, detail = "Email already registered")

    return result

@router.delete("/{user_id}", response_model=UserRead)
async def delete_user_admin(session: db_session, user_id: int, admin: current_admin_user):

    result = await remove_user(session, user_id)

    if result == RemoveUserResult.USER_NOT_FOUND:
        raise HTTPException(status_code=404, detail="User not found")

    return result

@router.delete("/me", response_model=UserRead)
async def delete_user(session: db_session, user: current_active_user):

    result = await remove_user(session, user.id)

    if result == RemoveUserResult.USER_NOT_FOUND:
        raise HTTPException(status_code=404, detail="User not found")

    return result