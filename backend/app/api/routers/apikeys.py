from fastapi import APIRouter

from app.api.deps.users import current_user, owner_or_admin
from app.services.apikeys_service import (fetch_user_apikeys, revoke_apikey,
                                          validate_and_create_apikey)
from backend.app.api.deps.db import db_session

router = APIRouter(prefix="/apikeys", tags=["apikeys"])

@router.post("", status_code=201)
async def post_apikey(user: current_user, session: db_session, name: str):

    return await validate_and_create_apikey(user, session, name)

@router.delete("/{key_id}")
async def delete_api_key(key_id: int, user: owner_or_admin, session: db_session):

    return await revoke_apikey(key_id, user, session)

@router.get("")
async def get_my_keys(user: owner_or_admin, session: db_session):
    
    return await fetch_user_apikeys(user, session)