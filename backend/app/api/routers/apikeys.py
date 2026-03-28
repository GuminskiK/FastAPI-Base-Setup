from fastapi import APIRouter, HTTPException
from app.services.users import current_user, owner_or_admin
from app.core.db import db_session
from app.services.apikeys_service import *

router = APIRouter(prefix="/apikeys", tags=["apikeys"])

@router.post("", status_code=201)
async def post_apikey(user: current_user, session: db_session, name: str):

    result = await validate_and_create_apikey(user, session, name)

    if result == CreateApikeyResult.ADMIN:
        raise HTTPException(
            status_code=403, 
            detail="Admin accounts can't have apikeys. Use service account"
        )

    return result

@router.delete("/{key_id}")
async def delete_api_key(key_id: int, user: owner_or_admin, session: db_session):

    return await revoke_apikey(key_id, user, session)

@router.get("")
async def get_my_keys(user: owner_or_admin, session: db_session):
    
    return await fetch_user_apikeys(user, session)