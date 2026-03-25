from fastapi import APIRouter, Depends, HTTPException, status, Body, Request, Form
from app.core.auth.apikeys import generate_api_key_for_user, revoke_user_api_key
from app.services.users import current_user
from app.core.db import db_session
from app.models.APIKeys import APIKey
from sqlmodel import select


router = APIRouter(prefix="/apikeys", tags=["apikeys"])

@router.post("/apikeys")
async def create_api_key(user: current_user, session: db_session, name: str = Body(..., embed=True)):
    key = await generate_api_key_for_user(session, user.id, name)
    return {"api_key": key}

@router.delete("/apikeys/{key_id}")
async def delete_api_key(key_id: int, user: current_user, session: db_session):
    await revoke_user_api_key(session, user.id, key_id)
    return {"message": "api key revoked"}

@router.get("/apikeys")
async def get_my_keys(user: current_user, session: db_session):
    result = await session.exec(select(APIKey).where(APIKey.user_id == user.id))
    apikeys = result.all()
    return [{"id": k.id, "name": k.name, "key_hint": k.key_hint, "created_at": k.created_at} for k in apikeys]
    