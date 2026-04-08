import pytest

from app.core.auth.apikeys import (generate_api_key_for_user,
                                   get_user_by_api_key, revoke_user_api_key)


@pytest.mark.asyncio
async def test_api_key_for_user_flow(client, db_session):

    client.post(
        "/users", 
        json={ "username": "TestUser", "email": "mymail@gmail.com", "plain_password": "TestPassword1!"}
    )

    apikey = await generate_api_key_for_user(db_session, 1, "MyKey")
    user = await get_user_by_api_key(db_session, apikey)

    assert user.username == "TestUser"

    from sqlmodel import select

    from app.models.APIKeys import APIKey
    key_obj = (await db_session.exec(select(APIKey).where(APIKey.user_id == user.id))).first()

    await revoke_user_api_key(db_session, user.id, key_obj.id)
    result = await get_user_by_api_key(db_session, apikey)

    assert result is None
