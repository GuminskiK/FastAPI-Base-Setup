from app.core.auth.jwt import create_access_token, _now, create_refresh_token, decode_token, store_refresh_token, revoke_refresh, is_refresh_valid, revoke_all_user_sessions, _hash_jti
from app.core.config import settings
import pytest

APP_NAME = settings.APP_NAME
exp = 1000

def test_create_access_token():
    encoded_token = create_access_token("TestUser", 1)
    token = decode_token(encoded_token)
    assert token["sub"] == "TestUser"
    assert token["id"] == 1
    assert token["iss"] == APP_NAME
    assert token["aud"] == APP_NAME + "-api"
    assert "jti" in token
    assert token["typ"] == "access"
    
def test_create_refresh_token():
    encoded_token = create_refresh_token("TestUser", 1)
    token = decode_token(encoded_token)
    assert token["sub"] == "TestUser"
    assert token["id"] == 1
    assert token["iss"] == APP_NAME
    assert token["aud"] == APP_NAME + "-api"
    assert "jti" in token
    assert token["typ"] == "refresh"

class FakeAsyncRedis:
    def __init__(self):
        self.data = {}
        self.expires = {}

    async def hset(self, name, mapping):
        if name not in self.data:
            self.data[name] = {}
        self.data[name].update(mapping)

    async def expire(self, name, time):
        self.expires[name] = time

    async def set(self, name, value, ex=None):
        self.data[name] = value
        if ex:
            self.expires[name] = ex

    async def get(self, name):
        return self.data.get(name)

    async def sadd(self, name, value):
        if name not in self.data:
            self.data[name] = set()
        self.data[name].add(value)

    async def hget(self, name, key):
        return self.data.get(name, {}).get(key)

    async def srem(self, name, value):
        if name in self.data and value in self.data[name]:
            self.data[name].remove(value)

    async def delete(self, name):
        self.data.pop(name, None)
        self.expires.pop(name, None)

    async def exists(self, name):
        return 1 if name in self.data else 0

    async def smembers(self, name):
        return self.data.get(name, set())

@pytest.mark.asyncio
async def test_store_refresh_token():
    redis = FakeAsyncRedis()
    jti = "test-jti-123"
    user_id = "user_42"
    exp = int(_now().timestamp()) + 3600

    sid = await store_refresh_token(redis, jti, user_id, exp, device="iOS", ip="127.0.0.1")
    key = f"refresh:{_hash_jti(jti)}"
    assert key in redis.data
    assert redis.data[key]["user_id"] == user_id
    assert redis.data[key]["device"] == "iOS"
    assert redis.data[key]["ip"] == "127.0.0.1"
    
    index_key = f"user_session_index:{user_id}:{sid}"
    assert redis.data[index_key] == key
    assert sid in redis.data[f"user_sessions:{user_id}"]

@pytest.mark.asyncio
async def test_store_refresh_token_exp_zero():
    redis = FakeAsyncRedis()
    sid = await store_refresh_token(redis, "jti", "1", -100)
    assert sid is None
    assert not redis.data

@pytest.mark.asyncio
async def test_revoke_refresh():
    redis = FakeAsyncRedis()
    jti = "test-jti-123"
    user_id = "user_42"
    
    sid = await store_refresh_token(redis, jti, user_id, int(_now().timestamp()) + 3600)
    
    assert f"refresh:{_hash_jti(jti)}" in redis.data
    
    await revoke_refresh(redis, jti)
    
    assert f"refresh:{_hash_jti(jti)}" not in redis.data
    assert f"user_session_index:{user_id}:{sid}" not in redis.data
    assert sid not in redis.data.get(f"user_sessions:{user_id}", set())

@pytest.mark.asyncio
async def test_is_refresh_valid():
    redis = FakeAsyncRedis()
    jti = "test-jti-123"
    user_id = "user_42"
    
    assert not await is_refresh_valid(redis, jti)
    await store_refresh_token(redis, jti, user_id, int(_now().timestamp()) + 3600)
    assert await is_refresh_valid(redis, jti)
    
@pytest.mark.asyncio
async def test_revoke_all_user_sessions():
    redis = FakeAsyncRedis()
    user_id = "user_42"
    jti1 = "jti1"
    jti2 = "jti2"
    
    sid1 = await store_refresh_token(redis, jti1, user_id, int(_now().timestamp()) + 3600)
    sid2 = await store_refresh_token(redis, jti2, user_id, int(_now().timestamp()) + 3600)
    
    await revoke_all_user_sessions(redis, user_id)
    
    assert f"user_sessions:{user_id}" not in redis.data
    assert f"refresh:{_hash_jti(jti1)}" not in redis.data
    assert f"refresh:{_hash_jti(jti2)}" not in redis.data
    assert f"user_session_index:{user_id}:{sid1}" not in redis.data
    assert f"user_session_index:{user_id}:{sid2}" not in redis.data


