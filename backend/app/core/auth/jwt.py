from datetime import datetime, timezone, timedelta
from typing import Any, Optional
from jose import jwt
from passlib.context import CryptContext
from app.core.config import settings
import uuid
import hashlib
import logging

pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__time_cost=2,
    argon2__memory_cost=65536,
    argon2__parallelism=2,
)


ALGORITHM = settings.ALGORITHM
SECRET_KEY = settings.SECRET_KEY
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS = settings.REFRESH_TOKEN_EXPIRE_DAYS
APP_NAME = settings.APP_NAME

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_jti(jti: str) -> str:
    return hashlib.sha256(jti.encode()).hexdigest()


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_password_hash(plain: str) -> str:
    return pwd_context.hash(plain)


def create_access_token(username: str, id: int, expires_delta: timedelta | None = None) -> str:
    expire = _now() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    jti = str(uuid.uuid4())
    to_encode = {
        "sub": username,
        "id": id,
        "iat": int(_now().timestamp()),
        "exp": int(expire.timestamp()),
        "iss": APP_NAME,
        "aud": APP_NAME + "-api",
        "jti": jti,
        "typ": "access",
    }
    return encode_token(to_encode)


def create_refresh_token(username: str, id: int, expires_delta: timedelta | None = None) -> str:
    expire = _now() + (expires_delta or timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
    jti = str(uuid.uuid4())
    to_encode = {
        "sub": username,
        "id": id,
        "iat": int(_now().timestamp()),
        "exp": int(expire.timestamp()),
        "iss": APP_NAME,
        "aud": APP_NAME + "-api",
        "jti": jti,
        "typ": "refresh",
    }
    return encode_token(to_encode)


def encode_token(to_encode: dict) -> str:
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict[str, Any]:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], audience=APP_NAME + "-api", issuer=APP_NAME)


async def store_refresh_token(redis_client, jti: str, user_id: str, exp: int | datetime, *, device: Optional[str] = None, ip: Optional[str] = None):
    now = _now()
    if isinstance(exp, int):
        ttl = int(exp - int(now.timestamp()))
    else:
        ttl = int((exp - now).total_seconds())

    if ttl <= 0:
        return

    key = f"refresh:{_hash_jti(jti)}"
    sid = uuid.uuid4().hex[:16]
    created = int(now.timestamp())
    mapping = {
        "sid": str(sid),
        "user_id": str(user_id),
        "created_at": str(created),
        "last_seen": str(created),
    }
    if device:
        mapping["device"] = device
    if ip:
        mapping["ip"] = ip

    
    await redis_client.hset(key, mapping=mapping)
    await redis_client.expire(key, ttl)

    index_key = f"user_session_index:{user_id}:{sid}"
    try:
        await redis_client.set(index_key, key, ex=ttl)
        await redis_client.sadd(f"user_sessions:{user_id}", sid)
    except Exception:
        logging.exception("Failed adding session index or membership")
    return sid


async def revoke_refresh(redis_client, jti: str):
    key = f"refresh:{_hash_jti(jti)}"
    try:
        user_id = await redis_client.hget(key, "user_id")
        sid = await redis_client.hget(key, "sid")
        if user_id and sid:
            await redis_client.srem(f"user_sessions:{user_id}", sid)
            await redis_client.delete(f"user_session_index:{user_id}:{sid}")
    except Exception:
        logging.exception("Failed reading user_id for revoke")
    await redis_client.delete(key)


async def is_refresh_valid(redis_client, jti: str) -> bool:
    key = f"refresh:{_hash_jti(jti)}"
    return (await redis_client.exists(key)) == 1


async def revoke_all_user_sessions(redis_client, user_id: str):
    set_key = f"user_sessions:{user_id}"
    sids = await redis_client.smembers(set_key)
    if not sids:
        return
    for sid in sids:
        try:
            index_key = f"user_session_index:{user_id}:{sid}"
            refresh_key = await redis_client.get(index_key)
            if refresh_key:
                await redis_client.delete(refresh_key)
            await redis_client.delete(index_key)
        except Exception:
            logging.exception("Failed deleting session for sid %s", sid)
    await redis_client.delete(set_key)