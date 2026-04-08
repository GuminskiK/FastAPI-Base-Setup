import redis.asyncio as redis
from app.core.config import settings
from typing import Annotated
from fastapi import Depends

_redis = redis.from_url(settings.REDIS_URL, decode_responses=True)

def get_redis() -> redis.Redis:
    return _redis

redis_client = Annotated[redis.Redis, Depends(get_redis)]

