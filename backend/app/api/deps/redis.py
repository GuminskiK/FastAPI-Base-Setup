from typing import Annotated

import redis.asyncio as redis
from fastapi import Depends

from app.core.config import settings

_redis = redis.from_url(settings.REDIS_URL, decode_responses=True)

def get_redis() -> redis.Redis:
    return _redis

redis_client = Annotated[redis.Redis, Depends(get_redis)]

