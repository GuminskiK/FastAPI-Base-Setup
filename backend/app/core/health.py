import shutil
import os
from typing import Tuple, Any
from app.core.db import db_session
from app.core.redis import redis_client

def check_disk(min_free_percent: float = 10.0) -> Tuple[bool, dict]:
    """Return (ok, info) for disk usage check."""
    total, used, free = shutil.disk_usage(os.path.abspath(os.sep))
    free_pct = round(free / total * 100, 2)
    ok = free_pct >= min_free_percent
    return ok, {"free_percent": free_pct}


from sqlalchemy import text

async def check_db(session: db_session, timeout: int = 3) -> Tuple[bool, Any]:
    try:
        await session.exec(text("SELECT 1"))
        return True, None
    except Exception as e:
        return False, str(e)

async def check_redis(session: redis_client, timeout: int = 3) -> Tuple[bool, Any]:
    try:
        if await session.ping():
            return True, None
        return False, "ping failed"
    except Exception as e:
        return False, str(e)