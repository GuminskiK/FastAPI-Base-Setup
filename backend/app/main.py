from fastapi import FastAPI, Depends
from app.core.config import settings
from app.core.health import check_disk, check_db, check_redis
from app.core.redis import redis_client
from app.core.db import db_session
from fastapi.middleware.cors import CORSMiddleware
from app.api.routers import users

app = FastAPI()
app.include_router(users.router)

origins = [
    "http://localhost.tiangolo.com",
    "https://localhost.tiangolo.com",
    "http://localhost",
    "http://localhost:8080",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.get("/health")
async def health(redis: redis_client, db: db_session):
    result = {"status": "ok", "checks": {}}

    # Disk usage
    disk_ok, disk_info = check_disk()
    result["checks"]["disk"] = disk_info
    if not disk_ok:
        result["status"] = "degraded"

    # DB Check
    db_ok, db_info = await check_db(db)
    result["checks"]["db"] = {"ok": db_ok, "info": db_info}
    if not db_ok:
        result["status"] = "down"

    # Redis Check
    redis_ok, redis_info = await check_redis(redis)
    result["checks"]["redis"] = {"ok": redis_ok, "info": redis_info}
    if not redis_ok:
        result["status"] = "down"

    return result