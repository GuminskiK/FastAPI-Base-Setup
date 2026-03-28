from fastapi import FastAPI
from app.core.health import check_disk, check_db, check_redis
from app.core.redis import redis_client
from app.core.db import db_session
from fastapi.middleware.cors import CORSMiddleware
from app.api.routers import users, auth, apikeys, two_fa
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):

    from app.core.db import AsyncSessionLocal
    from app.core.config import settings
    from app.models.Users import User
    from sqlmodel import select
    from app.core.auth.utils import get_blind_index
    from app.core.auth.jwt import get_password_hash
    async with AsyncSessionLocal() as session:
        # Check if superuser exists
        query = select(User).where(User.username == settings.FIRST_SUPERUSER)
        result = await session.exec(query)
        user = result.first()
        
        if not user:
            print("Creating first superuser...")
            superuser = User(
                username=settings.FIRST_SUPERUSER,
                email=f"{settings.FIRST_SUPERUSER}@example.com",
                email_blind_index=get_blind_index(f"{settings.FIRST_SUPERUSER}@example.com"),
                hashed_password=get_password_hash(settings.FIRST_SUPERUSER_PASSWORD),
                is_superuser=True,
                is_2fa_enabled=False 
            )
            session.add(superuser)
            await session.commit()
            print(f"Superuser '{settings.FIRST_SUPERUSER}' created.")
        else:
            print("Superuser already exists.")

    yield

app = FastAPI()
app.include_router(users.router)
app.include_router(auth.router)
app.include_router(apikeys.router)
app.include_router(two_fa.router)

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