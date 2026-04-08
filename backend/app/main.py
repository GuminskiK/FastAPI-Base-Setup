from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.api.routers import apikeys, auth, two_fa, users
from app.core.health import check_db, check_disk, check_redis
from app.core.rate_limiting import limiter
from app.api.deps.db import db_session
from app.api.deps.redis import redis_client
from app.core.logger.logger import setup_logging
from app.core.logger.logging_middleware import StructlogMiddleware

# Initialize structural logging globally
setup_logging(json_logs=False, log_level="INFO")  # SET json_logs=True for Sentry/Loki!

@asynccontextmanager
async def lifespan(app: FastAPI):

    from sqlmodel import SQLModel, select

    from app.core.auth.jwt import get_password_hash
    from app.core.auth.utils import get_blind_index
    from app.core.config import settings
    from app.models.Users import User
    from app.api.deps.db import AsyncSessionLocal, engine

    # Utworzenie wszystkich tabel przez engine
    try:
        async with engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

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
    except Exception as e:
        print(f"Skipping DB init / superuser creation, DB likely not initialized or unreachable (e.g. Test Mode): {e}")
    yield

app = FastAPI(lifespan=lifespan)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(StructlogMiddleware)

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