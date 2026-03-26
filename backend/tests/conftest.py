import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import SQLModel

from app.main import app
from app.core.db import get_session
from app.core.redis import get_redis
from app.models.Users import User
from app.services.users import get_current_admin_user

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

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

    async def smembers(self, name):
        return self.data.get(name, set())

    async def hget(self, name, key):
        return self.data.get(name, {}).get(key)
        
    async def hgetall(self, name):
        return self.data.get(name, {})

    async def srem(self, name, value):
        if name in self.data and value in self.data[name]:
            self.data[name].remove(value)

    async def delete(self, name):
        self.data.pop(name, None)
        self.expires.pop(name, None)
        return 1

    async def exists(self, name):
        return int(name in self.data)

    async def sismember(self, name, value):
        return value in self.data.get(name, set())

    async def ttl(self, name):
        return 3600

    def pipeline(self):
        class FakePipeline:
            def __init__(self, parent):
                self.parent = parent
            def srem(self, name, value):
                if name in self.parent.data and value in self.parent.data[name]:
                    self.parent.data[name].remove(value)
            def delete(self, name):
                if name in self.parent.data:
                    del self.parent.data[name]
            async def execute(self):
                pass
        return FakePipeline(self)

engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestingSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

@pytest_asyncio.fixture(scope="function")
async def db_session():
    """
    Tworzy nową strukturę bazy danych przed każdym testem i usuwa ją po teście.
    Dzięki temu baza jest CAŁKOWICIE czysta w każdym teście.
    """
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
        
    async with TestingSessionLocal() as session:
        yield session
        
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)

@pytest.fixture(scope="function")
def client(db_session):
    """
    Nadpisuje metodę pobierania sesji w aplikacji, podpinając naszą sesję testową,
    oraz override'uje Redis.
    """
    async def override_get_session():
        yield db_session

    fake_redis = FakeAsyncRedis()
    def override_get_redis():
        return fake_redis

    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[get_redis] = override_get_redis
    
    with TestClient(app) as test_client:
        yield test_client
    
    app.dependency_overrides.pop(get_session, None)
    app.dependency_overrides.pop(get_redis, None)


@pytest.fixture(scope="function")
def override_admin():
    """
    Nadpisuje zależność wymagającą bycia administratorem (get_current_admin_user).
    Dzięki temu wstrzykiwany jest gotowy "admin" bez konieczności logowania się i używania nagłówka Bearer.
    """
    async def mock_admin():
        return User(
            id=999,
            username="testadmin",
            email="admin@example.com",
            is_superuser=True,
            hashed_password="mocked_password",
            email_blind_index="mocked_index"
        )
    
    app.dependency_overrides[get_current_admin_user] = mock_admin
    yield
    app.dependency_overrides.pop(get_current_admin_user, None)
