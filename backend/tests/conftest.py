import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlmodel import SQLModel

from app.main import app
from app.core.db import get_session

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

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
    oraz dostarcza obiekt TestClient dla testów.
    """
    async def override_get_session():
        yield db_session

    app.dependency_overrides[get_session] = override_get_session
    
    with TestClient(app) as test_client:
        yield test_client
    
    app.dependency_overrides.clear()
