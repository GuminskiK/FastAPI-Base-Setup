from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"Hello": "World"}

def test_healthcheck():
    response = client.get("/health")
    assert isinstance(response.json(), dict)
    assert "status" in response.json()
