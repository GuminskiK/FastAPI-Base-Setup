from app.main import app

def get_auth_headers(client, username="TestUser", password="TestPassword"):
    client.post("/users", json={"username": username, "email": f"{username}@example.com", "plain_password": password})
    login_response = client.post("/auth/token", data={"username": username, "password": password})
    token = login_response.json().get("access_token")
    return {"Authorization": f"Bearer {token}"} if token else {}

def test_create_api_key(client):
    headers = get_auth_headers(client)

    response = client.post(
        "/apikeys?name=MyKey",
        headers=headers
    )

    assert response.status_code == 201
    assert "api_key" in response.json()

def test_delete_api_key(client):
    headers = get_auth_headers(client)
    client.post(
        "/apikeys?name=MyKey",
        headers=headers
    )

    response = client.delete(
        "/apikeys/1?user_id=1", headers=headers
    )

    assert response.status_code == 200
    assert response.json() == {"message": "api key revoked"}

def test_get_my_keys(client):
    headers = get_auth_headers(client)
    client.post(
        "/apikeys?name=MyKey", headers=headers
    )

    response = client.get("/apikeys?user_id=1", headers=headers)

    assert response.status_code == 200
    assert "key_hint" in response.json()[0]
