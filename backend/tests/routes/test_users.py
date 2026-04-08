def test_post_good(client):
    
    response = client.post(
        "/users", 
        json={ "username": "TestUser", "email": "test@example.com", "plain_password": "TestPassword1!"}
    )

    print("RESP:", response.json())
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == "TestUser"
    assert data["email"] == "test@example.com"
    assert data["id"] == 1
    assert data["is_activated"] is False
    assert data["is_superuser"] is False
    assert data["is_totp_enabled"] is False

def test_post_no_username(client):

    response = client.post(
        "/users",
        json={"plain_password": "TestPassword1!"}
    )

    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "missing"
    assert "username" in response.json()["detail"][0]["loc"]

def test_get_user_ok(client, override_admin):

    client.post(
        "/users",
        json={ "username": "TestUser", "email": "test@example.com", "plain_password": "TestPassword1!"}
    )

    response = client.get("/users/1")

    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "TestUser"
    assert data["email"] == "test@example.com"
    assert data["id"] == 1
    assert data["is_activated"] is False
    assert data["is_superuser"] is False
    assert data["is_totp_enabled"] is False

def test_get_user_no_user(client, override_admin):

    response = client.get("/users/1")

    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}

def test_get_all_users(client, override_admin):

    client.post(
        "/users",
        json={ "username": "TestUser", "email": "test@example.com", "plain_password": "TestPassword1!"}
    )

    client.post(
        "/users",
        json={ "username": "TestUser2", "email": "test2@example.com", "plain_password": "TestPassword1!"}
    )

    response = client.get("/users")

    assert response.status_code == 200
    response_data = response.json()
    assert any(user["username"] == "TestUser" and user["email"] == "test@example.com" for user in response_data)
    assert any(user["username"] == "TestUser2" and user["email"] == "test2@example.com" for user in response_data)

def test_get_users_no_user(client, override_admin):

    response = client.get("/users")

    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}


def test_patch_user_ok(client, override_admin):

    client.post(
        "/users",
        json={ "username": "TestUser", "email": "test@example.com", "plain_password": "TestPassword1!"}
    )

    response = client.patch(
        "/users/1",
        json={ "username": "TestUserPatched"}
    )

    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "TestUserPatched"
    assert data["email"] == "test@example.com"
    assert "id" in data

def test_patch_user_no_user(client, override_admin):

    response = client.patch(
        "/users/1",
        json={ "username": "TestUserPatched"}
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}

def test_patch_unknown_field(client, override_admin):

    client.post(
        "/users", 
        json={ "username": "TestUser", "email": "test@example.com", "plain_password": "TestPassword1!"}
    )

    response = client.patch(
        "/users/1",
        json={ "username": "TestUserPatched", "unknown": "-------"}
    )

    assert response.status_code == 200

def test_delete_user(client, override_admin):

    client.post(
        "/users",
        json={ "username": "TestUser", "email": "test@example.com", "plain_password": "TestPassword1!"}
    )

    response = client.delete(
        "/users/1",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "TestUser"
    assert data["email"] == "test@example.com"
    assert data["id"] == 1
