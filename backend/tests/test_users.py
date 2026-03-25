def test_post_good(client):
    
    response = client.post(
        "/users", 
        json={ "username": "TestUser", "plain_password": "TestPassword"}
    )

    assert response.status_code == 201
    assert response.json() == {"username": "TestUser"}

def test_post_no_username(client):
    
    response = client.post(
        "/users", 
        json={"plain_password": "TestPassword"}
    )

    assert response.status_code == 422
    assert response.json()["detail"][0]["type"] == "missing"
    assert "username" in response.json()["detail"][0]["loc"]

def test_get_user_ok(client):
    
    client.post(
        "/users", 
        json={ "username": "TestUser", "plain_password": "TestPassword"}
    )

    response = client.get("/users/1")

    assert response.status_code == 200
    assert response.json() == {"username": "TestUser"}

def test_get_user_no_user(client):

    response = client.get("/users/1")

    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}

def test_get_all_users(client):
    
    client.post(
        "/users", 
        json={ "username": "TestUser", "plain_password": "TestPassword"}
    )

    client.post(
        "/users", 
        json={ "username": "TestUser2", "plain_password": "TestPassword"}
    )

    response = client.get("/users")

    assert response.status_code == 200
    response_data = response.json()
    assert {"username": "TestUser"} in response_data
    assert {"username": "TestUser2"} in response_data

def test_get_users_no_user(client):

    response = client.get("/users")

    assert response.status_code == 404
    assert response.json() == {"detail": "Users not found"}


def test_patch_user_ok(client):

    client.post(
        "/users", 
        json={ "username": "TestUser", "plain_password": "TestPassword"}
    )

    response = client.patch(
        "/users/1", 
        json={ "username": "TestUserPatched", "plain_password": "TestPassword"}
    )
        
    assert response.status_code == 200
    assert response.json() == {"username": "TestUserPatched"}

def test_patch_user_no_user(client):

    response = client.patch(
        "/users/1", 
        json={ "username": "TestUserPatched", "plain_password": "TestPassword"}
    )
        
    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}

def test_patch_unknown_field(client):

    client.post(
        "/users", 
        json={ "username": "TestUser", "plain_password": "TestPassword"}
    )

    response = client.patch(
        "/users/1", 
        json={ "username": "TestUserPatched", "unknown": "-------"}
    )

    assert response.status_code == 200

def test_delete_user(client):

    client.post(
        "/users", 
        json={ "username": "TestUser", "plain_password": "TestPassword"}
    )

    response = client.delete(
        "/users/1",
    )

    assert response.status_code == 200
    assert response.json() == {"username": "TestUser"}
    
def test_delete_user_no_user(client):
    
    response = client.delete(
        "/users/1",
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}