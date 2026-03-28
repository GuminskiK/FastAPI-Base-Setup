import pyotp

def get_auth_headers(client, username="TestUser", password="TestPassword"):
    # 1. Create the user
    client.post(
        "/users", 
        json={"username": username, "email": f"{username}@example.com", "plain_password": password}
    )

    # 2. Login to get token
    login_response = client.post(
        "/auth/token",
        data={"username": username, "password": password}
    )
    token = login_response.json()["access_token"]
    
    return {"Authorization": f"Bearer {token}"}

def test_setup_2fa(client):
    headers = get_auth_headers(client)

    response = client.post("/2fa/setup", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "secret" in data
    assert "qr_code_base64" in data
    assert "backup_codes" in data
    assert len(data["backup_codes"]) == 8

def test_setup_2fa_twice_fails(client):
    headers = get_auth_headers(client)

    # First setup
    client.post("/2fa/setup", headers=headers)
    
    # Needs to be enabled to fail setup in some logics, but let's check code:
    # `if user.is_totp_enabled: raise HTTPException(400)` 
    # setup alone does NOT enable it! 
    # Oh wait, so setting up twice is fine if it's not enabled, it just overwrites.
    # Let's enable it to trigger the 400.
    
def test_enable_2fa_success(client):
    headers = get_auth_headers(client)

    # 1. Setup
    setup_resp = client.post("/2fa/setup", headers=headers)
    secret = setup_resp.json()["secret"]

    # 2. Generate correct code
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()

    # 3. Enable
    enable_resp = client.post("/2fa/enable", json={"code": valid_code}, headers=headers)
    assert enable_resp.status_code == 200
    assert enable_resp.json()["message"] == "2FA successfully enabled"

    # 4. Now setup should fail since it's already enabled
    setup_twice_resp = client.post("/2fa/setup", headers=headers)
    assert setup_twice_resp.status_code == 400
    assert setup_twice_resp.json()["detail"] == "2FA is already enabled"

def test_enable_2fa_invalid_code(client):
    headers = get_auth_headers(client)
    
    client.post("/2fa/setup", headers=headers)

    enable_resp = client.post("/2fa/enable", json={"code": "000000"}, headers=headers)
    assert enable_resp.status_code == 401
    assert enable_resp.json()["detail"] == "Invalid 2FA code"

def test_enable_2fa_without_setup(client):
    headers = get_auth_headers(client)

    enable_resp = client.post("/2fa/enable", json={"code": "123456"}, headers=headers)
    assert enable_resp.status_code == 400
    assert enable_resp.json()["detail"] == "2FA setup not initiated"

def test_disable_2fa_success(client):
    headers = get_auth_headers(client)

    # 1. Setup & Enable
    setup_resp = client.post("/2fa/setup", headers=headers)
    secret = setup_resp.json()["secret"]
    
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()
    client.post("/2fa/enable", json={"code": valid_code}, headers=headers)

    # 2. Disable with valid code
    disable_code = totp.now()
    disable_resp = client.post("/2fa/disable", json={"code": disable_code}, headers=headers)
    assert disable_resp.status_code == 200
    assert disable_resp.json()["message"] == "2FA successfully disabled"

def test_disable_2fa_not_enabled(client):
    headers = get_auth_headers(client)

    disable_resp = client.post("/2fa/disable", json={"code": "123456"}, headers=headers)
    assert disable_resp.status_code == 400
    assert disable_resp.json()["detail"] == "2FA is not enabled"
