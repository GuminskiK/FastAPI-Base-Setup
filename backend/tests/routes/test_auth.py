import pyotp
from unittest.mock import patch
from datetime import timedelta
from app.core.auth.jwt import create_token
from app.models.Tokens import TokenTypes

def test_login_success(client):
    # Setup user
    client.post(
        "/users", 
        json={"username": "AuthUser", "email": "auth@example.com", "plain_password": "AuthPassword"}
    )
    
    # Login
    response = client.post(
        "/auth/token",
        data={"username": "AuthUser", "password": "AuthPassword"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"

def test_login_invalid_credentials(client):
    # Setup user
    client.post(
        "/users", 
        json={"username": "AuthUser2", "email": "auth2@example.com", "plain_password": "AuthPassword"}
    )
    
    response = client.post(
        "/auth/token",
        data={"username": "AuthUser2", "password": "WrongPassword"}
    )
    
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"

def test_login_with_2fa(client):
    # Setup user
    client.post(
        "/users", 
        json={"username": "TwoFaUser", "email": "2fa@example.com", "plain_password": "password"}
    )
    
    # First login to setup 2FA
    login_resp = client.post(
        "/auth/token",
        data={"username": "TwoFaUser", "password": "password"}
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Setup 2FA
    setup_resp = client.post("/2fa/setup", headers=headers)
    secret = setup_resp.json()["secret"]
    
    # Enable 2FA
    valid_code = pyotp.TOTP(secret).now()
    client.post("/2fa/enable", json={"code": valid_code}, headers=headers)

    # Now login without 2FA should fail with 403
    resp_no_2fa = client.post(
        "/auth/token",
        data={"username": "TwoFaUser", "password": "password"}
    )
    assert resp_no_2fa.status_code == 403
    assert resp_no_2fa.json()["detail"] == "2FA required"
    
    # Login with valid 2FA should succeed
    valid_code_login = pyotp.TOTP(secret).now()
    resp_with_2fa = client.post(
        "/auth/token",
        data={"username": "TwoFaUser", "password": "password", "mfa_code": valid_code_login}
    )
    assert resp_with_2fa.status_code == 200
    assert "access_token" in resp_with_2fa.json()

def test_refresh_token(client):
    client.post(
        "/users", 
        json={"username": "RefUser", "email": "ref@example.com", "plain_password": "password"}
    )
    login_resp = client.post(
        "/auth/token",
        data={"username": "RefUser", "password": "password"}
    )
    assert login_resp.status_code == 200
    refresh_token = login_resp.json()["refresh_token"]

    # Refresh the token
    refresh_resp = client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    
    print("RESP:", refresh_resp.json())
    assert refresh_resp.status_code == 200
    data = refresh_resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    
    # Using old refresh token again should fail (since valid=False after refresh)
    refresh_fail = client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    assert refresh_fail.status_code == 401

def test_refresh_token_reuse_detection(client):
    client.post(
        "/users", 
        json={"username": "ReuseUser", "email": "reuse@example.com", "plain_password": "password"}
    )
    login_resp = client.post(
        "/auth/token",
        data={"username": "ReuseUser", "password": "password"}
    )
    old_refresh_token = login_resp.json()["refresh_token"]

    # 1. Successful refresh
    client.post(
        "/auth/refresh",
        json={"refresh_token": old_refresh_token}
    )
    
    # 2. Reusing the old refresh token -> triggers reuse detection
    reuse_resp = client.post(
        "/auth/refresh",
        json={"refresh_token": old_refresh_token}
    )
    # The application raises 401 for token reuse specifically
    assert reuse_resp.status_code == 401
    assert reuse_resp.json()["detail"] in ["Refresh token reuse detected; all sessions revoked", "Refresh revoked or expired"]

def test_logout(client):
    client.post(
        "/users", 
        json={"username": "OutUser", "email": "out@example.com", "plain_password": "password"}
    )
    login_resp = client.post(
        "/auth/token",
        data={"username": "OutUser", "password": "password"}
    )
    refresh_token = login_resp.json()["refresh_token"]

    logout_resp = client.post(
        "/auth/logout",
        json={"refresh_token": refresh_token}
    )
    assert logout_resp.status_code == 200

    # Refreshing after logout should fail
    refresh_fail = client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token}
    )
    assert refresh_fail.status_code == 401

def test_get_sessions_and_logout_specific(client):
    client.post(
        "/users", 
        json={"username": "SessionUser", "email": "sess@example.com", "plain_password": "password"}
    )
    
    # Session 1
    resp1 = client.post(
        "/auth/token",
        data={"username": "SessionUser", "password": "password"},
        headers={"user-agent": "TestDevice 1"}
    )
    token1 = resp1.json()["access_token"]
    
    # Session 2
    client.post(
        "/auth/token",
        data={"username": "SessionUser", "password": "password"},
        headers={"user-agent": "TestDevice 2"}
    )

    # Get active sessions
    sessions_resp = client.get(
        "/auth/sessions?user_id=1",
        headers={"Authorization": f"Bearer {token1}"}
    )
    print("SESS:", sessions_resp.json())
    assert sessions_resp.status_code == 200
    sessions = sessions_resp.json()
    
    # Should have 2 sessions
    assert len(sessions) >= 2
    
    # Find Device 2 sid
    sid2 = next(s["sid"] for s in sessions if s["device"] == "TestDevice 2")
    
    # Delete Device 2 session
    delete_resp = client.post(
        f"/auth/logout/{sid2}?user_id=1",
        headers={"Authorization": f"Bearer {token1}"}
    )
    assert delete_resp.status_code == 200
    
    # Verify it was deleted
    sessions_resp2 = client.get(
        "/auth/sessions?user_id=1",
        headers={"Authorization": f"Bearer {token1}"}
    )
    sessions2 = sessions_resp2.json()
    assert not any(s["device"] == "TestDevice 2" for s in sessions2)

@patch("app.services.email_service.fm.send_message")
def test_activate_account(mock_send_message, client):
    # 1. Create a User
    # W mocku blokujemy faktyczną próbę nawiązania po TCP z serwerem w testach
    resp = client.post(
        "/users",
        json={"username": "ActivationTestUser", "email": "activate@example.com", "plain_password": "password123"}
    )
    assert resp.status_code == 201
    
    user_data = resp.json()
    user_id = user_data["id"]
    assert user_data["is_activated"] is False

    # 2. Generowanie poprawnego tokenu (tak samo jak kod dziala w tle)
    activation_token = create_token(user_id, "ActivationTestUser", TokenTypes.ACTIVATE, timedelta(days=1))

    # 3. Próba aktywacji konta tokenem
    activate_resp = client.patch(f"/auth/activate/{activation_token}")
    
    assert activate_resp.status_code == 200
    assert activate_resp.json()["is_activated"] is True

@patch("app.services.email_service.fm.send_message")
def test_change_password_flow(mock_send_message, client):
    # 1. Setup User
    user_resp = client.post(
        "/users",
        json={"username": "PassUser", "email": "pass@example.com", "plain_password": "OldPassword"}
    )
    user_id = user_resp.json()["id"]

    # 2. Request Password Reset (Forgot Password)
    forgot_resp = client.post("/auth/forgot_password", json={"email": "pass@example.com"})
    assert forgot_resp.status_code == 200
    assert "Jeśli to konto instnieje" in forgot_resp.json()["message"]
    
    # 3. Zbudowanie poprawnego tokenu resetujacego
    reset_token = create_token(user_id, "PassUser", TokenTypes.CHANGE_PASSWORD, timedelta(minutes=60))

    # 4. Wykorzystanie go na endpoincie zmiany hasla
    new_password = "NewSuperPassword123"
    change_resp = client.patch(f"/auth/change_password/{reset_token}", json={"plain_password": new_password})
    
    assert change_resp.status_code == 200
    assert "Hasło zostało pomyślnie zmienione" in change_resp.json()["message"]

    # 5. Weryfikacja (Logowanie Starym haslem musi byc odrzucone)
    fail_login = client.post("/auth/token", data={"username": "PassUser", "password": "OldPassword"})
    assert fail_login.status_code == 401
    
    # 6. Weryfikacja (Logowanie Nowym haslem dziala)
    success_login = client.post("/auth/token", data={"username": "PassUser", "password": new_password})
    assert success_login.status_code == 200
    assert "access_token" in success_login.json()
