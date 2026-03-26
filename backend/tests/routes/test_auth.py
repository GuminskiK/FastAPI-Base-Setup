import pytest
import time
import pyotp

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
    
    print("RESP:", refresh_resp.json()); assert refresh_resp.status_code == 200
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
        "/auth/sessions",
        headers={"Authorization": f"Bearer {token1}"}
    )
    print("SESS:", sessions_resp.json()); assert sessions_resp.status_code == 200
    sessions = sessions_resp.json()
    
    # Should have 2 sessions
    assert len(sessions) >= 2
    
    # Find Device 2 sid
    sid2 = next(s["sid"] for s in sessions if s["device"] == "TestDevice 2")
    
    # Delete Device 2 session
    delete_resp = client.post(
        f"/auth/logout/{sid2}",
        headers={"Authorization": f"Bearer {token1}"}
    )
    assert delete_resp.status_code == 200
    
    # Verify it was deleted
    sessions_resp2 = client.get(
        "/auth/sessions",
        headers={"Authorization": f"Bearer {token1}"}
    )
    sessions2 = sessions_resp2.json()
    assert not any(s["device"] == "TestDevice 2" for s in sessions2)
