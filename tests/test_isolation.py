"""
SecureBiz Lab - Security Testing: Multi-tenant Isolation.
================================================================================
This test verifies that authenticated users can access only their authorized
organization, and that missing authentication or missing organization context
is rejected. Uses httpx.AsyncClient + ASGITransport.
================================================================================
"""

import asyncio

import httpx
from app.main import app


USER_A = "a2c643f2-7212-4693-bc7f-d220cb9cdaf4"
ORG_A = "1a40e607-b991-4b06-ad1f-13106d65b12a"
ORG_B = "00000000-0000-0000-0000-000000000001"

TEST_EMAIL = "test-user@test.com"
TEST_PASSWORD = "TestPassword!2026"


async def _login(client):
    """Authenticate and return (access_token, raw_refresh_token)."""
    response = await client.post(
        "/auth/login",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
    )
    assert response.status_code == 200, (
        f"Test login failed: status={response.status_code}"
    )
    payload = response.json()
    access_token = payload.get("access_token")
    raw_refresh = response.cookies.get("refresh_token")
    assert access_token, "Login response did not contain an access token."
    assert raw_refresh, "Login response did not contain a refresh token cookie."
    return access_token, raw_refresh


async def _logout(client, raw_refresh):
    """Revoke the refresh-token family and verify successful cleanup."""
    response = await client.post(
        "/auth/logout",
        headers={"Cookie": f"refresh_token={raw_refresh}"},
    )
    assert response.status_code == 200, (
        f"logout cleanup failed: status={response.status_code}"
    )
    assert response.json().get("status") == "logged out", (
        "logout cleanup returned an unexpected response"
    )


async def _authenticated_get(extra_headers):
    """Authenticated GET /organizations/me; revoke its family in finally."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="https://testserver"
    ) as client:
        access_token, raw_refresh = await _login(client)
        try:
            headers = {
                "Authorization": f"Bearer {access_token}",
                **extra_headers,
            }
            return await client.get("/organizations/me", headers=headers)
        finally:
            await _logout(client, raw_refresh)


async def _unauthenticated_get(headers):
    """GET /organizations/me without creating an authentication session."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="https://testserver"
    ) as client:
        return await client.get("/organizations/me", headers=headers)


def test_access_own_organization():
    """Legitimate access: authenticated user must receive Organization A."""
    response = asyncio.run(_authenticated_get({"X-Organization-Id": ORG_A}))
    assert response.status_code == 200
    assert response.json()["id"] == ORG_A


def test_cross_tenant_access_rejected():
    """Organization B access must be rejected for a user of Organization A."""
    response = asyncio.run(_authenticated_get({"X-Organization-Id": ORG_B}))
    assert response.status_code == 403
    assert "detail" in response.json()


def test_no_jwt_rejected():
    """Organization context without a JWT must return 401."""
    response = asyncio.run(_unauthenticated_get({"X-Organization-Id": ORG_A}))
    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required."


def test_no_organization_header_rejected():
    """A valid JWT without organization context must return 400."""
    response = asyncio.run(_authenticated_get({}))
    assert response.status_code == 400
    assert response.json()["detail"] == "Header X-Organization-Id is required."
