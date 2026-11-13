"""
SecureBiz Lab - Security Testing: /roles Isolation.
================================================================================
This test verifies that the authenticated /roles route is protected by:
    - JWT authentication (get_current_user)
    - organization context (X-Organization-Id)
    - tenant isolation (RLS on public.roles)

Cases covered:
    1. Authenticated user of ORG_A: 200 OK (list is empty in the current
       test data because the test user has no role granting 'roles:read').
       The call succeeds.
    2. Authenticated user of ORG_A with X-Organization-Id = ORG_B: 403
       (context signing refused, no membership in ORG_B).
    3. No JWT: 401.
    4. Valid JWT without X-Organization-Id: 400.

NOTE: httpx.ASGITransport does not trigger FastAPI's lifespan, so
init_vault_key() is not called. This is intentional: the Ed25519 key and
the JWT KV secret are already provisioned in Vault by the container
startup. No auto-resync of the public key happens during the tests.

Runs inside the API container (vault:8200 and db:5432 are Docker-internal
DNS names).
================================================================================
"""

import asyncio

import httpx
from app.main import app


ORG_A = "1a40e607-b991-4b06-ad1f-13106d65b12a"
ORG_B = "00000000-0000-0000-0000-000000000001"

TEST_EMAIL = "test-user@test.com"
TEST_PASSWORD = "TestPassword!2026"


async def _login(client):
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
    assert access_token, "Login response does not contain an access token."
    assert raw_refresh, "Login response does not contain a refresh token."
    return access_token, raw_refresh


async def _logout(client, raw_refresh):
    response = await client.post(
        "/auth/logout",
        headers={"Cookie": f"refresh_token={raw_refresh}"},
    )
    assert response.status_code == 200, (
        f"Test logout failed: status={response.status_code}"
    )
    assert response.json().get("status") == "logged out", (
        "logout cleanup returned an unexpected response"
    )


async def _authenticated_get(organization_id=None):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="https://testserver"
    ) as client:
        access_token, raw_refresh = await _login(client)
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            if organization_id is not None:
                headers["X-Organization-Id"] = organization_id
            return await client.get("/roles", headers=headers)
        finally:
            await _logout(client, raw_refresh)


async def _unauthenticated_get():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="https://testserver"
    ) as client:
        return await client.get(
            "/roles",
            headers={"X-Organization-Id": ORG_A},
        )


def test_list_roles_for_org_a_returns_successful_response():
    """
    Vérifie qu'un utilisateur authentifié disposant d'un contexte valide
    pour ORG_A peut interroger /roles.

    Le résultat attendu est une liste vide dans l'état actuel des données
    de test (le compte test-user@test.com n'a aucun rôle dans ORG_A).
    Ce test ne démontre pas à lui seul l'application de roles:read par RLS.
    """
    response = asyncio.run(_authenticated_get(ORG_A))
    assert response.status_code == 200, (
        f"Expected 200, got {response.status_code}: {response.text[:200]}"
    )
    assert response.json() == []


def test_roles_cross_tenant_access_rejected():
    response = asyncio.run(_authenticated_get(ORG_B))
    assert response.status_code == 403, (
        f"Expected 403, got {response.status_code}: {response.text[:200]}"
    )
    assert "detail" in response.json()


def test_roles_no_jwt_rejected():
    response = asyncio.run(_unauthenticated_get())
    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required."


def test_roles_no_organization_header_rejected():
    response = asyncio.run(_authenticated_get())
    assert response.status_code == 400
    assert response.json()["detail"] == "Header X-Organization-Id is required."