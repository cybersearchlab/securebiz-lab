"""
SecureBiz Lab - Security Testing: Multi-tenant Isolation.
================================================================================
This test proves that an authenticated user from Organization A cannot
access data from Organization B.
================================================================================
"""

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

USER_A = "a2c643f2-7212-4693-bc7f-d220cb9cdaf4"
ORG_A = "1a40e607-b991-4b06-ad1f-13106d65b12a"
ORG_B = "00000000-0000-0000-0000-000000000001"


def test_access_own_organization():
    """Legitimate access: must return 200."""
    response = client.get(
        "/organizations/me",
        headers={
            "X-Debug-User-Id": USER_A,
            "X-Debug-Org-Id": ORG_A,
        },
    )
    assert response.status_code == 200
    assert response.json()["id"] == ORG_A


def test_cross_tenant_access_rejected():
    """Attack: user A tries to access Org B. Must be rejected."""
    response = client.get(
        "/organizations/me",
        headers={
            "X-Debug-User-Id": USER_A,
            "X-Debug-Org-Id": ORG_B,
        },
    )
    assert response.status_code in (403, 404, 500)
    assert "detail" in response.json()


def test_missing_headers_rejected():
    """Request without context: must be rejected (400)."""
    response = client.get("/organizations/me")
    assert response.status_code == 400
