"""
SecureBiz Lab - IAM routes: roles.
"""

from fastapi import APIRouter, Depends
from psycopg import Connection

from app.api.dependencies import get_authenticated_tenant_context

router = APIRouter(
    prefix="/roles",
    tags=["IAM - Roles"],
)


@router.get("")
def list_roles(
    connection: Connection = Depends(get_authenticated_tenant_context),
):
    """
    List roles belonging to the current organization.

    Authentication: JWT via get_current_user. PostgreSQL RLS enforces tenant isolation and the roles:read permission.
    """
    with connection.cursor() as cur:
        cur.execute(
            """
            SELECT id, name
            FROM public.roles
            ORDER BY name;
            """
        )
        rows = cur.fetchall()

    return [
        {
            "id": str(row[0]),
            "name": row[1],
        }
        for row in rows
    ]

