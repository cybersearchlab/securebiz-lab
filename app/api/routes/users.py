"""
SecureBiz Lab - IAM routes: users.
"""

from fastapi import APIRouter, Depends
from psycopg import Connection

from app.api.dependencies import get_tenant_context

router = APIRouter(
    prefix="/users",
    tags=["IAM - Users"],
)


@router.get("")
def list_users(
    connection: Connection = Depends(get_tenant_context),
):
    """
    List users belonging to the current organization.

    PostgreSQL RLS enforces tenant isolation and the users:read permission.
    """
    with connection.cursor() as cur:
        cur.execute(
            """
            SELECT id, email, status
            FROM public.users
            ORDER BY email;
            """
        )
        rows = cur.fetchall()

    return [
        {
            "id": str(row[0]),
            "email": row[1],
            "status": row[2],
        }
        for row in rows
    ]

