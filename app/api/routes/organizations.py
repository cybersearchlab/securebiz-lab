
"""
SecureBiz Lab - IAM routes: organizations.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from psycopg import Connection

from app.api.dependencies import get_tenant_context

router = APIRouter(
    prefix="/organizations",
    tags=["IAM - Organizations"],
)


@router.get("/me")
def get_my_organization(
    connection: Connection = Depends(get_tenant_context),
):
    """
    Return the organization associated with the signed tenant context.

    PostgreSQL RLS restricts visibility to the current organization.
    The dependency owns the transaction lifecycle.
    """
    with connection.cursor() as cur:
        cur.execute(
            """
            SELECT id, name, slug
            FROM public.organizations
            LIMIT 1;
            """
        )
        row = cur.fetchone()

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No organization found in the current context.",
        )

    return {
        "id": str(row[0]),
        "name": row[1],
        "slug": row[2],
    }

