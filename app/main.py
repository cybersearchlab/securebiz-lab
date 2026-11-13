"""
app/main.py
================================================================================
SecureBiz Lab - FastAPI Application Entry Point
================================================================================

Responsibilities:
    • Bootstrap the FastAPI application.
    • Register startup lifecycle events (Vault initialization).
    • Expose base endpoints (root, health).

This file MUST NOT contain:
    • Business logic (belongs to routes or services).
    • Database queries (belongs to services).
    • Cryptographic context signing (belongs to the future security service).

================================================================================
"""

# 1. Standard library
import logging
from contextlib import asynccontextmanager

# 2. Third-party
from fastapi import FastAPI, HTTPException
from psycopg import OperationalError

# 3. Local
from app.core.database import get_database_session # <-- CHANGEMENT ICI
from app.api.routes.organizations import router as organizations_router
from app.api.routes.users import router as users_router
from app.api.routes.roles import router as roles_router
from app.api.routes.auth import router as auth_router

# Configure basic logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting SecureBiz Lab API...")
    logger.info(
        "Vault provisioning is an ADMIN operation. "
        "Run 'python scripts/init_vault.py' inside the container "
        "before using the API. If Vault was restarted in -dev mode, "
        "the Ed25519 key and JWT secret must be re-provisioned."
    )
    yield


app = FastAPI(
    title="SecureBiz Lab API",
    description="Security assessment and DevSecOps laboratory for business applications.",
    version="0.3.0",
    lifespan=lifespan,
)

# Register API routers
app.include_router(organizations_router)
app.include_router(users_router)
app.include_router(roles_router)
app.include_router(auth_router)



@app.get("/")
def root():
    """
    Root endpoint returning basic API information.
    """
    return {
        "application": "SecureBiz Lab",
        "version": "0.3.0",
        "status": "running",
    }


@app.get("/health")
def health_check():
    """
    Health check endpoint.
    Verifies that the API is running and that the database is reachable.
    """
    try:
        # <-- CHANGEMENT ICI
        with get_database_session() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1;")
                cursor.fetchone()

        return {
            "status": "healthy",
            "api": "available",
            "database": "connected",
        }

    except (OperationalError, OSError) as exc:
        logger.error(f"Health check failed: {exc}")
        raise HTTPException(
            status_code=503,
            detail={
                "status": "unhealthy",
                "database": "unavailable",
            },
        )


