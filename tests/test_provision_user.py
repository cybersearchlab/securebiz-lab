"""
SecureBiz Lab - Unit tests for scripts/provision_user.py
===============================================================================

SCOPE:
    Test the provisioning CLI without real Vault or PostgreSQL access.

SECURITY:
    - Vault HTTP requests are mocked.
    - PostgreSQL connections are mocked.
    - No real credentials are created.
    - No real database transaction is executed.
    - Argon2id hashing remains REAL.

LIMITATION:
    These tests validate Python logic and simulated SQL interactions.
    They do not validate PostgreSQL constraints, roles or Vault policies.
"""

import importlib.util
import os
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import psycopg


# ---------------------------------------------------------------------------
# Import the CLI safely.
# VAULT_TOKEN is checked at module import time.
# ---------------------------------------------------------------------------

SCRIPT_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "provision_user.py"
)

_IMPORT_ENV = {
    "VAULT_TOKEN": "unit-test-vault-token-never-used",
    "VAULT_ADDR": "http://vault.invalid:8200",
    "DB_HOST": "unit-test-db",
    "DB_PORT": "5433",
    "DB_NAME": "securebiz_test",
}

_previous_env = {key: os.environ.get(key) for key in _IMPORT_ENV}

try:
    os.environ.update(_IMPORT_ENV)

    spec = importlib.util.spec_from_file_location(
        "_securebiz_provision_user_test",
        SCRIPT_PATH,
    )

    assert spec is not None
    assert spec.loader is not None

    provision_user = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(provision_user)

finally:
    for key, value in _previous_env.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


# ---------------------------------------------------------------------------
# Shared test data
# ---------------------------------------------------------------------------

USER_ID = str(uuid.uuid4())
TEST_PASSWORD = "Unit-Test-Password!2026"
GENERATED_PASSWORD = "Generated-Test-Password!2026"

VAULT_DATA = {"db_password": "fake-provisioner-db-password"}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def cli(monkeypatch):
    """Prepare a valid CLI invocation and isolate external dependencies."""
    monkeypatch.setattr(
        sys, "argv",
        ["provision_user.py", "--user-id", USER_ID],
    )

    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"data": {"data": dict(VAULT_DATA)}}

    vault_request = MagicMock(return_value=response)
    monkeypatch.setattr(provision_user.requests, "get", vault_request)
    return vault_request


@pytest.fixture
def database(monkeypatch):
    """Create a fully simulated PostgreSQL connection and cursor."""
    connection = MagicMock()
    cursor = MagicMock()

    connection.__enter__.return_value = connection
    connection.__exit__.return_value = False
    connection.closed = False

    connection.cursor.return_value = cursor
    cursor.__enter__.return_value = cursor
    cursor.__exit__.return_value = False

    connect_mock = MagicMock(return_value=connection)
    monkeypatch.setattr(provision_user.psycopg, "connect", connect_mock)

    return {"connect": connect_mock, "connection": connection, "cursor": cursor}


def configure_password(monkeypatch, password=TEST_PASSWORD):
    """Provide two matching password entries."""
    password_mock = MagicMock(side_effect=[password, password])
    monkeypatch.setattr(provision_user.getpass, "getpass", password_mock)
    return password_mock


# ---------------------------------------------------------------------------
# 1. Invalid UUID
# ---------------------------------------------------------------------------

def test_invalid_uuid_rejected(cli, monkeypatch):
    monkeypatch.setattr(
        sys, "argv",
        ["provision_user.py", "--user-id", "invalid-uuid"],
    )

    with pytest.raises(SystemExit) as exc:
        provision_user.main()

    assert exc.value.code == 2
    cli.assert_not_called()


# ---------------------------------------------------------------------------
# 2. Vault unavailable
# ---------------------------------------------------------------------------

def test_vault_unavailable(cli, monkeypatch):
    cli.side_effect = RuntimeError("simulated Vault failure")
    configure_password(monkeypatch)

    with pytest.raises(SystemExit) as exc:
        provision_user.main()

    assert str(exc.value.code).startswith("FATAL: cannot read Vault secret:")
    provision_user.requests.get.assert_called_once()


# ---------------------------------------------------------------------------
# 3. Missing Vault password key
# ---------------------------------------------------------------------------

def test_vault_missing_password_key(cli, monkeypatch):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"data": {"data": {"unexpected_key": "x"}}}
    cli.return_value = response

    configure_password(monkeypatch)

    with pytest.raises(SystemExit) as exc:
        provision_user.main()

    assert exc.value.code == "FATAL: Vault secret missing key 'db_password'"


# ---------------------------------------------------------------------------
# 4. Empty password
# ---------------------------------------------------------------------------

def test_empty_password_rejected(cli, monkeypatch):
    password_mock = MagicMock(return_value="")
    monkeypatch.setattr(provision_user.getpass, "getpass", password_mock)

    with pytest.raises(SystemExit) as exc:
        provision_user.main()

    assert exc.value.code == "FATAL: empty password"
    password_mock.assert_called_once()


# ---------------------------------------------------------------------------
# 5. Password confirmation mismatch
# ---------------------------------------------------------------------------

def test_password_confirmation_mismatch(cli, monkeypatch):
    password_mock = MagicMock(side_effect=["First!2026", "Second!2026"])
    monkeypatch.setattr(provision_user.getpass, "getpass", password_mock)

    with pytest.raises(SystemExit) as exc:
        provision_user.main()

    assert exc.value.code == "FATAL: passwords do not match"
    assert password_mock.call_count == 2


# ---------------------------------------------------------------------------
# 6. Automatic password generation
# ---------------------------------------------------------------------------

def test_generate_password_without_getpass(cli, database, monkeypatch, capsys):
    monkeypatch.setattr(
        sys, "argv",
        ["provision_user.py", "--user-id", USER_ID, "--generate"],
    )

    generated_mock = MagicMock(return_value=GENERATED_PASSWORD)
    monkeypatch.setattr(provision_user.secrets, "token_urlsafe", generated_mock)

    password_mock = MagicMock()
    monkeypatch.setattr(provision_user.getpass, "getpass", password_mock)

    provision_user.main()

    generated_mock.assert_called_once_with(32)
    password_mock.assert_not_called()

    output = capsys.readouterr().out
    assert "GENERATED_PASSWORD:" in output
    assert "WARNING:" in output

    database["cursor"].execute.assert_called_once()
    hashed = database["cursor"].execute.call_args.args[1][1]

    assert hashed.startswith("$argon2id$")
    assert provision_user._HASHER.verify(hashed, GENERATED_PASSWORD)
    database["connection"].commit.assert_called_once()


# ---------------------------------------------------------------------------
# 7. Successful provisioning
# ---------------------------------------------------------------------------

def test_provisioning_success(cli, database, monkeypatch):
    configure_password(monkeypatch)
    provision_user.main()

    database["connect"].assert_called_once_with(
        host=provision_user.DB_HOST,
        port=provision_user.DB_PORT,
        dbname=provision_user.DB_NAME,
        user=provision_user.DB_USER,
        password=VAULT_DATA["db_password"],
        connect_timeout=5,
    )

    cursor = database["cursor"]
    cursor.execute.assert_called_once()

    query, params = cursor.execute.call_args.args
    assert "INSERT INTO auth_private.credentials" in query.as_string(None)
    assert params[0] == USER_ID

    password_hash = params[1]
    assert password_hash.startswith("$argon2id$")
    assert provision_user._HASHER.verify(password_hash, TEST_PASSWORD)
    assert TEST_PASSWORD not in params

    database["connection"].commit.assert_called_once()

    # Verify that both Psycopg context managers were exited.
    # psycopg3's `with psycopg.connect(...) as conn:` closes the connection
    # on context exit (it does not call conn.close() explicitly from Python).
    database["cursor"].__exit__.assert_called_once()
    database["connection"].__exit__.assert_called_once()


# ---------------------------------------------------------------------------
# 8. Duplicate credential
# ---------------------------------------------------------------------------

def test_duplicate_credential(cli, database, monkeypatch):
    configure_password(monkeypatch)
    database["cursor"].execute.side_effect = psycopg.errors.UniqueViolation("dup")

    with pytest.raises(SystemExit) as exc:
        provision_user.main()

    assert exc.value.code == "FAILED: a credential already exists for this user_id."
    database["connection"].commit.assert_not_called()


# ---------------------------------------------------------------------------
# 9. User does not exist
# ---------------------------------------------------------------------------

def test_user_not_found(cli, database, monkeypatch):
    configure_password(monkeypatch)
    database["cursor"].execute.side_effect = psycopg.errors.ForeignKeyViolation("missing")

    with pytest.raises(SystemExit) as exc:
        provision_user.main()

    assert exc.value.code == "FAILED: user_id does not exist in public.users."
    database["connection"].commit.assert_not_called()


# ---------------------------------------------------------------------------
# 10. Insufficient PostgreSQL privileges
# ---------------------------------------------------------------------------

def test_insufficient_privilege(cli, database, monkeypatch):
    configure_password(monkeypatch)
    database["cursor"].execute.side_effect = psycopg.errors.InsufficientPrivilege("denied")

    with pytest.raises(SystemExit) as exc:
        provision_user.main()

    assert exc.value.code == (
        "FAILED: securebiz_provisioner lacks INSERT "
        "on auth_private.credentials."
    )
    database["connection"].commit.assert_not_called()


# ---------------------------------------------------------------------------
# 11. Generic PostgreSQL error
# ---------------------------------------------------------------------------

def test_generic_database_error(cli, database, monkeypatch):
    configure_password(monkeypatch)
    database["cursor"].execute.side_effect = psycopg.Error("simulated failure")

    with pytest.raises(SystemExit) as exc:
        provision_user.main()

    assert exc.value.code == "FAILED: database error: Error"
    database["connection"].commit.assert_not_called()