import base64
import json
import time
import uuid

import jwt
import pytest

from app.core import jwt as jwt_module
from app.core.jwt import (
    TokenValidationError,
    create_access_token,
    verify_access_token,
)


SECRET = "unit-test-secret-that-is-never-used-outside-tests"
PREVIOUS_SECRET = "previous-unit-test-secret"
KID = "test-key-v1"
PREVIOUS_KID = "test-key-v0"

VALID_USER_ID = str(uuid.uuid4())
REQUIRED_CLAIMS = (
    "sub",
    "iss",
    "aud",
    "iat",
    "exp",
    "jti",
    "token_type",
)


@pytest.fixture(autouse=True)
def mock_jwt_secret_provider(monkeypatch):
    """Prevent every test from accessing the real Vault provider."""
    monkeypatch.setattr(
        jwt_module,
        "get_jwt_secret",
        lambda: (SECRET, KID, None, None),
    )


def make_payload(**overrides):
    """Build a valid JWT payload, with optional claim overrides."""
    now = int(time.time())

    payload = {
        "sub": VALID_USER_ID,
        "iss": jwt_module.settings.JWT_ISSUER,
        "aud": jwt_module.settings.JWT_AUDIENCE,
        "iat": now,
        "exp": now + 900,
        "jti": str(uuid.uuid4()),
        "token_type": "access",
    }
    payload.update(overrides)
    return payload


def make_token(payload=None, secret=SECRET, kid=KID, headers=None):
    """Sign a token with the test key and selected key identifier."""
    token_headers = {"kid": kid}
    if headers:
        token_headers.update(headers)

    return jwt.encode(
        payload if payload is not None else make_payload(),
        secret,
        algorithm="HS256",
        headers=token_headers,
    )


def replace_header(token, header):
    """Replace a JWT header without changing its payload or signature."""
    encoded_header = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    ).rstrip(b"=").decode("ascii")

    parts = token.split(".")
    return ".".join([encoded_header, parts[1], parts[2]])


def remove_claim(payload, claim):
    result = dict(payload)
    result.pop(claim, None)
    return result


def test_create_access_token_returns_signed_jwt():
    token = create_access_token(VALID_USER_ID)

    assert isinstance(token, str)
    assert len(token.split(".")) == 3

    header = jwt.get_unverified_header(token)
    assert header["alg"] == "HS256"
    assert header["kid"] == KID

    claims = jwt.decode(
        token,
        SECRET,
        algorithms=["HS256"],
        options={
            "verify_signature": True,
            "verify_exp": True,
            "verify_aud": False,
            "verify_iss": False,
        },
    )
    assert claims["sub"] == VALID_USER_ID
    assert claims["token_type"] == "access"


def test_create_access_token_rejects_non_canonical_uuid():
    with pytest.raises(ValueError):
        create_access_token("NOT-A-UUID")


def test_verify_access_token_accepts_valid_token():
    token = make_token()

    claims = verify_access_token(token)

    assert claims["sub"] == VALID_USER_ID
    assert claims["token_type"] == "access"
    assert claims["iss"] == jwt_module.settings.JWT_ISSUER
    assert claims["aud"] == jwt_module.settings.JWT_AUDIENCE


def test_verify_access_token_accepts_previous_rotation_key(monkeypatch):
    token = make_token(secret=PREVIOUS_SECRET, kid=PREVIOUS_KID)

    monkeypatch.setattr(
        jwt_module,
        "get_jwt_secret",
        lambda: (SECRET, KID, PREVIOUS_SECRET, PREVIOUS_KID),
    )

    claims = verify_access_token(token)

    assert claims["sub"] == VALID_USER_ID


@pytest.mark.parametrize(
    "claim",
    REQUIRED_CLAIMS,
)
def test_verify_access_token_rejects_each_missing_required_claim(claim):
    payload = remove_claim(make_payload(), claim)
    token = make_token(payload)

    with pytest.raises(TokenValidationError):
        verify_access_token(token)


def test_verify_access_token_rejects_empty_token():
    with pytest.raises(TokenValidationError):
        verify_access_token("")


@pytest.mark.parametrize("value", [None, 123, b"not-a-token"])
def test_verify_access_token_rejects_non_string_token(value):
    with pytest.raises(TokenValidationError):
        verify_access_token(value)


def test_verify_access_token_rejects_malformed_token():
    with pytest.raises(TokenValidationError):
        verify_access_token("not.a.valid.jwt.token")


def test_verify_access_token_rejects_none_algorithm():
    token = make_token()
    header = {
        "alg": "none",
        "typ": "JWT",
        "kid": KID,
    }

    with pytest.raises(TokenValidationError):
        verify_access_token(replace_header(token, header))


def test_verify_access_token_rejects_unexpected_algorithm():
    token = make_token()
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": KID,
    }

    with pytest.raises(TokenValidationError):
        verify_access_token(replace_header(token, header))


def test_verify_access_token_rejects_missing_kid():
    token = make_token()
    header = {
        "alg": "HS256",
        "typ": "JWT",
    }

    with pytest.raises(TokenValidationError):
        verify_access_token(replace_header(token, header))


@pytest.mark.parametrize("kid", ["unknown-key", 123, ["invalid"]])
def test_verify_access_token_rejects_invalid_kid(kid):
    token = make_token()
    header = {
        "alg": "HS256",
        "typ": "JWT",
        "kid": kid,
    }

    with pytest.raises(TokenValidationError):
        verify_access_token(replace_header(token, header))


def test_verify_access_token_rejects_wrong_issuer():
    token = make_token(make_payload(iss="wrong-issuer"))

    with pytest.raises(TokenValidationError):
        verify_access_token(token)


def test_verify_access_token_rejects_wrong_audience():
    token = make_token(make_payload(aud="wrong-audience"))

    with pytest.raises(TokenValidationError):
        verify_access_token(token)


def test_verify_access_token_rejects_expired_token():
    now = int(time.time())
    token = make_token(
        make_payload(
            iat=now - 120,
            exp=now - 60,
        )
    )

    with pytest.raises(TokenValidationError):
        verify_access_token(token)


def test_verify_access_token_rejects_wrong_token_type():
    token = make_token(make_payload(token_type="refresh"))

    with pytest.raises(TokenValidationError):
        verify_access_token(token)


@pytest.mark.parametrize(
    "claim,value",
    [
        ("sub", "not-a-uuid"),
        ("sub", str(uuid.uuid4()).upper()),
        ("jti", "not-a-uuid"),
        ("jti", str(uuid.uuid4()).upper()),
    ],
)
def test_verify_access_token_rejects_non_canonical_uuid_claims(claim, value):
    token = make_token(make_payload(**{claim: value}))

    with pytest.raises(TokenValidationError):
        verify_access_token(token)


def test_verify_access_token_rejects_future_iat():
    now = int(time.time())
    token = make_token(make_payload(iat=now + 120, exp=now + 900))

    with pytest.raises(TokenValidationError):
        verify_access_token(token)


@pytest.mark.parametrize(
    "claim,value",
    [
        ("iat", "not-an-integer"),
        ("exp", "not-an-integer"),
        ("iat", 1.5),
        ("exp", 1.5),
    ],
)
def test_verify_access_token_rejects_invalid_timestamp_types(claim, value):
    token = make_token(make_payload(**{claim: value}))

    with pytest.raises(TokenValidationError):
        verify_access_token(token)


def test_verify_access_token_rejects_exp_not_after_iat():
    now = int(time.time())
    token = make_token(
        make_payload(
            iat=now - 120,
            exp=now - 180,
        )
    )

    with pytest.raises(TokenValidationError):
        verify_access_token(token)


def test_verify_access_token_rejects_tampered_signature():
    token = make_token()
    parts = token.split(".")

    first_character = parts[2][0]
    replacement = "A" if first_character != "A" else "B"
    parts[2] = replacement + parts[2][1:]
    tampered_token = ".".join(parts)

    with pytest.raises(TokenValidationError):
        verify_access_token(tampered_token)


def test_verify_access_token_rejects_inconsistent_rotation_state(monkeypatch):
    token = make_token()

    monkeypatch.setattr(
        jwt_module,
        "get_jwt_secret",
        lambda: (SECRET, KID, PREVIOUS_SECRET, None),
    )

    with pytest.raises(RuntimeError):
        verify_access_token(token)