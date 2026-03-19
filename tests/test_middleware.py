"""Middleware integration tests — FastAPI, Flask require_auth, assert_no_pii."""
import pytest
from coresdk.testing._mock import MockSDK, FakeSpanExporter, assert_no_pii
from coresdk._types import AuthDecision


# ---------------------------------------------------------------------------
# FastAPI middleware tests
# ---------------------------------------------------------------------------

@pytest.fixture
def fastapi_app():
    """Minimal FastAPI app with CoreSDKMiddleware using MockSDK."""
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from coresdk.middleware.fastapi import CoreSDKMiddleware

    sdk = MockSDK(default_claims={"sub": "alice", "roles": ["admin"]})
    app = FastAPI()
    app.add_middleware(CoreSDKMiddleware, sdk=sdk)

    @app.get("/hello")
    async def hello():
        return {"message": "ok"}

    return TestClient(app, raise_server_exceptions=False), sdk


def test_fastapi_middleware_passes_valid_token(fastapi_app):
    """A request with a Bearer token should reach the handler (200)."""
    client, _ = fastapi_app
    response = client.get("/hello", headers={"Authorization": "Bearer valid-token"})
    assert response.status_code == 200
    assert response.json() == {"message": "ok"}


def test_fastapi_middleware_rejects_missing_token_in_strict_mode():
    """Without a token in strict mode (not dev_mode), middleware returns 401."""
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from coresdk.middleware.fastapi import CoreSDKMiddleware
    from coresdk._config import SDKConfig
    from coresdk._client import CoreSDKClient
    import coresdk as _sdk_mod

    sdk = MockSDK()
    sdk.config = type("C", (), {"fail_mode": "closed", "dev_mode": False, "tenant_id": "t"})()

    app = FastAPI()
    app.add_middleware(CoreSDKMiddleware, sdk=sdk)

    @app.get("/secret")
    async def secret():
        return {"data": "sensitive"}

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/secret")
    assert response.status_code == 401
    body = response.json()
    assert body.get("status") == 401 or "Unauthorized" in str(body)


def test_fastapi_require_auth_dependency_allowed():
    """require_auth dependency passes through when token is valid."""
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi import FastAPI, Depends
    from fastapi.testclient import TestClient
    from coresdk.middleware.fastapi import require_auth

    sdk = MockSDK(default_claims={"sub": "bob", "roles": ["viewer"]})

    app = FastAPI()

    @app.get("/protected")
    async def protected(claims=Depends(require_auth(sdk))):
        return {"sub": claims["sub"]}

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/protected", headers={"Authorization": "Bearer good-token"})
    assert response.status_code == 200
    assert response.json()["sub"] == "bob"


def test_fastapi_require_auth_dependency_rejected():
    """require_auth dependency returns 403 when token is denied."""
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi import FastAPI, Depends
    from fastapi.testclient import TestClient
    from coresdk.middleware.fastapi import require_auth

    sdk = MockSDK()
    sdk.set_token_rejected("bad-token", reason="invalid signature")

    app = FastAPI()

    @app.get("/protected")
    async def protected(claims=Depends(require_auth(sdk))):
        return {"sub": claims["sub"]}

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/protected", headers={"Authorization": "Bearer bad-token"})
    assert response.status_code == 403


# ---------------------------------------------------------------------------
# Flask require_auth tests
# ---------------------------------------------------------------------------

def test_flask_require_auth_rejects_missing_token():
    """Flask CoreSDKFlask returns 401 RFC 9457 when Authorization is absent."""
    pytest.importorskip("flask")
    from flask import Flask
    from coresdk.middleware.flask import CoreSDKFlask

    sdk = MockSDK()
    app = Flask(__name__)
    CoreSDKFlask(sdk, app)

    @app.route("/data")
    def data():
        return {"result": "secret"}

    with app.test_client() as client:
        response = client.get("/data")
        assert response.status_code == 401
        body = response.get_json()
        assert body["status"] == 401
        assert "Unauthorized" in body["title"]


def test_flask_require_auth_passes_with_token():
    """Flask middleware allows requests with a Bearer token."""
    pytest.importorskip("flask")
    from flask import Flask
    from coresdk.middleware.flask import CoreSDKFlask

    sdk = MockSDK(default_claims={"sub": "carol"})
    app = Flask(__name__)
    CoreSDKFlask(sdk, app)

    @app.route("/data")
    def data():
        return {"result": "ok"}

    with app.test_client() as client:
        response = client.get("/data", headers={"Authorization": "Bearer any-token"})
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# assert_no_pii tests
# ---------------------------------------------------------------------------

def test_assert_no_pii_catches_email():
    """assert_no_pii raises AssertionError when a span attribute contains an email."""

    class FakeSpan:
        attributes = {"user_info": "contact us at alice@example.com for support"}

    with pytest.raises(AssertionError, match="PII detected"):
        assert_no_pii([FakeSpan()])


def test_assert_no_pii_catches_ssn():
    """assert_no_pii raises AssertionError when a span attribute contains a SSN."""

    class FakeSpan:
        attributes = {"note": "ssn is 123-45-6789"}

    with pytest.raises(AssertionError, match="PII detected"):
        assert_no_pii([FakeSpan()])


def test_assert_no_pii_passes_clean_span():
    """assert_no_pii does not raise for clean span attributes."""

    class FakeSpan:
        attributes = {"route": "/api/users", "method": "GET", "status": "200"}

    assert_no_pii([FakeSpan()])  # must not raise
