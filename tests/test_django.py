"""Tests for Django CoreSDKMiddleware — auth enforcement, claims, exclude paths, concurrency."""

from __future__ import annotations

import concurrent.futures
from unittest.mock import MagicMock

import pytest

# Configure Django settings before any Django import
try:
    from django.conf import settings as _dj_settings

    if not _dj_settings.configured:
        _dj_settings.configure(
            DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
            DATABASES={},
            INSTALLED_APPS=[],
            DEFAULT_CHARSET="utf-8",
        )
except ImportError:
    pass

from coresdk._types import AuthDecision
from coresdk.testing._mock import MockSDK


# ---------------------------------------------------------------------------
# Helpers — build a minimal Django request/response stack without runserver
# ---------------------------------------------------------------------------


def _make_django_request(path: str = "/api/data", auth_header: str | None = None):
    """Create a minimal Django HttpRequest-like object."""
    pytest.importorskip("django")
    from django.http import HttpRequest

    req = HttpRequest()
    req.method = "GET"
    req.path = path
    req.META["SERVER_NAME"] = "testserver"
    req.META["SERVER_PORT"] = "80"
    if auth_header is not None:
        req.META["HTTP_AUTHORIZATION"] = auth_header
    return req


def _get_response_ok(request):
    """Minimal get_response that always returns 200."""
    pytest.importorskip("django")
    from django.http import HttpResponse

    return HttpResponse("OK", status=200)


# ---------------------------------------------------------------------------
# 401 when no Authorization header
# ---------------------------------------------------------------------------


def test_django_middleware_no_auth_header_returns_401():
    pytest.importorskip("django")
    from coresdk.middleware.django import CoreSDKMiddleware

    sdk = MockSDK()
    middleware = CoreSDKMiddleware(get_response=_get_response_ok, sdk=sdk)

    request = _make_django_request(auth_header=None)
    response = middleware(request)

    assert response.status_code == 401
    import json

    body = json.loads(response.content)
    assert body["status"] == 401
    assert "Unauthorized" in body["title"]


def test_django_middleware_empty_bearer_returns_401():
    pytest.importorskip("django")
    from coresdk.middleware.django import CoreSDKMiddleware

    sdk = MockSDK()
    middleware = CoreSDKMiddleware(get_response=_get_response_ok, sdk=sdk)

    request = _make_django_request(auth_header="Bearer ")
    response = middleware(request)

    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Claims stored in request.coresdk_claims
# ---------------------------------------------------------------------------


def test_django_middleware_stores_claims_on_request():
    pytest.importorskip("django")
    from coresdk.middleware.django import CoreSDKMiddleware

    claims = {"sub": "alice", "roles": ["admin"], "tenant_id": "acme"}
    sdk = MockSDK(default_claims=claims)
    captured = {}

    def get_response(request):
        from django.http import HttpResponse

        captured["claims"] = getattr(request, "coresdk_claims", "NOT_SET")
        return HttpResponse("OK", status=200)

    middleware = CoreSDKMiddleware(get_response=get_response, sdk=sdk)
    request = _make_django_request(auth_header="Bearer valid-token")
    middleware(request)

    assert captured["claims"] is not None
    assert captured["claims"]["sub"] == "alice"
    assert captured["claims"]["roles"] == ["admin"]


# ---------------------------------------------------------------------------
# Exclude paths bypass auth
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/healthz", "/readyz"])
def test_django_middleware_exempt_paths_bypass_auth(path):
    pytest.importorskip("django")
    from coresdk.middleware.django import CoreSDKMiddleware

    sdk = MockSDK()
    middleware = CoreSDKMiddleware(get_response=_get_response_ok, sdk=sdk)

    # No Authorization header — should still pass through
    request = _make_django_request(path=path, auth_header=None)
    response = middleware(request)

    assert response.status_code == 200


def test_django_middleware_admin_path_bypasses_auth():
    pytest.importorskip("django")
    from coresdk.middleware.django import CoreSDKMiddleware

    sdk = MockSDK()
    middleware = CoreSDKMiddleware(get_response=_get_response_ok, sdk=sdk)

    request = _make_django_request(path="/admin/login/", auth_header=None)
    response = middleware(request)

    assert response.status_code == 200


# ---------------------------------------------------------------------------
# Async view works via ASGI (if Django 4.1+)
# ---------------------------------------------------------------------------


def test_django_middleware_sync_view_passes_with_token():
    """Synchronous view returns 200 when valid Bearer token provided."""
    pytest.importorskip("django")
    from coresdk.middleware.django import CoreSDKMiddleware

    sdk = MockSDK(default_claims={"sub": "bob", "roles": ["viewer"]})
    middleware = CoreSDKMiddleware(get_response=_get_response_ok, sdk=sdk)

    request = _make_django_request(auth_header="Bearer some-valid-token")
    response = middleware(request)

    assert response.status_code == 200


# ---------------------------------------------------------------------------
# Thread safety — 10 concurrent requests get independent claims
# ---------------------------------------------------------------------------


def test_django_middleware_thread_safety():
    """10 concurrent requests each see their own sub in claims."""
    pytest.importorskip("django")
    from django.http import HttpResponse

    from coresdk._types import AuthDecision
    from coresdk.middleware.django import CoreSDKMiddleware

    results: list[str] = []

    def get_response_capture(request):
        claims = getattr(request, "coresdk_claims", None)
        sub = claims["sub"] if claims else "none"
        results.append(sub)
        return HttpResponse("OK", status=200)

    # Build an SDK mock that returns a different sub per token
    class PerTokenSDK:
        config = MockSDK._MockConfig()

        def authorize_sync(self, token: str, **kwargs) -> AuthDecision:
            return AuthDecision(
                allowed=True,
                claims={"sub": token, "tenant_id": "t", "roles": []},
                reason="",
            )

    sdk = PerTokenSDK()
    middleware = CoreSDKMiddleware(get_response=get_response_capture, sdk=sdk)

    def make_request(i: int):
        req = _make_django_request(auth_header=f"Bearer user-{i}")
        middleware(req)
        return i

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(make_request, i) for i in range(10)]
        concurrent.futures.wait(futures)

    assert len(results) == 10
    # Each sub should correspond to one of the user-* tokens
    for sub in results:
        assert sub.startswith("user-")

    # All subs are distinct (no cross-contamination)
    assert len(set(results)) == 10
