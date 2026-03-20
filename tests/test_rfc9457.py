"""Expanded RFC 9457 ProblemDetailError tests."""

from __future__ import annotations

import json

import pytest

from coresdk.errors._rfc9457 import ProblemDetailError

# ---------------------------------------------------------------------------
# Factory methods
# ---------------------------------------------------------------------------


def test_factory_unauthorized_status():
    err = ProblemDetailError.unauthorized("Bad token")
    assert err.status == 401


def test_factory_unauthorized_title():
    err = ProblemDetailError.unauthorized("token expired")
    assert err.title == "Unauthorized"


def test_factory_unauthorized_detail():
    err = ProblemDetailError.unauthorized("token expired")
    assert err.detail == "token expired"


def test_factory_unauthorized_type_uri():
    err = ProblemDetailError.unauthorized("x")
    assert err.type_uri is not None
    assert "unauthorized" in err.type_uri.lower()


def test_factory_forbidden_status():
    err = ProblemDetailError.forbidden("Access denied")
    assert err.status == 403


def test_factory_forbidden_title():
    err = ProblemDetailError.forbidden("no permission")
    assert err.title == "Forbidden"


def test_factory_forbidden_detail():
    err = ProblemDetailError.forbidden("missing role admin")
    assert err.detail == "missing role admin"


def test_factory_forbidden_type_uri():
    err = ProblemDetailError.forbidden("x")
    assert err.type_uri is not None
    assert "forbidden" in err.type_uri.lower()


# ---------------------------------------------------------------------------
# Custom status codes
# ---------------------------------------------------------------------------


def test_custom_status_429():
    err = ProblemDetailError("Too Many Requests", 429, detail="rate limit exceeded")
    assert err.status == 429
    assert err.title == "Too Many Requests"


def test_custom_status_503():
    err = ProblemDetailError("Service Unavailable", 503)
    assert err.status == 503


def test_custom_status_in_to_dict():
    err = ProblemDetailError("Conflict", 409, detail="duplicate key")
    d = err.to_dict()
    assert d["status"] == 409


# ---------------------------------------------------------------------------
# to_dict — RFC 9457 required fields
# ---------------------------------------------------------------------------


def test_to_dict_contains_title():
    err = ProblemDetailError("Not Found", 404)
    assert "title" in err.to_dict()


def test_to_dict_contains_status():
    err = ProblemDetailError("Not Found", 404)
    assert "status" in err.to_dict()


def test_to_dict_contains_type_when_set():
    err = ProblemDetailError(
        "Not Found", 404, type_uri="https://example.com/errors/not-found"
    )
    d = err.to_dict()
    assert "type" in d
    assert d["type"] == "https://example.com/errors/not-found"


def test_to_dict_omits_type_when_none():
    err = ProblemDetailError("Error", 500)
    d = err.to_dict()
    assert "type" not in d


def test_to_dict_contains_detail_when_set():
    err = ProblemDetailError("Bad Request", 400, detail="field 'name' is required")
    d = err.to_dict()
    assert "detail" in d
    assert d["detail"] == "field 'name' is required"


def test_to_dict_omits_detail_when_none():
    err = ProblemDetailError("Error", 500)
    d = err.to_dict()
    assert "detail" not in d


def test_to_dict_includes_instance():
    err = ProblemDetailError("Not Found", 404, instance="/users/99")
    d = err.to_dict()
    assert d.get("instance") == "/users/99"


def test_to_dict_includes_extensions():
    err = ProblemDetailError("Error", 422, retry_after=30, trace_id="abc123")
    d = err.to_dict()
    assert d.get("retry_after") == 30
    assert d.get("trace_id") == "abc123"


# ---------------------------------------------------------------------------
# Content-Type constant
# ---------------------------------------------------------------------------


def test_content_type_is_problem_json():
    """ProblemDetailError.CONTENT_TYPE must be application/problem+json per RFC 9457."""
    assert ProblemDetailError.CONTENT_TYPE == "application/problem+json"


def test_content_type_used_in_response_headers_flask():
    """Flask middleware returns 401 with RFC 9457 body fields on missing token."""
    pytest.importorskip("flask")
    from flask import Flask

    from coresdk.middleware.flask import CoreSDKFlask
    from coresdk.testing._mock import MockSDK

    sdk = MockSDK()
    app = Flask(__name__)
    CoreSDKFlask(sdk, app)

    @app.route("/protected")
    def protected():
        return {"data": "ok"}

    with app.test_client() as client:
        resp = client.get("/protected")
        assert resp.status_code == 401
        body = resp.get_json()
        # RFC 9457 required fields present in body
        assert body is not None
        assert body.get("status") == 401
        assert "Unauthorized" in body.get("title", "")


def test_content_type_used_in_response_headers_django():
    """Django middleware sets Content-Type: application/problem+json on 401 responses."""
    pytest.importorskip("django")

    try:
        from django.conf import settings as _s

        if not _s.configured:
            _s.configure(DEFAULT_AUTO_FIELD="django.db.models.BigAutoField", DATABASES={}, INSTALLED_APPS=[], DEFAULT_CHARSET="utf-8")  # noqa: E501
    except Exception:  # noqa: S110
        pass

    from django.http import HttpRequest, HttpResponse

    from coresdk.middleware.django import CoreSDKMiddleware
    from coresdk.testing._mock import MockSDK

    sdk = MockSDK()

    def get_response(req):
        return HttpResponse("OK", status=200)

    middleware = CoreSDKMiddleware(get_response=get_response, sdk=sdk)

    req = HttpRequest()
    req.method = "GET"
    req.path = "/api/data"
    req.META["SERVER_NAME"] = "testserver"
    req.META["SERVER_PORT"] = "80"
    # No Authorization header → should return 401 problem+json

    resp = middleware(req)
    assert resp.status_code == 401
    assert "application/problem+json" in resp["Content-Type"]


# ---------------------------------------------------------------------------
# JSON serialisation round-trip
# ---------------------------------------------------------------------------


def test_to_json_roundtrip_all_fields():
    err = ProblemDetailError(
        "Validation Error",
        422,
        detail="email is invalid",
        type_uri="https://example.com/errors/validation",
        instance="/users",
        field="email",
    )
    parsed = json.loads(err.to_json())
    assert parsed["title"] == "Validation Error"
    assert parsed["status"] == 422
    assert parsed["detail"] == "email is invalid"
    assert parsed["type"] == "https://example.com/errors/validation"
    assert parsed["instance"] == "/users"
    assert parsed["field"] == "email"


def test_to_json_is_valid_json():
    err = ProblemDetailError("Error", 500, detail="something broke")
    result = err.to_json()
    parsed = json.loads(result)  # must not raise
    assert isinstance(parsed, dict)


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


def test_is_exception():
    err = ProblemDetailError("Error", 500)
    assert isinstance(err, Exception)


def test_str_representation_contains_title():
    err = ProblemDetailError("Not Found", 404)
    assert "Not Found" in str(err)


def test_repr_contains_status_and_title():
    err = ProblemDetailError("Bad Request", 400)
    r = repr(err)
    assert "400" in r
    assert "Bad Request" in r


def test_can_raise_and_catch():
    with pytest.raises(ProblemDetailError) as exc_info:
        raise ProblemDetailError.unauthorized("session expired")
    assert exc_info.value.status == 401


def test_to_response_returns_tuple():
    err = ProblemDetailError("Not Found", 404, detail="missing")
    body, status = err.to_response()
    assert status == 404
    assert body["title"] == "Not Found"
