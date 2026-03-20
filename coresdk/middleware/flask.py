"""Flask middleware for CoreSDK — JWT auth + OTel tracing."""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from coresdk.errors._rfc9457 import ProblemDetailError

try:
    from flask import Response, g, request

    _flask_available = True
except ImportError:
    _flask_available = False

try:
    from opentelemetry import trace as _otel_trace

    tracer = _otel_trace.get_tracer("coresdk", "0.1.0")
    _StatusCode = _otel_trace.StatusCode
except ImportError:
    tracer = None  # type: ignore
    _StatusCode = None  # type: ignore


def _problem_response(body: dict, status: int):
    """Return a Flask response with Content-Type: application/problem+json."""
    import json
    return Response(
        json.dumps(body),
        status=status,
        mimetype="application/problem+json",
    )


class CoreSDKFlask:
    """Flask extension that adds JWT auth and OTel tracing."""

    def __init__(self, sdk, app=None) -> None:
        self.sdk = sdk
        if app is not None:
            self.init_app(app)

    def init_app(self, app) -> None:
        app.before_request(self._before_request)
        app.register_error_handler(ProblemDetailError, self._handle_problem_detail)

    def _before_request(self) -> Any:
        if request.path in ("/healthz", "/readyz"):
            return None

        auth_header = request.headers.get("Authorization", "")
        token = (
            auth_header.removeprefix("Bearer ").strip() if auth_header.startswith("Bearer ") else ""
        )

        if not token:
            return _problem_response({
                "type": "https://coresdk.io/errors/unauthorized",
                "title": "Unauthorized",
                "status": 401,
                "detail": "Missing Bearer token",
            }, 401)

        import contextlib

        @contextlib.contextmanager
        def _span_ctx():
            if tracer is not None:
                with tracer.start_as_current_span("coresdk.auth") as sp:
                    yield sp
            else:
                yield None

        with _span_ctx() as span:
            try:
                decision = self.sdk.authorize_sync(
                    token, action=request.method, resource=request.path
                )
                if not decision.allowed:
                    return _problem_response({
                        "type": "https://coresdk.io/errors/unauthorized",
                        "title": "Unauthorized",
                        "status": 401,
                        "detail": decision.reason or "Token rejected",
                    }, 401)
                if decision.reason == "fail-open":
                    if span and _StatusCode:  # type: ignore[truthy-function]
                        span.set_status(_StatusCode.OK)
                    g.claims = None
                else:
                    g.claims = decision.claims
                    if span and _StatusCode:  # type: ignore[truthy-function]
                        span.set_status(_StatusCode.OK)
            except ProblemDetailError as exc:
                if span:
                    span.record_exception(exc)
                    if _StatusCode:  # type: ignore[truthy-function]
                        span.set_status(_StatusCode.ERROR)
                return _problem_response(exc.to_dict(), exc.status)
            except Exception as exc:
                if span:
                    span.record_exception(exc)
                    if _StatusCode:  # type: ignore[truthy-function]
                        span.set_status(_StatusCode.ERROR)
                g.claims = None

        return None

    def _handle_problem_detail(self, error: ProblemDetailError) -> Any:
        return _problem_response(error.to_dict(), error.status)


def require_auth(f: Callable) -> Callable:
    """Decorator: raise 403 if g.claims is None."""

    @functools.wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not getattr(g, "claims", None):
            return _problem_response({
                "type": "https://coresdk.io/errors/forbidden",
                "title": "Forbidden",
                "status": 403,
            }, 403)
        return f(*args, **kwargs)

    return wrapper
