"""Flask middleware for CoreSDK — JWT auth + OTel tracing."""

from __future__ import annotations

import functools
import logging
import uuid
from collections.abc import Callable
from typing import Any

from coresdk._context import _current_request_id
from coresdk._types import TrialState
from coresdk.errors._rfc9457 import ProblemDetailError

logger = logging.getLogger(__name__)

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

    def __init__(self, sdk, app=None, *, pii_masking: bool = True) -> None:
        self.sdk = sdk
        if pii_masking:
            self._auto_wire_pii_masking()
        if app is not None:
            self.init_app(app)

    def _auto_wire_pii_masking(self) -> None:
        """Auto-register PIIMaskingSpanProcessor if OTel is available."""
        try:
            from opentelemetry import trace

            from coresdk.tracing.processor import PIIMaskingSpanProcessor

            provider = trace.get_tracer_provider()
            if hasattr(provider, "add_span_processor"):
                provider.add_span_processor(PIIMaskingSpanProcessor())
                logger.debug("PIIMaskingSpanProcessor auto-wired")
        except ImportError:
            pass  # OTel not installed

    def init_app(self, app) -> None:
        app.before_request(self._before_request)
        app.after_request(self._after_request)
        app.register_error_handler(ProblemDetailError, self._handle_problem_detail)

    def _before_request(self) -> Any:
        # Request ID propagation
        incoming_id = request.headers.get("X-Request-ID", "")
        request_id = incoming_id or str(uuid.uuid4())
        g.coresdk_rid_token = _current_request_id.set(request_id)
        g.coresdk_request_id = request_id

        if request.path in ("/healthz", "/readyz"):
            return None

        auth_header = request.headers.get("Authorization", "")
        token = (
            auth_header.removeprefix("Bearer ").strip() if auth_header.startswith("Bearer ") else ""
        )

        if not token:
            return _problem_response(
                {
                    "type": "https://coresdk.io/errors/unauthorized",
                    "title": "Unauthorized",
                    "status": 401,
                    "detail": "Missing Bearer token",
                },
                401,
            )

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
                    return _problem_response(
                        {
                            "type": "https://coresdk.io/errors/unauthorized",
                            "title": "Unauthorized",
                            "status": 401,
                            "detail": decision.reason or "Token rejected",
                        },
                        401,
                    )
                if decision.reason == "fail-open":
                    if span and _StatusCode:  # type: ignore[truthy-function]
                        span.set_status(_StatusCode.OK)
                    g.claims = None
                else:
                    g.claims = decision.claims
                    if span and _StatusCode:  # type: ignore[truthy-function]
                        span.set_status(_StatusCode.OK)

                # Trial state injection
                try:
                    trial_info = self.sdk.check_entitlement("__trial__")
                    if trial_info.expires_at > 0:
                        import time

                        days = max(0, int((trial_info.expires_at - time.time()) / 86400))
                        g.coresdk_trial = TrialState(
                            is_trial=True,
                            trial_ends_at=trial_info.expires_at,
                            days_remaining=days,
                        )
                except Exception:  # noqa: S110
                    pass  # no license configured or trial not applicable

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

    def _after_request(self, response: Response) -> Response:
        # Request ID propagation
        request_id = getattr(g, "coresdk_request_id", "")
        if request_id:
            response.headers["X-Request-ID"] = request_id
        rid_token = getattr(g, "coresdk_rid_token", None)
        if rid_token is not None:
            _current_request_id.reset(rid_token)
        return response

    def _handle_problem_detail(self, error: ProblemDetailError) -> Any:
        return _problem_response(error.to_dict(), error.status)


def require_auth(f: Callable) -> Callable:
    """Decorator: raise 403 if g.claims is None."""

    @functools.wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not getattr(g, "claims", None):
            return _problem_response(
                {
                    "type": "https://coresdk.io/errors/forbidden",
                    "title": "Forbidden",
                    "status": 403,
                },
                403,
            )
        return f(*args, **kwargs)

    return wrapper
