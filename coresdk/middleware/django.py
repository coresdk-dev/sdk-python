"""Django middleware for CoreSDK — JWT auth + OTel tracing."""

from __future__ import annotations

import contextlib
import logging
import uuid
from collections.abc import Callable

from coresdk._context import _current_request_id
from coresdk._types import TrialState
from coresdk.errors._rfc9457 import ProblemDetailError

logger = logging.getLogger(__name__)

try:
    from django.http import HttpRequest, HttpResponse, JsonResponse

    _django_available = True
except ImportError:
    _django_available = False

try:
    from opentelemetry import trace as _otel_trace

    tracer = _otel_trace.get_tracer("coresdk", "0.1.0")
    _StatusCode = _otel_trace.StatusCode
except ImportError:
    tracer = None  # type: ignore
    _StatusCode = None  # type: ignore


@contextlib.contextmanager
def _span_ctx(name: str):
    if tracer is not None:
        with tracer.start_as_current_span(name) as sp:
            yield sp
    else:
        yield None


class CoreSDKMiddleware:
    """Django middleware: validates JWT, injects claims into request."""

    EXEMPT_PATHS = frozenset(["/healthz", "/readyz", "/admin/"])

    def __init__(
        self,
        get_response: Callable,
        sdk=None,
        fail_mode: str = "open",
        *,
        pii_masking: bool = True,
    ) -> None:
        self.get_response = get_response
        self.fail_mode = fail_mode
        if sdk is None:
            from coresdk import SDK

            sdk = SDK.from_env()
        self.sdk = sdk
        if pii_masking:
            self._auto_wire_pii_masking()

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

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Request ID propagation
        incoming_id = request.headers.get("X-Request-ID", "")
        request_id = incoming_id or str(uuid.uuid4())
        rid_token = _current_request_id.set(request_id)
        request.coresdk_request_id = request_id  # type: ignore[attr-defined]

        if request.path in self.EXEMPT_PATHS or request.path.startswith("/admin/"):
            response = self.get_response(request)
            response["X-Request-ID"] = request_id
            _current_request_id.reset(rid_token)
            return response

        auth_header = request.headers.get("Authorization", "")
        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()

        if not token:
            response = JsonResponse(
                {
                    "type": "https://coresdk.io/errors/unauthorized",
                    "title": "Unauthorized",
                    "status": 401,
                    "detail": "Missing Bearer token",
                },
                status=401,
                content_type="application/problem+json",
            )
            response["X-Request-ID"] = request_id
            _current_request_id.reset(rid_token)
            return response

        with _span_ctx("coresdk.auth") as span:
            try:
                decision = self.sdk.authorize_sync(
                    token, action=request.method, resource=request.path
                )
                if decision.reason == "fail-open":
                    request.coresdk_claims = None  # type: ignore[attr-defined]
                else:
                    request.coresdk_claims = decision.claims  # type: ignore[attr-defined]
                    c = decision.claims
                    if c is None:
                        tenant_id = ""
                    elif isinstance(c, dict):
                        tenant_id = c.get("tenant_id", "")
                    else:
                        tenant_id = c.tenant_id
                    if span and tenant_id:
                        span.set_attribute("coresdk.tenant_id", tenant_id)
                if span and _StatusCode:  # type: ignore[truthy-function]
                    span.set_status(_StatusCode.OK)

                # Trial state injection
                try:
                    trial_info = self.sdk.check_entitlement("__trial__")
                    if trial_info.expires_at > 0:
                        import time

                        days = max(0, int((trial_info.expires_at - time.time()) / 86400))
                        request.coresdk_trial = TrialState(  # type: ignore[attr-defined]
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
                response = JsonResponse(
                    exc.to_dict(),
                    status=exc.status,
                    content_type="application/problem+json",
                )
                response["X-Request-ID"] = request_id
                _current_request_id.reset(rid_token)
                return response
            except Exception as exc:
                if span:
                    span.record_exception(exc)
                    if _StatusCode:  # type: ignore[truthy-function]
                        span.set_status(_StatusCode.ERROR)
                logger.warning(
                    "CoreSDK auth error (fail-open): %s", type(exc).__name__, exc_info=True
                )
                if self.fail_mode != "open":
                    response = JsonResponse(
                        {
                            "type": "https://errors.coresdk.io/internal-error",
                            "title": "Internal Server Error",
                            "status": 500,
                            "detail": "CoreSDK auth error — fail-closed mode active",
                        },
                        status=500,
                        content_type="application/problem+json",
                    )
                    response["X-Request-ID"] = request_id
                    _current_request_id.reset(rid_token)
                    return response
                request.coresdk_claims = None  # type: ignore[attr-defined]

        response = self.get_response(request)
        response["X-Request-ID"] = request_id
        _current_request_id.reset(rid_token)
        return response
