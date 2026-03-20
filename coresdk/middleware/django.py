"""Django middleware for CoreSDK — JWT auth + OTel tracing."""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable

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

    def __init__(self, get_response: Callable, sdk=None, fail_mode: str = "open") -> None:
        self.get_response = get_response
        self.fail_mode = fail_mode
        if sdk is None:
            from coresdk import SDK

            sdk = SDK.from_env()
        self.sdk = sdk

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.path in self.EXEMPT_PATHS or request.path.startswith("/admin/"):
            return self.get_response(request)

        auth_header = request.headers.get("Authorization", "")
        token = ""
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()

        if not token:
            return JsonResponse(
                {
                    "type": "https://coresdk.io/errors/unauthorized",
                    "title": "Unauthorized",
                    "status": 401,
                    "detail": "Missing Bearer token",
                },
                status=401,
                content_type="application/problem+json",
            )

        with _span_ctx("coresdk.auth") as span:
            try:
                decision = self.sdk.authorize_sync(
                    token, action=request.method, resource=request.path
                )
                if decision.reason == "fail-open":
                    request.coresdk_claims = None  # type: ignore[attr-defined]
                else:
                    request.coresdk_claims = decision.claims  # type: ignore[attr-defined]
                    tenant_id = decision.claims.tenant_id if decision.claims else ""
                    if span and tenant_id:
                        span.set_attribute("coresdk.tenant_id", tenant_id)
                if span and _StatusCode:  # type: ignore[truthy-function]
                    span.set_status(_StatusCode.OK)
            except ProblemDetailError as exc:
                if span:
                    span.record_exception(exc)
                    if _StatusCode:  # type: ignore[truthy-function]
                        span.set_status(_StatusCode.ERROR)
                return JsonResponse(
                    exc.to_dict(),
                    status=exc.status,
                    content_type="application/problem+json",
                )
            except Exception as exc:
                if span:
                    span.record_exception(exc)
                    if _StatusCode:  # type: ignore[truthy-function]
                        span.set_status(_StatusCode.ERROR)
                logger.warning(
                    "CoreSDK auth error (fail-open): %s", type(exc).__name__, exc_info=True
                )
                if self.fail_mode != "open":
                    return JsonResponse(
                        {
                            "type": "https://errors.coresdk.io/internal-error",
                            "title": "Internal Server Error",
                            "status": 500,
                            "detail": "CoreSDK auth error — fail-closed mode active",
                        },
                        status=500,
                        content_type="application/problem+json",
                    )
                request.coresdk_claims = None  # type: ignore[attr-defined]

        return self.get_response(request)
