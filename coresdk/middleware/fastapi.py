"""FastAPI middleware adapter — JWT auth + span creation + RFC 9457 errors."""

import fnmatch
import logging
import os
import uuid
from collections.abc import Callable

from coresdk._context import _current_request_id
from coresdk._types import Claims, TrialState

logger = logging.getLogger(__name__)


def _is_excluded(path: str, patterns: list[str]) -> bool:
    """Check if *path* matches any exclude pattern (exact, prefix, or glob).

    Supports:
    - Exact match: ``"/healthz"``
    - Glob patterns: ``"/api/v1/*"`` (uses :func:`fnmatch.fnmatch`)
    - Prefix match: ``"/api/"`` matches ``"/api/users"``
    """
    for pattern in patterns:
        if "*" in pattern:
            if fnmatch.fnmatch(path, pattern):
                return True
        elif path == pattern or path.startswith(pattern.rstrip("/") + "/"):
            return True
    return False


try:
    from fastapi import Depends, HTTPException, Request
    from fastapi.responses import JSONResponse
    from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
    from starlette.middleware.base import BaseHTTPMiddleware

    _bearer_scheme = HTTPBearer(auto_error=False)

    def require_auth(sdk) -> Callable:
        """FastAPI dependency that validates the Bearer token via sidecar.

        Usage::

            @app.get("/protected")
            async def handler(claims = Depends(require_auth(sdk))):
                return {"sub": claims["sub"]}
        """

        async def _dependency(
            credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),  # noqa: B008
        ) -> Claims:
            if credentials is None:
                raise HTTPException(
                    status_code=401,
                    detail={
                        "type": "https://coresdk.io/errors/unauthorized",
                        "title": "Unauthorized",
                        "status": 401,
                        "detail": "Missing Bearer token",
                    },
                    headers={"WWW-Authenticate": "Bearer"},
                )
            decision = sdk.authorize(credentials.credentials)
            if not decision.allowed:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "type": "https://coresdk.io/errors/forbidden",
                        "title": "Forbidden",
                        "status": 403,
                        "detail": decision.reason or "Forbidden",
                    },
                )
            claims = decision.claims
            if isinstance(claims, dict):
                claims = Claims.from_dict(claims)
            return claims

        return _dependency

    class CoreSDKMiddleware(BaseHTTPMiddleware):
        """FastAPI middleware: validates JWT, attaches user context, creates OTel span.

        Shadow mode (safe migration)::

            CoreSDKMiddleware(
                app, sdk,
                fallback_validator=my_existing_validator,
                shadow_mode=True,  # validate with both, log discrepancies, use fallback
            )
        """

        def __init__(
            self,
            app,
            sdk,
            *,
            exclude_paths: list | None = None,
            fallback_validator=None,
            fallback_on_sidecar_error: bool = True,
            shadow_mode: bool = False,
            pii_masking: bool = True,
            debug_headers: bool | None = None,
            inject_headers: bool | None = None,
        ):
            super().__init__(app)
            self.sdk = sdk
            if inject_headers is not None:
                self.inject_headers = inject_headers
            elif hasattr(sdk, "config") and hasattr(sdk.config, "inject_headers"):
                self.inject_headers = sdk.config.inject_headers
            else:
                self.inject_headers = True
            if exclude_paths is not None:
                self.exclude_paths = exclude_paths
            elif hasattr(sdk, "config") and hasattr(sdk.config, "exclude_paths"):
                self.exclude_paths = sdk.config.exclude_paths
            else:
                self.exclude_paths = ["/healthz", "/readyz", "/metrics"]
            self.fallback_validator = fallback_validator
            # fallback_on_sidecar_error=True: returns 200 with empty claims instead of
            # propagating the error — use in shadow/canary mode only
            self.fallback_on_sidecar_error = fallback_on_sidecar_error
            self.shadow_mode = shadow_mode
            if debug_headers is None:
                self.debug_headers = os.environ.get("CORESDK_ENV") == "development"
            else:
                self.debug_headers = debug_headers
            if pii_masking:
                self._auto_wire_pii_masking()

        def _auto_wire_pii_masking(self) -> None:
            """Auto-register PIIMaskingSpanProcessor if OTel is available."""
            try:
                from opentelemetry import trace
                from opentelemetry.sdk.trace import TracerProvider

                from coresdk.tracing.processor import PIIMaskingSpanProcessor

                provider = trace.get_tracer_provider()
                if not isinstance(provider, TracerProvider):
                    return
                provider.add_span_processor(PIIMaskingSpanProcessor())
                logger.debug("PIIMaskingSpanProcessor auto-wired")
            except ImportError:
                pass  # OTel not installed

        async def dispatch(self, request: Request, call_next):
            if _is_excluded(request.url.path, self.exclude_paths):
                return await call_next(request)

            # Request ID propagation
            incoming_id = request.headers.get("X-Request-ID", "")
            request_id = incoming_id or str(uuid.uuid4())
            rid_token = _current_request_id.set(request_id)
            request.state.request_id = request_id

            auth_header = request.headers.get("Authorization", "")
            token = ""
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]

            if not token:
                # In shadow mode with fallback, let fallback handle missing token
                if self.shadow_mode and self.fallback_validator:
                    response = await call_next(request)
                    response.headers["X-Request-ID"] = request_id
                    _current_request_id.reset(rid_token)
                    return response
                resp = JSONResponse(
                    status_code=401,
                    content={
                        "type": "https://coresdk.io/errors/unauthorized",
                        "title": "Unauthorized",
                        "status": 401,
                        "detail": "Missing Authorization header",
                    },
                    media_type="application/problem+json",
                )
                resp.headers["X-Request-ID"] = request_id
                _current_request_id.reset(rid_token)
                return resp

            # Shadow mode: validate with both, log discrepancies, use fallback result
            if self.shadow_mode and self.fallback_validator:
                response = await self._dispatch_shadow(request, call_next, token)
                response.headers["X-Request-ID"] = request_id
                _current_request_id.reset(rid_token)
                return response

            decision = None
            debug_info = None
            try:
                decision = self.sdk.authorize(token)
                claims = decision.claims
                request.state.coresdk_user = claims

                # Fallback on sidecar error
                can_fallback = (
                    not decision.allowed
                    and self.fallback_validator
                    and self.fallback_on_sidecar_error
                    and decision.reason == "fail-open"
                )
                if can_fallback:
                    fallback_result = self.fallback_validator(token)
                    if fallback_result:
                        request.state.coresdk_user = fallback_result
                        response = await call_next(request)
                        response.headers["X-Request-ID"] = request_id
                        _current_request_id.reset(rid_token)
                        return response

                if not decision.allowed and decision.reason != "fail-open":
                    resp = JSONResponse(
                        status_code=403,
                        content={
                            "type": "https://coresdk.io/errors/forbidden",
                            "title": "Forbidden",
                            "status": 403,
                            "detail": decision.reason or "Forbidden",
                        },
                        media_type="application/problem+json",
                    )
                    resp.headers["X-Request-ID"] = request_id
                    _current_request_id.reset(rid_token)
                    return resp
                request.state.coresdk_tenant = getattr(claims, "tenant_id", "")

                # Inject tenant/user headers for downstream services
                if self.inject_headers and decision is not None and decision.allowed:
                    tenant_id = getattr(request.state, "coresdk_tenant", "")
                    user_id = ""
                    if decision.claims is not None:
                        user_id = getattr(decision.claims, "sub", "") or getattr(
                            decision.claims, "subject", ""
                        )
                    raw_headers = list(request.scope.get("headers", []))
                    if tenant_id:
                        raw_headers.append((b"x-tenant-id", tenant_id.encode()))
                    if user_id:
                        raw_headers.append((b"x-user-uuid", user_id.encode()))
                    request.scope["headers"] = raw_headers

                # Trial state injection
                try:
                    trial_info = self.sdk.check_entitlement("__trial__")
                    if trial_info.expires_at > 0:
                        import time

                        days = max(0, int((trial_info.expires_at - time.time()) / 86400))
                        request.state.coresdk_trial = TrialState(
                            is_trial=True,
                            trial_ends_at=trial_info.expires_at,
                            days_remaining=days,
                        )
                except Exception:  # noqa: S110
                    pass  # no license configured or trial not applicable

            except Exception as e:
                if self.sdk.config.fail_mode == "open":
                    logger.warning("Auth failed, failing open: %s", e)
                    response = await call_next(request)
                    response.headers["X-Request-ID"] = request_id
                    _current_request_id.reset(rid_token)
                    return response
                resp = JSONResponse(
                    status_code=401,
                    content={
                        "type": "https://coresdk.io/errors/unauthorized",
                        "title": "Unauthorized",
                        "status": 401,
                        "detail": str(e),
                    },
                    media_type="application/problem+json",
                )
                resp.headers["X-Request-ID"] = request_id
                _current_request_id.reset(rid_token)
                return resp

            # Debug trace headers
            if self.debug_headers:
                import base64
                import json
                import time

                debug_info = {
                    "request_id": request_id,
                    "auth": (
                        {"allowed": decision.allowed, "reason": decision.reason}
                        if decision is not None
                        else None
                    ),
                    "tenant_id": getattr(request.state, "coresdk_tenant", ""),
                    "timestamp": time.time(),
                }

            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id

            if self.debug_headers and debug_info:
                import base64
                import json

                response.headers["X-Coresdk-Debug"] = base64.b64encode(
                    json.dumps(debug_info).encode()
                ).decode()

            _current_request_id.reset(rid_token)
            return response

        async def _dispatch_shadow(self, request: Request, call_next, token: str):
            """Shadow mode: validate with both CoreSDK and fallback, log discrepancies."""
            coresdk_allowed = False
            try:
                decision = self.sdk.authorize(token)
                coresdk_allowed = decision.allowed
            except Exception as e:
                logger.debug("Shadow mode: CoreSDK auth error: %s", e)

            fallback_result = None
            fallback_allowed = False
            try:
                fallback_result = self.fallback_validator(token)
                fallback_allowed = bool(fallback_result)
            except Exception as e:
                logger.debug("Shadow mode: fallback auth error: %s", e)

            # Log discrepancy
            match = coresdk_allowed == fallback_allowed
            if not match:
                logger.warning(
                    "Shadow mode discrepancy: CoreSDK=%s, fallback=%s, path=%s",
                    coresdk_allowed,
                    fallback_allowed,
                    request.url.path,
                )

            # Always use fallback result in shadow mode
            if fallback_result:
                request.state.coresdk_user = fallback_result
            return await call_next(request)

except ImportError:

    class CoreSDKMiddleware:  # type: ignore
        def __init__(self, *args, **kwargs):
            raise ImportError("fastapi required: pip install coresdk[fastapi]")

    def require_auth(*args, **kwargs):  # type: ignore
        raise ImportError("fastapi required: pip install coresdk[fastapi]")
