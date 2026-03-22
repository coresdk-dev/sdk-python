"""FastAPI middleware adapter — JWT auth + span creation + RFC 9457 errors."""

import logging
from collections.abc import Callable

logger = logging.getLogger(__name__)


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
        ) -> dict:
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
            return decision.claims

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
        ):
            super().__init__(app)
            self.sdk = sdk
            self.exclude_paths = exclude_paths or ["/healthz", "/readyz", "/metrics"]
            self.fallback_validator = fallback_validator
            self.fallback_on_sidecar_error = fallback_on_sidecar_error
            self.shadow_mode = shadow_mode
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

        async def dispatch(self, request: Request, call_next):
            if request.url.path in self.exclude_paths:
                return await call_next(request)

            auth_header = request.headers.get("Authorization", "")
            token = ""
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]

            if not token:
                # In shadow mode with fallback, let fallback handle missing token
                if self.shadow_mode and self.fallback_validator:
                    return await call_next(request)
                return JSONResponse(
                    status_code=401,
                    content={
                        "type": "https://coresdk.io/errors/unauthorized",
                        "title": "Unauthorized",
                        "status": 401,
                        "detail": "Missing Authorization header",
                    },
                    media_type="application/problem+json",
                )

            # Shadow mode: validate with both, log discrepancies, use fallback result
            if self.shadow_mode and self.fallback_validator:
                return await self._dispatch_shadow(request, call_next, token)

            try:
                decision = self.sdk.authorize(token)
                claims = decision.claims if hasattr(decision, "claims") else decision
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
                        return await call_next(request)

                if not decision.allowed and decision.reason != "fail-open":
                    return JSONResponse(
                        status_code=403,
                        content={
                            "type": "https://coresdk.io/errors/forbidden",
                            "title": "Forbidden",
                            "status": 403,
                            "detail": decision.reason or "Forbidden",
                        },
                        media_type="application/problem+json",
                    )
                request.state.coresdk_tenant = (
                    claims.get("tenant_id", "")
                    if isinstance(claims, dict)
                    else getattr(claims, "tenant_id", "")
                )
            except Exception as e:
                if self.sdk.config.fail_mode == "open":
                    logger.warning("Auth failed, failing open: %s", e)
                    return await call_next(request)
                return JSONResponse(
                    status_code=401,
                    content={
                        "type": "https://coresdk.io/errors/unauthorized",
                        "title": "Unauthorized",
                        "status": 401,
                        "detail": str(e),
                    },
                    media_type="application/problem+json",
                )

            return await call_next(request)

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
