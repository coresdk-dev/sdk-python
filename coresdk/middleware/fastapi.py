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
        """FastAPI middleware: validates JWT, attaches user context, creates OTel span."""

        def __init__(self, app, sdk, *, exclude_paths: list | None = None):
            super().__init__(app)
            self.sdk = sdk
            self.exclude_paths = exclude_paths or ["/healthz", "/readyz", "/metrics"]

        async def dispatch(self, request: Request, call_next):
            if request.url.path in self.exclude_paths:
                return await call_next(request)

            auth_header = request.headers.get("Authorization", "")
            token = ""
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]

            if not token:
                if self.sdk.config.dev_mode:
                    return await call_next(request)
                return JSONResponse(
                    status_code=401,
                    content={"type": "https://coresdk.io/errors/unauthorized",
                             "title": "Unauthorized", "status": 401,
                             "detail": "Missing Authorization header"},
                    media_type="application/problem+json",
                )

            try:
                claims = self.sdk.authorize(token)
                request.state.coresdk_user = claims
                request.state.coresdk_tenant = claims.get("tenant_id", "")
            except Exception as e:
                if self.sdk.config.fail_mode == "open":
                    logger.warning(f"Auth failed, failing open: {e}")
                    return await call_next(request)
                return JSONResponse(
                    status_code=401,
                    content={"type": "https://coresdk.io/errors/unauthorized",
                             "title": "Unauthorized", "status": 401,
                             "detail": str(e)},
                    media_type="application/problem+json",
                )

            return await call_next(request)

except ImportError:
    class CoreSDKMiddleware:  # type: ignore
        def __init__(self, *args, **kwargs):
            raise ImportError("fastapi required: pip install coresdk[fastapi]")

    def require_auth(*args, **kwargs):  # type: ignore
        raise ImportError("fastapi required: pip install coresdk[fastapi]")
