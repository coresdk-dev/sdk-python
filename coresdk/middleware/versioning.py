"""API versioning middleware — RFC 8594 Sunset/Deprecation headers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class VersionPolicy:
    """Versioning policy for an API route or route prefix."""

    deprecated_at: str | None = None  # ISO 8601 date, e.g. "2026-06-01"
    sunset_at: str | None = None  # ISO 8601 date when the endpoint will be removed
    successor: str | None = None  # URL or path of the replacement endpoint


try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    class ApiVersionMiddleware(BaseHTTPMiddleware):
        """Injects RFC 8594 Sunset, Deprecation, and Link headers per route.

        Usage::

            policies = {
                "/api/v1/": VersionPolicy(
                    deprecated_at="2026-06-01",
                    sunset_at="2026-12-01",
                    successor="/api/v2/",
                ),
            }
            app.add_middleware(ApiVersionMiddleware, policies=policies)
        """

        def __init__(self, app, policies: dict[str, VersionPolicy] | None = None):
            super().__init__(app)
            self.policies = policies or {}

        async def dispatch(self, request: Request, call_next):
            response = await call_next(request)
            path = request.url.path

            for prefix, policy in self.policies.items():
                if path.startswith(prefix):
                    if policy.deprecated_at:
                        response.headers["Deprecation"] = policy.deprecated_at
                    if policy.sunset_at:
                        response.headers["Sunset"] = policy.sunset_at
                    if policy.successor:
                        response.headers["Link"] = f'<{policy.successor}>; rel="successor-version"'
                    break  # first match wins

            return response

except ImportError:

    class ApiVersionMiddleware:  # type: ignore[no-redef]
        def __init__(self, *args, **kwargs):
            raise ImportError("starlette required: pip install coresdk[fastapi]")
