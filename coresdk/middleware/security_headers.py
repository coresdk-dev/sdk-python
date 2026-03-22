"""Security headers middleware — OWASP-compliant defaults, zero config."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SecurityHeadersConfig:
    """Configuration for security response headers.

    Defaults pass OWASP ZAP and Mozilla Observatory scans.
    """

    content_security_policy: str = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"
        " img-src 'self' data:; font-src 'self'; connect-src 'self';"
        " frame-ancestors 'none'"
    )
    x_frame_options: str = "DENY"
    x_content_type_options: str = "nosniff"
    strict_transport_security: str = "max-age=31536000; includeSubDomains"
    referrer_policy: str = "strict-origin-when-cross-origin"
    permissions_policy: str = "camera=(), microphone=(), geolocation=(), payment=()"
    x_xss_protection: str = "0"  # Disabled per modern best practice (CSP replaces it)
    cross_origin_opener_policy: str = "same-origin"


try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request

    class SecurityHeadersMiddleware(BaseHTTPMiddleware):
        def __init__(self, app, config: SecurityHeadersConfig | None = None):
            super().__init__(app)
            self.config = config or SecurityHeadersConfig()

        async def dispatch(self, request: Request, call_next):
            response = await call_next(request)
            c = self.config
            response.headers["Content-Security-Policy"] = c.content_security_policy
            response.headers["X-Frame-Options"] = c.x_frame_options
            response.headers["X-Content-Type-Options"] = c.x_content_type_options
            response.headers["Strict-Transport-Security"] = c.strict_transport_security
            response.headers["Referrer-Policy"] = c.referrer_policy
            response.headers["Permissions-Policy"] = c.permissions_policy
            response.headers["X-XSS-Protection"] = c.x_xss_protection
            response.headers["Cross-Origin-Opener-Policy"] = c.cross_origin_opener_policy
            return response

except ImportError:

    class SecurityHeadersMiddleware:  # type: ignore[no-redef]
        def __init__(self, *args, **kwargs):
            raise ImportError("starlette required: pip install coresdk[fastapi]")
