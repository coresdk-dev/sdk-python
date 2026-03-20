"""Hand-written proto stubs for coresdk.v1.AuthService.
Replace with buf-generated code when protoc/buf CLI is available.

Message shapes mirror proto/coresdk/v1/auth.proto and
proto/coresdk/v1/common.proto exactly.
"""
import dataclasses


@dataclasses.dataclass
class ProblemDetail:
    """RFC 9457 Problem Details — mirrors coresdk.v1.ProblemDetail."""
    type: str = ""
    title: str = ""
    status: int = 0
    detail: str = ""
    instance: str = ""
    extensions: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class TenantContext:
    """Mirrors coresdk.v1.TenantContext."""
    tenant_id: str = ""
    tenant_name: str = ""
    roles: list[str] = dataclasses.field(default_factory=list)
    attributes: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class RequestMetadata:
    """Mirrors coresdk.v1.RequestMetadata."""
    request_id: str = ""
    trace_id: str = ""
    span_id: str = ""
    service_name: str = ""


@dataclasses.dataclass
class ValidateTokenRequest:
    """Mirrors coresdk.v1.ValidateTokenRequest."""
    token: str = ""
    tenant: TenantContext | None = None
    metadata: RequestMetadata | None = None
    expected_audience: str = ""


@dataclasses.dataclass
class ValidateTokenResponse:
    """Mirrors coresdk.v1.ValidateTokenResponse."""
    valid: bool = False
    subject: str = ""
    roles: list[str] = dataclasses.field(default_factory=list)
    claims: dict[str, str] = dataclasses.field(default_factory=dict)
    expires_at: int = 0
    error: ProblemDetail | None = None


@dataclasses.dataclass
class AuthorizeRequest:
    """Mirrors coresdk.v1.AuthorizeRequest."""
    subject: str = ""
    action: str = ""
    resource: str = ""
    tenant: TenantContext | None = None
    metadata: RequestMetadata | None = None
    context: dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class AuthorizeResponse:
    """Mirrors coresdk.v1.AuthorizeResponse."""
    allowed: bool = False
    reason: str = ""
    error: ProblemDetail | None = None


@dataclasses.dataclass
class GetJwksRequest:
    """Mirrors coresdk.v1.GetJwksRequest."""
    tenant: TenantContext | None = None


@dataclasses.dataclass
class GetJwksResponse:
    """Mirrors coresdk.v1.GetJwksResponse."""
    jwks_json: str = ""
