"""Hand-written proto stubs for coresdk.v1.AuthService.
Replace with buf-generated code when protoc/buf CLI is available.

Message shapes mirror proto/coresdk/v1/auth.proto and
proto/coresdk/v1/common.proto exactly.
"""
import dataclasses
from typing import Dict, List, Optional


@dataclasses.dataclass
class ProblemDetail:
    """RFC 9457 Problem Details — mirrors coresdk.v1.ProblemDetail."""
    type: str = ""
    title: str = ""
    status: int = 0
    detail: str = ""
    instance: str = ""
    extensions: Dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class TenantContext:
    """Mirrors coresdk.v1.TenantContext."""
    tenant_id: str = ""
    tenant_name: str = ""
    roles: List[str] = dataclasses.field(default_factory=list)
    attributes: Dict[str, str] = dataclasses.field(default_factory=dict)


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
    tenant: Optional[TenantContext] = None
    metadata: Optional[RequestMetadata] = None
    expected_audience: str = ""


@dataclasses.dataclass
class ValidateTokenResponse:
    """Mirrors coresdk.v1.ValidateTokenResponse."""
    valid: bool = False
    subject: str = ""
    roles: List[str] = dataclasses.field(default_factory=list)
    claims: Dict[str, str] = dataclasses.field(default_factory=dict)
    expires_at: int = 0
    error: Optional[ProblemDetail] = None


@dataclasses.dataclass
class AuthorizeRequest:
    """Mirrors coresdk.v1.AuthorizeRequest."""
    subject: str = ""
    action: str = ""
    resource: str = ""
    tenant: Optional[TenantContext] = None
    metadata: Optional[RequestMetadata] = None
    context: Dict[str, str] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class AuthorizeResponse:
    """Mirrors coresdk.v1.AuthorizeResponse."""
    allowed: bool = False
    reason: str = ""
    error: Optional[ProblemDetail] = None


@dataclasses.dataclass
class GetJwksRequest:
    """Mirrors coresdk.v1.GetJwksRequest."""
    tenant: Optional[TenantContext] = None


@dataclasses.dataclass
class GetJwksResponse:
    """Mirrors coresdk.v1.GetJwksResponse."""
    jwks_json: str = ""
