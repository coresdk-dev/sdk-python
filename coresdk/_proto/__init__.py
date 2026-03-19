"""Hand-written proto stubs for coresdk.v1.
Replace with buf-generated code when protoc/buf CLI is available.
"""
from .auth_pb2 import (
    TenantContext,
    RequestMetadata,
    ProblemDetail,
    ValidateTokenRequest,
    ValidateTokenResponse,
    AuthorizeRequest,
    AuthorizeResponse,
    GetJwksRequest,
    GetJwksResponse,
)
from .policy_pb2 import (
    PolicyEvaluateRequest,
    PolicyEvaluateResponse,
    WatchPolicyUpdatesRequest,
    PolicyBundleUpdate,
)

__all__ = [
    "TenantContext",
    "RequestMetadata",
    "ProblemDetail",
    "ValidateTokenRequest",
    "ValidateTokenResponse",
    "AuthorizeRequest",
    "AuthorizeResponse",
    "GetJwksRequest",
    "GetJwksResponse",
    "PolicyEvaluateRequest",
    "PolicyEvaluateResponse",
    "WatchPolicyUpdatesRequest",
    "PolicyBundleUpdate",
]
