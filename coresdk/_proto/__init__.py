"""Hand-written proto stubs for coresdk.v1.
Replace with buf-generated code when protoc/buf CLI is available.
"""
from .auth_pb2 import (
    AuthorizeRequest,
    AuthorizeResponse,
    GetJwksRequest,
    GetJwksResponse,
    ProblemDetail,
    RequestMetadata,
    TenantContext,
    ValidateTokenRequest,
    ValidateTokenResponse,
)
from .policy_pb2 import (
    PolicyBundleUpdate,
    PolicyEvaluateRequest,
    PolicyEvaluateResponse,
    WatchPolicyUpdatesRequest,
)

__all__ = [
    "AuthorizeRequest",
    "AuthorizeResponse",
    "GetJwksRequest",
    "GetJwksResponse",
    "PolicyBundleUpdate",
    "PolicyEvaluateRequest",
    "PolicyEvaluateResponse",
    "ProblemDetail",
    "RequestMetadata",
    "TenantContext",
    "ValidateTokenRequest",
    "ValidateTokenResponse",
    "WatchPolicyUpdatesRequest",
]
