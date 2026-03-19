"""Hand-written proto stubs for coresdk.v1.PolicyService.
Replace with buf-generated code when protoc/buf CLI is available.

Message shapes mirror proto/coresdk/v1/policy.proto exactly.
"""
import dataclasses
from typing import Optional

from .auth_pb2 import TenantContext, RequestMetadata, ProblemDetail


@dataclasses.dataclass
class PolicyEvaluateRequest:
    """Mirrors coresdk.v1.PolicyEvaluateRequest."""
    rule: str = ""          # e.g. "data.authz.allow"
    input_json: str = ""    # JSON-encoded input document
    tenant: Optional[TenantContext] = None
    metadata: Optional[RequestMetadata] = None


@dataclasses.dataclass
class PolicyEvaluateResponse:
    """Mirrors coresdk.v1.PolicyEvaluateResponse."""
    result: bool = False
    reason: str = ""
    dry_run: bool = False
    error: Optional[ProblemDetail] = None


@dataclasses.dataclass
class WatchPolicyUpdatesRequest:
    """Mirrors coresdk.v1.WatchPolicyUpdatesRequest."""
    tenant: Optional[TenantContext] = None
    last_bundle_version: str = ""


@dataclasses.dataclass
class PolicyBundleUpdate:
    """Mirrors coresdk.v1.PolicyBundleUpdate."""
    bundle_version: str = ""
    bundle_data: bytes = b""
    updated_at: int = 0
