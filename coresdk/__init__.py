"""CoreSDK — auth, policy, observability. One import."""

from contextlib import contextmanager

from coresdk._async_sdk import AsyncSDK
from coresdk._client import CoreSDKClient
from coresdk._config import SDKConfig
from coresdk._context import _current_request_id, _current_tenant, _current_user
from coresdk._types import (
    AuditRecord,
    AuthDecision,
    Claims,
    FlagDecision,
    LicenseInfo,
    RateLimitDecision,
    SamlDecision,
)
from coresdk.errors._rfc9457 import ProblemDetailError
from coresdk.middleware.django import CoreSDKMiddleware as DjangoMiddleware
from coresdk.middleware.flask import CoreSDKFlask, require_auth
from coresdk.tracing.decorator import trace

__all__ = [
    "SDK",
    "AsyncSDK",
    "AuditRecord",
    "AuthDecision",
    "Claims",
    "CoreSDKFlask",
    "DjangoMiddleware",
    "FlagDecision",
    "LicenseInfo",
    "ProblemDetailError",
    "RateLimitDecision",
    "SamlDecision",
    "get_current_tenant",
    "get_current_user",
    "get_request_id",
    "require_auth",
    "trace",
]
__version__ = "0.2.0"


def get_request_id() -> str:
    """Return the request ID for the current context (set by middleware)."""
    return _current_request_id.get()


def get_current_tenant() -> str:
    """Return the tenant ID set by the nearest enclosing tenant_scope()."""
    return _current_tenant.get()


def get_current_user() -> str:
    """Return the user ID set by the nearest enclosing tenant_scope()."""
    return _current_user.get()


class SDK:
    """Main CoreSDK entry point. Initialize with SDK.from_env()."""

    def __init__(self, config: SDKConfig) -> None:
        self.config = config
        self._client = CoreSDKClient(config)

    @classmethod
    def from_env(cls) -> "SDK":
        """Initialize SDK from environment variables.

        Reads: CORESDK_SIDECAR_ADDR, CORESDK_TENANT_ID, CORESDK_ENV,
               CORESDK_FAIL_MODE, CORESDK_SERVICE_NAME, CORESDK_LOG_LEVEL
        """
        config = SDKConfig.from_env()
        return cls(config)

    def authorize(self, token: str, *, action: str = "", resource: str = "") -> AuthDecision:
        """Validate a JWT and authorize the request."""
        return self._client.validate_token(token, action=action, resource=resource)

    def authorize_sync(self, token: str, *, action: str = "", resource: str = "") -> AuthDecision:
        """Synchronous authorize — same as authorize() since the SDK is currently sync."""
        return self.authorize(token, action=action, resource=resource)

    def evaluate_policy(self, rule: str, input_data: dict) -> bool:
        """Evaluate a Rego policy rule."""
        return self._client.evaluate_policy(rule, input_data)

    def check_rate_limit(
        self,
        key: str,
        *,
        tenant_id: str = "",
        limit: int = 0,
        window_seconds: int = 0,
    ) -> RateLimitDecision:
        """Check a rate limit via the sidecar."""
        return self._client.check_rate_limit(
            key, tenant_id=tenant_id, limit=limit, window_seconds=window_seconds
        )

    def emit_audit_event(
        self,
        *,
        action: str,
        resource_type: str = "",
        resource_id: str = "",
        tenant_id: str = "",
        user_id: str = "",
        outcome: str = "success",
        metadata: dict | None = None,
    ) -> AuditRecord:
        """Emit a tamper-evident audit event."""
        return self._client.emit_audit_event(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            tenant_id=tenant_id,
            user_id=user_id,
            outcome=outcome,
            metadata=metadata,
        )

    def evaluate_flag(
        self,
        flag_key: str,
        tenant_id: str = "",
        *,
        user_id: str = "",
        attributes: dict | None = None,
    ) -> FlagDecision:
        """Evaluate a feature flag via gRPC (cached at sidecar)."""
        return self._client.evaluate_flag(
            flag_key, tenant_id=tenant_id, user_id=user_id, attributes=attributes
        )

    def check_entitlement(self, entitlement_key: str, *, tenant_id: str = "") -> LicenseInfo:
        """Check a license entitlement."""
        return self._client.check_entitlement(entitlement_key, tenant_id=tenant_id)

    def assert_entitlement(self, entitlement_key: str, *, tenant_id: str = "") -> None:
        """Assert a license entitlement; raises ProblemDetailError if not entitled."""
        info = self.check_entitlement(entitlement_key, tenant_id=tenant_id)
        if not info.entitled:
            raise ProblemDetailError(
                title="License Required",
                status=403,
                detail=f"Not entitled to: {entitlement_key}",
                type_uri="https://coresdk.io/errors/license",
            )

    def get_entitlement(self, entitlement_key: str, *, tenant_id: str = "") -> int:
        """Get a numeric license entitlement value."""
        return self.check_entitlement(entitlement_key, tenant_id=tenant_id).numeric_value

    def license_expires_at(self, *, tenant_id: str = "") -> int:
        """Get the license expiration timestamp."""
        return self.check_entitlement("__license_meta__", tenant_id=tenant_id).expires_at

    def revoke_token(self, token: str, *, tenant_id: str = "", reason: str = "") -> bool:
        """Revoke a JWT token."""
        return self._client.revoke_token(token, tenant_id=tenant_id, reason=reason)

    def is_revoked(self, token: str) -> bool:
        """Check if a token has been revoked."""
        return self._client.is_revoked(token)

    def validate_saml_assertion(
        self,
        assertion_b64: str,
        *,
        idp_entity_id: str = "",
        tenant_id: str = "",
    ) -> SamlDecision:
        """Validate a SAML assertion."""
        return self._client.validate_saml_assertion(
            assertion_b64, idp_entity_id=idp_entity_id, tenant_id=tenant_id
        )

    def authorize_request(
        self, token: str, action: str = "", resource: str = "", *, tenant_id: str = ""
    ) -> AuthDecision:
        """Combined auth + authz check via AuthService/Authorize."""
        return self._client.authorize_request(
            token, action=action, resource=resource, tenant_id=tenant_id
        )

    def get_jwks(self) -> str:
        """Get cached JWKS keys from the sidecar as JSON string."""
        return self._client.get_jwks()

    def dry_run_policy(self, rule: str, input_data: dict) -> bool:
        """Dry-run a policy evaluation (does not enforce)."""
        return self._client.dry_run_policy(rule, input_data)

    def get_config(self) -> dict:
        """Get the current config snapshot from the sidecar."""
        return self._client.get_config()

    def resolve_tenant(self, token: str, tenant_hint: str = "") -> dict:
        """Resolve a tenant from a token."""
        return self._client.resolve_tenant(token, tenant_hint=tenant_hint)

    def validate_isolation(self, requesting_tenant_id: str, resource_tenant_id: str) -> bool:
        """Validate cross-tenant isolation."""
        return self._client.validate_isolation(requesting_tenant_id, resource_tenant_id)

    @contextmanager
    def tenant_scope(self, tenant_id: str, user_id: str = ""):  # noqa: ANN201
        """Context manager that sets tenant/user scope for all SDK calls within the block.

        Usage::

            with sdk.tenant_scope("ten_xxx", "usr_xxx"):
                sdk.emit_audit_event(action="login")  # auto-scoped
        """
        t_token = _current_tenant.set(tenant_id)
        u_token = _current_user.set(user_id)
        try:
            yield
        finally:
            _current_tenant.reset(t_token)
            _current_user.reset(u_token)
