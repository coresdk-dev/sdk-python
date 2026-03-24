"""Async SDK entry point — mirrors SDK but all methods are async/await native."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from coresdk._async_client import AsyncCoreSDKClient
from coresdk._config import SDKConfig
from coresdk._context import _current_tenant, _current_user
from coresdk._types import (
    AgentToken,
    AuditRecord,
    AuthDecision,
    EgressDecision,
    ExplainResult,
    FlagDecision,
    LicenseInfo,
    RateLimitDecision,
    SamlDecision,
)
from coresdk.errors._rfc9457 import ProblemDetailError


class AsyncSDK:
    """Async CoreSDK entry point for FastAPI / asyncio services.

    Usage::

        sdk = AsyncSDK.from_env()
        decision = await sdk.authorize(token)
        allowed = await sdk.evaluate_policy("data.myapp.allow", {"action": "read"})
        rate = await sdk.check_rate_limit("user:123")
    """

    def __init__(self, config: SDKConfig) -> None:
        self.config = config
        self._client = AsyncCoreSDKClient(config)

    @classmethod
    def from_env(cls) -> AsyncSDK:
        """Initialize from environment variables."""
        return cls(SDKConfig.from_env())

    @classmethod
    def from_config(cls, path: str | Path) -> AsyncSDK:
        """Load SDK configuration from a TOML or JSON file.

        See :meth:`SDK.from_config` for file format details.
        """
        from coresdk import _load_config_file

        return cls(_load_config_file(path))

    async def authorize(self, token: str, *, action: str = "", resource: str = "") -> AuthDecision:
        """Validate a JWT and authorize the request (async)."""
        return await self._client.validate_token(token, action=action, resource=resource)

    async def evaluate_policy(self, rule: str, input_data: dict) -> bool:
        """Evaluate a Rego policy rule (async)."""
        return await self._client.evaluate_policy(rule, input_data)

    async def check_rate_limit(
        self,
        key: str,
        *,
        tenant_id: str = "",
        limit: int = 0,
        window_seconds: int = 0,
    ) -> RateLimitDecision:
        """Check a rate limit (async)."""
        return await self._client.check_rate_limit(
            key, tenant_id=tenant_id, limit=limit, window_seconds=window_seconds
        )

    async def emit_audit_event(
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
        """Emit a tamper-evident audit event (async)."""
        return await self._client.emit_audit_event(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            tenant_id=tenant_id,
            user_id=user_id,
            outcome=outcome,
            metadata=metadata,
        )

    async def evaluate_flag(
        self,
        flag_key: str,
        tenant_id: str = "",
        *,
        user_id: str = "",
        attributes: dict | None = None,
    ) -> FlagDecision:
        """Evaluate a feature flag via gRPC (async)."""
        return await self._client.evaluate_flag(
            flag_key, tenant_id=tenant_id, user_id=user_id, attributes=attributes
        )

    async def check_entitlement(self, entitlement_key: str, *, tenant_id: str = "") -> LicenseInfo:
        """Check a license entitlement (async)."""
        return await self._client.check_entitlement(entitlement_key, tenant_id=tenant_id)

    async def assert_entitlement(self, entitlement_key: str, *, tenant_id: str = "") -> None:
        """Assert a license entitlement; raises ProblemDetailError if not entitled."""
        info = await self.check_entitlement(entitlement_key, tenant_id=tenant_id)
        if not info.entitled:
            raise ProblemDetailError(
                title="License Required",
                status=403,
                detail=f"Not entitled to: {entitlement_key}",
                type_uri="https://coresdk.io/errors/license",
            )

    async def get_entitlement(self, entitlement_key: str, *, tenant_id: str = "") -> int:
        """Get a numeric license entitlement value (async)."""
        info = await self.check_entitlement(entitlement_key, tenant_id=tenant_id)
        return info.numeric_value

    async def license_expires_at(self, *, tenant_id: str = "") -> int:
        """Get the license expiration timestamp (async)."""
        info = await self.check_entitlement("__license_meta__", tenant_id=tenant_id)
        return info.expires_at

    async def revoke_token(self, token: str, *, tenant_id: str = "", reason: str = "") -> bool:
        """Revoke a JWT token (async)."""
        return await self._client.revoke_token(token, tenant_id=tenant_id, reason=reason)

    async def is_revoked(self, token: str) -> bool:
        """Check if a token has been revoked (async)."""
        return await self._client.is_revoked(token)

    async def validate_saml_assertion(
        self,
        assertion_b64: str,
        *,
        idp_entity_id: str = "",
        tenant_id: str = "",
    ) -> SamlDecision:
        """Validate a SAML assertion (async)."""
        return await self._client.validate_saml_assertion(
            assertion_b64, idp_entity_id=idp_entity_id, tenant_id=tenant_id
        )

    async def mask_dict_rpc(
        self,
        data: dict,
        extra_blocked_fields: list[str] | None = None,
        extra_patterns: list[str] | None = None,
    ) -> dict:
        """Mask PII in a dict via the sidecar (async)."""
        return await self._client.mask_dict_rpc(data, extra_blocked_fields, extra_patterns)

    async def mask_string_rpc(
        self,
        value: str,
        extra_patterns: list[str] | None = None,
    ) -> str:
        """Mask PII in a string via the sidecar (async)."""
        return await self._client.mask_string_rpc(value, extra_patterns)

    async def health(self) -> bool:
        """Check sidecar health (async)."""
        return await self._client.health()

    async def authorize_request(
        self,
        token: str,
        action: str = "",
        resource: str = "",
        *,
        tenant_id: str = "",
    ) -> AuthDecision:
        """Combined auth + authz check (async)."""
        return await self._client.authorize_request(
            token, action=action, resource=resource, tenant_id=tenant_id
        )

    async def get_jwks(self) -> str:
        """Get cached JWKS keys (async)."""
        return await self._client.get_jwks()

    async def dry_run_policy(self, rule: str, input_data: dict) -> bool:
        """Dry-run policy evaluation (async)."""
        return await self._client.dry_run_policy(rule, input_data)

    async def get_config(self) -> dict:
        """Get current config snapshot (async)."""
        return await self._client.get_config()

    async def resolve_tenant(self, token: str, tenant_hint: str = "") -> dict:
        """Resolve a tenant from a token (async)."""
        return await self._client.resolve_tenant(token, tenant_hint=tenant_hint)

    async def validate_isolation(
        self,
        requesting_tenant_id: str,
        resource_tenant_id: str,
    ) -> bool:
        """Validate cross-tenant isolation (async)."""
        return await self._client.validate_isolation(requesting_tenant_id, resource_tenant_id)

    async def explain_authorize(
        self, token: str, *, action: str = "", resource: str = ""
    ) -> ExplainResult:
        """Authorize and get a structured explanation of why the decision was made (async)."""
        return await self._client.explain_authorize(token, action=action, resource=resource)

    async def mint_agent_token(
        self,
        parent_token: str,
        target_service: str,
        scopes: list,
        ttl_seconds: int = 300,
    ) -> AgentToken:
        """Mint a short-lived scoped JWT for agent-to-agent calls (async)."""
        return await self._client.mint_agent_token(
            parent_token, target_service, scopes, ttl_seconds
        )

    async def check_egress(self, url: str, *, service_name: str = "") -> EgressDecision:
        """Check if an outbound URL is safe (SSRF protection) (async). Fail-open."""
        return await self._client.check_egress(url, service_name=service_name)

    @asynccontextmanager
    async def async_tenant_scope(self, tenant_id: str, user_id: str = "") -> AsyncIterator[None]:
        """Async context manager that sets tenant/user scope for all SDK calls within the block.

        Usage::

            async with sdk.async_tenant_scope("ten_xxx", "usr_xxx"):
                await sdk.emit_audit_event(action="login")  # auto-scoped
        """
        t_token = _current_tenant.set(tenant_id)
        u_token = _current_user.set(user_id)
        try:
            yield
        finally:
            _current_tenant.reset(t_token)
            _current_user.reset(u_token)
