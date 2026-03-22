"""Async gRPC client for CoreSDK sidecar — asyncio-native, no event-loop blocking."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import grpc.aio

from coresdk._client import (
    _decode_fields,
    _encode_string,
    _encode_varint_field,
    _field_bool,
    _field_int,
    _field_str,
)
from coresdk._config import SDKConfig
from coresdk._types import (
    AuditRecord,
    AuthDecision,
    Claims,
    FlagDecision,
    LicenseInfo,
    RateLimitDecision,
    SamlDecision,
)
from coresdk.errors._rfc9457 import CoreSDKError, ProblemDetailError

logger = logging.getLogger(__name__)


class AsyncCoreSDKClient:
    """Async gRPC channel to sidecar. Uses grpc.aio for native asyncio support."""

    def __init__(self, config: SDKConfig) -> None:
        self.config = config
        self._channel: grpc.aio.Channel | None = None
        self._metadata: list[tuple[str, str]] = [
            ("x-service-name", config.service_name),
        ]
        if config.service_token:
            self._metadata.append(("x-service-token", config.service_token))

    async def _get_channel(self) -> grpc.aio.Channel | None:
        if self._channel is None:
            try:
                options = [
                    ("grpc.keepalive_time_ms", 30000),
                    ("grpc.keepalive_timeout_ms", 10000),
                    ("grpc.keepalive_permit_without_calls", True),
                ]
                if self.config.dev_mode or not self.config.tls_cert:
                    self._channel = grpc.aio.insecure_channel(
                        self.config.sidecar_addr, options=options
                    )
                else:
                    with Path(self.config.tls_cert).open("rb") as f:
                        cert = f.read()
                    with Path(self.config.tls_key).open("rb") as f:
                        key = f.read()
                    with Path(self.config.tls_ca).open("rb") as f:
                        ca = f.read()
                    creds = grpc.ssl_channel_credentials(ca, key, cert)
                    self._channel = grpc.aio.secure_channel(
                        self.config.sidecar_addr, creds, options=options
                    )
            except Exception as e:
                if self.config.fail_mode == "open":
                    logger.warning("CoreSDK sidecar unreachable (%s) — failing open", e)
                    return None
                raise
        return self._channel

    def _fail_open_decision(self, tenant_id: str = "") -> AuthDecision:
        tid = tenant_id or self.config.tenant_id
        return AuthDecision(
            allowed=True,
            claims=Claims(sub="unknown", tenant_id=tid, roles=[], exp=0),
            reason="fail-open",
            tenant_id=tid,
        )

    async def _call(self, path: str, payload: bytes) -> bytes:
        """Make a unary-unary gRPC call, returning raw response bytes."""
        channel = await self._get_channel()
        if channel is None:
            raise ConnectionError("no channel")
        stub = channel.unary_unary(
            path,
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        result: bytes = await stub(payload, metadata=self._metadata)
        return result

    async def health(self) -> bool:
        """Check sidecar health via gRPC health check. Returns True if SERVING."""
        channel = await self._get_channel()
        if channel is None:
            return False
        try:
            payload = _encode_string(1, "")
            stub = channel.unary_unary(
                "/grpc.health.v1.Health/Check",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response_bytes = await stub(payload, metadata=self._metadata, timeout=5)
            fields = _decode_fields(response_bytes)
            return _field_int(fields, 1) == 1
        except Exception:
            return False

    # -----------------------------------------------------------------
    # Auth
    # -----------------------------------------------------------------

    async def validate_token(
        self, token: str, *, action: str = "", resource: str = "", tenant_id: str = ""
    ) -> AuthDecision:
        effective_tenant = tenant_id or self.config.tenant_id
        channel = await self._get_channel()
        if channel is None:
            return self._fail_open_decision(effective_tenant)
        try:
            payload = (
                _encode_string(1, token)
                + _encode_string(2, effective_tenant)
                + _encode_string(3, resource)
                + _encode_string(4, action)
            )
            response_bytes = await self._call("/coresdk.v1.AuthService/ValidateToken", payload)
            fields = _decode_fields(response_bytes)
            allowed = _field_bool(fields, 1)
            subject = _field_str(fields, 2)
            tenant = _field_str(fields, 3) or effective_tenant
            reason = _field_str(fields, 5)
            roles = [r.decode("utf-8") if isinstance(r, bytes) else r for r in fields.get(4, [])]
            return AuthDecision(
                allowed=allowed,
                claims=Claims(sub=subject, tenant_id=tenant, roles=roles, exp=0)
                if allowed
                else Claims.empty(tenant),
                reason=reason,
                tenant_id=tenant,
            )
        except grpc.RpcError as e:
            if self.config.fail_mode == "open":
                logger.warning("Auth RPC failed, failing open: %s", e)
                return self._fail_open_decision(effective_tenant)
            raise ProblemDetailError(
                title="Unauthorized",
                status=401,
                detail=str(e),
                type_uri="https://coresdk.io/errors/unauthorized",
            ) from e
        except Exception as exc:
            if self.config.fail_mode == "closed":
                raise CoreSDKError(f"CoreSDK fail-closed: {exc}") from exc
            logger.warning("Auth unexpected error, failing open: %s", exc)
            return self._fail_open_decision(effective_tenant)

    # -----------------------------------------------------------------
    # Policy
    # -----------------------------------------------------------------

    async def evaluate_policy(self, rule: str, input_data: dict) -> bool:
        channel = await self._get_channel()
        if channel is None:
            policy_mode = self.config.policy_fail_mode or self.config.fail_mode
            if policy_mode == "open":
                return True
            raise CoreSDKError("CoreSDK sidecar unreachable and policy fail mode is closed")
        try:
            payload = (
                _encode_string(1, rule)
                + _encode_string(2, json.dumps(input_data))
                + _encode_string(3, self.config.tenant_id)
            )
            response_bytes = await self._call("/coresdk.v1.PolicyService/Evaluate", payload)
            fields = _decode_fields(response_bytes)
            return _field_bool(fields, 1)
        except grpc.RpcError as e:
            policy_mode = self.config.policy_fail_mode or self.config.fail_mode
            if policy_mode == "open":
                logger.warning("Policy RPC failed, failing open: %s", e)
                return True
            raise ProblemDetailError(
                title="Policy Error",
                status=500,
                detail=str(e),
                type_uri="https://coresdk.io/errors/policy",
            ) from e

    # -----------------------------------------------------------------
    # Rate Limiting
    # -----------------------------------------------------------------

    async def check_rate_limit(
        self,
        key: str,
        tenant_id: str = "",
        limit: int = 0,
        window_seconds: int = 0,
    ) -> RateLimitDecision:
        channel = await self._get_channel()
        if channel is None:
            return RateLimitDecision(allowed=True, remaining=0, retry_after_ms=0)
        try:
            payload = (
                _encode_string(1, key)
                + _encode_string(2, tenant_id or self.config.tenant_id)
                + _encode_varint_field(3, limit)
                + _encode_varint_field(4, window_seconds)
            )
            response_bytes = await self._call("/coresdk.v1.RateLimitService/Check", payload)
            fields = _decode_fields(response_bytes)
            return RateLimitDecision(
                allowed=_field_bool(fields, 1),
                remaining=_field_int(fields, 2),
                retry_after_ms=_field_int(fields, 3),
            )
        except grpc.RpcError as e:
            if self.config.fail_mode == "open":
                logger.warning("RateLimit RPC failed, failing open: %s", e)
                return RateLimitDecision(allowed=True, remaining=0, retry_after_ms=0)
            raise

    # -----------------------------------------------------------------
    # Audit
    # -----------------------------------------------------------------

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
        channel = await self._get_channel()
        if channel is None:
            return AuditRecord(event_id="", sequence_id=0, record_hash="", previous_hash="")
        try:
            payload = (
                _encode_string(1, action)
                + _encode_string(2, resource_type)
                + _encode_string(3, resource_id)
                + _encode_string(4, tenant_id or self.config.tenant_id)
                + _encode_string(5, user_id)
                + _encode_string(6, outcome)
                + _encode_string(7, json.dumps(metadata or {}))
            )
            response_bytes = await self._call("/coresdk.v1.AuditService/Emit", payload)
            fields = _decode_fields(response_bytes)
            return AuditRecord(
                event_id=_field_str(fields, 1),
                sequence_id=_field_int(fields, 2),
                record_hash=_field_str(fields, 3),
                previous_hash=_field_str(fields, 4),
            )
        except grpc.RpcError as e:
            if self.config.fail_mode == "open":
                logger.warning("Audit RPC failed, failing open: %s", e)
                return AuditRecord(event_id="", sequence_id=0, record_hash="", previous_hash="")
            raise

    # -----------------------------------------------------------------
    # Feature Flags
    # -----------------------------------------------------------------

    async def evaluate_flag(
        self,
        flag_key: str,
        tenant_id: str = "",
        user_id: str = "",
        attributes: dict | None = None,
    ) -> FlagDecision:
        channel = await self._get_channel()
        if channel is None:
            return FlagDecision(enabled=True, variant="", reason="fail-open")
        try:
            payload = (
                _encode_string(1, flag_key)
                + _encode_string(2, tenant_id or self.config.tenant_id)
                + _encode_string(3, user_id)
                + _encode_string(4, json.dumps(attributes or {}))
            )
            response_bytes = await self._call("/coresdk.v1.FlagService/Evaluate", payload)
            fields = _decode_fields(response_bytes)
            return FlagDecision(
                enabled=_field_bool(fields, 1),
                variant=_field_str(fields, 2),
                reason=_field_str(fields, 3),
            )
        except grpc.RpcError as e:
            if self.config.fail_mode == "open":
                logger.warning("Flag RPC failed, failing open: %s", e)
                return FlagDecision(enabled=True, variant="", reason="fail-open")
            raise

    # -----------------------------------------------------------------
    # License
    # -----------------------------------------------------------------

    async def check_entitlement(
        self,
        entitlement_key: str,
        tenant_id: str = "",
    ) -> LicenseInfo:
        channel = await self._get_channel()
        if channel is None:
            return LicenseInfo(entitled=True, numeric_value=0, expires_at=0, plan="")
        try:
            payload = _encode_string(1, entitlement_key) + _encode_string(
                2, tenant_id or self.config.tenant_id
            )
            response_bytes = await self._call(
                "/coresdk.v1.LicenseService/CheckEntitlement", payload
            )
            fields = _decode_fields(response_bytes)
            return LicenseInfo(
                entitled=_field_bool(fields, 1),
                numeric_value=_field_int(fields, 2),
                expires_at=_field_int(fields, 3),
                plan=_field_str(fields, 4),
            )
        except grpc.RpcError as e:
            if self.config.fail_mode == "open":
                logger.warning("License RPC failed, failing open: %s", e)
                return LicenseInfo(entitled=True, numeric_value=0, expires_at=0, plan="")
            raise

    # -----------------------------------------------------------------
    # Token Revocation
    # -----------------------------------------------------------------

    async def revoke_token(
        self,
        token: str,
        tenant_id: str = "",
        reason: str = "",
    ) -> bool:
        try:
            payload = (
                _encode_string(1, token)
                + _encode_string(2, tenant_id or self.config.tenant_id)
                + _encode_string(3, reason)
            )
            response_bytes = await self._call("/coresdk.v1.AuthService/RevokeToken", payload)
            fields = _decode_fields(response_bytes)
            return _field_bool(fields, 1)
        except Exception as e:
            logger.warning("RevokeToken RPC failed: %s", e)
            return False

    async def is_revoked(self, token: str) -> bool:
        try:
            payload = _encode_string(1, token)
            response_bytes = await self._call("/coresdk.v1.AuthService/IsRevoked", payload)
            fields = _decode_fields(response_bytes)
            return _field_bool(fields, 1)
        except Exception as e:
            logger.warning("IsRevoked RPC failed: %s", e)
            return False

    # -----------------------------------------------------------------
    # SAML
    # -----------------------------------------------------------------

    async def validate_saml_assertion(
        self,
        assertion_b64: str,
        idp_entity_id: str = "",
        tenant_id: str = "",
    ) -> SamlDecision:
        channel = await self._get_channel()
        if channel is None:
            return SamlDecision(valid=False, user_id="", email="")
        try:
            payload = (
                _encode_string(1, assertion_b64)
                + _encode_string(2, idp_entity_id)
                + _encode_string(3, tenant_id or self.config.tenant_id)
            )
            response_bytes = await self._call(
                "/coresdk.v1.AuthService/ValidateSAMLAssertion", payload
            )
            fields = _decode_fields(response_bytes)
            groups = [r.decode("utf-8") if isinstance(r, bytes) else r for r in fields.get(4, [])]
            return SamlDecision(
                valid=_field_bool(fields, 1),
                user_id=_field_str(fields, 2),
                email=_field_str(fields, 3),
                groups=groups,
                attributes=json.loads(_field_str(fields, 5) or "{}"),
            )
        except grpc.RpcError as e:
            if self.config.fail_mode == "open":
                logger.warning("SAML RPC failed, failing open: %s", e)
                return SamlDecision(valid=False, user_id="", email="")
            raise

    # -----------------------------------------------------------------
    # Masking (via sidecar)
    # -----------------------------------------------------------------

    async def mask_dict_rpc(
        self,
        data: dict,
        extra_blocked_fields: list[str] | None = None,
        extra_patterns: list[str] | None = None,
    ) -> dict:
        """Mask PII in a dict via the sidecar's MaskingService (async)."""
        channel = await self._get_channel()
        if channel is None:
            return data
        try:
            payload = _encode_string(1, json.dumps(data))
            for f in extra_blocked_fields or []:
                payload += _encode_string(2, f)
            for p in extra_patterns or []:
                payload += _encode_string(3, p)
            response_bytes = await self._call("/coresdk.v1.MaskingService/Mask", payload)
            fields = _decode_fields(response_bytes)
            result: dict = json.loads(_field_str(fields, 1) or "{}")
            return result
        except Exception as e:
            logger.warning("Masking RPC failed: %s", e)
            return data

    async def mask_string_rpc(
        self,
        value: str,
        extra_patterns: list[str] | None = None,
    ) -> str:
        """Mask PII in a string via the sidecar's MaskingService (async)."""
        channel = await self._get_channel()
        if channel is None:
            return value
        try:
            payload = _encode_string(1, value)
            for p in extra_patterns or []:
                payload += _encode_string(2, p)
            response_bytes = await self._call("/coresdk.v1.MaskingService/MaskString", payload)
            fields = _decode_fields(response_bytes)
            return _field_str(fields, 1) or value
        except Exception as e:
            logger.warning("MaskString RPC failed: %s", e)
            return value

    async def check_prompt(self, messages: list[dict]) -> dict:
        """Check LLM messages for prompt injection via the sidecar's MaskingService (async)."""
        channel = await self._get_channel()
        if channel is None:
            return {"safe": True, "detections": [], "risk": "none"}
        try:
            payload = _encode_string(1, json.dumps(messages))
            response_bytes = await self._call(
                "/coresdk.v1.MaskingService/CheckPrompt", payload
            )
            fields = _decode_fields(response_bytes)
            result: dict = json.loads(_field_str(fields, 1) or '{"safe": true, "detections": [], "risk": "none"}')
            return result
        except Exception as e:
            logger.warning("CheckPrompt RPC failed: %s", e)
            return {"safe": True, "detections": [], "risk": "none"}

    # -----------------------------------------------------------------
    # Authorize (combined auth + authz)
    # -----------------------------------------------------------------

    async def authorize_request(
        self,
        token: str,
        action: str = "",
        resource: str = "",
        tenant_id: str = "",
    ) -> AuthDecision:
        """Combined auth+authz via AuthService/Authorize (async)."""
        channel = await self._get_channel()
        if channel is None:
            return self._fail_open_decision()
        try:
            payload = (
                _encode_string(2, action) + _encode_string(3, resource) + _encode_string(7, token)
            )
            response_bytes = await self._call("/coresdk.v1.AuthService/Authorize", payload)
            fields = _decode_fields(response_bytes)
            allowed = _field_bool(fields, 1)
            reason = _field_str(fields, 2)
            tid = tenant_id or self.config.tenant_id
            claims = (
                Claims(sub="", tenant_id=tid, roles=[], exp=0)
                if allowed
                else Claims.empty(tid)
            )
            return AuthDecision(allowed=allowed, claims=claims, reason=reason, tenant_id=tid)
        except grpc.RpcError as e:
            if self.config.fail_mode == "open":
                logger.warning("Authorize RPC failed, failing open: %s", e)
                return self._fail_open_decision()
            raise

    # -----------------------------------------------------------------
    # GetJwks
    # -----------------------------------------------------------------

    async def get_jwks(self) -> str:
        """Get cached JWKS keys from the sidecar (async)."""
        try:
            response_bytes = await self._call("/coresdk.v1.AuthService/GetJwks", b"")
            fields = _decode_fields(response_bytes)
            return _field_str(fields, 1) or '{"keys":[]}'
        except Exception as e:
            logger.warning("GetJwks RPC failed: %s", e)
            return '{"keys":[]}'

    # -----------------------------------------------------------------
    # Policy DryRun
    # -----------------------------------------------------------------

    async def dry_run_policy(self, rule: str, input_data: dict) -> bool:
        """Dry-run policy evaluation (async)."""
        channel = await self._get_channel()
        if channel is None:
            policy_mode = self.config.policy_fail_mode or self.config.fail_mode
            if policy_mode == "open":
                return True
            raise CoreSDKError("CoreSDK sidecar unreachable and policy fail mode is closed")
        try:
            payload = (
                _encode_string(1, rule)
                + _encode_string(2, json.dumps(input_data))
                + _encode_string(3, self.config.tenant_id)
            )
            response_bytes = await self._call("/coresdk.v1.PolicyService/DryRun", payload)
            fields = _decode_fields(response_bytes)
            return _field_bool(fields, 1)
        except grpc.RpcError as e:
            policy_mode = self.config.policy_fail_mode or self.config.fail_mode
            if policy_mode == "open":
                logger.warning("DryRun RPC failed, failing open: %s", e)
                return True
            raise

    # -----------------------------------------------------------------
    # GetConfig
    # -----------------------------------------------------------------

    async def get_config(self) -> dict:
        """Get current config snapshot (async)."""
        try:
            response_bytes = await self._call("/coresdk.v1.ConfigService/GetConfig", b"")
            fields = _decode_fields(response_bytes)
            snapshot_bytes = fields.get(1, [b""])[0]
            if isinstance(snapshot_bytes, bytes) and snapshot_bytes:
                snap_fields = _decode_fields(snapshot_bytes)
                version = _field_str(snap_fields, 1)
                values: dict[str, str] = {}
                for entry_bytes in snap_fields.get(2, []):
                    if isinstance(entry_bytes, bytes):
                        entry_fields = _decode_fields(entry_bytes)
                        k = _field_str(entry_fields, 1)
                        v = _field_str(entry_fields, 2)
                        if k:
                            values[k] = v
                return {"version": version, **values}
            return {}
        except Exception as e:
            logger.warning("GetConfig RPC failed: %s", e)
            return {}

    # -----------------------------------------------------------------
    # Tenant
    # -----------------------------------------------------------------

    async def resolve_tenant(self, token: str, tenant_hint: str = "") -> dict:
        """Resolve a tenant from a token (async)."""
        try:
            payload = _encode_string(1, token) + _encode_string(2, tenant_hint)
            response_bytes = await self._call("/coresdk.v1.TenantService/ResolveTenant", payload)
            fields = _decode_fields(response_bytes)
            tenant_bytes = fields.get(1, [b""])[0]
            if isinstance(tenant_bytes, bytes) and tenant_bytes:
                tf = _decode_fields(tenant_bytes)
                return {"tenant_id": _field_str(tf, 1), "tenant_name": _field_str(tf, 2)}
            return {"tenant_id": ""}
        except Exception as e:
            logger.warning("ResolveTenant RPC failed: %s", e)
            return {"tenant_id": self.config.tenant_id}

    async def validate_isolation(
        self,
        requesting_tenant_id: str,
        resource_tenant_id: str,
    ) -> bool:
        """Validate cross-tenant isolation (async)."""
        try:
            payload = _encode_string(1, requesting_tenant_id) + _encode_string(
                2, resource_tenant_id
            )
            response_bytes = await self._call(
                "/coresdk.v1.TenantService/ValidateIsolation",
                payload,
            )
            fields = _decode_fields(response_bytes)
            return _field_bool(fields, 1)
        except Exception as e:
            logger.warning("ValidateIsolation RPC failed: %s", e)
            return requesting_tenant_id == resource_tenant_id
