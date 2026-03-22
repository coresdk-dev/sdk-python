"""gRPC client for CoreSDK sidecar — manual protobuf encoding, no protoc required."""

import json
import logging
from pathlib import Path

import grpc

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


# ---------------------------------------------------------------------------
# Minimal protobuf wire encoding helpers
# ---------------------------------------------------------------------------


def _varint(n: int) -> bytes:
    buf = []
    while True:
        towrite = n & 0x7F
        n >>= 7
        if n:
            buf.append(towrite | 0x80)
        else:
            buf.append(towrite)
            break
    return bytes(buf)


def _encode_string(field_num: int, value: str) -> bytes:
    if not value:
        return b""
    encoded = value.encode("utf-8")
    tag = (field_num << 3) | 2
    return _varint(tag) + _varint(len(encoded)) + encoded


def _read_varint(data: bytes, pos: int) -> tuple:
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def _decode_fields(data: bytes) -> dict:
    """Decode protobuf wire fields into {field_num: [value, ...]}."""
    fields: dict = {}
    i = 0
    while i < len(data):
        tag, i = _read_varint(data, i)
        field_num = tag >> 3
        wire_type = tag & 0x7
        if wire_type == 0:  # varint
            val, i = _read_varint(data, i)
            fields.setdefault(field_num, []).append(val)
        elif wire_type == 2:  # length-delimited
            length, i = _read_varint(data, i)
            val = data[i : i + length]
            i += length
            fields.setdefault(field_num, []).append(val)
        elif wire_type == 5:  # 32-bit
            i += 4
        elif wire_type == 1:  # 64-bit
            i += 8
        else:
            break
    return fields


def _field_str(fields: dict, num: int, default: str = "") -> str:
    raw = fields.get(num, [b""])[0]
    return raw.decode("utf-8") if isinstance(raw, bytes) else default


def _field_bool(fields: dict, num: int) -> bool:
    return bool(fields.get(num, [0])[0])


def _encode_varint_field(field_num: int, value: int) -> bytes:
    """Encode an integer field (varint wire type 0)."""
    if value == 0:
        return b""
    tag = (field_num << 3) | 0
    return _varint(tag) + _varint(value)


def _field_int(fields: dict, num: int) -> int:
    """Decode a varint integer field."""
    return int(fields.get(num, [0])[0])


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class CoreSDKClient:
    """Lazy gRPC channel to sidecar. Fail-open when sidecar unreachable in dev mode."""

    def __init__(self, config: SDKConfig) -> None:
        self.config = config
        self._channel = None

    def _get_channel(self) -> grpc.Channel | None:
        if self._channel is None:
            try:
                options = [
                    ("grpc.keepalive_time_ms", 30000),
                    ("grpc.keepalive_timeout_ms", 10000),
                    ("grpc.keepalive_permit_without_calls", True),
                ]
                if self.config.dev_mode or not self.config.tls_cert:
                    self._channel = grpc.insecure_channel(self.config.sidecar_addr, options=options)
                else:
                    with Path(self.config.tls_cert).open("rb") as f:
                        cert = f.read()
                    with Path(self.config.tls_key).open("rb") as f:
                        key = f.read()
                    with Path(self.config.tls_ca).open("rb") as f:
                        ca = f.read()
                    creds = grpc.ssl_channel_credentials(ca, key, cert)
                    self._channel = grpc.secure_channel(
                        self.config.sidecar_addr, creds, options=options
                    )
            except Exception as e:
                if self.config.fail_mode == "open":
                    logger.warning("CoreSDK sidecar unreachable (%s) — failing open", e)
                    return None
                raise
        return self._channel

    def validate_token(
        self, token: str, *, action: str = "", resource: str = "", tenant_id: str = ""
    ) -> AuthDecision:
        effective_tenant = tenant_id or self.config.tenant_id
        channel = self._get_channel()
        if channel is None:
            return AuthDecision(
                allowed=True,
                claims=Claims.empty(effective_tenant),
                reason="fail-open",
                tenant_id=effective_tenant,
            )
        try:
            # ValidateTokenRequest: token(1), tenant_id(2), resource(3), action(4)
            payload = (
                _encode_string(1, token)
                + _encode_string(2, effective_tenant)
                + _encode_string(3, resource)
                + _encode_string(4, action)
            )
            stub = channel.unary_unary(
                "/coresdk.v1.AuthService/ValidateToken",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response_bytes = stub(payload)

            # ValidateTokenResponse: valid(1), subject(2), roles(3), claims_map(4), expires_at(5)
            fields = _decode_fields(response_bytes)
            allowed = _field_bool(fields, 1)
            subject = _field_str(fields, 2)
            # roles is repeated string at field 3 (proto-correct field number)
            roles = [r.decode("utf-8") if isinstance(r, bytes) else r for r in fields.get(3, [])]
            # claims_map at field 4: map<string,string> with extra JWT claims
            # Each map entry is a length-delimited message: key(1), value(2)
            claims_map: dict[str, str] = {}
            for entry in fields.get(4, []):
                if isinstance(entry, bytes) and entry:
                    ef = _decode_fields(entry)
                    k = _field_str(ef, 1)
                    v = _field_str(ef, 2)
                    if k:
                        claims_map[k] = v
            expires_at = _field_int(fields, 5)
            # Normalize: groups → roles (enterprise IdPs emit "groups" instead of "roles")
            if not roles and "groups" in claims_map:
                roles = [g.strip() for g in claims_map["groups"].split(",") if g.strip()]
            tenant = claims_map.get("tenant_id", "") or effective_tenant
            email = claims_map.get("email", "")
            scopes_raw = claims_map.get("scopes", "") or claims_map.get("scope", "")
            scopes = [s.strip() for s in scopes_raw.split() if s.strip()] if scopes_raw else []
            # Error detail at field 6 (nested ProblemDetail message, detail string at field 3)
            reason = ""
            if 6 in fields:
                err_bytes = fields[6][0]
                if isinstance(err_bytes, bytes) and err_bytes:
                    err_fields = _decode_fields(err_bytes)
                    reason = _field_str(err_fields, 3)
            extra = {
                k: v for k, v in claims_map.items()
                if k not in {"tenant_id", "email", "scopes", "scope", "groups"}
            }

            # Always return a Claims object — never None — to prevent AttributeError
            # at call sites that don't check decision.allowed first (Issue B).
            return AuthDecision(
                allowed=allowed,
                claims=Claims(
                    sub=subject,
                    tenant_id=tenant,
                    roles=roles,
                    exp=expires_at,
                    email=email,
                    scopes=scopes,
                    extra=extra,
                ),
                reason=reason,
                tenant_id=tenant,
            )
        except grpc.RpcError as e:
            if self.config.fail_mode == "open":
                logger.warning("Auth RPC failed, failing open: %s", e)
                return AuthDecision(
                    allowed=True,
                    claims=Claims.empty(effective_tenant),
                    reason="fail-open",
                    tenant_id=effective_tenant,
                )
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
            return AuthDecision(
                allowed=True,
                claims=Claims.empty(effective_tenant),
                reason="fail-open",
                tenant_id=effective_tenant,
            )

    def evaluate_policy(self, rule: str, input_data: dict) -> bool:
        channel = self._get_channel()
        if channel is None:
            return True
        try:
            # EvaluatePolicyRequest: rule(1), input_json(2), tenant_id(3)
            payload = (
                _encode_string(1, rule)
                + _encode_string(2, json.dumps(input_data))
                + _encode_string(3, self.config.tenant_id)
            )
            stub = channel.unary_unary(
                "/coresdk.v1.PolicyService/Evaluate",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response_bytes = stub(payload)

            # EvaluatePolicyResponse: allowed(1), result_json(2)
            fields = _decode_fields(response_bytes)
            return _field_bool(fields, 1)
        except grpc.RpcError as e:
            if self.config.fail_mode == "open":
                logger.warning("Policy RPC failed, failing open: %s", e)
                return True
            raise ProblemDetailError(
                title="Policy Error",
                status=500,
                detail=str(e),
                type_uri="https://coresdk.io/errors/policy",
            ) from e
        except Exception as exc:
            if self.config.fail_mode == "closed":
                raise CoreSDKError(f"CoreSDK fail-closed: {exc}") from exc
            logger.warning("Policy unexpected error, failing open: %s", exc)
            return True

    def is_enabled(self, flag_key: str, tenant_id: str = "") -> bool:
        """Check if a feature flag is enabled.

        Delegates to evaluate_flag() (gRPC sidecar) for consistency with all
        other SDK methods.  Falls back to fail-open only when evaluate_flag
        raises and fail_mode is open.
        """
        try:
            result = self.evaluate_flag(flag_key, tenant_id=tenant_id)
            return result.enabled
        except Exception:
            if getattr(self.config, "fail_mode", "open") == "closed":
                raise
            return True  # fail-open

    # -----------------------------------------------------------------
    # Rate Limiting
    # -----------------------------------------------------------------

    def check_rate_limit(
        self,
        key: str,
        tenant_id: str = "",
        limit: int = 0,
        window_seconds: int = 0,
    ) -> RateLimitDecision:
        """Check a rate limit via the sidecar."""
        channel = self._get_channel()
        if channel is None:
            return RateLimitDecision(allowed=True, remaining=0, retry_after_ms=0)
        try:
            payload = (
                _encode_string(1, key)
                + _encode_string(2, tenant_id or self.config.tenant_id)
                + _encode_varint_field(3, limit)
                + _encode_varint_field(4, window_seconds)
            )
            stub = channel.unary_unary(
                "/coresdk.v1.RateLimitService/Check",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response_bytes = stub(payload)
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
            raise ProblemDetailError(
                title="Rate Limit Error",
                status=500,
                detail=str(e),
                type_uri="https://coresdk.io/errors/ratelimit",
            ) from e

    # -----------------------------------------------------------------
    # Audit
    # -----------------------------------------------------------------

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
        """Emit a tamper-evident audit event via the sidecar."""
        channel = self._get_channel()
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
            stub = channel.unary_unary(
                "/coresdk.v1.AuditService/Emit",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response_bytes = stub(payload)
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
            raise ProblemDetailError(
                title="Audit Error",
                status=500,
                detail=str(e),
                type_uri="https://coresdk.io/errors/audit",
            ) from e

    # -----------------------------------------------------------------
    # Feature Flags (gRPC)
    # -----------------------------------------------------------------

    def evaluate_flag(
        self,
        flag_key: str,
        tenant_id: str = "",
        user_id: str = "",
        attributes: dict | None = None,
    ) -> FlagDecision:
        """Evaluate a feature flag via the sidecar gRPC (not HTTP fallback)."""
        channel = self._get_channel()
        if channel is None:
            return FlagDecision(enabled=True, variant="", reason="fail-open")
        try:
            payload = (
                _encode_string(1, flag_key)
                + _encode_string(2, tenant_id or self.config.tenant_id)
                + _encode_string(3, user_id)
                + _encode_string(4, json.dumps(attributes or {}))
            )
            stub = channel.unary_unary(
                "/coresdk.v1.FlagService/Evaluate",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response_bytes = stub(payload)
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
            raise ProblemDetailError(
                title="Flag Error",
                status=500,
                detail=str(e),
                type_uri="https://coresdk.io/errors/flags",
            ) from e

    # -----------------------------------------------------------------
    # License
    # -----------------------------------------------------------------

    def check_entitlement(
        self,
        entitlement_key: str,
        tenant_id: str = "",
    ) -> LicenseInfo:
        """Check a license entitlement via the sidecar."""
        channel = self._get_channel()
        if channel is None:
            return LicenseInfo(entitled=True, numeric_value=0, expires_at=0, plan="")
        try:
            payload = _encode_string(1, entitlement_key) + _encode_string(
                2, tenant_id or self.config.tenant_id
            )
            stub = channel.unary_unary(
                "/coresdk.v1.LicenseService/CheckEntitlement",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response_bytes = stub(payload)
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
            raise ProblemDetailError(
                title="License Error",
                status=403,
                detail=str(e),
                type_uri="https://coresdk.io/errors/license",
            ) from e

    # -----------------------------------------------------------------
    # Token Revocation
    # -----------------------------------------------------------------

    def revoke_token(
        self,
        token: str,
        tenant_id: str = "",
        reason: str = "",
    ) -> bool:
        """Revoke a JWT token via the sidecar."""
        channel = self._get_channel()
        if channel is None:
            return False
        try:
            payload = (
                _encode_string(1, token)
                + _encode_string(2, tenant_id or self.config.tenant_id)
                + _encode_string(3, reason)
            )
            stub = channel.unary_unary(
                "/coresdk.v1.AuthService/RevokeToken",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response_bytes = stub(payload)
            fields = _decode_fields(response_bytes)
            return _field_bool(fields, 1)
        except grpc.RpcError as e:
            logger.warning("RevokeToken RPC failed: %s", e)
            return False

    def is_revoked(self, token: str) -> bool:
        """Check if a token has been revoked."""
        channel = self._get_channel()
        if channel is None:
            return False
        try:
            payload = _encode_string(1, token)
            stub = channel.unary_unary(
                "/coresdk.v1.AuthService/IsRevoked",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response_bytes = stub(payload)
            fields = _decode_fields(response_bytes)
            return _field_bool(fields, 1)
        except grpc.RpcError as e:
            logger.warning("IsRevoked RPC failed: %s", e)
            return False

    # -----------------------------------------------------------------
    # SAML
    # -----------------------------------------------------------------

    def validate_saml_assertion(
        self,
        assertion_b64: str,
        idp_entity_id: str = "",
        tenant_id: str = "",
    ) -> SamlDecision:
        """Validate a SAML assertion via the sidecar."""
        channel = self._get_channel()
        if channel is None:
            return SamlDecision(valid=False, user_id="", email="")
        try:
            payload = (
                _encode_string(1, assertion_b64)
                + _encode_string(2, idp_entity_id)
                + _encode_string(3, tenant_id or self.config.tenant_id)
            )
            stub = channel.unary_unary(
                "/coresdk.v1.AuthService/ValidateSAMLAssertion",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response_bytes = stub(payload)
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
            raise ProblemDetailError(
                title="SAML Error",
                status=401,
                detail=str(e),
                type_uri="https://coresdk.io/errors/saml",
            ) from e

    # -----------------------------------------------------------------
    # Masking (via sidecar)
    # -----------------------------------------------------------------

    def mask_dict_rpc(
        self,
        data: dict,
        extra_blocked_fields: list[str] | None = None,
        extra_patterns: list[str] | None = None,
    ) -> dict:
        """Mask PII in a dict via the sidecar's MaskingService."""
        channel = self._get_channel()
        if channel is None:
            return data
        try:
            payload = _encode_string(1, json.dumps(data))
            # repeated string fields for extra_blocked_fields (tag 2) and extra_patterns (tag 3)
            for f in extra_blocked_fields or []:
                payload += _encode_string(2, f)
            for p in extra_patterns or []:
                payload += _encode_string(3, p)
            stub = channel.unary_unary(
                "/coresdk.v1.MaskingService/Mask",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response_bytes = stub(payload)
            fields = _decode_fields(response_bytes)
            result: dict = json.loads(_field_str(fields, 1) or "{}")
            return result
        except grpc.RpcError as e:
            logger.warning("Masking RPC failed: %s", e)
            return data

    def mask_string_rpc(
        self,
        value: str,
        extra_patterns: list[str] | None = None,
    ) -> str:
        """Mask PII in a string via the sidecar's MaskingService."""
        channel = self._get_channel()
        if channel is None:
            return value
        try:
            payload = _encode_string(1, value)
            for p in extra_patterns or []:
                payload += _encode_string(2, p)
            stub = channel.unary_unary(
                "/coresdk.v1.MaskingService/MaskString",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response_bytes = stub(payload)
            fields = _decode_fields(response_bytes)
            return _field_str(fields, 1) or value
        except grpc.RpcError as e:
            logger.warning("MaskString RPC failed: %s", e)
            return value

    # -----------------------------------------------------------------
    # Authorize (combined auth + authz)
    # -----------------------------------------------------------------

    def authorize_request(
        self,
        token: str,
        action: str = "",
        resource: str = "",
        tenant_id: str = "",
    ) -> AuthDecision:
        """Combined auth+authz via AuthService/Authorize."""
        effective_tenant = tenant_id or self.config.tenant_id
        channel = self._get_channel()
        if channel is None:
            return AuthDecision(
                allowed=True,
                claims=Claims.empty(effective_tenant),
                reason="fail-open",
                tenant_id=effective_tenant,
            )
        try:
            # AuthorizeRequest: subject(1), action(2), resource(3), token(7)
            payload = (
                _encode_string(2, action) + _encode_string(3, resource) + _encode_string(7, token)
            )
            stub = channel.unary_unary(
                "/coresdk.v1.AuthService/Authorize",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response_bytes = stub(payload)
            # AuthorizeResponse: allowed(1), reason(2), subject(3), roles(4), tenant_id(5)
            fields = _decode_fields(response_bytes)
            allowed = _field_bool(fields, 1)
            reason = _field_str(fields, 2)
            # Parse subject/roles if the sidecar returns them; fall back to empty strings.
            subject = _field_str(fields, 3)
            roles = [r.decode("utf-8") if isinstance(r, bytes) else r for r in fields.get(4, [])]
            tenant = _field_str(fields, 5) or effective_tenant
            # Always return a Claims object — never None — to prevent AttributeError (Issue B+C).
            return AuthDecision(
                allowed=allowed,
                claims=Claims(sub=subject, tenant_id=tenant, roles=roles, exp=0),
                reason=reason,
                tenant_id=tenant,
            )
        except grpc.RpcError as e:
            if self.config.fail_mode == "open":
                logger.warning("Authorize RPC failed, failing open: %s", e)
                return AuthDecision(
                    allowed=True,
                    claims=Claims.empty(effective_tenant),
                    reason="fail-open",
                    tenant_id=effective_tenant,
                )
            raise ProblemDetailError(
                title="Forbidden",
                status=403,
                detail=str(e),
                type_uri="https://coresdk.io/errors/forbidden",
            ) from e

    # -----------------------------------------------------------------
    # GetJwks
    # -----------------------------------------------------------------

    def get_jwks(self) -> str:
        """Get the cached JWKS keys from the sidecar."""
        channel = self._get_channel()
        if channel is None:
            return '{"keys":[]}'
        try:
            # GetJwksRequest: tenant(1) — optional, send empty
            stub = channel.unary_unary(
                "/coresdk.v1.AuthService/GetJwks",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response_bytes = stub(b"")
            # GetJwksResponse: jwks_json(1)
            fields = _decode_fields(response_bytes)
            return _field_str(fields, 1) or '{"keys":[]}'
        except grpc.RpcError as e:
            logger.warning("GetJwks RPC failed: %s", e)
            return '{"keys":[]}'

    # -----------------------------------------------------------------
    # Policy DryRun
    # -----------------------------------------------------------------

    def dry_run_policy(self, rule: str, input_data: dict) -> bool:
        """Dry-run a policy evaluation (does not enforce)."""
        channel = self._get_channel()
        if channel is None:
            return True
        try:
            # PolicyEvaluateRequest: rule(1), input_json(2), tenant(3)
            payload = (
                _encode_string(1, rule)
                + _encode_string(2, json.dumps(input_data))
                + _encode_string(3, self.config.tenant_id)
            )
            stub = channel.unary_unary(
                "/coresdk.v1.PolicyService/DryRun",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response_bytes = stub(payload)
            # PolicyEvaluateResponse: result(1), reason(2), dry_run(3)
            fields = _decode_fields(response_bytes)
            return _field_bool(fields, 1)
        except grpc.RpcError as e:
            if self.config.fail_mode == "open":
                logger.warning("DryRun RPC failed, failing open: %s", e)
                return True
            raise ProblemDetailError(
                title="Policy Error",
                status=500,
                detail=str(e),
                type_uri="https://coresdk.io/errors/policy",
            ) from e

    # -----------------------------------------------------------------
    # GetConfig (one-shot snapshot)
    # -----------------------------------------------------------------

    def get_config(self) -> dict:
        """Get the current config snapshot from the sidecar."""
        channel = self._get_channel()
        if channel is None:
            return {}
        try:
            stub = channel.unary_unary(
                "/coresdk.v1.ConfigService/GetConfig",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response_bytes = stub(b"")
            # GetConfigResponse wraps ConfigSnapshot at tag 1
            # ConfigSnapshot: version(1), values map(2), updated_at(3)
            fields = _decode_fields(response_bytes)
            # The snapshot is a nested message at field 1
            snapshot_bytes = fields.get(1, [b""])[0]
            if isinstance(snapshot_bytes, bytes) and snapshot_bytes:
                snap_fields = _decode_fields(snapshot_bytes)
                version = _field_str(snap_fields, 1)
                # values is a map<string,string> at tag 2
                # Each entry is a length-delimited message: key(1), value(2)
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
        except grpc.RpcError as e:
            logger.warning("GetConfig RPC failed: %s", e)
            return {}

    # -----------------------------------------------------------------
    # Tenant: ResolveTenant
    # -----------------------------------------------------------------

    def resolve_tenant(self, token: str, tenant_hint: str = "") -> dict:
        """Resolve a tenant from a token."""
        channel = self._get_channel()
        if channel is None:
            return {"tenant_id": self.config.tenant_id}
        try:
            # ResolveTenantRequest: token(1), tenant_hint(2)
            payload = _encode_string(1, token) + _encode_string(2, tenant_hint)
            stub = channel.unary_unary(
                "/coresdk.v1.TenantService/ResolveTenant",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response_bytes = stub(payload)
            # ResolveTenantResponse: tenant context at tag 1
            fields = _decode_fields(response_bytes)
            tenant_bytes = fields.get(1, [b""])[0]
            if isinstance(tenant_bytes, bytes) and tenant_bytes:
                tf = _decode_fields(tenant_bytes)
                return {"tenant_id": _field_str(tf, 1), "tenant_name": _field_str(tf, 2)}
            return {"tenant_id": ""}
        except grpc.RpcError as e:
            logger.warning("ResolveTenant RPC failed: %s", e)
            return {"tenant_id": self.config.tenant_id}

    # -----------------------------------------------------------------
    # Tenant: ValidateIsolation
    # -----------------------------------------------------------------

    def validate_isolation(self, requesting_tenant_id: str, resource_tenant_id: str) -> bool:
        """Validate cross-tenant isolation."""
        channel = self._get_channel()
        if channel is None:
            return requesting_tenant_id == resource_tenant_id
        try:
            # ValidateIsolationRequest: requesting_tenant_id(1), resource_tenant_id(2)
            payload = _encode_string(1, requesting_tenant_id) + _encode_string(
                2, resource_tenant_id
            )
            stub = channel.unary_unary(
                "/coresdk.v1.TenantService/ValidateIsolation",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response_bytes = stub(payload)
            # ValidateIsolationResponse: isolated(1)
            fields = _decode_fields(response_bytes)
            return _field_bool(fields, 1)
        except grpc.RpcError as e:
            logger.warning("ValidateIsolation RPC failed: %s", e)
            return requesting_tenant_id == resource_tenant_id
