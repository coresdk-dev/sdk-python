"""gRPC client for CoreSDK sidecar — manual protobuf encoding, no protoc required."""

import json
import logging
from pathlib import Path

import grpc

from coresdk._config import SDKConfig
from coresdk._types import AuthDecision, Claims
from coresdk.errors._rfc9457 import ProblemDetailError

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

    def validate_token(self, token: str, *, action: str = "", resource: str = "") -> AuthDecision:
        channel = self._get_channel()
        if channel is None:
            return AuthDecision(
                allowed=True,
                claims=Claims(sub="unknown", tenant_id=self.config.tenant_id, roles=[], exp=0),
                reason="fail-open",
            )
        try:
            # ValidateTokenRequest: token(1), tenant_id(2), resource(3), action(4)
            payload = (
                _encode_string(1, token)
                + _encode_string(2, self.config.tenant_id)
                + _encode_string(3, resource)
                + _encode_string(4, action)
            )
            stub = channel.unary_unary(
                "/coresdk.v1.AuthService/ValidateToken",
                request_serializer=lambda x: x,
                response_deserializer=lambda x: x,
            )
            response_bytes = stub(payload)

            # ValidateTokenResponse: allowed(1), subject(2), tenant_id(3), roles(4), reason(5)
            fields = _decode_fields(response_bytes)
            allowed = _field_bool(fields, 1)
            subject = _field_str(fields, 2)
            tenant = _field_str(fields, 3) or self.config.tenant_id
            reason = _field_str(fields, 5)
            # roles is repeated string at field 4
            roles = [r.decode("utf-8") if isinstance(r, bytes) else r for r in fields.get(4, [])]

            return AuthDecision(
                allowed=allowed,
                claims=Claims(sub=subject, tenant_id=tenant, roles=roles, exp=0),
                reason=reason,
            )
        except grpc.RpcError as e:
            if self.config.fail_mode == "open":
                logger.warning("Auth RPC failed, failing open: %s", e)
                return AuthDecision(
                    allowed=True,
                    claims=Claims(sub="unknown", tenant_id=self.config.tenant_id, roles=[], exp=0),
                    reason="fail-open",
                )
            raise ProblemDetailError(
                title="Unauthorized",
                status=401,
                detail=str(e),
                type_uri="https://coresdk.io/errors/unauthorized",
            ) from e

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
