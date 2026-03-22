"""Tests for CoreSDKClient — fail-open, fail-closed, env var parsing, edge cases."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from coresdk._client import CoreSDKClient
from coresdk._config import SDKConfig
from coresdk.errors._rfc9457 import ProblemDetailError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _unreachable_config(fail_mode: str = "open") -> SDKConfig:
    """Config pointing at a port nothing is listening on."""
    return SDKConfig(
        sidecar_addr="localhost:19999",
        tenant_id="test-tenant",
        fail_mode=fail_mode,
        dev_mode=True,  # insecure channel so we don't need TLS certs
    )


# ---------------------------------------------------------------------------
# Fail-open behaviour
# ---------------------------------------------------------------------------


def test_validate_token_fail_open_when_sidecar_unreachable():
    """When sidecar is unreachable and fail_mode='open', returns allowed=True."""
    config = _unreachable_config(fail_mode="open")
    client = CoreSDKClient(config)

    decision = client.validate_token("some-token")

    assert decision.allowed is True
    assert decision.reason == "fail-open"


def test_validate_token_fail_open_claims_are_safe():
    """Fail-open claims contain 'sub' and 'roles' keys (safe defaults)."""
    client = CoreSDKClient(_unreachable_config("open"))
    decision = client.validate_token("tok")

    assert decision.claims is not None
    assert hasattr(decision.claims, "sub")
    assert hasattr(decision.claims, "roles")


def test_evaluate_policy_fail_open_returns_true():
    """evaluate_policy returns True (allow) when sidecar unreachable in fail-open mode."""
    client = CoreSDKClient(_unreachable_config("open"))
    result = client.evaluate_policy("authz.allow", {"user": "alice"})
    assert result is True


# ---------------------------------------------------------------------------
# Fail-closed behaviour
# ---------------------------------------------------------------------------


def test_validate_token_fail_closed_raises_problem_detail():
    """When fail_mode='closed' and sidecar is unreachable, RPC error raises ProblemDetailError."""
    import grpc

    config = _unreachable_config(fail_mode="closed")
    client = CoreSDKClient(config)

    # Force the channel to be created so _get_channel returns a channel
    # then make stub() raise an RpcError
    fake_channel = MagicMock()
    fake_stub = MagicMock()
    rpc_error = grpc.RpcError()
    rpc_error.code = lambda: grpc.StatusCode.UNAVAILABLE  # type: ignore[method-assign]
    rpc_error.details = lambda: "connection refused"  # type: ignore[method-assign]
    fake_stub.side_effect = rpc_error
    fake_channel.unary_unary.return_value = fake_stub
    client._channel = fake_channel

    with pytest.raises(ProblemDetailError) as exc_info:
        client.validate_token("some-token")

    assert exc_info.value.status == 401


def test_evaluate_policy_fail_closed_raises_problem_detail():
    """evaluate_policy raises ProblemDetailError when fail_mode='closed' and RPC fails."""
    import grpc

    config = _unreachable_config(fail_mode="closed")
    client = CoreSDKClient(config)

    fake_channel = MagicMock()
    fake_stub = MagicMock()
    rpc_error = grpc.RpcError()
    rpc_error.code = lambda: grpc.StatusCode.UNAVAILABLE  # type: ignore[method-assign]
    rpc_error.details = lambda: "connection refused"  # type: ignore[method-assign]
    fake_stub.side_effect = rpc_error
    fake_channel.unary_unary.return_value = fake_stub
    client._channel = fake_channel

    with pytest.raises(ProblemDetailError) as exc_info:
        client.evaluate_policy("authz.allow", {})

    assert exc_info.value.status == 500


# ---------------------------------------------------------------------------
# SDKConfig env var parsing
# ---------------------------------------------------------------------------


def test_sdk_config_defaults():
    """SDKConfig defaults are sane when no env vars set."""
    with patch.dict(os.environ, {}, clear=False):
        # Remove relevant env vars if present
        env_clean = {
            k: v
            for k, v in os.environ.items()
            if k
            not in {
                "CORESDK_SIDECAR_ADDR",
                "CORESDK_TENANT_ID",
                "CORESDK_FAIL_MODE",
                "CORESDK_ENV",
                "CORESDK_SERVICE_NAME",
            }
        }
        with patch.dict(os.environ, env_clean, clear=True):
            cfg = SDKConfig.from_env()

    assert cfg.sidecar_addr == "localhost:50051"
    assert cfg.tenant_id == "default"
    assert cfg.fail_mode == "closed"
    assert cfg.dev_mode is False


def test_sdk_config_sidecar_addr_from_env():
    """CORESDK_SIDECAR_ADDR overrides default sidecar address."""
    with patch.dict(os.environ, {"CORESDK_SIDECAR_ADDR": "sidecar.internal:8080"}):
        cfg = SDKConfig.from_env()
    assert cfg.sidecar_addr == "sidecar.internal:8080"


def test_sdk_config_tenant_id_from_env():
    """CORESDK_TENANT_ID is read correctly."""
    with patch.dict(os.environ, {"CORESDK_TENANT_ID": "acme-corp"}):
        cfg = SDKConfig.from_env()
    assert cfg.tenant_id == "acme-corp"


def test_sdk_config_fail_mode_closed_from_env():
    """CORESDK_FAIL_MODE=closed sets fail_mode='closed'."""
    with patch.dict(os.environ, {"CORESDK_FAIL_MODE": "closed"}):
        cfg = SDKConfig.from_env()
    assert cfg.fail_mode == "closed"


def test_sdk_config_dev_mode_from_env():
    """CORESDK_ENV=development sets dev_mode=True."""
    with patch.dict(os.environ, {"CORESDK_ENV": "development"}):
        cfg = SDKConfig.from_env()
    assert cfg.dev_mode is True


def test_sdk_config_dev_mode_false_for_production():
    """CORESDK_ENV=production leaves dev_mode=False."""
    with patch.dict(os.environ, {"CORESDK_ENV": "production"}):
        cfg = SDKConfig.from_env()
    assert cfg.dev_mode is False


# ---------------------------------------------------------------------------
# validate_token edge cases
# ---------------------------------------------------------------------------


def test_validate_token_empty_string_fail_open_returns_decision():
    """Empty token in fail-open mode still returns a valid AuthDecision (no exception)."""
    client = CoreSDKClient(_unreachable_config("open"))
    # Sidecar unreachable → fail-open path is hit before token validation
    decision = client.validate_token("")
    assert decision.allowed is True


def test_validate_token_empty_string_fail_closed_raises():
    """Empty token in fail-closed mode raises when the RPC fails."""
    import grpc

    config = _unreachable_config(fail_mode="closed")
    client = CoreSDKClient(config)

    fake_channel = MagicMock()
    fake_stub = MagicMock()
    rpc_error = grpc.RpcError()
    rpc_error.code = lambda: grpc.StatusCode.INVALID_ARGUMENT  # type: ignore[method-assign]
    rpc_error.details = lambda: "empty token"  # type: ignore[method-assign]
    fake_stub.side_effect = rpc_error
    fake_channel.unary_unary.return_value = fake_stub
    client._channel = fake_channel

    with pytest.raises(ProblemDetailError):
        client.validate_token("")


# ---------------------------------------------------------------------------
# evaluate_policy return type
# ---------------------------------------------------------------------------


def test_evaluate_policy_returns_bool():
    """evaluate_policy always returns a bool (True in fail-open / unreachable sidecar)."""
    client = CoreSDKClient(_unreachable_config("open"))
    result = client.evaluate_policy("some.rule", {"key": "value"})
    assert isinstance(result, bool)
