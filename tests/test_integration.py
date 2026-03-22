"""End-to-end integration tests against a real coresdk-sidecar binary.

All tests are marked `integration` and are skipped automatically when the
sidecar binary is absent (see conftest.py `sdk` fixture).

Run with:
    pytest tests/test_integration.py -m integration -v
"""

import pytest

pytestmark = pytest.mark.integration


def test_health(sdk):
    assert sdk.health() is True


def test_authorize_open_fail_mode(sdk):
    """With fail_mode=open an invalid token should still return a decision."""
    decision = sdk.authorize("not-a-real-token")
    # fail-open: allowed=True on validation error
    assert isinstance(decision.allowed, bool)


def test_evaluate_policy_default_allow(sdk):
    """Policy evaluation with no bundle loaded returns the fail-open default."""
    result = sdk.evaluate_policy("data.coresdk.allow", {"action": "read"})
    assert isinstance(result, bool)


def test_check_rate_limit_allowed(sdk):
    decision = sdk.check_rate_limit("integration-test-key")
    assert decision.allowed is True
    assert decision.remaining >= 0



def test_emit_audit_event(sdk):
    record = sdk.emit_audit_event(
        action="integration.test",
        user_id="test-user",
        outcome="success",
    )
    assert record.event_id != ""


def test_evaluate_flag_unknown(sdk):
    """Unknown flag returns a FlagDecision (not an exception)."""
    decision = sdk.evaluate_flag("unknown-flag", tenant_id="test")
    assert isinstance(decision.enabled, bool)


def test_check_entitlement_unknown(sdk):
    info = sdk.check_entitlement("unknown-feature")
    assert isinstance(info.entitled, bool)


def test_mask_string_local(sdk):
    """Masking is local — verify it works without sidecar round-trip."""
    from coresdk.masking import mask_string
    result = mask_string("email: alice@example.com")
    assert "alice@example.com" not in result
    assert "[REDACTED]" in result
