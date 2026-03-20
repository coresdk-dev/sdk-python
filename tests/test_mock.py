"""Tests for MockSDK test double."""

from coresdk.testing import MockSDK


def test_mock_sdk_authorize_returns_decision():
    mock = MockSDK()
    decision = mock.authorize("valid-token")
    assert decision.allowed is True
    assert decision.claims is not None
    assert decision.claims.sub == "test-user"


def test_mock_sdk_authorize_records_calls():
    mock = MockSDK()
    mock.authorize("tok1")
    mock.authorize("tok2", action="read")
    assert len(mock.authorize_calls) == 2
    assert mock.authorize_calls[0]["token"] == "tok1"
    assert mock.authorize_calls[1]["action"] == "read"


def test_set_token_rejected():
    mock = MockSDK()
    mock.set_token_rejected("bad")
    decision = mock.authorize("bad")
    assert decision.allowed is False
    # valid token still works
    decision = mock.authorize("good")
    assert decision.allowed is True


def test_mock_sdk_deny_all():
    mock = MockSDK(default_allow=False)
    decision = mock.authorize("any-token")
    assert decision.allowed is False


def test_mock_evaluate_policy():
    mock = MockSDK()
    result = mock.evaluate_policy("data.app.allow", {"role": "admin"})
    assert result is True
    assert len(mock.policy_calls) == 1
    assert mock.policy_calls[0]["rule"] == "data.app.allow"


def test_mock_is_enabled():
    mock = MockSDK()
    assert mock.is_enabled("my-flag") is True
