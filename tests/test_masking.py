"""Test PII masking in spans."""

from coresdk.tracing.processor import REDACTED, mask_attributes, mask_value


def test_masks_password_field():
    attrs = {"username": "alice", "password": "secret123"}
    result = mask_attributes(attrs)
    assert result["password"] == REDACTED
    assert result["username"] == "alice"


def test_masks_bearer_token():
    result = mask_value("Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig")
    assert result == REDACTED


def test_masks_jwt():
    jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature"
    result = mask_value(jwt)
    assert result == REDACTED


def test_masks_email():
    result = mask_value("user@example.com")
    assert result == REDACTED


def test_does_not_mask_safe_values():
    result = mask_value("hello world")
    assert result == "hello world"


def test_blocked_field_name():
    attrs = {"api_key": "sk-abc123", "action": "read"}
    result = mask_attributes(attrs)
    assert result["api_key"] == REDACTED
    assert result["action"] == "read"


def test_api_key_prefix_auto_masking():
    """SDKConfig.api_key_prefix auto-populates masking engine patterns."""
    from unittest.mock import patch

    from coresdk import SDK
    from coresdk._config import SDKConfig

    cfg = SDKConfig(api_key_prefix="cpod_")
    with patch("coresdk._client.CoreSDKClient.__init__", return_value=None):
        sdk = SDK(cfg)

    # Should mask strings matching the prefix + 8+ alphanumeric chars
    assert sdk.mask_string("key is cpod_abc12345xyz") == f"key is {REDACTED}"
    assert sdk.mask_dict({"token": "cpod_ABCDEFGHIJ"}) == {"token": REDACTED}

    # Should NOT mask short suffixes (< 8 chars)
    assert sdk.mask_string("cpod_short") == "cpod_short"

    # Without prefix, default engine still works for standard PII
    cfg_no_prefix = SDKConfig()
    with patch("coresdk._client.CoreSDKClient.__init__", return_value=None):
        sdk2 = SDK(cfg_no_prefix)
    assert sdk2.mask_string("hello world") == "hello world"
    assert sdk2.mask_string("user@example.com") == REDACTED
