"""Test PII masking in spans."""
from coresdk.tracing.processor import mask_attributes, mask_value, REDACTED


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
