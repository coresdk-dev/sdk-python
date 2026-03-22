"""MockSDK, FakeSpanExporter, assert_no_pii — no sidecar needed for tests."""

import re
from typing import Any

from coresdk._types import (
    AuditRecord,
    AuthDecision,
    Claims,
    FlagDecision,
    LicenseInfo,
    RateLimitDecision,
    SamlDecision,
)


class MockSDK:
    """Drop-in replacement for SDK in tests. No sidecar required."""

    def __init__(
        self,
        *,
        default_allow: bool = True,
        default_claims: "Claims | None" = None,
        fail_mode: str = "open",
    ) -> None:
        self.default_allow = default_allow
        if isinstance(default_claims, dict):
            default_claims = Claims.from_dict(default_claims)
        self.default_claims = default_claims or Claims(
            sub="test-user", tenant_id="", roles=["user"], exp=0
        )
        self.fail_mode = fail_mode
        self.authorize_calls: list[dict] = []
        self.policy_calls: list[dict] = []
        self.config = self._MockConfig()

    def set_token_decision(self, token: str, decision: AuthDecision) -> None:
        """Override the AuthDecision returned for a specific token."""
        if not hasattr(self, "_token_overrides"):
            self._token_overrides: dict = {}
        self._token_overrides[token] = decision

    def set_token_rejected(self, token: str, reason: str = "rejected") -> None:
        """Make a specific token return allowed=False."""
        self.set_token_decision(
            token, AuthDecision(allowed=False, claims=Claims.empty(), reason=reason)
        )

    def set_policy_result(self, rule: str, result: bool) -> None:
        """Override the result of dry_run_policy / evaluate_policy for a specific rule."""
        if not hasattr(self, "_policy_overrides"):
            self._policy_overrides: dict[str, bool] = {}
        self._policy_overrides[rule] = result

    def authorize(self, token: str, **kwargs: Any) -> AuthDecision:  # noqa: ANN401
        self.authorize_calls.append({"token": token, **kwargs})
        overrides = getattr(self, "_token_overrides", {})
        if token in overrides:
            return overrides[token]  # type: ignore[no-any-return]
        claims = self.default_claims if self.default_allow else Claims.empty()
        return AuthDecision(
            allowed=self.default_allow,
            claims=claims,
            reason="" if self.default_allow else "denied-by-mock",
        )

    def authorize_sync(self, token: str, **kwargs: Any) -> AuthDecision:  # noqa: ANN401
        return self.authorize(token, **kwargs)

    def evaluate_policy(self, rule: str, input_data: dict) -> bool:
        self.policy_calls.append({"rule": rule, "input": input_data})
        overrides: dict[str, bool] = getattr(self, "_policy_overrides", {})
        return overrides.get(rule, True)

    def is_enabled(self, flag_key: str, tenant_id: str = "") -> bool:
        return True

    def check_rate_limit(self, key: str, **kwargs: Any) -> RateLimitDecision:  # noqa: ANN401
        return RateLimitDecision(allowed=True, remaining=999, retry_after_ms=0)

    def emit_audit_event(self, **kwargs: Any) -> AuditRecord:  # noqa: ANN401
        return AuditRecord(
            event_id="mock-id",
            sequence_id=0,
            record_hash="mock",
            previous_hash="genesis",
            action=kwargs.get("action", ""),
            tenant_id=kwargs.get("tenant_id", ""),
        )

    def evaluate_flag(
        self,
        flag_key: str,
        tenant_id: str = "",
        **kwargs: Any,  # noqa: ANN401
    ) -> FlagDecision:
        return FlagDecision(enabled=True, variant="", reason="mock")

    def check_entitlement(self, key: str, **kwargs: Any) -> LicenseInfo:  # noqa: ANN401
        return LicenseInfo(entitled=True, numeric_value=0, expires_at=0, plan="enterprise")

    def assert_entitlement(self, key: str, **kwargs: Any) -> None:  # noqa: ANN401
        pass

    def get_entitlement(self, key: str, **kwargs: Any) -> int:  # noqa: ANN401
        return 0

    def license_expires_at(self, **kwargs: Any) -> int:  # noqa: ANN401
        return 0

    def revoke_token(self, token: str, **kwargs: Any) -> bool:  # noqa: ANN401
        return True

    def is_revoked(self, token: str) -> bool:
        return False

    def validate_saml_assertion(
        self,
        assertion_b64: str,
        **kwargs: Any,  # noqa: ANN401
    ) -> SamlDecision:
        return SamlDecision(valid=True, user_id="mock-user", email="mock@example.com")

    def authorize_request(
        self,
        token: str,
        action: str = "",
        resource: str = "",
        **kwargs: Any,  # noqa: ANN401
    ) -> AuthDecision:
        return self.authorize(token, action=action, resource=resource)

    def get_jwks(self) -> str:
        return '{"keys":[]}'

    def dry_run_policy(self, rule: str, input_data: dict) -> bool:
        overrides: dict[str, bool] = getattr(self, "_policy_overrides", {})
        return overrides.get(rule, True)

    def get_config(self) -> dict:
        return {"version": "mock"}

    def resolve_tenant(self, token: str, tenant_hint: str = "") -> dict:
        return {"tenant_id": "test", "tenant_name": "Test Tenant"}

    def validate_isolation(self, requesting_tenant_id: str, resource_tenant_id: str) -> bool:
        return requesting_tenant_id == resource_tenant_id

    def check_prompt(self, messages: list[dict]) -> dict:
        """Mock prompt injection check — always returns safe."""
        return {"safe": True, "detections": [], "risk": "none"}

    def mask_dict_rpc(self, data: dict, **kwargs: Any) -> dict:  # noqa: ANN401
        return data

    def mask_string_rpc(self, value: str, **kwargs: Any) -> str:  # noqa: ANN401
        return value

    class _MockConfig:
        def __init__(self) -> None:
            self.fail_mode: str = "open"
            self.dev_mode: bool = True
            self.tenant_id: str = "test"
            self.service_name: str = "test-service"

    config: _MockConfig


class FakeSpanExporter:
    """Captures exported spans for test assertions."""

    def __init__(self) -> None:
        self.spans: list[Any] = []

    def export(self, spans: list[Any]) -> int:
        self.spans.extend(spans)
        return 0

    def get_spans(self) -> list[Any]:
        return list(self.spans)

    def shutdown(self) -> None:
        pass

    def clear(self) -> None:
        self.spans.clear()


class CaptureAuditDrain:
    """Captures audit events emitted via sdk.emit_audit_event() for test assertions.

    Usage::

        drain = CaptureAuditDrain()
        # ... code that calls sdk.emit_audit_event() ...
        assert len(drain.events) == 1
        assert drain.events[0].action == "user.login"
    """

    def __init__(self) -> None:
        self.events: list[AuditRecord] = []

    def capture(self, record: AuditRecord) -> None:
        self.events.append(record)

    def clear(self) -> None:
        self.events.clear()

    def get_events(self, action: str | None = None) -> list[AuditRecord]:
        """Return captured events, optionally filtered by event_id substring match."""
        if action is None:
            return list(self.events)
        return [e for e in self.events if action in e.event_id]

    @property
    def count(self) -> int:
        return len(self.events)


PII_PATTERNS = [
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",  # email
    r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
    r"\b(?:\d[ -]?){15,16}\b",  # credit card
    r"Bearer\s+\S+",  # Bearer token
    r"eyJ[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)+",  # JWT
    r"\bsk-[A-Za-z0-9_\-]{4,}\b",  # API key (sk-*)
]


def assert_no_pii(spans: list[Any]) -> None:
    """Assert no PII appears in span attributes. Raises AssertionError if found."""
    for span in spans:
        attrs = getattr(span, "attributes", {}) or {}
        for key, value in attrs.items():
            if not isinstance(value, str):
                continue
            for pattern in PII_PATTERNS:
                if re.search(pattern, value):
                    raise AssertionError(
                        f"PII detected in span attribute '{key}': "
                        f"matched pattern '{pattern}'. "
                        f"Value: {value[:20]}..."
                    )
