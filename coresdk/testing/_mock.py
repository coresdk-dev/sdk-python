"""MockSDK, FakeSpanExporter, assert_no_pii — no sidecar needed for tests."""
import re
from typing import Any, Dict, List

from coresdk._types import AuthDecision


class MockSDK:
    """Drop-in replacement for SDK in tests. No sidecar required."""

    def __init__(
        self,
        *,
        default_allow: bool = True,
        default_claims: Dict[str, Any] | None = None,
        fail_mode: str = "open",
    ):
        self.default_allow = default_allow
        self.default_claims = default_claims or {"sub": "test-user", "roles": ["user"]}
        self.fail_mode = fail_mode
        self.authorize_calls: List[dict] = []
        self.policy_calls: List[dict] = []

    def set_token_decision(self, token: str, decision: AuthDecision) -> None:
        """Override the AuthDecision returned for a specific token."""
        if not hasattr(self, "_token_overrides"):
            self._token_overrides: dict = {}
        self._token_overrides[token] = decision

    def set_token_rejected(self, token: str, reason: str = "rejected") -> None:
        """Make a specific token return allowed=False."""
        self.set_token_decision(token, AuthDecision(allowed=False, claims={}, reason=reason))

    def authorize(self, token: str, **kwargs) -> AuthDecision:
        self.authorize_calls.append({"token": token, **kwargs})
        overrides = getattr(self, "_token_overrides", {})
        if token in overrides:
            return overrides[token]
        return AuthDecision(
            allowed=self.default_allow,
            claims=self.default_claims.copy(),
            reason="" if self.default_allow else "denied-by-mock",
        )

    def authorize_sync(self, token: str, **kwargs) -> AuthDecision:
        return self.authorize(token, **kwargs)

    def evaluate_policy(self, rule: str, input_data: dict) -> bool:
        self.policy_calls.append({"rule": rule, "input": input_data})
        return True

    def is_enabled(self, flag_key: str, tenant_id: str = "") -> bool:
        return True

    class _MockConfig:
        fail_mode = "open"
        dev_mode = True
        tenant_id = "test"
        service_name = "test-service"

    config = _MockConfig()


class FakeSpanExporter:
    """Captures exported spans for test assertions."""

    def __init__(self):
        self.spans: List[Any] = []

    def export(self, spans) -> int:
        self.spans.extend(spans)
        return 0

    def get_spans(self) -> List[Any]:
        return list(self.spans)

    def shutdown(self) -> None:
        pass

    def clear(self) -> None:
        self.spans.clear()


PII_PATTERNS = [
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",   # email
    r"\b\d{3}-\d{2}-\d{4}\b",                                  # SSN
    r"\b(?:\d[ -]?){15,16}\b",                                 # credit card
    r"Bearer\s+\S+",                                            # Bearer token
    r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",  # JWT
    r"\bsk-[A-Za-z0-9]{8,}\b",                                 # API key (sk-*)
]


def assert_no_pii(spans: List[Any]) -> None:
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
