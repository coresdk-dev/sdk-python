"""CoreSDK — auth, policy, observability. One import."""

import json
import re
import warnings
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from coresdk._async_sdk import AsyncSDK
from coresdk._client import CoreSDKClient
from coresdk._config import SDKConfig
from coresdk._context import _current_request_id, _current_tenant, _current_user
from coresdk._types import (
    AuditRecord,
    AuthDecision,
    Claims,
    FlagDecision,
    LicenseInfo,
    RateLimitDecision,
    SamlDecision,
    TrialState,
)
from coresdk.errors._rfc9457 import ProblemDetailError
from coresdk.logging import coresdk_structlog_processor
from coresdk.masking import MaskingConfig, MaskingEngine, mask_dict, mask_llm_content, mask_string
from coresdk.middleware.django import CoreSDKMiddleware as DjangoMiddleware
from coresdk.middleware.flask import CoreSDKFlask, require_auth
from coresdk.tracing.decorator import trace

__all__ = [
    "SDK",
    "AsyncSDK",
    "AuditRecord",
    "AuthDecision",
    "Claims",
    "CoreSDKFlask",
    "DjangoMiddleware",
    "FlagDecision",
    "LicenseInfo",
    "MaskingConfig",
    "ProblemDetailError",
    "RateLimitDecision",
    "SamlDecision",
    "TrialState",
    "coresdk_structlog_processor",
    "get_current_tenant",
    "get_current_user",
    "get_request_id",
    "mask_dict",
    "mask_llm_content",
    "mask_string",
    "require_auth",
    "trace",
]
__version__ = "0.2.0"


def get_request_id() -> str:
    """Return the request ID for the current context (set by middleware)."""
    return _current_request_id.get()


def get_current_tenant() -> str:
    """Return the tenant ID set by the nearest enclosing tenant_scope()."""
    return _current_tenant.get()


def get_current_user() -> str:
    """Return the user ID set by the nearest enclosing tenant_scope()."""
    return _current_user.get()


def _load_config_file(path: str | Path) -> SDKConfig:
    """Load an SDKConfig from a TOML or JSON file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"CoreSDK config file not found: {path}")

    if p.suffix == ".toml":
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                raise ImportError(
                    "Install 'tomli' for TOML config support: pip install tomli"
                ) from None
        with p.open("rb") as f:
            data = tomllib.load(f).get("coresdk", {})
    elif p.suffix == ".json":
        with p.open() as f:
            data = json.load(f)
    else:
        raise ValueError(f"Unsupported config file format: {p.suffix} (use .toml or .json)")

    config = SDKConfig(**{k: v for k, v in data.items() if k in SDKConfig.__dataclass_fields__})
    config.validate()
    return config



class SDK:
    """Main CoreSDK entry point. Initialize with SDK.from_env()."""

    def __init__(self, config: SDKConfig) -> None:
        self.config = config
        self._client = CoreSDKClient(config)
        self._masking_engine = self._build_masking_engine()

    def _build_masking_engine(self) -> MaskingEngine:
        """Build a MaskingEngine, adding api_key_prefix pattern if configured."""
        prefix = self.config.api_key_prefix
        if prefix:
            pattern = r"\b" + re.escape(prefix) + r"[A-Za-z0-9_\-]{8,}"
            return MaskingEngine(MaskingConfig(extra_patterns=[pattern]))
        return MaskingEngine()

    @classmethod
    def from_env(cls) -> "SDK":
        """Initialize SDK from environment variables.

        Reads: CORESDK_SIDECAR_ADDR, CORESDK_TENANT_ID, CORESDK_ENV,
               CORESDK_FAIL_MODE, CORESDK_SERVICE_NAME, CORESDK_LOG_LEVEL
        """
        config = SDKConfig.from_env()
        return cls(config)

    @classmethod
    def from_config(cls, path: str | Path) -> "SDK":
        """Load SDK configuration from a TOML or JSON file.

        Supports TOML (requires tomllib/tomli) and JSON. TOML is preferred.
        File format (TOML)::

            [coresdk]
            sidecar_addr = "localhost:50051"
            tenant_id = "my-tenant"
            fail_mode = "closed"
            service_name = "my-service"

        JSON equivalent::

            {"sidecar_addr": "localhost:50051", "tenant_id": "my-tenant"}
        """
        config = _load_config_file(path)
        return cls(config)

    def authorize(
        self, token: str, *, action: str = "", resource: str = "", tenant_id: str = ""
    ) -> AuthDecision:
        """Validate a JWT and authorize the request."""
        return self._client.validate_token(
            token, action=action, resource=resource, tenant_id=tenant_id
        )

    def authorize_sync(
        self, token: str, *, action: str = "", resource: str = "", tenant_id: str = ""
    ) -> AuthDecision:
        """Deprecated: use authorize() directly — the SDK is synchronous by default."""
        warnings.warn(
            "authorize_sync() is deprecated and will be removed in a future version. "
            "Use authorize() directly — the SDK is already synchronous.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.authorize(token, action=action, resource=resource, tenant_id=tenant_id)

    def evaluate_policy(self, rule: str, input_data: dict) -> bool:
        """Evaluate a Rego policy rule."""
        return self._client.evaluate_policy(rule, input_data)

    def check_rate_limit(
        self,
        key: str,
        *,
        tenant_id: str = "",
        limit: int = 0,
        window_seconds: int = 0,
    ) -> RateLimitDecision:
        """Check a rate limit via the sidecar."""
        return self._client.check_rate_limit(
            key, tenant_id=tenant_id, limit=limit, window_seconds=window_seconds
        )

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
        """Emit a tamper-evident audit event."""
        return self._client.emit_audit_event(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            tenant_id=tenant_id,
            user_id=user_id,
            outcome=outcome,
            metadata=metadata,
        )

    def evaluate_flag(
        self,
        flag_key: str,
        tenant_id: str = "",
        *,
        user_id: str = "",
        attributes: dict | None = None,
    ) -> FlagDecision:
        """Evaluate a feature flag via gRPC (cached at sidecar)."""
        return self._client.evaluate_flag(
            flag_key, tenant_id=tenant_id, user_id=user_id, attributes=attributes
        )

    def check_entitlement(self, entitlement_key: str, *, tenant_id: str = "") -> LicenseInfo:
        """Check a license entitlement."""
        return self._client.check_entitlement(entitlement_key, tenant_id=tenant_id)

    def assert_entitlement(self, entitlement_key: str, *, tenant_id: str = "") -> None:
        """Assert a license entitlement; raises ProblemDetailError if not entitled."""
        info = self.check_entitlement(entitlement_key, tenant_id=tenant_id)
        if not info.entitled:
            raise ProblemDetailError(
                title="License Required",
                status=403,
                detail=f"Not entitled to: {entitlement_key}",
                type_uri="https://coresdk.io/errors/license",
            )

    def get_entitlement(self, entitlement_key: str, *, tenant_id: str = "") -> int:
        """Get a numeric license entitlement value."""
        return self.check_entitlement(entitlement_key, tenant_id=tenant_id).numeric_value

    def license_expires_at(self, *, tenant_id: str = "") -> int:
        """Get the license expiration timestamp."""
        return self.check_entitlement("__license_meta__", tenant_id=tenant_id).expires_at

    def revoke_token(self, token: str, *, tenant_id: str = "", reason: str = "") -> bool:
        """Revoke a JWT token."""
        return self._client.revoke_token(token, tenant_id=tenant_id, reason=reason)

    def is_revoked(self, token: str) -> bool:
        """Check if a token has been revoked."""
        return self._client.is_revoked(token)

    def validate_saml_assertion(
        self,
        assertion_b64: str,
        *,
        idp_entity_id: str = "",
        tenant_id: str = "",
    ) -> SamlDecision:
        """Validate a SAML assertion."""
        return self._client.validate_saml_assertion(
            assertion_b64, idp_entity_id=idp_entity_id, tenant_id=tenant_id
        )

    def authorize_request(
        self, token: str, action: str = "", resource: str = "", *, tenant_id: str = ""
    ) -> AuthDecision:
        """Combined auth + authz check via AuthService/Authorize."""
        return self._client.authorize_request(
            token, action=action, resource=resource, tenant_id=tenant_id
        )

    def get_jwks(self) -> str:
        """Get cached JWKS keys from the sidecar as JSON string."""
        return self._client.get_jwks()

    def dry_run_policy(self, rule: str, input_data: dict) -> bool:
        """Dry-run a policy evaluation (does not enforce)."""
        return self._client.dry_run_policy(rule, input_data)

    def get_config(self) -> dict:
        """Get the current config snapshot from the sidecar."""
        return self._client.get_config()

    def resolve_tenant(self, token: str, tenant_hint: str = "") -> dict:
        """Resolve a tenant from a token."""
        return self._client.resolve_tenant(token, tenant_hint=tenant_hint)

    def validate_isolation(self, requesting_tenant_id: str, resource_tenant_id: str) -> bool:
        """Validate cross-tenant isolation."""
        return self._client.validate_isolation(requesting_tenant_id, resource_tenant_id)

    def mask_dict_remote(
        self,
        data: dict,
        extra_blocked_fields: list[str] | None = None,
        extra_patterns: list[str] | None = None,
    ) -> dict:
        """Mask PII in a dict using the sidecar's MaskingService (remote, via gRPC)."""
        return self._client.mask_dict_rpc(
            data,
            extra_blocked_fields=extra_blocked_fields,
            extra_patterns=extra_patterns,
        )

    def mask_string_remote(
        self,
        value: str,
        extra_patterns: list[str] | None = None,
    ) -> str:
        """Mask PII in a string using the sidecar's MaskingService (remote, via gRPC)."""
        return self._client.mask_string_rpc(value, extra_patterns=extra_patterns)

    def mask_dict_rpc(
        self,
        data: dict,
        extra_blocked_fields: list[str] | None = None,
        extra_patterns: list[str] | None = None,
    ) -> dict:
        """Deprecated: use mask_dict_remote() for sidecar masking or
        mask_dict() for local masking."""
        warnings.warn(
            "mask_dict_rpc() is deprecated. Use mask_dict_remote() for sidecar masking "
            "or mask_dict() for local masking.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.mask_dict_remote(
            data,
            extra_blocked_fields=extra_blocked_fields,
            extra_patterns=extra_patterns,
        )

    def mask_string_rpc(
        self,
        value: str,
        extra_patterns: list[str] | None = None,
    ) -> str:
        """Deprecated: use mask_string_remote() for sidecar masking or
        mask_string() for local masking."""
        warnings.warn(
            "mask_string_rpc() is deprecated. Use mask_string_remote() for sidecar masking "
            "or mask_string() for local masking.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.mask_string_remote(value, extra_patterns=extra_patterns)

    def mask_dict(self, data: dict) -> dict:
        """Mask PII in a dict using the SDK's local MaskingEngine.

        If ``api_key_prefix`` was set on :class:`SDKConfig`, keys matching
        that prefix are automatically redacted.
        """
        return self._masking_engine.mask_dict(data)

    def mask_string(self, value: str) -> str:
        """Mask PII in a string using the SDK's local MaskingEngine.

        If ``api_key_prefix`` was set on :class:`SDKConfig`, keys matching
        that prefix are automatically redacted.
        """
        return self._masking_engine.mask_string(value)

    def check_prompt(
        self,
        messages: list[dict],
        *,
        custom_patterns: list[str] | None = None,
    ) -> dict:
        """Detect prompt injection attempts in LLM messages (local, no sidecar).

        Scans each message's ``content`` field for common injection patterns
        such as "ignore previous instructions", "reveal your prompt", role
        manipulation, and delimiter-based jailbreaks.

        Returns a dict with keys:
        - ``safe`` (bool): True if no injection patterns detected.
        - ``risk`` (str): One of ``"none"``, ``"low"``, ``"medium"``, ``"high"``.
        - ``detections`` (list[dict]): Each entry has ``pattern`` and ``message_index``.
        """
        import re

        _injection_patterns = [
            (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)",
             "high"),
            (r"reveal\s+(your\s+)?(system\s+)?prompt", "high"),
            (r"you\s+are\s+now\s+(?!an?\s+AI)", "medium"),
            (r"pretend\s+(you\s+are|to\s+be)", "medium"),
            (r"act\s+as\s+(if\s+you\s+(are|were)|a\s+)", "medium"),
            (r"(DAN|jailbreak|prompt\s+injection)", "high"),
            (r"(</?(system|assistant|user|human)>|\[INST\]|\[/INST\])", "medium"),
            (r"forget\s+(everything|all)\s+(you|I|we)\s+(know|said|discussed)", "medium"),
        ]

        _compiled = custom_patterns or []
        all_patterns = [(re.compile(p, re.IGNORECASE), sev) for p, sev in _injection_patterns]
        for cp in _compiled:
            all_patterns.append((re.compile(cp, re.IGNORECASE), "medium"))

        detections = []
        severity_rank = {"none": 0, "low": 1, "medium": 2, "high": 3}
        max_sev = "none"

        for idx, msg in enumerate(messages):
            content = msg.get("content", "") if isinstance(msg, dict) else ""
            if not isinstance(content, str):
                continue
            for pat, sev in all_patterns:
                if pat.search(content):
                    detections.append(
                        {"pattern": pat.pattern, "message_index": idx, "severity": sev}
                    )
                    if severity_rank[sev] > severity_rank[max_sev]:
                        max_sev = sev

        return {
            "safe": len(detections) == 0,
            "risk": max_sev,
            "detections": detections,
        }

    @contextmanager
    def tenant_scope(self, tenant_id: str, user_id: str = "") -> Iterator[None]:
        """Context manager that sets tenant/user scope for all SDK calls within the block.

        Usage::

            with sdk.tenant_scope("ten_xxx", "usr_xxx"):
                sdk.emit_audit_event(action="login")  # auto-scoped
        """
        t_token = _current_tenant.set(tenant_id)
        u_token = _current_user.set(user_id)
        try:
            yield
        finally:
            _current_tenant.reset(t_token)
            _current_user.reset(u_token)
