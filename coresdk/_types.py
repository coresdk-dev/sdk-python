"""Shared types for CoreSDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Claims:
    """Parsed JWT claims."""

    sub: str
    tenant_id: str
    roles: list[str]
    exp: int
    # First-class fields for common JWT claims
    email: str = ""
    scopes: list[str] = field(default_factory=list)
    # Raw map of all other claims returned by the sidecar
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def empty(cls, tenant_id: str = "") -> Claims:
        """Return a safe empty Claims used on denied/error decisions."""
        return cls(sub="", tenant_id=tenant_id, roles=[], exp=0)


@dataclass
class AuthDecision:
    """Result of an authorization check."""

    allowed: bool
    # Always non-None: empty Claims on denial prevents AttributeError
    # at call sites that don't check decision.allowed first.
    claims: Claims = field(default_factory=Claims.empty)
    reason: str = ""
    tenant_id: str = ""


@dataclass
class RateLimitDecision:
    """Result of a rate limit check."""

    allowed: bool
    remaining: int = 0
    retry_after_ms: int = 0


@dataclass
class AuditRecord:
    """Result of emitting an audit event (includes hash chain fields)."""

    event_id: str
    sequence_id: int = 0
    record_hash: str = ""
    previous_hash: str = ""


@dataclass
class FlagDecision:
    """Result of a feature flag evaluation."""

    enabled: bool
    variant: str = ""
    reason: str = ""


@dataclass
class LicenseInfo:
    """License entitlement check result."""

    entitled: bool
    numeric_value: int = 0
    expires_at: int = 0
    plan: str = ""


@dataclass
class SamlDecision:
    """Result of SAML assertion validation."""

    valid: bool
    user_id: str = ""
    email: str = ""
    groups: list[str] = field(default_factory=list)
    attributes: dict[str, str] = field(default_factory=dict)


@dataclass
class TrialState:
    """Trial/grace period information derived from license token."""

    is_trial: bool = False
    trial_ends_at: int = 0
    days_remaining: int = 0
