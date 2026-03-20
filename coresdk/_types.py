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
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthDecision:
    """Result of an authorization check."""

    allowed: bool
    claims: Claims | None = None
    reason: str = ""
