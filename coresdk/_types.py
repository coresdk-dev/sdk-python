"""Shared types for CoreSDK."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AuthDecision:
    """Result of an authorization check."""

    allowed: bool
    claims: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
