"""Shared types for CoreSDK."""
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class AuthDecision:
    """Result of an authorization check."""

    allowed: bool
    claims: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""
