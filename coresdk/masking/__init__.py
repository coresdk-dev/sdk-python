"""CoreSDK local PII masking — no sidecar needed.

Provides :class:`MaskingEngine` for programmatic masking of dicts, strings,
and LLM prompt/response text.  Reuses the canonical blocked-field set and
regex patterns from :mod:`coresdk.tracing.processor`.

Quick start::

    from coresdk.masking import mask_dict, mask_string, mask_llm_content

    safe = mask_dict({"email": "alice@example.com", "name": "Alice"})
    safe_text = mask_string("Contact alice@example.com for details")
    safe_prompt = mask_llm_content("My SSN is 123-45-6789")
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from coresdk.tracing.processor import (
    _APIKEY_RE,
    _BEARER_RE,
    _CC_RE,
    _EMAIL_RE,
    _JWT_RE,
    _SSN_RE,
    BLOCKED_FIELDS,
    REDACTED,
)

__all__ = [
    "MaskingConfig",
    "MaskingEngine",
    "mask_dict",
    "mask_llm_content",
    "mask_string",
]


@dataclass
class MaskingConfig:
    """Configuration for :class:`MaskingEngine`.

    Parameters
    ----------
    extra_blocked_fields:
        Additional field names whose values are always redacted.
    extra_patterns:
        Additional regex *source* strings compiled at engine init
        (e.g. ``"cpod_[A-Za-z0-9]{32}"``).
    extra_literals:
        Literal strings that will be replaced when found anywhere in a value.
    allowlist_mode:
        When ``True``, **only** fields listed in *allowlist* are kept;
        every other field is redacted.
    allowlist:
        Field names to keep when *allowlist_mode* is ``True``.
    api_key_prefixes:
        Additional API key prefixes (e.g. ``['sk-', 'pk-']``) whose values
        are always redacted.
    """

    extra_blocked_fields: list[str] = field(default_factory=list)
    extra_patterns: list[str] = field(default_factory=list)
    extra_literals: list[str] = field(default_factory=list)
    allowlist_mode: bool = False
    allowlist: set[str] = field(default_factory=set)
    api_key_prefixes: list[str] = field(default_factory=list)


def _luhn_check(digits: str) -> bool:
    """Return ``True`` if *digits* passes the Luhn checksum."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


class MaskingEngine:
    """Stateful masking engine driven by a :class:`MaskingConfig`."""

    def __init__(self, config: MaskingConfig | None = None) -> None:
        self._config = config or MaskingConfig()

        # Normalize allowlist to lowercase for case-insensitive matching.
        self._allowlist_lower: frozenset[str] = frozenset(k.lower() for k in self._config.allowlist)

        # Build the effective blocked-field set.
        self._blocked: frozenset[str] = BLOCKED_FIELDS | frozenset(
            f.lower() for f in self._config.extra_blocked_fields
        )

        # Collect all regex patterns (base + extras).
        self._patterns: list[re.Pattern[str]] = [
            _EMAIL_RE,
            _SSN_RE,
            _CC_RE,
            _JWT_RE,
            _BEARER_RE,
            _APIKEY_RE,
        ]
        for src in self._config.extra_patterns:
            self._patterns.append(re.compile(src))
        for prefix in self._config.api_key_prefixes:
            self._patterns.append(re.compile(re.escape(prefix) + r"[A-Za-z0-9_\-]{8,}"))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def mask_value(self, value: str) -> str:
        """Redact *value* if any PII pattern matches."""
        for pat in self._patterns:
            if pat.search(value):
                if pat is _CC_RE:
                    digits = re.sub(r"[^0-9]", "", value)
                    if not _luhn_check(digits):
                        continue
                return REDACTED
        for lit in self._config.extra_literals:
            if lit in value:
                return REDACTED
        return value

    def mask_field(self, field_name: str, value: str) -> str:
        """Redact *value* when *field_name* is blocked or value has PII."""
        lower = field_name.lower()
        suffix = lower.rsplit(".", 1)[-1]
        if lower in self._blocked or suffix in self._blocked:
            return REDACTED
        return self.mask_value(value)

    def mask_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Recursively mask all sensitive values in *data*.

        Handles nested dicts, lists, and bare strings.  Non-string leaf
        values are passed through unchanged.
        """
        return self._walk_dict(data)

    def mask_string(self, value: str) -> str:
        """Replace all PII occurrences inside *value* with ``[REDACTED]``.

        Unlike :meth:`mask_value` (which redacts the *entire* string on
        first match), this method performs in-place substitution so
        surrounding context is preserved.
        """
        return self._sub_patterns(value)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _sub_patterns(self, text: str) -> str:
        """Substitute all pattern matches and literals inside *text*."""
        for pat in self._patterns:
            if pat is _CC_RE:
                # Apply Luhn validation before redacting credit card matches.
                def _cc_replacer(m: re.Match) -> str:
                    digits = re.sub(r"[^0-9]", "", m.group())
                    return REDACTED if _luhn_check(digits) else m.group()
                text = pat.sub(_cc_replacer, text)
            else:
                text = pat.sub(REDACTED, text)
        for lit in self._config.extra_literals:
            text = text.replace(lit, REDACTED)
        return text

    def _walk(self, value: Any) -> Any:  # noqa: ANN401
        """Recursively walk an arbitrary value."""
        if isinstance(value, dict):
            return self._walk_dict(value)
        if isinstance(value, list):
            return [self._walk(item) for item in value]
        if isinstance(value, str):
            return self.mask_value(value)
        return value

    def _walk_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Recursively walk a dict, masking fields and values."""
        result: dict[str, Any] = {}
        for key, value in data.items():
            # Allowlist mode: redact everything not in the allowlist.
            if self._config.allowlist_mode and key.lower() not in self._allowlist_lower:
                result[key] = REDACTED
                continue

            lower = key.lower()
            suffix = lower.rsplit(".", 1)[-1]
            if lower in self._blocked or suffix in self._blocked:
                result[key] = REDACTED
            elif isinstance(value, dict):
                result[key] = self._walk_dict(value)
            elif isinstance(value, list):
                result[key] = [self._walk(item) for item in value]
            elif isinstance(value, str):
                result[key] = self.mask_value(value)
            else:
                result[key] = value
        return result


# ------------------------------------------------------------------
# Module-level convenience functions
# ------------------------------------------------------------------

_DEFAULT_ENGINE: MaskingEngine | None = None


def _engine(config: MaskingConfig | None) -> MaskingEngine:
    """Return a :class:`MaskingEngine`, caching the default instance."""
    if config is not None:
        return MaskingEngine(config)
    global _DEFAULT_ENGINE
    if _DEFAULT_ENGINE is None:
        _DEFAULT_ENGINE = MaskingEngine()
    return _DEFAULT_ENGINE


def mask_dict(data: dict[str, Any], config: MaskingConfig | None = None) -> dict[str, Any]:
    """Recursively mask PII in *data*.

    Pass a :class:`MaskingConfig` for custom rules; ``None`` uses the
    built-in defaults.
    """
    return _engine(config).mask_dict(data)


def mask_string(value: str, config: MaskingConfig | None = None) -> str:
    """Substitute all PII occurrences inside *value* with ``[REDACTED]``."""
    return _engine(config).mask_string(value)


def mask_llm_content(text: str, config: MaskingConfig | None = None) -> str:
    """Mask PII in LLM prompt or response text.

    Functionally identical to :func:`mask_string` but named explicitly
    for the LLM content-safety use case.
    """
    return _engine(config).mask_string(text)
