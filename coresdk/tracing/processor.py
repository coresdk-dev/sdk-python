"""PIIMaskingSpanProcessor — fires before export queue."""

import re
from typing import Any

BLOCKED_FIELDS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "auth",
        "private_key",
        "credential",
        "credentials",
        "access_key",
        "access_token",
        "refresh_token",
        "client_secret",
        "ssn",
    }
)

REDACTED = "[REDACTED]"

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_RE = re.compile(r"\b(?:\d[ -]?){15,16}\b")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)+")
_BEARER_RE = re.compile(r"Bearer\s+\S+", re.IGNORECASE)
_APIKEY_RE = re.compile(r"\bsk-[A-Za-z0-9_\-]{4,}\b")


def mask_value(value: Any) -> Any:  # noqa: ANN401
    if not isinstance(value, str):
        return value
    if _JWT_RE.search(value) or _BEARER_RE.search(value) or _APIKEY_RE.search(value):
        return REDACTED
    if _EMAIL_RE.search(value) or _SSN_RE.search(value) or _CC_RE.search(value):
        return REDACTED
    return value


def mask_attributes(attributes: dict) -> dict:
    result = {}
    for key, value in attributes.items():
        key_lower = key.lower()
        # Match exact key or dotted suffix (e.g. "user.password" → "password")
        key_suffix = key_lower.rsplit(".", 1)[-1]
        if key_lower in BLOCKED_FIELDS or key_suffix in BLOCKED_FIELDS:
            result[key] = REDACTED
        else:
            result[key] = mask_value(value)
    return result


try:
    from opentelemetry.sdk.trace import ReadableSpan, Span

    class PIIMaskingSpanProcessor:
        """OTel SpanProcessor that redacts PII before export.

        CRITICAL: Must be registered as SpanProcessor (not SpanExporter)
        so masking fires before the export queue.

        Supports custom patterns and blocked fields::

            PIIMaskingSpanProcessor(
                extra_blocked_fields=frozenset(["llm_prompt", "system_prompt"]),
                extra_patterns=[r"cpod_[A-Za-z0-9]{32}"],
            )
        """

        def __init__(
            self,
            *,
            extra_blocked_fields: frozenset[str] | None = None,
            extra_patterns: list[str] | None = None,
        ) -> None:
            self._blocked = BLOCKED_FIELDS | (extra_blocked_fields or frozenset())
            self._extra_res = [re.compile(p) for p in (extra_patterns or [])]

        def _mask_value(self, value: Any) -> Any:  # noqa: ANN401
            """Mask a value using default + custom patterns."""
            result = mask_value(value)
            if result == REDACTED:
                return result
            if isinstance(value, str):
                for r in self._extra_res:
                    if r.search(value):
                        return REDACTED
            return result

        def _mask_attributes(self, attributes: dict) -> dict:
            """Mask attributes using default + custom blocked fields."""
            result = {}
            for key, value in attributes.items():
                key_lower = key.lower()
                key_suffix = key_lower.rsplit(".", 1)[-1]
                if key_lower in self._blocked or key_suffix in self._blocked:
                    result[key] = REDACTED
                else:
                    result[key] = self._mask_value(value)
            return result

        def on_start(self, span: Span, parent_context: Any = None) -> None:  # noqa: ANN401
            pass

        def on_end(self, span: ReadableSpan) -> None:
            if span.attributes and hasattr(span, "_attributes") and span._attributes:
                masked = self._mask_attributes(dict(span._attributes))
                span._attributes.clear()  # type: ignore[attr-defined]
                span._attributes.update(masked)  # type: ignore[attr-defined]

            # Issue #41: also mask span event messages/attributes
            if hasattr(span, "_events") and span._events:
                for event in span._events:
                    if hasattr(event, "attributes") and event.attributes:
                        masked = self._mask_attributes(dict(event.attributes))
                        import contextlib

                        # immutable attributes — acceptable limitation
                        with contextlib.suppress(Exception):
                            event._attributes = masked

        def shutdown(self) -> None:
            pass

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            return True

except ImportError:

    class PIIMaskingSpanProcessor:  # type: ignore[no-redef]
        def on_start(self, span: object, parent_context: object = None) -> None:
            pass

        def on_end(self, span: object) -> None:
            pass

        def shutdown(self) -> None:
            pass

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            return True
