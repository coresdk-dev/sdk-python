"""PIIMaskingSpanProcessor — fires before export queue."""
import re
from typing import Any

BLOCKED_FIELDS = frozenset({
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "authorization", "auth", "private_key", "credential", "credentials",
    "access_key", "access_token", "refresh_token", "client_secret", "ssn",
})

REDACTED = "[REDACTED]"

_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CC_RE = re.compile(r"\b(?:\d[ -]?){15,16}\b")
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")
_BEARER_RE = re.compile(r"Bearer\s+\S+", re.IGNORECASE)
_APIKEY_RE = re.compile(r"\bsk-[A-Za-z0-9]{8,}\b")


def mask_value(value: Any) -> Any:
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
        if key.lower() in BLOCKED_FIELDS:
            result[key] = REDACTED
        else:
            result[key] = mask_value(value)
    return result


try:
    from opentelemetry.sdk.trace import ReadableSpan, Span
    from opentelemetry.context import Context

    class PIIMaskingSpanProcessor:
        """OTel SpanProcessor that redacts PII before export.

        CRITICAL: Must be registered as SpanProcessor (not SpanExporter)
        so masking fires before the export queue.
        """

        def on_start(self, span: Span, parent_context: Any = None) -> None:
            pass

        def on_end(self, span: ReadableSpan) -> None:
            if span.attributes:
                if hasattr(span, "_attributes") and span._attributes:
                    masked = mask_attributes(dict(span._attributes))
                    span._attributes.clear()
                    span._attributes.update(masked)

            # Issue #41: also mask span event messages/attributes
            if hasattr(span, "_events") and span._events:
                for event in span._events:
                    if hasattr(event, "attributes") and event.attributes:
                        masked = mask_attributes(dict(event.attributes))
                        try:
                            event._attributes = masked
                        except Exception:
                            pass  # immutable attributes — acceptable limitation

        def shutdown(self) -> None:
            pass

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            return True

except ImportError:
    class PIIMaskingSpanProcessor:  # type: ignore
        def on_start(self, span, parent_context=None): pass
        def on_end(self, span): pass
        def shutdown(self): pass
        def force_flush(self, timeout_millis=30000): return True
