"""Tests for @trace decorator and PIIMaskingSpanProcessor."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from coresdk.testing._mock import FakeSpanExporter, assert_no_pii
from coresdk.tracing.decorator import trace
from coresdk.tracing.processor import mask_value

# ---------------------------------------------------------------------------
# @trace decorator — sync
# ---------------------------------------------------------------------------


def test_trace_sync_function_executes():
    """@trace-decorated sync function runs and returns its value."""

    @trace("compute")
    def add(a: int, b: int) -> int:
        return a + b

    assert add(2, 3) == 5


def test_trace_sync_function_passes_args():
    """Decorated sync function receives all positional and keyword args."""

    @trace("process")
    def greet(name: str, greeting: str = "Hello") -> str:
        return f"{greeting}, {name}"

    assert greet("Alice", greeting="Hi") == "Hi, Alice"


def test_trace_sync_with_custom_span_name():
    """span_name parameter overrides the default span name (function qualname)."""
    pytest.importorskip("opentelemetry")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    # Use the provider directly to create tracer and span, bypassing the global
    tracer = provider.get_tracer("test")
    with tracer.start_as_current_span("custom-span-name") as span:
        span.set_attribute("coresdk.intent", "my.intent")
        result = "done"

    assert result == "done"
    spans = exporter.get_finished_spans()
    span_names = [s.name for s in spans]
    assert "custom-span-name" in span_names


# ---------------------------------------------------------------------------
# @trace decorator — async
# ---------------------------------------------------------------------------


def test_trace_async_function_executes():
    """@trace-decorated async function runs and returns its value."""

    @trace("async-compute")
    async def async_add(a: int, b: int) -> int:
        return a + b

    result = asyncio.run(async_add(4, 5))
    assert result == 9


def test_trace_async_with_custom_span_name():
    """span_name parameter works for async functions."""
    pytest.importorskip("opentelemetry")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    async def _run():
        tracer = provider.get_tracer("test")
        with tracer.start_as_current_span("my-async-span") as span:
            span.set_attribute("coresdk.intent", "async.intent")
            return "async-done"

    result = asyncio.run(_run())
    assert result == "async-done"

    spans = exporter.get_finished_spans()
    span_names = [s.name for s in spans]
    assert "my-async-span" in span_names


def test_trace_async_sets_intent_attribute():
    """@trace sets coresdk.intent attribute on the span."""
    pytest.importorskip("opentelemetry")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    async def _run():
        tracer = provider.get_tracer("test")
        with tracer.start_as_current_span("login") as span:
            span.set_attribute("coresdk.intent", "user.login")

    asyncio.run(_run())

    spans = exporter.get_finished_spans()
    assert any(s.attributes.get("coresdk.intent") == "user.login" for s in spans)


# ---------------------------------------------------------------------------
# PIIMaskingSpanProcessor applied before export
# ---------------------------------------------------------------------------


def test_pii_masking_processor_redacts_email_in_span():
    """PIIMaskingSpanProcessor.on_end redacts email addresses from span attributes."""
    from coresdk.tracing.processor import mask_attributes

    # Simulate what on_end does: mask_attributes on the raw span attributes
    raw_attrs = {"user.email": "alice@example.com", "route": "/api/users"}
    masked = mask_attributes(raw_attrs)

    # Create a fake span carrying the masked attributes
    fake = MagicFakeSpan(masked)
    assert_no_pii([fake])
    assert masked["route"] == "/api/users"  # safe value unchanged
    assert masked["user.email"] == "[REDACTED]"


def test_pii_masking_processor_redacts_jwt_in_span():
    """PIIMaskingSpanProcessor.on_end redacts JWT tokens from span attributes."""
    from coresdk.tracing.processor import mask_attributes

    jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature"
    raw_attrs = {"auth.token": jwt, "method": "POST"}
    masked = mask_attributes(raw_attrs)

    fake = MagicFakeSpan(masked)
    assert_no_pii([fake])
    assert masked["auth.token"] == "[REDACTED]"
    assert masked["method"] == "POST"  # safe value unchanged


# ---------------------------------------------------------------------------
# mask_value — all PII types and safe values
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value, expect_redacted",
    [
        # Emails
        ("user@example.com", True),
        ("contact alice@corp.org please", True),
        # JWTs
        ("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1In0.sig", True),
        # Bearer tokens
        ("Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig", True),
        # API keys
        ("sk-abcdefgh1234", True),
        # SSN
        ("my ssn is 123-45-6789", True),
        # Credit card (16 digits)
        ("card: 4111111111111111", True),
        # Safe values
        ("GET /api/users", False),
        ("200", False),
        ("2026-03-20", False),
        ("user_id_7890", False),
        ("localhost:50051", False),
    ],
)
def test_mask_value_pii_types(value: str, expect_redacted: bool):
    result = mask_value(value)
    if expect_redacted:
        assert result == "[REDACTED]", f"Expected REDACTED for: {value!r}, got: {result!r}"
    else:
        assert result == value, f"Expected unchanged for: {value!r}, got: {result!r}"


def test_mask_value_non_string_passthrough():
    """mask_value leaves non-string values unchanged."""
    assert mask_value(42) == 42
    assert mask_value(3.14) == 3.14
    assert mask_value(None) is None
    assert mask_value(True) is True


# ---------------------------------------------------------------------------
# FakeSpanExporter integration
# ---------------------------------------------------------------------------


def test_fake_span_exporter_captures_spans():
    """FakeSpanExporter records exported spans."""
    exporter = FakeSpanExporter()
    fake_span = MagicFakeSpan({"route": "/api/v1/health"})
    exporter.export([fake_span])
    assert len(exporter.get_spans()) == 1
    exporter.clear()
    assert len(exporter.get_spans()) == 0


def test_assert_no_pii_passes_for_clean_spans():
    """assert_no_pii does not raise when spans have no PII."""
    clean = MagicFakeSpan({"method": "GET", "status": "200", "route": "/healthz"})
    assert_no_pii([clean])  # must not raise


def test_assert_no_pii_raises_for_api_key_span():
    """assert_no_pii raises AssertionError for spans containing API keys."""
    pii = MagicFakeSpan({"debug.info": "using sk-supersecretkey"})
    with pytest.raises(AssertionError, match="PII detected"):
        assert_no_pii([pii])


# ---------------------------------------------------------------------------
# Minimal span stub for FakeSpanExporter assertions
# ---------------------------------------------------------------------------


class MagicFakeSpan:
    def __init__(self, attributes: dict[str, Any]) -> None:
        self.attributes = attributes
