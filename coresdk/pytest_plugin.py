"""pytest plugin for CoreSDK — fixtures for testing SDK-instrumented code."""
from __future__ import annotations

import pytest

from coresdk.testing import MockSDK, FakeSpanExporter, assert_no_pii


@pytest.fixture
def mock_sdk() -> MockSDK:
    """Pre-configured MockSDK that allows all requests. No sidecar needed."""
    return MockSDK()


@pytest.fixture
def fake_exporter() -> FakeSpanExporter:
    """FakeSpanExporter that captures spans for assertion."""
    return FakeSpanExporter()


# Aliases used by some test suites
@pytest.fixture
def coresdk_mock() -> MockSDK:
    """Pre-configured MockSDK that allows all requests."""
    return MockSDK()


@pytest.fixture
def coresdk_deny() -> MockSDK:
    """MockSDK that denies all requests."""
    return MockSDK(default_allow=False)


@pytest.fixture
def coresdk_spans():
    """Provides an in-memory span exporter for asserting OTel spans.

    Requires opentelemetry-sdk. Skips if not installed.

    Usage::

        def test_something(coresdk_spans):
            spans = coresdk_spans.get_finished_spans()
            assert_no_pii(spans)
    """
    try:
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor
        from opentelemetry import trace
    except ImportError:
        pytest.skip("opentelemetry-sdk not installed")
        return

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    original = trace.get_tracer_provider()
    trace.set_tracer_provider(provider)

    yield exporter

    trace.set_tracer_provider(original)
    exporter.clear()


@pytest.fixture
def assert_no_pii_fixture(coresdk_spans):
    """Automatically asserts no PII in all finished spans after each test."""
    yield
    spans = coresdk_spans.get_finished_spans()
    assert_no_pii(spans)
