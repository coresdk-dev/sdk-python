"""@trace(intent="...") decorator — sets coresdk.intent OTel span attribute."""
import asyncio
import functools
from collections.abc import Callable
from typing import Any


def trace(intent: str, *, span_name: str | None = None) -> Callable[[Callable], Callable]:
    """Decorator that creates an OTel span with coresdk.intent attribute."""
    def decorator(func: Callable) -> Callable:
        name = span_name or func.__qualname__

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
            try:
                from opentelemetry import trace as otel_trace
                tracer = otel_trace.get_tracer("coresdk")
                with tracer.start_as_current_span(name) as span:
                    span.set_attribute("coresdk.intent", intent)
                    return await func(*args, **kwargs)
            except ImportError:
                return await func(*args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
            try:
                from opentelemetry import trace as otel_trace
                tracer = otel_trace.get_tracer("coresdk")
                with tracer.start_as_current_span(name) as span:
                    span.set_attribute("coresdk.intent", intent)
                    return func(*args, **kwargs)
            except ImportError:
                return func(*args, **kwargs)

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator
