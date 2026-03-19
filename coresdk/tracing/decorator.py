"""@trace(intent="...") decorator — sets coresdk.intent OTel span attribute."""
import functools
from typing import Callable, Optional


def trace(intent: str, *, span_name: Optional[str] = None):
    """Decorator that creates an OTel span with coresdk.intent attribute."""
    def decorator(func: Callable) -> Callable:
        name = span_name or func.__qualname__

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                from opentelemetry import trace as otel_trace
                tracer = otel_trace.get_tracer("coresdk")
                with tracer.start_as_current_span(name) as span:
                    span.set_attribute("coresdk.intent", intent)
                    return await func(*args, **kwargs)
            except ImportError:
                return await func(*args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                from opentelemetry import trace as otel_trace
                tracer = otel_trace.get_tracer("coresdk")
                with tracer.start_as_current_span(name) as span:
                    span.set_attribute("coresdk.intent", intent)
                    return func(*args, **kwargs)
            except ImportError:
                return func(*args, **kwargs)

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator
