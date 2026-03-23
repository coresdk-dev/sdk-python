"""Error-handling decorators that eliminate try/except boilerplate."""

from __future__ import annotations

import functools
import inspect
import logging
from collections.abc import Callable
from typing import Any, TypeVar

from coresdk.errors._rfc9457 import ProblemDetailError

logger = logging.getLogger(__name__)
F = TypeVar("F", bound=Callable[..., Any])


def _get_tracer() -> Any:  # noqa: ANN401
    """Lazy tracer getter — fetched at call time, not import time."""
    try:
        from opentelemetry import trace as otel_trace

        return otel_trace.get_tracer("coresdk")
    except ImportError:
        return None


def coresdk_route(operation: str = "") -> Callable[[F], F]:
    """Decorator for FastAPI route handlers.

    Auto-converts exceptions to RFC 9457 ProblemDetail JSON responses
    with correct HTTP status codes. Creates an OTel span if available.

    Usage::

        @app.post("/workflows")
        @coresdk_route(operation="create_workflow")
        async def create_workflow(data: WorkflowCreate):
            # just logic — no try/except needed
            return await service.create(data)
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
            span_name = operation or func.__name__
            tracer = _get_tracer()
            if tracer is not None:
                with tracer.start_as_current_span(span_name) as span:
                    span.set_attribute("coresdk.operation", span_name)
                    try:
                        return await func(*args, **kwargs)
                    except ProblemDetailError:
                        raise  # already an RFC 9457 error — pass through
                    except Exception as exc:
                        logger.exception("coresdk_route[%s]: unhandled error", span_name)
                        raise ProblemDetailError(
                            title="Internal Server Error",
                            status=500,
                            detail=str(exc),
                            type_uri="https://coresdk.io/errors/internal",
                        ) from exc
            else:
                try:
                    return await func(*args, **kwargs)
                except ProblemDetailError:
                    raise
                except Exception as exc:
                    logger.exception("coresdk_route[%s]: unhandled error", span_name)
                    raise ProblemDetailError(
                        title="Internal Server Error",
                        status=500,
                        detail=str(exc),
                        type_uri="https://coresdk.io/errors/internal",
                    ) from exc

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
            span_name = operation or func.__name__
            tracer = _get_tracer()
            if tracer is not None:
                with tracer.start_as_current_span(span_name) as span:
                    span.set_attribute("coresdk.operation", span_name)
                    try:
                        return func(*args, **kwargs)
                    except ProblemDetailError:
                        raise
                    except Exception as exc:
                        logger.exception("coresdk_route[%s]: unhandled error", span_name)
                        raise ProblemDetailError(
                            title="Internal Server Error",
                            status=500,
                            detail=str(exc),
                            type_uri="https://coresdk.io/errors/internal",
                        ) from exc
            else:
                try:
                    return func(*args, **kwargs)
                except ProblemDetailError:
                    raise
                except Exception as exc:
                    logger.exception("coresdk_route[%s]: unhandled error", span_name)
                    raise ProblemDetailError(
                        title="Internal Server Error",
                        status=500,
                        detail=str(exc),
                        type_uri="https://coresdk.io/errors/internal",
                    ) from exc

        if inspect.iscoroutinefunction(func):
            return async_wrapper  # type: ignore[return-value]
        return sync_wrapper  # type: ignore[return-value]

    return decorator


def coresdk_service(operation: str = "") -> Callable[[F], F]:
    """Decorator for service-layer functions.

    Auto-converts exceptions to ProblemDetailError with appropriate status.
    Re-raises ProblemDetailError unchanged. Creates an OTel span if available.

    Usage::

        @coresdk_service(operation="process_payment")
        async def process_payment(tenant_id: str, amount: float):
            # just logic — exceptions auto-wrapped
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
            span_name = operation or func.__name__
            tracer = _get_tracer()
            if tracer is not None:
                with tracer.start_as_current_span(span_name) as span:
                    span.set_attribute("coresdk.operation", span_name)
                    try:
                        return await func(*args, **kwargs)
                    except ProblemDetailError:
                        raise
                    except ValueError as exc:
                        raise ProblemDetailError(
                            title="Bad Request",
                            status=400,
                            detail=str(exc),
                            type_uri="https://coresdk.io/errors/bad-request",
                        ) from exc
                    except PermissionError as exc:
                        raise ProblemDetailError(
                            title="Forbidden",
                            status=403,
                            detail=str(exc),
                            type_uri="https://coresdk.io/errors/forbidden",
                        ) from exc
                    except LookupError as exc:
                        raise ProblemDetailError(
                            title="Not Found",
                            status=404,
                            detail=str(exc),
                            type_uri="https://coresdk.io/errors/not-found",
                        ) from exc
                    except Exception as exc:
                        logger.exception(
                            "coresdk_service[%s]: unhandled error",
                            span_name,
                        )
                        raise ProblemDetailError(
                            title="Internal Server Error",
                            status=500,
                            detail=str(exc),
                            type_uri="https://coresdk.io/errors/internal",
                        ) from exc
            else:
                try:
                    return await func(*args, **kwargs)
                except ProblemDetailError:
                    raise
                except ValueError as exc:
                    raise ProblemDetailError(
                        title="Bad Request",
                        status=400,
                        detail=str(exc),
                        type_uri="https://coresdk.io/errors/bad-request",
                    ) from exc
                except PermissionError as exc:
                    raise ProblemDetailError(
                        title="Forbidden",
                        status=403,
                        detail=str(exc),
                        type_uri="https://coresdk.io/errors/forbidden",
                    ) from exc
                except LookupError as exc:
                    raise ProblemDetailError(
                        title="Not Found",
                        status=404,
                        detail=str(exc),
                        type_uri="https://coresdk.io/errors/not-found",
                    ) from exc
                except Exception as exc:
                    logger.exception(
                        "coresdk_service[%s]: unhandled error",
                        span_name,
                    )
                    raise ProblemDetailError(
                        title="Internal Server Error",
                        status=500,
                        detail=str(exc),
                        type_uri="https://coresdk.io/errors/internal",
                    ) from exc

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
            span_name = operation or func.__name__
            tracer = _get_tracer()
            if tracer is not None:
                with tracer.start_as_current_span(span_name) as span:
                    span.set_attribute("coresdk.operation", span_name)
                    try:
                        return func(*args, **kwargs)
                    except ProblemDetailError:
                        raise
                    except ValueError as exc:
                        raise ProblemDetailError(
                            title="Bad Request",
                            status=400,
                            detail=str(exc),
                            type_uri="https://coresdk.io/errors/bad-request",
                        ) from exc
                    except PermissionError as exc:
                        raise ProblemDetailError(
                            title="Forbidden",
                            status=403,
                            detail=str(exc),
                            type_uri="https://coresdk.io/errors/forbidden",
                        ) from exc
                    except LookupError as exc:
                        raise ProblemDetailError(
                            title="Not Found",
                            status=404,
                            detail=str(exc),
                            type_uri="https://coresdk.io/errors/not-found",
                        ) from exc
                    except Exception as exc:
                        logger.exception(
                            "coresdk_service[%s]: unhandled error",
                            span_name,
                        )
                        raise ProblemDetailError(
                            title="Internal Server Error",
                            status=500,
                            detail=str(exc),
                            type_uri="https://coresdk.io/errors/internal",
                        ) from exc
            else:
                try:
                    return func(*args, **kwargs)
                except ProblemDetailError:
                    raise
                except ValueError as exc:
                    raise ProblemDetailError(
                        title="Bad Request",
                        status=400,
                        detail=str(exc),
                        type_uri="https://coresdk.io/errors/bad-request",
                    ) from exc
                except PermissionError as exc:
                    raise ProblemDetailError(
                        title="Forbidden",
                        status=403,
                        detail=str(exc),
                        type_uri="https://coresdk.io/errors/forbidden",
                    ) from exc
                except LookupError as exc:
                    raise ProblemDetailError(
                        title="Not Found",
                        status=404,
                        detail=str(exc),
                        type_uri="https://coresdk.io/errors/not-found",
                    ) from exc
                except Exception as exc:
                    logger.exception(
                        "coresdk_service[%s]: unhandled error",
                        span_name,
                    )
                    raise ProblemDetailError(
                        title="Internal Server Error",
                        status=500,
                        detail=str(exc),
                        type_uri="https://coresdk.io/errors/internal",
                    ) from exc

        if inspect.iscoroutinefunction(func):
            return async_wrapper  # type: ignore[return-value]
        return sync_wrapper  # type: ignore[return-value]

    return decorator
