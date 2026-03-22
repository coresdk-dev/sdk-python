"""Resilience decorators — circuit breaker, retry with backoff, and timeout.

Recommended stacking order (outermost first)::

    @retry(max_attempts=3)
    @circuit_breaker(failure_threshold=5)
    @timeout(ms=3000)
    async def call_service(): ...
"""

from __future__ import annotations

import asyncio
import enum
import functools
import logging
import os
import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, TypeVar, overload

from coresdk.errors._rfc9457 import ProblemDetailError

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


# ---------------------------------------------------------------------------
# Circuit breaker state machine
# ---------------------------------------------------------------------------


class CircuitState(enum.Enum):
    """States for a circuit breaker."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    """Thread-safe circuit breaker with automatic OPEN -> HALF_OPEN recovery.

    Args:
        name: Identifier for this breaker instance.
        failure_threshold: Number of consecutive failures before opening the circuit.
        recovery_timeout_s: Seconds to wait in OPEN state before transitioning to HALF_OPEN.
    """

    name: str
    failure_threshold: int = 5
    recovery_timeout_s: float = 30.0

    _state: CircuitState = field(default=CircuitState.CLOSED, init=False, repr=False)
    _failure_count: int = field(default=0, init=False, repr=False)
    _opened_at: float = field(default=0.0, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    @property
    def state(self) -> CircuitState:
        """Return the current state, auto-transitioning OPEN -> HALF_OPEN after recovery timeout."""
        with self._lock:
            if self._state is CircuitState.OPEN:
                elapsed = time.monotonic() - self._opened_at
                if elapsed >= self.recovery_timeout_s:
                    self._state = CircuitState.HALF_OPEN
                    logger.debug(
                        "CircuitBreaker[%s]: OPEN -> HALF_OPEN after %.1fs",
                        self.name,
                        elapsed,
                    )
            return self._state

    @property
    def failure_count(self) -> int:
        """Current consecutive failure count."""
        with self._lock:
            return self._failure_count

    @property
    def opened_at(self) -> float:
        """Monotonic timestamp when the circuit was last opened (0.0 if not open)."""
        with self._lock:
            return self._opened_at

    def record_success(self) -> None:
        """Record a successful call — reset to CLOSED."""
        with self._lock:
            previous = self._state
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._opened_at = 0.0
        if previous is not CircuitState.CLOSED:
            logger.info("CircuitBreaker[%s]: %s -> CLOSED (success)", self.name, previous.value)

    def record_failure(self) -> None:
        """Record a failed call — open the circuit when threshold is reached."""
        with self._lock:
            self._failure_count += 1
            threshold_hit = self._failure_count >= self.failure_threshold
            if threshold_hit and self._state is not CircuitState.OPEN:
                self._state = CircuitState.OPEN
                self._opened_at = time.monotonic()
                logger.warning(
                    "CircuitBreaker[%s]: -> OPEN after %d failures",
                    self.name,
                    self._failure_count,
                )


# ---------------------------------------------------------------------------
# Circuit breaker registry
# ---------------------------------------------------------------------------


class CircuitBreakerRegistry:
    """Named registry of :class:`CircuitBreaker` instances.

    Use :meth:`from_env` to create a registry pre-configured from environment
    variables, or instantiate directly for manual control.
    """

    def __init__(
        self,
        *,
        default_failure_threshold: int = 5,
        default_recovery_timeout_s: float = 30.0,
    ) -> None:
        self._default_failure_threshold = default_failure_threshold
        self._default_recovery_timeout_s = default_recovery_timeout_s
        self._breakers: dict[str, CircuitBreaker] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls) -> CircuitBreakerRegistry:
        """Create a registry reading defaults from environment variables.

        Supported env vars:
            CORESDK_CB_FAILURE_THRESHOLD  (int, default 5)
            CORESDK_CB_RECOVERY_TIMEOUT_S (float, default 30.0)
        """
        threshold = int(os.environ.get("CORESDK_CB_FAILURE_THRESHOLD", "5"))
        timeout_s = float(os.environ.get("CORESDK_CB_RECOVERY_TIMEOUT_S", "30.0"))
        return cls(default_failure_threshold=threshold, default_recovery_timeout_s=timeout_s)

    def get_or_create(self, name: str, **kwargs: Any) -> CircuitBreaker:  # noqa: ANN401
        """Return the breaker for *name*, creating one if it does not exist.

        Extra *kwargs* (``failure_threshold``, ``recovery_timeout_s``) are
        forwarded to :class:`CircuitBreaker` only when a new instance is created.
        """
        with self._lock:
            if name not in self._breakers:
                ft = kwargs.get("failure_threshold", self._default_failure_threshold)
                rt = kwargs.get("recovery_timeout_s", self._default_recovery_timeout_s)
                self._breakers[name] = CircuitBreaker(
                    name=name,
                    failure_threshold=ft,
                    recovery_timeout_s=rt,
                )
            return self._breakers[name]

    def get_state(self, name: str) -> CircuitState:
        """Return the current state of breaker *name*.

        Raises:
            KeyError: If no breaker with the given name has been registered.
        """
        with self._lock:
            breaker = self._breakers.get(name)
        if breaker is None:
            raise KeyError(f"No circuit breaker registered with name {name!r}")
        return breaker.state

    def breaker(self, name: str, **kwargs: Any) -> Callable[[F], F]:  # noqa: ANN401
        """Decorator that wraps an async function with a named circuit breaker.

        Usage::

            registry = CircuitBreakerRegistry.from_env()

            @registry.breaker("my-service")
            async def call_my_service() -> str:
                ...

        Raises:
            ProblemDetailError: When the circuit is OPEN at call time (HTTP 503).
        """
        cb = self.get_or_create(name, **kwargs)

        def decorator(func: F) -> F:
            import inspect

            if not inspect.iscoroutinefunction(func):
                raise TypeError(
                    f"@circuit_breaker / registry.breaker() requires an async function, "
                    f"got sync function {func.__qualname__!r}. "
                    f"Wrap with `async def` or use a thread pool executor."
                )

            @functools.wraps(func)
            async def wrapper(*args: Any, **kw: Any) -> Any:  # noqa: ANN401
                current = cb.state
                if current is CircuitState.OPEN:
                    raise ProblemDetailError(
                        "Service Unavailable",
                        503,
                        detail=f"Circuit breaker {cb.name!r} is OPEN — call rejected",
                        type_uri="https://coresdk.io/errors/circuit-open",
                    )
                try:
                    result = await func(*args, **kw)
                except Exception:
                    cb.record_failure()
                    raise
                else:
                    cb.record_success()
                    return result

            return wrapper  # type: ignore[return-value]

        return decorator


# ---------------------------------------------------------------------------
# @retry decorator
# ---------------------------------------------------------------------------


@overload
def retry(func: F) -> F: ...


@overload
def retry(
    *,
    max_attempts: int = 3,
    backoff_ms: int = 100,
    max_backoff_ms: int = 5000,
) -> Callable[[F], F]: ...


def retry(
    func: F | None = None,
    *,
    max_attempts: int = 3,
    backoff_ms: int = 100,
    max_backoff_ms: int = 5000,
) -> F | Callable[[F], F]:
    """Retry an async function with exponential backoff and jitter.

    Can be used with or without arguments::

        @retry
        async def fetch(): ...

        @retry(max_attempts=5, backoff_ms=200)
        async def fetch(): ...

    The delay between attempt *n* and *n+1* is::

        base = min(backoff_ms * 2 ** n, max_backoff_ms)
        delay = base * random.uniform(0.75, 1.25)   # +-25% jitter
    """

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
            last_exc: Exception | None = None
            for attempt in range(max_attempts):
                try:
                    return await fn(*args, **kwargs)
                except Exception as exc:
                    last_exc = exc
                    if attempt + 1 >= max_attempts:
                        break
                    base_delay_ms = min(backoff_ms * (2**attempt), max_backoff_ms)
                    jitter = random.uniform(0.75, 1.25)  # noqa: S311
                    delay_s = (base_delay_ms * jitter) / 1000.0
                    logger.debug(
                        "retry: attempt %d/%d failed (%s), sleeping %.3fs",
                        attempt + 1,
                        max_attempts,
                        exc,
                        delay_s,
                    )
                    await asyncio.sleep(delay_s)
            raise last_exc  # type: ignore[misc]

        return wrapper  # type: ignore[return-value]

    if func is not None:
        # Called as @retry without parentheses
        return decorator(func)
    return decorator


# ---------------------------------------------------------------------------
# @circuit_breaker decorator
# ---------------------------------------------------------------------------


def circuit_breaker(
    *,
    failure_threshold: int = 5,
    recovery_timeout_s: float = 30.0,
) -> Callable[[F], F]:
    """Decorator that wraps an async function with an anonymous circuit breaker.

    Usage::

        @circuit_breaker(failure_threshold=3, recovery_timeout_s=10.0)
        async def call_external() -> dict:
            ...

    Raises:
        ProblemDetailError: When the circuit is OPEN at call time (HTTP 503).
    """

    def decorator(func: F) -> F:
        import inspect

        if not inspect.iscoroutinefunction(func):
            raise TypeError(
                f"@circuit_breaker / registry.breaker() requires an async function, "
                f"got sync function {func.__qualname__!r}. "
                f"Wrap with `async def` or use a thread pool executor."
            )

        cb = CircuitBreaker(
            name=f"_anon_{func.__module__}.{func.__qualname__}",
            failure_threshold=failure_threshold,
            recovery_timeout_s=recovery_timeout_s,
        )

        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
            current = cb.state
            if current is CircuitState.OPEN:
                raise ProblemDetailError(
                    "Service Unavailable",
                    503,
                    detail=f"Circuit breaker {cb.name!r} is OPEN — call rejected",
                    type_uri="https://coresdk.io/errors/circuit-open",
                )
            try:
                result = await func(*args, **kwargs)
            except Exception:
                cb.record_failure()
                raise
            else:
                cb.record_success()
                return result

        # Expose the breaker instance for testing / introspection.
        wrapper._circuit_breaker = cb  # type: ignore[attr-defined]
        return wrapper  # type: ignore[return-value]

    return decorator


# ---------------------------------------------------------------------------
# @timeout decorator
# ---------------------------------------------------------------------------


def timeout(*, ms: int = 5000) -> Callable[[F], F]:
    """Decorator that enforces an async timeout on the wrapped function.

    Uses :func:`asyncio.wait_for` under the hood.

    Usage::

        @timeout(ms=3000)
        async def slow_call() -> str:
            ...

    Raises:
        asyncio.TimeoutError: When the function does not complete within *ms* milliseconds.
    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
            return await asyncio.wait_for(func(*args, **kwargs), timeout=ms / 1000.0)

        return wrapper  # type: ignore[return-value]

    return decorator


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "CircuitBreaker",
    "CircuitBreakerRegistry",
    "CircuitState",
    "circuit_breaker",
    "retry",
    "timeout",
]
