"""CoreSDK structlog integration — injects request context into log events."""

from __future__ import annotations

from typing import Any

try:
    import structlog  # noqa: F401

    _structlog_available = True
except ImportError:
    _structlog_available = False


def coresdk_structlog_processor(
    logger: Any,  # noqa: ANN401
    method: str,
    event_dict: dict,
) -> dict:
    """Structlog processor that injects CoreSDK context vars into every log event.

    Injects: request_id, tenant_id, user_id from coresdk ContextVars.

    Usage::

        import structlog
        from coresdk.logging import coresdk_structlog_processor

        structlog.configure(
            processors=[
                coresdk_structlog_processor,
                structlog.processors.JSONRenderer(),
            ]
        )
    """
    from coresdk._context import _current_request_id, _current_tenant, _current_user

    request_id = _current_request_id.get()
    tenant_id = _current_tenant.get()
    user_id = _current_user.get()

    if request_id:
        event_dict.setdefault("request_id", request_id)
    if tenant_id:
        event_dict.setdefault("tenant_id", tenant_id)
    if user_id:
        event_dict.setdefault("user_id", user_id)

    return event_dict
