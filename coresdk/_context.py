"""Internal context variables shared across coresdk modules.

This module exists to avoid circular imports between __init__.py and middleware modules.
"""

from __future__ import annotations

import contextvars

_current_request_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    "coresdk_request_id", default=""
)
_current_tenant: contextvars.ContextVar[str] = contextvars.ContextVar(
    "coresdk_tenant_id", default=""
)
_current_user: contextvars.ContextVar[str] = contextvars.ContextVar("coresdk_user_id", default="")
