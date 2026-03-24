"""CoreSDK egress wrappers — SSRF-safe HTTP clients."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._client import CoreSDKClient

try:
    import requests

    class CoreSDKSession(requests.Session):
        """A requests.Session that checks egress policy before each request."""

        def __init__(self, sdk: CoreSDKClient) -> None:
            super().__init__()
            self._sdk = sdk

        def send(  # type: ignore[override]
            self,
            request: requests.PreparedRequest,
            **kwargs: bool | str | None | float,
        ) -> requests.Response:
            decision = self._sdk.check_egress(str(request.url) if request.url else "")
            if not decision.allowed:
                raise PermissionError(f"CoreSDK egress blocked: {decision.reason}")
            return super().send(request, **kwargs)  # type: ignore[arg-type]

except ImportError:
    pass  # requests not installed

try:
    import httpx

    class CoreSDKTransport(httpx.BaseTransport):
        """An httpx transport that checks egress policy before each request."""

        def __init__(self, sdk: CoreSDKClient, inner: httpx.BaseTransport | None = None) -> None:
            self._sdk = sdk
            self._inner = inner or httpx.HTTPTransport()

        def handle_request(self, request: httpx.Request) -> httpx.Response:
            decision = self._sdk.check_egress(str(request.url))
            if not decision.allowed:
                raise PermissionError(f"CoreSDK egress blocked: {decision.reason}")
            return self._inner.handle_request(request)

except ImportError:
    pass  # httpx not installed
