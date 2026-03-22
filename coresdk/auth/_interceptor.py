"""gRPC auth interceptor — attaches JWT to outgoing calls."""

from __future__ import annotations

from collections.abc import Callable

import grpc


class JwtClientInterceptor(grpc.UnaryUnaryClientInterceptor):
    """Attaches a Bearer JWT to every outgoing unary gRPC call.

    Usage::

        interceptor = JwtClientInterceptor(token_fn=lambda: my_token)
        channel = grpc.intercept_channel(channel, interceptor)
    """

    def __init__(self, token_fn: Callable[[], str]) -> None:
        self._token_fn = token_fn

    def intercept_unary_unary(
        self,
        continuation: Callable,
        client_call_details: grpc.ClientCallDetails,
        request: object,
    ) -> grpc.Future:
        metadata = list(client_call_details.metadata or [])
        token = self._token_fn()
        if token:
            metadata.append(("authorization", f"Bearer {token}"))
        new_details = _ClientCallDetails(client_call_details, metadata)
        return continuation(new_details, request)


class _ClientCallDetails(grpc.ClientCallDetails):
    """Mutable copy of ClientCallDetails with updated metadata."""

    def __init__(
        self,
        original: grpc.ClientCallDetails,
        metadata: list,
    ) -> None:
        self.method = original.method
        self.timeout = original.timeout
        self.metadata = metadata
        self.credentials = original.credentials
        self.wait_for_ready = original.wait_for_ready
        self.compression = original.compression
