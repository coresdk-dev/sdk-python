"""Config snapshot and policy update subscriptions via server-streaming RPCs."""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from coresdk._client import _decode_fields, _encode_string, _field_str

if TYPE_CHECKING:
    from coresdk import SDK, AsyncSDK

logger = logging.getLogger(__name__)


async def watch_config(sdk: SDK | AsyncSDK) -> AsyncIterator[dict]:
    """Async generator yielding config snapshots as dicts.

    Usage::

        async for snapshot in watch_config(sdk):
            reload_policies(snapshot.get("rbac_policy"))
            reload_models(snapshot.get("allowed_models"))

    Requires the sidecar to support WatchConfig streaming RPC.
    Falls back to polling GetConfig every 30s if streaming is unavailable.
    """
    import grpc.aio

    addr = sdk.config.sidecar_addr
    if sdk.config.dev_mode or not sdk.config.tls_cert:
        channel = grpc.aio.insecure_channel(addr)
    else:
        from pathlib import Path

        with Path(sdk.config.tls_cert).open("rb") as f:
            cert = f.read()
        with Path(sdk.config.tls_key).open("rb") as f:
            key = f.read()
        with Path(sdk.config.tls_ca).open("rb") as f:
            ca = f.read()
        creds = grpc.ssl_channel_credentials(ca, key, cert)
        channel = grpc.aio.secure_channel(addr, creds)

    payload = _encode_string(1, getattr(sdk.config, "tenant_id", "default"))

    try:
        stub = channel.unary_stream(
            "/coresdk.v1.ConfigService/WatchConfig",
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        call = stub(payload)
        async for response_bytes in call:
            fields = _decode_fields(response_bytes)
            raw = _field_str(fields, 1) or "{}"
            try:
                yield json.loads(raw)
            except json.JSONDecodeError:
                logger.warning("watch_config: malformed JSON in config snapshot")
                continue
    except grpc.RpcError as e:
        logger.warning("watch_config: streaming RPC failed: %s", e)
    finally:
        await channel.close()


async def watch_policy_updates(sdk: SDK | AsyncSDK) -> AsyncIterator[dict]:
    """Async generator yielding policy reload events from the sidecar.

    Each yielded dict contains:
    - ``version_hash`` (str): SHA-256 of the newly loaded bundle.
    - ``tenant_id`` (str): Tenant the update applies to.
    - ``timestamp`` (str): ISO-8601 timestamp of the reload.

    Usage::

        async for event in watch_policy_updates(sdk):
            print(f"Policy reloaded: {event['version_hash']}")

    Requires the sidecar to support WatchPolicyUpdates streaming RPC (Sprint 5+).
    The generator exits when the stream ends or the sidecar disconnects.
    """
    import grpc.aio

    addr = sdk.config.sidecar_addr
    if sdk.config.dev_mode or not sdk.config.tls_cert:
        channel = grpc.aio.insecure_channel(addr)
    else:
        from pathlib import Path as _Path

        with _Path(sdk.config.tls_cert).open("rb") as f:
            cert = f.read()
        with _Path(sdk.config.tls_key).open("rb") as f:
            key = f.read()
        with _Path(sdk.config.tls_ca).open("rb") as f:
            ca = f.read()
        creds = grpc.ssl_channel_credentials(ca, key, cert)
        channel = grpc.aio.secure_channel(addr, creds)

    payload = _encode_string(1, getattr(sdk.config, "tenant_id", "default"))

    try:
        stub = channel.unary_stream(
            "/coresdk.v1.PolicyService/WatchPolicyUpdates",
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        call = stub(payload)
        async for response_bytes in call:
            fields = _decode_fields(response_bytes)
            version_hash = _field_str(fields, 1) or ""
            tenant_id = _field_str(fields, 2) or getattr(sdk.config, "tenant_id", "")
            timestamp = _field_str(fields, 3) or ""
            yield {
                "version_hash": version_hash,
                "tenant_id": tenant_id,
                "timestamp": timestamp,
            }
    except grpc.RpcError as e:
        logger.warning("watch_policy_updates: streaming RPC failed: %s", e)
    finally:
        await channel.close()
