"""Native ``grpc.aio`` client for the CoreSDK ``JobService``.

Mirrors :mod:`coresdk._jobs` but uses :mod:`grpc.aio` so the AsyncSDK no
longer has to bridge sync grpcio through ``asyncio.to_thread``. Wire
encoding/decoding is shared with the sync path — only the channel and stub
types change.

For unary RPCs this saves a thread hop per call. For streaming RPCs
(``WatchJob``, ``GetJobLogs``) it's load-bearing — each stream previously
burned one OS thread for its lifetime.
"""

from __future__ import annotations

from typing import AsyncIterator, Any

import grpc.aio

# Decoders and request encoders are pure functions shared with the sync path.
from coresdk._jobs import (
    _decode_fields,
    _decode_job,
    _decode_job_event,
    _decode_job_output,
    _decode_log_line,
    _encode_message,
    _encode_string,
    _encode_varint_field,
    encode_simple_job_request,
)
from coresdk.jobs import Job, JobEvent, JobOutput, LogLine


class AsyncJobsClient:
    """Native async gRPC client. Owned by ``AsyncSDK``; not constructed directly."""

    def __init__(self, async_sdk_client: Any):
        # ``async_sdk_client`` is the AsyncCoreSDKClient living on AsyncSDK.
        # We piggyback on its channel + metadata to avoid double-opening the
        # connection.
        self._client = async_sdk_client

    async def _channel(self) -> grpc.aio.Channel | None:
        return await self._client._get_channel()

    @property
    def _metadata(self):
        return self._client._metadata

    async def submit_job(self, payload: bytes) -> Job:
        ch = await self._channel()
        if ch is None:
            raise RuntimeError("sidecar unavailable — JobService cannot be reached")
        stub = ch.unary_unary(
            "/coresdk.v1.JobService/SubmitJob",
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        resp = await stub(payload, metadata=self._metadata)
        return _decode_job(resp)

    async def get_job(self, job_id: str, tenant_id: str) -> Job:
        ch = await self._channel()
        if ch is None:
            raise RuntimeError("sidecar unavailable")
        payload = encode_simple_job_request(2, job_id, tenant_id)
        stub = ch.unary_unary(
            "/coresdk.v1.JobService/GetJob",
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        resp = await stub(payload, metadata=self._metadata)
        return _decode_job(resp)

    async def cancel_job(self, job_id: str, tenant_id: str, reason: str = "") -> Job:
        ch = await self._channel()
        if ch is None:
            raise RuntimeError("sidecar unavailable")
        payload = _encode_string(1, job_id) + _encode_string(2, reason)
        payload += _encode_message(3, _encode_string(1, tenant_id))
        stub = ch.unary_unary(
            "/coresdk.v1.JobService/CancelJob",
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        resp = await stub(payload, metadata=self._metadata)
        return _decode_job(resp)

    async def list_jobs(
        self,
        tenant_id: str,
        state_filter: str = "",
        limit: int = 100,
    ) -> list[Job]:
        ch = await self._channel()
        if ch is None:
            raise RuntimeError("sidecar unavailable")
        payload = _encode_message(1, _encode_string(1, tenant_id))
        payload += _encode_string(2, state_filter)
        if limit:
            payload += _encode_varint_field(3, limit)
        stub = ch.unary_unary(
            "/coresdk.v1.JobService/ListJobs",
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        resp = await stub(payload, metadata=self._metadata)
        f = _decode_fields(resp)
        return [_decode_job(raw) for raw in f.get(1, [])]

    async def get_job_output(
        self, job_id: str, tenant_id: str, presign_ttl_seconds: int = 900
    ) -> JobOutput:
        ch = await self._channel()
        if ch is None:
            raise RuntimeError("sidecar unavailable")
        payload = _encode_string(1, job_id)
        if presign_ttl_seconds:
            payload += _encode_varint_field(2, presign_ttl_seconds)
        payload += _encode_message(3, _encode_string(1, tenant_id))
        stub = ch.unary_unary(
            "/coresdk.v1.JobService/GetJobOutput",
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        resp = await stub(payload, metadata=self._metadata)
        return _decode_job_output(resp)

    async def watch_job(
        self, job_id: str, tenant_id: str
    ) -> AsyncIterator[JobEvent]:
        ch = await self._channel()
        if ch is None:
            raise RuntimeError("sidecar unavailable")
        payload = _encode_string(1, job_id)
        payload += _encode_message(3, _encode_string(1, tenant_id))
        stub = ch.unary_stream(
            "/coresdk.v1.JobService/WatchJob",
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        call = stub(payload, metadata=self._metadata)
        async for resp in call:
            yield _decode_job_event(resp)

    async def stream_job_logs(
        self,
        job_id: str,
        tenant_id: str,
        follow: bool = True,
        tail_lines: int = 0,
    ) -> AsyncIterator[LogLine]:
        ch = await self._channel()
        if ch is None:
            raise RuntimeError("sidecar unavailable")
        payload = _encode_string(1, job_id)
        if follow:
            payload += _encode_varint_field(2, 1)
        if tail_lines:
            payload += _encode_varint_field(3, tail_lines)
        payload += _encode_message(4, _encode_string(1, tenant_id))
        stub = ch.unary_stream(
            "/coresdk.v1.JobService/GetJobLogs",
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        call = stub(payload, metadata=self._metadata)
        async for resp in call:
            line = _decode_log_line(resp)
            line.job_id = job_id
            yield line
