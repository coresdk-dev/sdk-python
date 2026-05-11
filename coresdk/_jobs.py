"""gRPC wire encoding for the CoreSDK ``JobService``.

Manual prost-style wire encoding — keeps the SDK protoc-free, mirroring the
patterns in :mod:`coresdk._client`. All seven RPCs are exposed:

- ``SubmitJob`` (unary)
- ``GetJob`` (unary)
- ``ListJobs`` (unary)
- ``CancelJob`` (unary)
- ``WatchJob`` (server-streaming → :class:`coresdk.jobs.JobEvent`)
- ``GetJobLogs`` (server-streaming → :class:`coresdk.jobs.LogLine`)
- ``GetJobOutput`` (unary)

Both sync and async paths are provided; the async path is a thin wrapper that
runs the sync stub inside a thread executor for ``submit/get/cancel`` (which
are RPC-bounded by single round trips) and uses a true ``grpc.aio`` streaming
stub for ``watch_job`` and ``stream_job_logs``.
"""

from __future__ import annotations

from typing import Any, Iterator

import grpc

from coresdk._client import (  # noqa: F401  (re-use existing helpers)
    _decode_fields,
    _encode_string,
    _encode_varint_field,
    _field_bool,
    _field_int,
    _field_str,
    _varint,
)
from coresdk.jobs import Job, JobEvent, JobOutput, LogLine, OutputFile, SecretRef

# Proto wire layout — keep these in sync with proto/coresdk/v1/jobs.proto.
#
# SubmitJobRequest:
#   1: kind, 2: image, 3: command repeated, 4: args repeated,
#   5: env map<string,string>, 6: Input, 7: SecretRef repeated,
#   8: secret_bundles repeated, 9: ResourceLimits, 10: timeout_seconds u32,
#   11: capture_logs bool, 12: capture_output bool, 13: output_prefix,
#   14: TenantContext, 15: user_id, 16: RequestMetadata
#
# Input:
#   1: InlineFiles (oneof), 2: input_s3_uri (oneof)
# InlineFiles:
#   1: files map<string, bytes>
# SecretRef:
#   1: name, 2: provider, 3: path, 4: version, 5: delivery enum
#
# Job:
#   1: job_id, 2: kind, 3: image, 4: state enum, 5: exit_code,
#   6: error, 7: input_s3_uri, 8: output_s3_uri, 9: logs_s3_uri,
#   10..12: timestamps, 13: tenant_id, 14: user_id, 15/16: k8s_*
#   17: resolved_secret_names repeated
#
# JobEvent:
#   1: job_id, 2: ts,  10: Created, 11: Scheduled, 12: Started,
#   13: Progress, 14: Succeeded, 15: Failed, 16: Cancelled


def _encode_bytes(field_num: int, value: bytes) -> bytes:
    tag = (field_num << 3) | 2
    return _varint(tag) + _varint(len(value)) + value


def _encode_message(field_num: int, payload: bytes) -> bytes:
    """Encode a nested message field."""
    tag = (field_num << 3) | 2
    return _varint(tag) + _varint(len(payload)) + payload


def _encode_string_map_entry(key: str, value: str) -> bytes:
    """One map<string,string> entry — itself a length-delimited submessage."""
    return _encode_string(1, key) + _encode_string(2, value)


def _encode_bytes_map_entry(key: str, value: bytes) -> bytes:
    """One map<string,bytes> entry."""
    return _encode_string(1, key) + _encode_bytes(2, value)


def _encode_string_map(field_num: int, m: dict[str, str]) -> bytes:
    out = b""
    for k, v in m.items():
        out += _encode_message(field_num, _encode_string_map_entry(k, v))
    return out


def _encode_bytes_map(field_num: int, m: dict[str, bytes]) -> bytes:
    out = b""
    for k, v in m.items():
        out += _encode_message(field_num, _encode_bytes_map_entry(k, v))
    return out


def _encode_tenant(tenant_id: str) -> bytes:
    """TenantContext { string tenant_id = 1; }"""
    if not tenant_id:
        return b""
    return _encode_message(14, _encode_string(1, tenant_id))


def _encode_secret_ref(r: SecretRef) -> bytes:
    payload = (
        _encode_string(1, r.name)
        + _encode_string(2, r.provider)
        + _encode_string(3, r.path)
        + _encode_string(4, r.version)
    )
    # delivery enum
    if r.delivery == "env":
        payload += _encode_varint_field(5, 1)
    elif r.delivery == "file":
        payload += _encode_varint_field(5, 2)
    return _encode_message(7, payload)


def _encode_input(
    inline_files: dict[str, bytes] | None,
    input_s3_uri: str | None,
) -> bytes:
    if inline_files:
        inline = _encode_bytes_map(1, inline_files)
        payload = _encode_message(1, inline)
        return _encode_message(6, payload)
    if input_s3_uri:
        payload = _encode_string(2, input_s3_uri)
        return _encode_message(6, payload)
    return b""


def encode_submit_job_request(
    *,
    kind: str,
    image: str,
    command: list[str],
    args: list[str],
    env: dict[str, str],
    inline_files: dict[str, bytes] | None,
    input_s3_uri: str | None,
    secret_refs: list[SecretRef],
    secret_bundles: list[str],
    timeout_seconds: int,
    capture_logs: bool,
    capture_output: bool,
    output_prefix: str,
    tenant_id: str,
    user_id: str,
) -> bytes:
    payload = _encode_string(1, kind) + _encode_string(2, image)
    for c in command:
        payload += _encode_string(3, c)
    for a in args:
        payload += _encode_string(4, a)
    payload += _encode_string_map(5, env)
    payload += _encode_input(inline_files, input_s3_uri)
    for r in secret_refs:
        payload += _encode_secret_ref(r)
    for b in secret_bundles:
        payload += _encode_string(8, b)
    if timeout_seconds:
        payload += _encode_varint_field(10, timeout_seconds)
    if capture_logs:
        payload += _encode_varint_field(11, 1)
    if capture_output:
        payload += _encode_varint_field(12, 1)
    if output_prefix:
        payload += _encode_string(13, output_prefix)
    payload += _encode_tenant(tenant_id)
    payload += _encode_string(15, user_id)
    return payload


def encode_simple_job_request(field_offset_for_tenant: int, job_id: str, tenant_id: str) -> bytes:
    """GetJobRequest / CancelJobRequest / WatchJobRequest skeleton — they all
    carry ``job_id`` (1) and ``tenant`` at the same tag offset.
    """
    payload = _encode_string(1, job_id)
    payload += _encode_message(field_offset_for_tenant, _encode_string(1, tenant_id))
    return payload


_JOB_STATE = {
    0: "pending",
    1: "pending",
    2: "scheduling",
    3: "running",
    4: "succeeded",
    5: "failed",
    6: "cancelled",
}


def _decode_job(payload: bytes) -> Job:
    f = _decode_fields(payload)
    state_int = _field_int(f, 4)
    resolved = [v.decode() for v in f.get(17, [])]
    return Job(
        job_id=_field_str(f, 1),
        kind=_field_str(f, 2),
        image=_field_str(f, 3),
        state=_JOB_STATE.get(state_int, "pending"),
        exit_code=_field_int(f, 5),
        error=_field_str(f, 6),
        input_s3_uri=_field_str(f, 7),
        output_s3_uri=_field_str(f, 8),
        logs_s3_uri=_field_str(f, 9),
        created_at=_field_int(f, 10),
        started_at=_field_int(f, 11),
        finished_at=_field_int(f, 12),
        tenant_id=_field_str(f, 13),
        user_id=_field_str(f, 14),
        k8s_namespace=_field_str(f, 15),
        k8s_job_name=_field_str(f, 16),
        resolved_secret_names=resolved,
    )


def _decode_job_event(payload: bytes) -> JobEvent:
    import json

    f = _decode_fields(payload)
    job_id = _field_str(f, 1)
    ts = _field_int(f, 2)
    # JobEvent has oneof at fields 10..16
    if 10 in f:
        sub = _decode_fields(f[10][0])
        return JobEvent(job_id=job_id, kind="created", ts=ts, image=_field_str(sub, 1))
    if 11 in f:
        sub = _decode_fields(f[11][0])
        return JobEvent(
            job_id=job_id, kind="scheduled", ts=ts, node_name=_field_str(sub, 1)
        )
    if 12 in f:
        return JobEvent(job_id=job_id, kind="started", ts=ts)
    if 13 in f:
        sub = _decode_fields(f[13][0])
        detail_raw = _field_str(sub, 3)
        try:
            detail = json.loads(detail_raw) if detail_raw else {}
        except json.JSONDecodeError:
            detail = {"raw": detail_raw}
        return JobEvent(
            job_id=job_id,
            kind="progress",
            ts=ts,
            stage=_field_str(sub, 1),
            percent=_field_int(sub, 2),
            detail=detail,
        )
    if 14 in f:
        sub = _decode_fields(f[14][0])
        return JobEvent(
            job_id=job_id,
            kind="succeeded",
            ts=ts,
            exit_code=_field_int(sub, 1),
            output_s3_uri=_field_str(sub, 2),
        )
    if 15 in f:
        sub = _decode_fields(f[15][0])
        return JobEvent(
            job_id=job_id,
            kind="failed",
            ts=ts,
            exit_code=_field_int(sub, 1),
            error=_field_str(sub, 2),
        )
    if 16 in f:
        sub = _decode_fields(f[16][0])
        return JobEvent(
            job_id=job_id, kind="cancelled", ts=ts, reason=_field_str(sub, 1)
        )
    return JobEvent(job_id=job_id, kind="unknown", ts=ts)


_LOG_STREAM = {0: "unspecified", 1: "stdout", 2: "stderr"}


def _decode_log_line(payload: bytes) -> LogLine:
    f = _decode_fields(payload)
    return LogLine(
        job_id="",  # populated by caller
        ts=_field_int(f, 1),
        stream=_LOG_STREAM.get(_field_int(f, 2), "unspecified"),
        line=_field_str(f, 3),
    )


def _decode_job_output(payload: bytes) -> JobOutput:
    f = _decode_fields(payload)
    files: list[OutputFile] = []
    for raw in f.get(1, []):
        sub = _decode_fields(raw)
        files.append(
            OutputFile(
                key=_field_str(sub, 1),
                s3_uri=_field_str(sub, 2),
                presigned_url=_field_str(sub, 3),
                size=_field_int(sub, 4),
                content_type=_field_str(sub, 5),
            )
        )
    return JobOutput(files=files)


# ── sync client ────────────────────────────────────────────────────────────


class JobsClient:
    """Sync gRPC client. Owned by ``SDK``; not constructed directly."""

    def __init__(self, sdk_client: Any):
        self._sdk = sdk_client

    def _channel(self) -> grpc.Channel | None:
        return self._sdk._get_channel()

    def _metadata(self):
        return self._sdk._metadata

    def submit_job(self, payload: bytes) -> Job:
        ch = self._channel()
        if ch is None:
            raise RuntimeError("sidecar unavailable — JobService cannot be reached")
        stub = ch.unary_unary(
            "/coresdk.v1.JobService/SubmitJob",
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        resp = stub(payload, metadata=self._metadata())
        return _decode_job(resp)

    def get_job(self, job_id: str, tenant_id: str) -> Job:
        ch = self._channel()
        if ch is None:
            raise RuntimeError("sidecar unavailable")
        payload = encode_simple_job_request(2, job_id, tenant_id)
        stub = ch.unary_unary(
            "/coresdk.v1.JobService/GetJob",
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        resp = stub(payload, metadata=self._metadata())
        return _decode_job(resp)

    def cancel_job(self, job_id: str, tenant_id: str, reason: str = "") -> Job:
        ch = self._channel()
        if ch is None:
            raise RuntimeError("sidecar unavailable")
        payload = _encode_string(1, job_id) + _encode_string(2, reason)
        payload += _encode_message(3, _encode_string(1, tenant_id))
        stub = ch.unary_unary(
            "/coresdk.v1.JobService/CancelJob",
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        resp = stub(payload, metadata=self._metadata())
        return _decode_job(resp)

    def list_jobs(
        self,
        tenant_id: str,
        state_filter: str = "",
        limit: int = 100,
    ) -> list[Job]:
        ch = self._channel()
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
        resp = stub(payload, metadata=self._metadata())
        f = _decode_fields(resp)
        return [_decode_job(raw) for raw in f.get(1, [])]

    def get_job_output(
        self, job_id: str, tenant_id: str, presign_ttl_seconds: int = 900
    ) -> JobOutput:
        ch = self._channel()
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
        resp = stub(payload, metadata=self._metadata())
        return _decode_job_output(resp)

    def watch_job(self, job_id: str, tenant_id: str) -> Iterator[JobEvent]:
        ch = self._channel()
        if ch is None:
            raise RuntimeError("sidecar unavailable")
        payload = _encode_string(1, job_id)
        payload += _encode_message(3, _encode_string(1, tenant_id))
        stub = ch.unary_stream(
            "/coresdk.v1.JobService/WatchJob",
            request_serializer=lambda x: x,
            response_deserializer=lambda x: x,
        )
        for resp in stub(payload, metadata=self._metadata()):
            yield _decode_job_event(resp)

    def stream_job_logs(
        self,
        job_id: str,
        tenant_id: str,
        follow: bool = True,
        tail_lines: int = 0,
    ) -> Iterator[LogLine]:
        ch = self._channel()
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
        for resp in stub(payload, metadata=self._metadata()):
            line = _decode_log_line(resp)
            line.job_id = job_id
            yield line
