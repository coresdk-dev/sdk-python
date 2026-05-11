"""High-level types and helpers for the CoreSDK Jobs service.

The submit/watch/cancel/output methods live on ``SDK`` and ``AsyncSDK``; this
module exports the public dataclasses they return.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional

JobStateName = Literal[
    "pending",
    "scheduling",
    "running",
    "succeeded",
    "failed",
    "cancelled",
]


@dataclass
class SecretRef:
    """Reference to a single secret to inject into a job container.

    Attributes:
        name: Env-var name (when ``delivery="env"``) or file basename (when
            ``delivery="file"``).
        provider: ``"aws"``, ``"vault"``, ``"azure"``, or empty for the
            engine default.
        path: Backend-specific secret path.
        version: Optional pinned version.
        delivery: ``"env"`` or ``"file"`` — empty selects the server default
            (``file`` for values > 1 KiB, ``env`` otherwise).
    """

    name: str
    path: str
    provider: str = ""
    version: str = ""
    delivery: str = ""


@dataclass
class Job:
    """Snapshot of a job's persistent state.

    Returned by ``submit_job``, ``get_job``, ``cancel_job``, ``list_jobs`` and
    every progress tick from ``watch_job``. Secret *values* are never carried
    here; only the resolved logical names appear in
    :attr:`resolved_secret_names`.
    """

    job_id: str
    kind: str = ""
    image: str = ""
    state: JobStateName = "pending"
    exit_code: int = 0
    error: str = ""
    input_s3_uri: str = ""
    output_s3_uri: str = ""
    logs_s3_uri: str = ""
    created_at: int = 0
    started_at: int = 0
    finished_at: int = 0
    tenant_id: str = ""
    user_id: str = ""
    k8s_namespace: str = ""
    k8s_job_name: str = ""
    resolved_secret_names: list[str] = field(default_factory=list)

    @property
    def is_terminal(self) -> bool:
        return self.state in ("succeeded", "failed", "cancelled")


@dataclass
class JobEvent:
    """A single event emitted while watching a job.

    The ``kind`` discriminator selects which of the optional payload fields is
    populated. Lifecycle kinds ("created", "scheduled", "started", "succeeded",
    "failed", "cancelled") map 1:1 to state transitions. The ``"progress"``
    kind carries domain-specific updates (e.g. ``stage="tool_use"``).
    """

    job_id: str
    kind: Literal[
        "created",
        "scheduled",
        "started",
        "progress",
        "succeeded",
        "failed",
        "cancelled",
        "unknown",
    ]
    ts: int = 0
    # progress
    stage: str = ""
    percent: int = 0
    detail: dict[str, Any] = field(default_factory=dict)
    # scheduled
    node_name: str = ""
    # created
    image: str = ""
    # succeeded
    exit_code: int = 0
    output_s3_uri: str = ""
    # failed
    error: str = ""
    # cancelled
    reason: str = ""


@dataclass
class LogLine:
    """One line of stdout/stderr tailed from a running job."""

    job_id: str
    line: str
    stream: Literal["stdout", "stderr", "unspecified"] = "stdout"
    ts: int = 0


@dataclass
class OutputFile:
    """One file in the job's output prefix, with a short-lived presigned URL."""

    key: str
    s3_uri: str
    presigned_url: str
    size: int = 0
    content_type: str = ""


@dataclass
class JobOutput:
    """Listing of files persisted under the job's output prefix."""

    files: list[OutputFile] = field(default_factory=list)


@dataclass
class RunJobResult:
    """Result of ``AsyncSDK.run_job`` — the convenience submit+watch+collect helper."""

    status: Literal["succeeded", "failed", "cancelled"]
    job_id: str
    exit_code: int = 0
    error: str = ""
    output_s3_uri: str = ""
    output: Optional[JobOutput] = None


__all__ = [
    "Job",
    "JobEvent",
    "JobOutput",
    "JobStateName",
    "LogLine",
    "OutputFile",
    "RunJobResult",
    "SecretRef",
]
