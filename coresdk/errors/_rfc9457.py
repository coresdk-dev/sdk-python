"""RFC 9457 ProblemDetail error type."""

import json
from typing import Any


class CoreSDKError(Exception):
    """General CoreSDK error — raised on fail-closed paths."""


class ProblemDetailError(Exception):
    """RFC 9457 Problem Details for HTTP APIs."""

    CONTENT_TYPE = "application/problem+json"

    def __init__(
        self,
        title: str,
        status: int,
        detail: str | None = None,
        type_uri: str | None = None,
        instance: str | None = None,
        **extensions: Any,  # noqa: ANN401
    ) -> None:
        self.title = title
        self.status = status
        self.detail = detail
        self.type_uri = type_uri
        self.instance = instance
        self.extensions = extensions
        super().__init__(title)

    def to_dict(self) -> dict:
        result = {"title": self.title, "status": self.status}
        if self.type_uri:
            result["type"] = self.type_uri
        if self.detail:
            result["detail"] = self.detail
        if self.instance:
            result["instance"] = self.instance
        result.update(self.extensions)
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    def to_response(self) -> tuple:
        """Return (body_dict, status_code) suitable for framework response helpers."""
        return self.to_dict(), self.status

    @classmethod
    def unauthorized(cls, detail: str) -> "ProblemDetailError":
        return cls(
            "Unauthorized", 401, detail=detail, type_uri="https://coresdk.io/errors/unauthorized"
        )

    @classmethod
    def forbidden(cls, detail: str) -> "ProblemDetailError":
        return cls("Forbidden", 403, detail=detail, type_uri="https://coresdk.io/errors/forbidden")

    def __repr__(self) -> str:
        return f"ProblemDetailError(status={self.status}, title={self.title!r})"
