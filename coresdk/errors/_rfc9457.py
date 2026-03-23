"""RFC 9457 ProblemDetail error type."""

import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi.responses import JSONResponse


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

    @classmethod
    def not_found(cls, detail: str) -> "ProblemDetailError":
        return cls("Not Found", 404, detail=detail, type_uri="https://coresdk.io/errors/not-found")

    @classmethod
    def bad_request(cls, detail: str) -> "ProblemDetailError":
        return cls(
            "Bad Request", 400, detail=detail, type_uri="https://coresdk.io/errors/bad-request"
        )

    def to_fastapi_response(self) -> "JSONResponse":
        """Return a FastAPI JSONResponse.

        Lazily imports FastAPI to avoid a hard dependency on the framework.
        """
        from fastapi.responses import JSONResponse

        return JSONResponse(content=self.to_dict(), status_code=self.status)

    def __repr__(self) -> str:
        return f"ProblemDetailError(status={self.status}, title={self.title!r})"


class CoreSDKError(ProblemDetailError):
    """Fail-closed sentinel — raised when sidecar is unreachable and fail_mode='closed'.

    Subclasses ProblemDetailError(503) so fail-closed errors produce RFC 9457 JSON
    rather than a plain traceback.
    """

    def __init__(self, detail: str = "CoreSDK sidecar unavailable") -> None:
        super().__init__(
            "Service Unavailable",
            503,
            detail=detail,
            type_uri="https://coresdk.io/errors/sidecar-unavailable",
        )
