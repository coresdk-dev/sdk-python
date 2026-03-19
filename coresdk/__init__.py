"""CoreSDK — auth, policy, observability. One import."""

from coresdk._config import SDKConfig
from coresdk._client import CoreSDKClient
from coresdk._types import AuthDecision
from coresdk.errors._rfc9457 import ProblemDetailError
from coresdk.tracing.decorator import trace
from coresdk.middleware.flask import CoreSDKFlask, require_auth
from coresdk.middleware.django import CoreSDKMiddleware as DjangoMiddleware

__all__ = [
    "SDK", "AuthDecision", "trace", "ProblemDetailError",
    "CoreSDKFlask", "require_auth", "DjangoMiddleware",
]
__version__ = "0.1.0"


class SDK:
    """Main CoreSDK entry point. Initialize with SDK.from_env()."""

    def __init__(self, config: SDKConfig):
        self.config = config
        self._client = CoreSDKClient(config)

    @classmethod
    def from_env(cls) -> "SDK":
        """Initialize SDK from environment variables.

        Reads: CORESDK_SIDECAR_ADDR, CORESDK_TENANT_ID, CORESDK_ENV,
               CORESDK_FAIL_MODE, CORESDK_SERVICE_NAME, CORESDK_LOG_LEVEL
        """
        config = SDKConfig.from_env()
        return cls(config)

    def authorize(self, token: str, *, action: str = "", resource: str = "") -> AuthDecision:
        """Validate a JWT and authorize the request."""
        return self._client.validate_token(token, action=action, resource=resource)

    def authorize_sync(self, token: str, *, action: str = "", resource: str = "") -> AuthDecision:
        """Synchronous authorize — same as authorize() since the SDK is currently sync."""
        return self.authorize(token, action=action, resource=resource)

    def evaluate_policy(self, rule: str, input_data: dict) -> bool:
        """Evaluate a Rego policy rule."""
        return self._client.evaluate_policy(rule, input_data)
