"""SDK configuration from environment variables."""

import json
import os
from dataclasses import dataclass, field

_DEFAULT_EXCLUDE_PATHS = ["/healthz", "/readyz", "/metrics"]


def _parse_exclude_paths() -> list[str]:
    raw = os.environ.get("CORESDK_EXCLUDE_PATHS", "")
    if raw:
        return [p.strip() for p in raw.split(",") if p.strip()]
    return list(_DEFAULT_EXCLUDE_PATHS)


def _parse_custom_prompt_patterns() -> list[tuple[str, str, str]]:
    raw = os.environ.get("CORESDK_CUSTOM_PROMPT_PATTERNS", "")
    if not raw:
        return []
    parsed = json.loads(raw)
    return [(str(p[0]), str(p[1]), str(p[2])) for p in parsed]


@dataclass
class SDKConfig:
    sidecar_addr: str = "localhost:50051"
    tenant_id: str = "default"
    service_name: str = "unknown-service"
    fail_mode: str = "closed"
    policy_fail_mode: str = ""
    dev_mode: bool = False
    log_level: str = "INFO"
    control_plane_url: str = ""
    tls_cert: str = ""
    tls_key: str = ""
    tls_ca: str = ""
    inject_headers: bool = True
    exclude_paths: list[str] = None  # type: ignore[assignment]
    api_key_prefix: str = ""
    custom_prompt_patterns: list[tuple[str, str, str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.exclude_paths is None:
            self.exclude_paths = list(_DEFAULT_EXCLUDE_PATHS)

    def validate(self) -> None:
        """Validate configuration. Raises ValueError on invalid settings."""
        if self.fail_mode not in {"open", "closed"}:
            raise ValueError(f"fail_mode must be 'open' or 'closed', got {self.fail_mode!r}")
        if self.policy_fail_mode and self.policy_fail_mode not in {"open", "closed"}:
            raise ValueError(
                f"policy_fail_mode must be 'open', 'closed', or empty, "
                f"got {self.policy_fail_mode!r}"
            )
        if not self.sidecar_addr:
            raise ValueError("sidecar_addr must not be empty")

    @classmethod
    def from_env(cls) -> "SDKConfig":
        env = os.environ.get("CORESDK_ENV", "production")
        default_fail_mode = "open" if env == "development" else "closed"
        config = cls(
            sidecar_addr=os.environ.get("CORESDK_SIDECAR_ADDR", "localhost:50051"),
            tenant_id=os.environ.get("CORESDK_TENANT_ID", "default"),
            service_name=os.environ.get("CORESDK_SERVICE_NAME", "unknown-service"),
            fail_mode=os.environ.get("CORESDK_FAIL_MODE", default_fail_mode),
            policy_fail_mode=os.environ.get("CORESDK_POLICY_FAIL_MODE", ""),
            control_plane_url=os.environ.get("CORESDK_CONTROL_PLANE_URL", ""),
            dev_mode=os.environ.get("CORESDK_ENV", "production") == "development",
            log_level=os.environ.get("CORESDK_LOG_LEVEL", "INFO"),
            tls_cert=os.environ.get("CORESDK_TLS_CERT", ""),
            tls_key=os.environ.get("CORESDK_TLS_KEY", ""),
            tls_ca=os.environ.get("CORESDK_TLS_CA", ""),
            inject_headers=os.environ.get(
                "CORESDK_INJECT_TENANT_HEADERS", "true"
            ).lower()
            in ("true", "1", "yes"),
            exclude_paths=_parse_exclude_paths(),
            api_key_prefix=os.environ.get("CORESDK_API_KEY_PREFIX", ""),
            custom_prompt_patterns=_parse_custom_prompt_patterns(),
        )
        config.validate()
        return config
