"""SDK configuration from environment variables."""

import os
from dataclasses import dataclass


@dataclass
class SDKConfig:
    sidecar_addr: str = "localhost:50051"
    tenant_id: str = "default"
    service_name: str = "unknown-service"
    fail_mode: str = "open"
    dev_mode: bool = False
    log_level: str = "INFO"
    control_plane_url: str = ""
    tls_cert: str = ""
    tls_key: str = ""
    tls_ca: str = ""

    @classmethod
    def from_env(cls) -> "SDKConfig":
        return cls(
            sidecar_addr=os.environ.get("CORESDK_SIDECAR_ADDR", "localhost:50051"),
            tenant_id=os.environ.get("CORESDK_TENANT_ID", "default"),
            service_name=os.environ.get("CORESDK_SERVICE_NAME", "unknown-service"),
            fail_mode=os.environ.get("CORESDK_FAIL_MODE", "open"),
            control_plane_url=os.environ.get("CORESDK_CONTROL_PLANE_URL", ""),
            dev_mode=os.environ.get("CORESDK_ENV", "production") == "development",
            log_level=os.environ.get("CORESDK_LOG_LEVEL", "INFO"),
            tls_cert=os.environ.get("CORESDK_TLS_CERT", ""),
            tls_key=os.environ.get("CORESDK_TLS_KEY", ""),
            tls_ca=os.environ.get("CORESDK_TLS_CA", ""),
        )
