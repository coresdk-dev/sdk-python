# CoreSDK Python

[![CI](https://github.com/coresdk-dev/sdk-python/actions/workflows/ci.yml/badge.svg)](https://github.com/coresdk-dev/sdk-python/actions)
[![PyPI](https://img.shields.io/pypi/v/coresdk.svg)](https://pypi.org/project/coresdk/)
[![Python](https://img.shields.io/pypi/pyversions/coresdk.svg)](https://pypi.org/project/coresdk/)
[![License](https://img.shields.io/pypi/l/coresdk.svg)](LICENSE)

Auth, policy enforcement, observability, and multi-tenancy for Python services — one import, backed by the CoreSDK sidecar.

## Install

```bash
pip install coresdk           # core only
pip install "coresdk[fastapi]"  # + FastAPI middleware
pip install "coresdk[flask]"    # + Flask middleware
```

## Quick start

```python
from coresdk import CoreSDKClient, SDKConfig

sdk = CoreSDKClient(SDKConfig(
    sidecar_addr="[::1]:50051",
    tenant_id="my-org",
    service_name="my-api",
))

# Validate a JWT (calls sidecar over gRPC)
claims = sdk.validate_token("Bearer eyJ...")
print(claims["sub"])

# Evaluate a Rego policy
allowed = sdk.evaluate_policy("data.authz.allow", {
    "subject": claims["sub"],
    "action": "read",
    "resource": "reports/q4",
})
```

## Authorize requests

```python
from coresdk import SDK

sdk = SDK.from_env()

# Authorize a token against a resource + action
decision = sdk.authorize("eyJ...", action="read", resource="/orders")
if decision.allowed:
    print(f"Allowed for {decision.claims['sub']}")
else:
    print(f"Denied: {decision.reason}")
```

## FastAPI middleware

```python
from coresdk.middleware.fastapi import CoreSDKMiddleware

app.add_middleware(CoreSDKMiddleware, sdk=sdk_adapter,
                   exclude_paths=["/healthz"])
```

All routes protected by default. Claims available via `request.state.coresdk_user`.

## Flask middleware

```python
from coresdk.middleware.flask import CoreSDKMiddleware

CoreSDKMiddleware(app, sdk=sdk_adapter, exclude_paths=["/healthz"])
```

Claims available via `flask.g.claims`.

## PII-safe tracing

```python
from coresdk.tracing.decorator import trace

@trace(intent="list-orders")
async def list_orders(tenant_id: str) -> list:
    ...
```

Secrets and PII are redacted from all span attributes before export. Set `OTEL_EXPORTER_OTLP_ENDPOINT` to send traces to your collector.

## Config from environment

| Variable | Default | Description |
|---|---|---|
| `CORESDK_SIDECAR_ADDR` | `[::1]:50051` | gRPC address of the sidecar |
| `CORESDK_TENANT_ID` | — | Default tenant slug |
| `CORESDK_SERVICE_NAME` | — | Service name in traces |
| `CORESDK_FAIL_MODE` | `open` | `open` or `closed` on sidecar error |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | OTLP trace exporter endpoint |

## mTLS

To enable mutual TLS between your application and the sidecar, set all three TLS environment variables:

| Variable | Description |
|----------|-------------|
| `CORESDK_TLS_CERT` | Path to the client certificate (PEM) |
| `CORESDK_TLS_KEY` | Path to the client private key (PEM) |
| `CORESDK_TLS_CA` | Path to the CA certificate (PEM) |

```bash
export CORESDK_TLS_CERT=/path/to/client.crt
export CORESDK_TLS_KEY=/path/to/client.key
export CORESDK_TLS_CA=/path/to/ca.crt
```

When all three are present, the SDK configures grpcio with TLS 1.3 mutual authentication automatically. See the [core-sdk README](https://github.com/coresdk-dev/core-sdk#mtls-configuration) for certificate generation instructions.

## Examples

Full working projects in [coresdk-dev/examples](https://github.com/coresdk-dev/examples):

- **[python/fastapi-app](https://github.com/coresdk-dev/examples/tree/develop/python/fastapi-app)** — FastAPI multi-tenant REST API
- **[python/flask-app](https://github.com/coresdk-dev/examples/tree/develop/python/flask-app)** — Flask multi-tenant REST API
- **[python/01_quickstart.py](https://github.com/coresdk-dev/examples/blob/develop/python/01_quickstart.py)** — 5-minute quickstart
- **[python/02_multi_tenant.py](https://github.com/coresdk-dev/examples/blob/develop/python/02_multi_tenant.py)** — Multi-tenant isolation
- **[python/03_fastapi_service.py](https://github.com/coresdk-dev/examples/blob/develop/python/03_fastapi_service.py)** — FastAPI integration
- **[python/04_flask_service.py](https://github.com/coresdk-dev/examples/blob/develop/python/04_flask_service.py)** — Flask integration
- **[python/05_policy_enforcement.py](https://github.com/coresdk-dev/examples/blob/develop/python/05_policy_enforcement.py)** — OPA/Rego policy
- **[python/06_pii_safe_tracing.py](https://github.com/coresdk-dev/examples/blob/develop/python/06_pii_safe_tracing.py)** — PII-safe OTEL tracing

## Sidecar

Download the sidecar binary from [coresdk-dev/core releases](https://github.com/coresdk-dev/core/releases):

```bash
# macOS (Apple Silicon)
curl -LO https://github.com/coresdk-dev/core/releases/latest/download/coresdk-sidecar-aarch64-apple-darwin.tar.gz
tar xf coresdk-sidecar-aarch64-apple-darwin.tar.gz
./coresdk-sidecar
```

Or run via Docker:

```bash
docker run -p 50051:50051 ghcr.io/coresdk-dev/sidecar:latest
```

## Development

```bash
git clone git@github.com:coresdk-dev/sdk-python.git && cd sdk-python
pip install -e ".[dev,fastapi,flask]"
pytest tests/ -v
```

## License

Apache-2.0 — see [LICENSE](LICENSE)
