# Contributing to the CoreSDK Python SDK

## Setup

```bash
git clone git@github.com:coresdk-dev/sdk-python.git && cd sdk-python
pip install -e ".[dev,fastapi,flask]"
```

## Running tests

```bash
# Unit tests only (no sidecar needed)
pytest tests/ -v -m "not integration"

# All tests (requires sidecar on localhost:50051)
CORESDK_ENV=development pytest tests/ -v
```

## Code style

```bash
ruff check .          # lint
ruff format .         # format
mypy coresdk/         # type check
```

## Adding a new SDK method

1. Add the gRPC call in `coresdk/_client.py` — follow the existing `_call_*` pattern, noting the proto field numbers
2. Expose the method on `SDK` in `coresdk/__init__.py`
3. Mirror it on `AsyncSDK` in `coresdk/_async_sdk.py`
4. Add a stub to `MockSDK` in `coresdk/testing/__init__.py`
5. Add a test in `tests/`
6. Document in `README.md`

## Architecture

- `coresdk/_client.py` — synchronous gRPC transport (hand-coded proto encoding)
- `coresdk/_async_client.py` — async gRPC transport via `grpc.aio`
- `coresdk/__init__.py` — public `SDK` class
- `coresdk/_async_sdk.py` — public `AsyncSDK` class
- `coresdk/_types.py` — public type definitions
- `coresdk/testing/` — `MockSDK`, `FakeSpanExporter`
- `coresdk/masking/` — local PII masking (no sidecar)
- `coresdk/resilience/` — circuit breaker, retry, timeout

See [core-sdk CONTRIBUTING](https://github.com/coresdk-dev/core-sdk/blob/develop/CONTRIBUTING.md) for the full architecture and gRPC method addition guide.
