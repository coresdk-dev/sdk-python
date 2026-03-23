"""Pytest fixtures for integration tests.

The `sdk` fixture starts the coresdk-sidecar binary on a random free port,
waits for it to be ready, yields an SDK instance, then terminates it.

All integration tests are automatically skipped when the binary is not in PATH.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time

import pytest

from coresdk import SDK
from coresdk._config import SDKConfig


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def sdk():
    binary = shutil.which("coresdk-sidecar")
    if binary is None:
        pytest.skip("coresdk-sidecar not in PATH — skipping integration tests")

    port = _free_port()
    addr = f"127.0.0.1:{port}"
    proc = subprocess.Popen(
        [binary],
        env={
            "CORESDK_SIDECAR_ADDR": addr,
            "CORESDK_TENANT_ID": "test",
            "CORESDK_FAIL_MODE": "open",
            "CORESDK_ENV": "development",
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    client = SDK(SDKConfig(sidecar_addr=addr, tenant_id="test", fail_mode="open"))

    # Poll until healthy (up to 10 s)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            if client.health():
                break
        except Exception:  # noqa: S110
            pass
        time.sleep(0.2)
    else:
        proc.terminate()
        pytest.skip("coresdk-sidecar did not become healthy in time")

    yield client

    proc.terminate()
    proc.wait(timeout=5)
