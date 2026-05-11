# Generated bindings produced by `buf generate` (sdk-sync.yml workflow).
# This package's purpose is to expose `coresdk.gen.coresdk.v1.*` *and* make
# the bare `coresdk.v1` import path resolve, because protoc-gen-python emits
# absolute imports based on the proto `package` declaration:
#
#     from coresdk.v1 import common_pb2 as ...
#
# Without the alias below, those imports raise `ModuleNotFoundError` when
# the SDK is installed normally (the gen dir is nested under coresdk.gen,
# so `coresdk.v1` does not point at the generated modules).
#
# We patch sys.modules at import time to make `coresdk.v1` resolve to
# `coresdk.gen.coresdk.v1`. Cheap: only fires when someone imports
# `coresdk.gen`, and only sets the alias once.
from __future__ import annotations

import importlib
import sys

_pkg = "coresdk.gen.coresdk.v1"
try:
    _v1 = importlib.import_module(_pkg)
    sys.modules.setdefault("coresdk.v1", _v1)
except Exception:  # noqa: BLE001  — best-effort; SDK falls back to manual codec
    pass

del importlib, sys, _pkg
