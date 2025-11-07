"""Dynamic loader for libaegis using CFFI (ABI mode)."""

import os
import sys
from pathlib import Path
from typing import Any

from cffi import FFI

__ALL__ = ["ffi", "lib"]


def _platform_lib_name() -> str:
    if sys.platform == "darwin":
        return "libaegis.dylib"
    if os.name == "nt":
        return "aegis.dll"
    return "libaegis.so"


def _load_libaegis():
    pkg_dir = Path(__file__).parent
    candidate = pkg_dir / "build" / _platform_lib_name()
    if candidate.exists():
        try:
            return ffi.dlopen(str(candidate))
        except Exception as e:
            raise OSError(f"Failed to load libaegis from {candidate}: {e}")
    else:
        raise OSError(f"Could not find libaegis at {candidate}")


ffi = FFI()
ffi.cdef(Path(__file__).with_name("aegis_cdef.h").read_text(encoding="utf-8"))
lib: Any = _load_libaegis()
lib.aegis_init()
