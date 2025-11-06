"""Dynamic loader for libaegis using CFFI (ABI mode).

This module loads the shared library bundled with the package.

Exports:
- ffi: a cffi.FFI instance with the libaegis API declared
- lib: the loaded libaegis shared library (ffi.dlopen)
- libc: the C runtime (for posix_memalign/free on POSIX)
- alloc_aligned(size, alignment): return (void*) pointer with requested alignment
"""

import os
import sys
from typing import Any

from cffi import FFI

ffi = FFI()

# Load CFFI cdef declarations from text file
cdef_path = os.path.join(os.path.dirname(__file__), "build", "aegis_cdef.h")
with open(cdef_path, "r", encoding="utf-8") as f:
    cdef_content = f.read()
ffi.cdef(cdef_content)

try:
    # ctypes is only used to resolve libc reliably across platforms
    import ctypes.util as _ctypes_util  # type: ignore
except Exception:  # pragma: no cover - very unlikely to happen
    _ctypes_util = None  # type: ignore[assignment]


def _platform_lib_name() -> str:
    if sys.platform == "darwin":
        return "libaegis.dylib"
    if os.name == "nt":
        return "aegis.dll"
    return "libaegis.so"


def _load_libaegis():
    pkg_dir = os.path.dirname(__file__)
    candidate = os.path.join(pkg_dir, "build", _platform_lib_name())
    if os.path.exists(candidate):
        try:
            return ffi.dlopen(candidate)
        except Exception as e:
            raise OSError(f"Failed to load libaegis from {candidate}: {e}")
    else:
        raise OSError(f"Could not find libaegis at {candidate}")


def _load_libc():
    # Use ctypes.util to find a usable libc name; fallback to None-dlopen on POSIX
    if _ctypes_util is not None:
        libc_name = _ctypes_util.find_library("c")  # type: ignore[attr-defined]
        if libc_name:
            try:
                return ffi.dlopen(libc_name)
            except Exception:
                pass
    # Fallback: try process globals (works on many Unix platforms)
    try:
        return ffi.dlopen(None)
    except Exception as e:
        raise OSError(f"Unable to load libc for aligned allocation: {e}")


lib: Any = _load_libaegis()
libc: Any = _load_libc()

# Initialize CPU feature selection (recommended by the library)
try:
    lib.aegis_init()
except Exception:
    # Non-fatal; functions will still work, maybe slower
    pass


def alloc_aligned(size: int, alignment: int = 64):
    """Allocate aligned memory via posix_memalign(); returns a void* cdata.

    The returned pointer must be freed with libc.free(). Attach a GC finalizer
    at call sites using ffi.gc(ptr, libc.free) after casting to the target type.
    """
    memptr = ffi.new("void **")
    rc = libc.posix_memalign(memptr, alignment, size)
    if rc != 0 or memptr[0] == ffi.NULL:
        raise MemoryError(f"posix_memalign({alignment}, {size}) failed with rc={rc}")
    return memptr[0]
