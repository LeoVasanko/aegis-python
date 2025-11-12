"""Setup script for pyaegis - builds CFFI extension with libaegis C library."""

import sys
from pathlib import Path

from cffi import FFI
from setuptools import setup

# Locate the static library (built by build_backend.py before this runs)
lib_name = "aegis.lib" if sys.platform == "win32" else "libaegis.a"
libaegis_static = Path("libaegis/zig-out/lib") / lib_name
if not libaegis_static.exists():
    raise RuntimeError(f"libaegis static library not found at {libaegis_static}")
libaegis_static = str(libaegis_static.resolve())

# Include directory for headers
libaegis_include = Path("libaegis/src/include")
if not libaegis_include.exists():
    raise RuntimeError(f"libaegis include directory not found at {libaegis_include}")
include_dirs = [str(libaegis_include)]

# Read the CDEF header
cdef_path = Path(__file__).parent / "pyaegis" / "aegis_cdef.h"
cdef_content = cdef_path.read_text(encoding="utf-8")

# Create CFFI builder
ffibuilder = FFI()
ffibuilder.cdef(cdef_content)

# Set the source
ffibuilder.set_source(
    "pyaegis._aegis",  # module name
    """
    #include "aegis.h"
    #include "aegis128l.h"
    #include "aegis128x2.h"
    #include "aegis128x4.h"
    #include "aegis256.h"
    #include "aegis256x2.h"
    #include "aegis256x4.h"
    """,
    include_dirs=include_dirs,
    extra_objects=[libaegis_static],
)

if __name__ == "__main__":
    setup(
        cffi_modules=["setup.py:ffibuilder"],
    )
