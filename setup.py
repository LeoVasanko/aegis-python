"""Setup script for pyaegis - builds CFFI extension linking to libaegis.a"""

from pathlib import Path

from cffi import FFI
from setuptools import setup


def find_libaegis():
    """Locate libaegis.a - check common locations."""
    libaegis_paths = [
        Path("libaegis/zig-out/lib/libaegis.a"),  # Zig build output (repo build)
        Path("libaegis/build/libaegis.a"),  # CMake build output (repo build)
        Path("../libaegis/zig-out/lib/libaegis.a"),  # When building from extracted sdist
        Path("../libaegis/build/libaegis.a"),  # When building from extracted sdist
        Path("/usr/local/lib/libaegis.a"),  # System install
        Path("/usr/lib/libaegis.a"),  # System install
    ]

    for path in libaegis_paths:
        if path.exists():
            print(f"Found libaegis.a at: {path.resolve()}")
            return str(path.resolve())
    
    # Return None instead of raising - will be caught during build
    return None


# Read the CDEF header
cdef_path = Path(__file__).parent / "pyaegis" / "aegis_cdef.h"
cdef_content = cdef_path.read_text(encoding="utf-8")

# Create CFFI builder
ffibuilder = FFI()
ffibuilder.cdef(cdef_content)

# Include directory for headers
include_dirs = []
libaegis_include = Path("libaegis/src/include")
if libaegis_include.exists():
    include_dirs.append(str(libaegis_include.resolve()))

# Try to find libaegis.a, but don't fail if not found (build backend will build it)
libaegis_static = find_libaegis()

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
    extra_objects=[libaegis_static] if libaegis_static else [],
)

if __name__ == "__main__":
    setup(
        cffi_modules=["setup.py:ffibuilder"],
    )
