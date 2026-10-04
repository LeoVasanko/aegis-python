"""Setup script for aeg - builds CFFI extension with libaegis C library."""

import sys
import sysconfig
from pathlib import Path

from cffi import FFI
from setuptools import setup

ROOT = Path(__file__).parent.resolve()

if sys.maxsize <= 2**32:
    raise RuntimeError(
        "aeg does not support 32-bit platforms; build with a 64-bit Python"
    )

libaegis_static = ROOT / "libaegis/zig-out/lib" / (
    "aegis.lib" if sys.platform == "win32" else "libaegis.a"
)

ffibuilder = FFI()
ffibuilder.cdef((ROOT / "src/aeg/aegis_cdef.h").read_text())

# Free-threaded Python does not support Limited API (abi3)
is_free_threaded = sysconfig.get_config_var("Py_GIL_DISABLED")

ffibuilder.set_source(
    "aeg._aegis",
    """
    #include "aegis.h"
    #include "aegis128l.h"
    #include "aegis128x2.h"
    #include "aegis128x4.h"
    #include "aegis256.h"
    #include "aegis256x2.h"
    #include "aegis256x4.h"
    """,
    include_dirs=[str(ROOT / "libaegis/src/include")],
    extra_objects=[str(libaegis_static)],
    py_limited_api=not is_free_threaded,
)

if __name__ == "__main__":
    setup(
        cffi_modules=["setup.py:ffibuilder"],
        options=(
            {"bdist_wheel": {"py_limited_api": "cp312"}} if not is_free_threaded else {}
        ),
    )
