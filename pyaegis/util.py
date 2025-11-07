"""Utility helpers for pyaegis.

Currently provides Python-side aligned allocation helpers that avoid relying
on libc/posix_memalign. Memory is owned by Python; C code only borrows it.
"""

from __future__ import annotations

from ._loader import ffi

__all__ = ["new_aligned_struct", "aligned_address"]


def aligned_address(obj) -> int:
    """Return the integer address of the start of a cffi array object."""
    return int(ffi.cast("uintptr_t", ffi.addressof(obj, 0)))


def new_aligned_struct(ctype: str, alignment: int) -> tuple[object, object]:
    """Allocate memory for one instance of ``ctype`` with requested alignment.

    This allocates a Python-owned unsigned char[] buffer large enough to find
    an aligned start address. Returns (ptr, owner) where ptr is a ``ctype *``
    and owner is the buffer object keeping the memory alive.
    """
    if alignment & (alignment - 1):  # Not power of two
        raise ValueError("alignment must be a power of two")
    size = ffi.sizeof(ctype)
    base = ffi.new("unsigned char[]", size + alignment - 1)
    addr = aligned_address(base)
    offset = (-addr) & (alignment - 1)
    aligned_uc = ffi.addressof(base, offset)
    ptr = ffi.cast(f"{ctype} *", aligned_uc)
    return ptr, base
