"""Utility helpers for pyaegis.

Currently provides Python-side aligned allocation helpers that avoid relying
on libc/posix_memalign. Memory is owned by Python; C code only borrows it.
"""

from __future__ import annotations

from typing import Protocol

from ._loader import ffi

__all__ = ["new_aligned_struct", "aligned_address", "Buffer", "nonce_increment", "wipe"]

try:
    from collections.abc import Buffer as _Buffer

    class Buffer(_Buffer, Protocol):  # type: ignore[misc]
        def __len__(self) -> int: ...
except ImportError:

    class Buffer(Protocol):
        def __len__(self) -> int: ...
        def __buffer__(self, flags: int) -> memoryview: ...


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


def nonce_increment(nonce: Buffer) -> None:
    """Increment the nonce in place using little-endian byte order.

    Useful for generating unique nonces for each consecutive message.

    Args:
        nonce: The nonce buffer to increment (modified in place).
    """
    n = memoryview(nonce)
    for i in range(len(n)):
        if n[i] < 255:
            n[i] += 1
            return
        n[i] = 0


def wipe(buffer: Buffer) -> None:
    """Set all bytes of the input buffer to zero.

    Useful for securely clearing sensitive data from memory.

    Args:
        buffer: The buffer to wipe (modified in place).
    """
    n = memoryview(buffer)
    for i in range(len(n)):
        n[i] = 0
