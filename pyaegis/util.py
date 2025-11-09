"""Utility helpers for pyaegis.

Currently provides Python-side aligned allocation helpers that avoid relying
on libc/posix_memalign. Memory is owned by Python; C code only borrows it.
"""

from typing import Protocol

from ._loader import ffi

__all__ = ["new_aligned_struct", "aligned_address", "Buffer", "nonce_increment", "wipe"]

try:
    from collections.abc import Buffer as _Buffer  # type: ignore[misc]

    class Buffer(_Buffer, Protocol):  # type: ignore[misc]
        pass
except ImportError:

    class Buffer(Protocol):
        def __buffer__(self, flags: int) -> memoryview: ...


def aligned_address(obj) -> int:
    """Return the integer address of the start of a cffi array object."""
    return int(ffi.cast("uintptr_t", ffi.addressof(obj, 0)))


class StructHolder:
    """Proxy object for aligned struct allocation.

    Exposes the aligned pointer as a property and wipes the buffer on deletion.
    """

    def __init__(self, ptr: object, view: memoryview):
        self._ptr = ptr
        self._view = view  # Keep memoryview slice and its bytearray alive

    @property
    def ptr(self) -> object:
        """The aligned pointer to the struct."""
        return self._ptr

    def __del__(self):
        wipe(self._view)
        del self._ptr, self._view


def new_aligned_struct(ctype: str, alignment: int) -> StructHolder:
    """Allocate memory for one instance of ``ctype`` with requested alignment."""
    # Allocate backing storage with extra space for alignment
    size = ffi.sizeof(ctype)
    view = memoryview(bytearray(size + alignment - 1))
    # Compute alignment offset from the base address
    offset = (-aligned_address(ffi.from_buffer(view))) & (alignment - 1)
    # Slice the memoryview to the aligned region (keeps bytearray alive)
    view = view[offset : offset + size]
    return StructHolder(ffi.from_buffer(f"{ctype} *", view), view)


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
