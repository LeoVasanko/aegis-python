"""SecureBuffer: locked, core-dump-excluded memory for sensitive data.

Backed by an anonymous mmap that is locked against swapping (mlock /
VirtualLock) and excluded from core dumps (MADV_DONTDUMP) where available.
The contents are wiped on close().

SecureBuffer is not used for return values; allocate one yourself and pass
it as an ``into`` target to keep plaintext/keys out of the regular heap:

    with SecureBuffer(4096) as buf:
        ciph.decrypt(key, nonce, ct, mac, into=buf)

Adapted from quantumpipe's securebuf module.
"""

import ctypes
import mmap
import os
from contextlib import suppress

from .util import wipe

__all__ = ["SecureBuffer"]


class SecureBuffer:
    """A fixed-size buffer in locked, non-dumped memory, wiped on close."""

    def __init__(self, size: int):
        if size <= 0:
            raise ValueError(f"size must be positive, got {size}")
        self._mmap = mmap.mmap(-1, size, access=mmap.ACCESS_WRITE)
        try:
            self._lock()
            self._dontdump()
        except BaseException:
            self._mmap.close()
            raise

    @property
    def closed(self) -> bool:
        """True if the buffer has been closed."""
        return self._mmap.closed

    def _addr(self) -> int:
        return ctypes.addressof(ctypes.c_char.from_buffer(self._mmap))

    def _lock(self) -> None:
        addr, size = self._addr(), len(self._mmap)
        if os.name == "nt":
            api = ctypes.WinDLL("kernel32", use_last_error=True)
            api.VirtualLock.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
            api.VirtualLock.restype = ctypes.c_bool
            if not api.VirtualLock(addr, size):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            libc = ctypes.CDLL(None, use_errno=True)
            libc.mlock.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
            libc.mlock.restype = ctypes.c_int
            if libc.mlock(addr, size):
                err = ctypes.get_errno()
                raise OSError(err, os.strerror(err))

    def _unlock(self) -> None:
        addr, size = self._addr(), len(self._mmap)
        if os.name == "nt":
            api = ctypes.WinDLL("kernel32", use_last_error=True)
            api.VirtualUnlock.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
            api.VirtualUnlock.restype = ctypes.c_bool
            if not api.VirtualUnlock(addr, size):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            libc = ctypes.CDLL(None, use_errno=True)
            libc.munlock.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
            libc.munlock.restype = ctypes.c_int
            if libc.munlock(addr, size):
                err = ctypes.get_errno()
                raise OSError(err, os.strerror(err))

    def _dontdump(self) -> None:
        if hasattr(self._mmap, "madvise") and hasattr(mmap, "MADV_DONTDUMP"):
            self._mmap.madvise(mmap.MADV_DONTDUMP)

    def close(self) -> None:
        """Wipe the contents, unlock and release the memory. Idempotent."""
        if self.closed:
            return
        wipe(self._mmap)
        self._unlock()
        self._mmap.close()

    def __buffer__(self, flags: int) -> memoryview:
        return memoryview(self._mmap)

    def __getitem__(self, key):
        return memoryview(self._mmap)[key]

    def __setitem__(self, key, value):
        memoryview(self._mmap)[key] = value

    def __bytes__(self):
        raise TypeError("SecureBuffer cannot be converted to bytes")

    def __len__(self) -> int:
        return len(self._mmap)

    def __enter__(self) -> "SecureBuffer":
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def __del__(self):
        with suppress(Exception):
            self.close()
