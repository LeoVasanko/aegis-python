"""Pluggable random sources for aeg, built on AEGIS streams.

``Random`` is seeded once from the OS (secrets), then deterministic: each call
produces AEGIS keystream under the current key/nonce and increments the nonce
afterwards (little-endian), so no output block is ever produced twice.
Modeled on quantumpipe's ChaCha20-based Random class.

Note: within the ``aeg`` package namespace this submodule shadows the stdlib
``random`` module; import it as ``from aeg import random`` (or ``aeg.random``).
"""

import errno
import secrets
from typing import Protocol

from ._loader import ffi
from .util import Buffer, nonce_increment

__all__ = ["RandomSource", "Random", "system_random", "as_raf_rng"]


class RandomSource(Protocol):
    """Callable returning n cryptographically secure random bytes."""

    def __call__(self, n: int) -> bytes: ...


class Random:
    """AEGIS stream RNG: seeded once from the OS, then deterministic.

    Each call produces keystream under the current key/nonce and increments
    the nonce afterwards, so no output block is ever produced twice.

    The primary way to create one is the cipher module's own random()
    helper, e.g. ``aeg.cipher("AEGIS-128X2").random()``.
    """

    def __init__(self, cipher, *, seed: Buffer | None = None):
        """Create a Random using the given cipher module.

        Args:
            cipher: Cipher module (from aeg.cipher()).
            seed: Optional nonce || key bytes (NONCEBYTES + KEYBYTES long).
                  Primarily for tests; default seeds from the OS via secrets.

        Raises:
            TypeError: If seed length is invalid.
        """
        self._cipher = cipher
        if seed is None:
            seed = secrets.token_bytes(cipher.NONCEBYTES + cipher.KEYBYTES)
        seed = memoryview(seed)
        if seed.nbytes != cipher.NONCEBYTES + cipher.KEYBYTES:
            raise TypeError(
                f"seed length must be {cipher.NONCEBYTES + cipher.KEYBYTES} "
                f"(nonce || key) for {cipher.NAME}"
            )
        self._nonce = bytearray(seed[: cipher.NONCEBYTES])
        self._key = seed[cipher.NONCEBYTES :]

    def bytes(self, n: int) -> bytearray:
        """Return n random bytes as a bytearray."""
        out = self._cipher.stream(self._key, self._nonce, n)
        nonce_increment(self._nonce)
        return out

    def into(self, buf: Buffer) -> None:
        """Fill buf in place with random bytes."""
        mv = memoryview(buf).cast("B")
        self._cipher.stream(self._key, self._nonce, into=mv)
        nonce_increment(self._nonce)

    def __call__(self, n: int) -> bytearray:
        """Alias for bytes(n); satisfies the RandomSource protocol."""
        return self.bytes(n)


def system_random(n: int) -> bytes:
    """Random source backed directly by secrets.token_bytes."""
    return secrets.token_bytes(n)


@ffi.callback("int(void*, uint8_t*, size_t)")
def _random_callback(user, out, length):
    try:
        source = ffi.from_handle(user)
        data = source(length)
        if len(data) != length:
            ffi.errno = errno.EINVAL
            return -1
        ffi.memmove(out, data, length)
        return 0
    except Exception:
        ffi.errno = errno.EIO
        return -1


def as_raf_rng(source: RandomSource):
    """Build an aegis_raf_rng* cdata wrapping a Python random source.

    Args:
        source: Callable returning n random bytes, e.g. a Random instance
                or system_random.

    Returns:
        Tuple of (rng, keepalive). Keep ``keepalive`` alive for as long as
        the rng may be called by C code.
    """
    handle = ffi.new_handle(source)
    rng = ffi.new("aegis_raf_rng*")
    rng.user = handle
    rng.random = _random_callback
    return rng, (handle, _random_callback)
