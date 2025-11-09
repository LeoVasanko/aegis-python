"""AEGIS-128X4"""
# All modules are generated from aegis256x4.py by tools/generate.py!
# DO NOT EDIT OTHER ALGORITHM FILES MANUALLY!

import errno
import secrets
from typing import Literal

from ._loader import ffi
from ._loader import lib as _lib
from .util import Buffer, new_aligned_struct, nonce_increment, wipe

NAME = "AEGIS-128X4"  #: Algorithm display name
KEYBYTES = 16  #: Key size in bytes (varies by algorithm)
NONCEBYTES = 16  #: Nonce size in bytes (varies by algorithm)
MACBYTES = 16  #: Normal MAC size (always 16)
MACBYTES_LONG = 32  #: Long MAC size (always 32)
ALIGNMENT = 64  #: Required alignment for internal structures
RATE = 64  #: Byte chunk size in internal processing


def random_key() -> bytearray:
    """
    Generate a secret key using cryptographically secure random bytes.

    It is recommended to wipe() the key after no longer needed.
    """
    return bytearray(secrets.token_bytes(KEYBYTES))


def random_nonce() -> bytearray:
    """
    Generate a public nonce using cryptographically secure random bytes.

    Nonces (a number used once) are public data that may be sent together
    with the ciphertext, but they need to be unique for each use.

    See also: nonce_increment() can be used to derive sequential nonces.
    """
    return bytearray(secrets.token_bytes(NONCEBYTES))


def _ptr(buf):
    return ffi.NULL if buf is None else ffi.from_buffer(buf)


def encrypt_detached(
    key: Buffer,
    nonce: Buffer,
    message: Buffer,
    ad: Buffer | None = None,
    *,
    maclen: int = MACBYTES,
    ct_into: Buffer | None = None,
    mac_into: Buffer | None = None,
) -> tuple[bytearray | memoryview, bytearray | memoryview]:
    """Encrypt message with associated data, returning ciphertext and MAC separately.

    Args:
        key: Secret key (generate with random_key()).
        nonce: Public nonce (generate with random_nonce()).
        message: The plaintext message to encrypt.
        ad: Associated data (optional).
        maclen: MAC length (16 or 32, default 16).
        ct_into: Buffer to write ciphertext into (default: bytearray created).
        mac_into: Buffer to write MAC into (default: bytearray created).

    Returns:
        Tuple of (ciphertext, mac)

    Raises:
        TypeError: If lengths are invalid.
        RuntimeError: If encryption fails.
    """
    if maclen not in (16, 32):
        raise TypeError("maclen must be 16 or 32")
    if len(key) != KEYBYTES:
        raise TypeError(f"key length must be {KEYBYTES}")
    if len(nonce) != NONCEBYTES:
        raise TypeError(f"nonce length must be {NONCEBYTES}")

    if ct_into is None:
        c = bytearray(len(message))
    else:
        if len(ct_into) < len(message):
            raise TypeError("ct_into length must be at least len(message)")
        c = ct_into
    if mac_into is None:
        mac = bytearray(maclen)
    else:
        if len(mac_into) < maclen:
            raise TypeError("mac_into length must be at least maclen")
        mac = mac_into

    rc = _lib.aegis128x4_encrypt_detached(
        ffi.from_buffer(c),
        ffi.from_buffer(mac),
        maclen,
        _ptr(message),
        len(message),
        _ptr(ad),
        0 if ad is None else len(ad),
        _ptr(nonce),
        _ptr(key),
    )
    if rc != 0:
        err_num = ffi.errno
        err_name = errno.errorcode.get(err_num, f"errno_{err_num}")
        raise RuntimeError(f"encrypt detached failed: {err_name}")
    return (
        c if ct_into is None else memoryview(c)[: len(message)],
        mac if mac_into is None else memoryview(mac)[:maclen],
    )  # type: ignore


def decrypt_detached(
    key: Buffer,
    nonce: Buffer,
    ct: Buffer,
    mac: Buffer,
    ad: Buffer | None = None,
    *,
    into: Buffer | None = None,
) -> bytearray | memoryview:
    """Decrypt ciphertext with detached MAC and associated data.

    Args:
        key: Secret key (same key used during encryption).
        nonce: Public nonce (same nonce used during encryption).
        ct: The ciphertext to decrypt.
        mac: The MAC to verify.
        ad: Associated data (optional).
        into: Buffer to write plaintext into (default: bytearray created).

    Returns:
        Plaintext as bytearray if into not provided, memoryview of into otherwise.

    Raises:
        TypeError: If lengths are invalid.
        ValueError: If authentication fails.
    """
    if len(key) != KEYBYTES:
        raise TypeError(f"key length must be {KEYBYTES}")
    if len(nonce) != NONCEBYTES:
        raise TypeError(f"nonce length must be {NONCEBYTES}")
    maclen = len(mac)
    if maclen not in (16, 32):
        raise TypeError("mac length must be 16 or 32")
    if into is None:
        out = bytearray(len(ct))
    else:
        if len(into) < len(ct):
            raise TypeError("into length must be at least len(ciphertext)")
        out = into

    rc = _lib.aegis128x4_decrypt_detached(
        ffi.from_buffer(out),
        _ptr(ct),
        len(ct),
        _ptr(mac),
        maclen,
        _ptr(ad),
        0 if ad is None else len(ad),
        _ptr(nonce),
        _ptr(key),
    )
    if rc != 0:
        raise ValueError("authentication failed")
    return out if into is None else memoryview(out)[: len(ct)]  # type: ignore


def encrypt(
    key: Buffer,
    nonce: Buffer,
    message: Buffer,
    ad: Buffer | None = None,
    *,
    maclen: int = MACBYTES,
    into: Buffer | None = None,
) -> bytearray | memoryview:
    """Encrypt message with associated data, returning ciphertext with appended MAC.

    Args:
        key: Secret key (generate with random_key()).
        nonce: Public nonce (generate with random_nonce()).
        message: The plaintext message to encrypt.
        ad: Associated data (optional).
        maclen: MAC length (16 or 32, default 16).
        into: Buffer to write ciphertext+MAC into (default: bytearray created).

    Returns:
        Ciphertext with appended MAC as bytearray if into not provided, memoryview of into otherwise.

    Raises:
        TypeError: If lengths are invalid.
        RuntimeError: If encryption fails.
    """
    if maclen not in (16, 32):
        raise TypeError("maclen must be 16 or 32")
    if len(key) != KEYBYTES:
        raise TypeError(f"key length must be {KEYBYTES}")
    if len(nonce) != NONCEBYTES:
        raise TypeError(f"nonce length must be {NONCEBYTES}")
    if into is None:
        out = bytearray(len(message) + maclen)
    else:
        if len(into) < len(message) + maclen:
            raise TypeError("into length must be at least len(message)+maclen")
        out = into

    rc = _lib.aegis128x4_encrypt(
        ffi.from_buffer(out),
        maclen,
        _ptr(message),
        len(message),
        _ptr(ad),
        0 if ad is None else len(ad),
        _ptr(nonce),
        _ptr(key),
    )
    if rc != 0:
        err_num = ffi.errno
        err_name = errno.errorcode.get(err_num, f"errno_{err_num}")
        raise RuntimeError(f"encrypt failed: {err_name}")
    return out if into is None else memoryview(out)[: len(message) + maclen]  # type: ignore


def decrypt(
    key: Buffer,
    nonce: Buffer,
    ct: Buffer,
    ad: Buffer | None = None,
    *,
    maclen: int = MACBYTES,
    into: Buffer | None = None,
) -> bytearray | memoryview:
    """Decrypt ciphertext with appended MAC and associated data.

    Args:
        key: Secret key (same key used during encryption).
        nonce: Public nonce (same nonce used during encryption).
        ct: The ciphertext with MAC to decrypt.
        ad: Associated data (optional).
        maclen: MAC length (16 or 32, default 16).
        into: Buffer to write plaintext into (default: bytearray created).

    Returns:
        Plaintext as bytearray if into not provided, memoryview of into otherwise.

    Raises:
        TypeError: If lengths are invalid.
        ValueError: If authentication fails.
    """
    if maclen not in (16, 32):
        raise TypeError("maclen must be 16 or 32")
    if len(key) != KEYBYTES:
        raise TypeError(f"key length must be {KEYBYTES}")
    if len(nonce) != NONCEBYTES:
        raise TypeError(f"nonce length must be {NONCEBYTES}")
    if len(ct) < maclen:
        raise TypeError("ciphertext too short for tag")
    expected_out = len(ct) - maclen
    if into is None:
        out = bytearray(expected_out)
    else:
        if len(into) < expected_out:
            raise TypeError(
                "into length must be at least len(ciphertext_with_tag)-maclen"
            )
        out = into

    rc = _lib.aegis128x4_decrypt(
        ffi.from_buffer(out),
        _ptr(ct),
        len(ct),
        maclen,
        _ptr(ad),
        0 if ad is None else len(ad),
        _ptr(nonce),
        _ptr(key),
    )
    if rc != 0:
        raise ValueError("authentication failed")
    return out if into is None else memoryview(out)[:expected_out]  # type: ignore


def stream(
    key: Buffer,
    nonce: Buffer | None,
    length: int | None = None,
    *,
    into: Buffer | None = None,
) -> bytearray | Buffer:
    """Generate a stream of pseudorandom bytes.

    Args:
        key: Secret key (generate with random_key()).
        nonce: Public nonce (generate with random_nonce(), uses zeroes for nonce if None).
        length: Number of bytes to generate (required if into is None).
        into: Buffer to write stream into (default: bytearray created).

    Returns:
        Pseudorandom bytes as bytearray, or into returned directly.

    Raises:
        TypeError: If lengths are invalid or neither length nor into provided.
    """
    if len(key) != KEYBYTES:
        raise TypeError(f"key length must be {KEYBYTES}")
    if nonce is not None and len(nonce) != NONCEBYTES:
        raise TypeError(f"nonce length must be {NONCEBYTES}")
    if into is None:
        if length is None:
            raise TypeError("provide either into or length")
        out = bytearray(length)
    else:
        if length is not None and len(into) < length:
            raise TypeError("into length must be at least length")
        out = into
    _lib.aegis128x4_stream(
        ffi.from_buffer(out),
        len(out),
        _ptr(nonce),
        _ptr(key),
    )
    return out if into is None else memoryview(out)[: length or len(out)]  # type: ignore


def encrypt_unauthenticated(
    key: Buffer,
    nonce: Buffer,
    message: Buffer,
    *,
    into: Buffer | None = None,
) -> bytearray | memoryview:
    """Encrypt message without authentication (for testing/debugging).

    Args:
        key: Secret key (generate with random_key()).
        nonce: Public nonce (generate with random_nonce()).
        message: The plaintext message to encrypt.
        into: Buffer to write ciphertext into (default: bytearray created).

    Returns:
        Ciphertext as bytearray if into not provided, memoryview of into otherwise.

    Raises:
        TypeError: If lengths are invalid.
    """
    if len(key) != KEYBYTES:
        raise TypeError(f"key length must be {KEYBYTES}")
    if len(nonce) != NONCEBYTES:
        raise TypeError(f"nonce length must be {NONCEBYTES}")
    if into is None:
        out = bytearray(len(message))
    else:
        if len(into) < len(message):
            raise TypeError("into length must be at least len(message)")
        out = into
    _lib.aegis128x4_encrypt_unauthenticated(
        ffi.from_buffer(out),
        _ptr(message),
        len(message),
        _ptr(nonce),
        _ptr(key),
    )
    return out if into is None else memoryview(out)[: len(message)]  # type: ignore


def decrypt_unauthenticated(
    key: Buffer,
    nonce: Buffer,
    ct: Buffer,
    *,
    into: Buffer | None = None,
) -> bytearray | memoryview:
    """Decrypt ciphertext without authentication (for testing/debugging).

    Args:
        key: Secret key (same key used during encryption).
        nonce: Public nonce (same nonce used during encryption).
        ct: The ciphertext to decrypt.
        into: Buffer to write plaintext into (default: bytearray created).

    Returns:
        Plaintext as bytearray if into not provided, memoryview of into otherwise.

    Raises:
        TypeError: If lengths are invalid.
    """
    if len(key) != KEYBYTES:
        raise TypeError(f"key length must be {KEYBYTES}")
    if len(nonce) != NONCEBYTES:
        raise TypeError(f"nonce length must be {NONCEBYTES}")
    if into is None:
        out = bytearray(len(ct))
    else:
        if len(into) < len(ct):
            raise TypeError("into length must be at least len(ciphertext)")
        out = into
    _lib.aegis128x4_decrypt_unauthenticated(
        ffi.from_buffer(out),
        _ptr(ct),
        len(ct),
        _ptr(nonce),
        _ptr(key),
    )
    return out if into is None else memoryview(out)[: len(ct)]  # type: ignore


# This is missing from C API but convenient to have here
def mac(
    key: Buffer,
    nonce: Buffer,
    data: Buffer,
    maclen: int = MACBYTES,
    into: Buffer | None = None,
) -> bytearray | memoryview:
    """Compute a MAC for the given data in one shot.

    Args:
        key: Secret key (generate with random_key())
        nonce: Public nonce (generate with random_nonce())
        data: Data to MAC
        maclen: MAC length (16 or 32, default 16)
        into: Buffer to write MAC into (default: bytearray created)

    Returns:
        MAC bytes as bytearray if into not provided, memoryview of into otherwise
    """
    mac_state = Mac(key, nonce, maclen)
    mac_state.update(data)
    return mac_state.final(into)


class Mac:
    """MAC calculation and verification with incremental updates.

    Example:
        a = Mac(key, nonce)
        a.update(data)
        ...
        mac = a.final()

    Hashlib compatible interface:
        a = Mac(key, nonce)
        a.update(data)
        bytes_mac = a.digest()
        hex_mac = a.hexdigest()
    """

    __slots__ = ("_proxy", "_maclen", "_cached_digest")

    def __init__(self, key: Buffer, nonce: Buffer, maclen: int = MACBYTES) -> None:
        """Create a MAC with the given key, nonce, and tag length.

        Raises:
            TypeError: If key, nonce, or maclen are invalid.
        """
        if maclen not in (16, 32):
            raise TypeError("maclen must be 16 or 32")
        if len(key) != KEYBYTES:
            raise TypeError(f"key length must be {KEYBYTES}")
        if len(nonce) != NONCEBYTES:
            raise TypeError(f"nonce length must be {NONCEBYTES}")

        self._maclen = maclen
        self._proxy = new_aligned_struct("aegis128x4_mac_state", ALIGNMENT)
        _lib.aegis128x4_mac_init(self._proxy.ptr, _ptr(key), _ptr(nonce))
        self._cached_digest: None | Literal[False] | bytes = None

    def reset(self) -> None:
        """Reset back to the original state, prior to any updates."""
        _lib.aegis128x4_mac_reset(self._proxy.ptr)
        self._cached_digest = None

    def clone(self) -> "Mac":
        """Return a clone of current MAC state."""
        clone = object.__new__(Mac)
        clone._maclen = self._maclen
        clone._proxy = new_aligned_struct("aegis128x4_mac_state", ALIGNMENT)
        _lib.aegis128x4_mac_state_clone(clone._proxy.ptr, self._proxy.ptr)
        clone._cached_digest = self._cached_digest
        return clone

    __deepcopy__ = clone

    def update(self, data: Buffer) -> None:
        """Update the MAC state with more data.

        Repeated calls to update() are equivalent to a single call with the concatenated data.
        """
        if self._cached_digest is not None:
            raise RuntimeError("Cannot update after final()")
        rc = _lib.aegis128x4_mac_update(self._proxy.ptr, _ptr(data), len(data))
        if rc != 0:
            err_num = ffi.errno
            err_name = errno.errorcode.get(err_num, f"errno_{err_num}")
            raise RuntimeError(f"mac update failed: {err_name}")

    def final(self, into: Buffer | None = None) -> bytearray | memoryview:
        """Calculate and return the MAC tag for the currently input data.

        This method can only be called once. After calling it, the MAC becomes unusable
        for further updates or calls to final().

        Args:
            into: Optional buffer to write the tag into (default: bytearray created).

        Returns:
            The tag as bytearray if into not provided, memoryview of into otherwise.

        Raises:
            TypeError: If lengths are invalid.
            RuntimeError: If finalization fails in the C library or if already finalized.
        """
        if self._cached_digest is not None:
            raise RuntimeError(
                "The MAC can only be calculated once. Use reset() to start over, or clone() before finalizing to continue."
            )
        maclen = self._maclen
        if into is None:
            out = bytearray(maclen)
        else:
            if len(into) < maclen:
                raise TypeError("into length must be at least maclen")
            out = into

        clone = self.clone()
        rc = _lib.aegis128x4_mac_final(clone._proxy.ptr, ffi.from_buffer(out), maclen)
        if rc != 0:
            err_num = ffi.errno
            err_name = errno.errorcode.get(err_num, f"errno_{err_num}")
            raise RuntimeError(f"mac final failed: {err_name}")
        self._cached_digest = False
        return out if into is None else memoryview(out)[:maclen]  # type: ignore

    def digest(self) -> bytes:
        """Calculate and return the MAC tag as bytes.

        After calling this method, the MAC becomes unusable for further updates.
        The result is cached and subsequent calls return the same value.
        Can be called after final() to get the cached digest.
        """
        if self._cached_digest:
            return self._cached_digest
        self._cached_digest = bytes(self.final())  # Overrides the False set by final()
        return self._cached_digest

    def hexdigest(self) -> str:
        """Calculate and return the MAC tag as a hex string.

        After calling this method, the MAC becomes unusable for further updates.
        The result is cached and subsequent calls return the same value.
        """
        return self.digest().hex()

    def verify(self, mac: Buffer):
        """Verify that the data entered so far matches the given MAC tag.

        Unlike the C library, this method does not alter the current state.

        Args:
            mac: The tag to verify against (16 or 32 bytes).

        Raises:
            TypeError: If tag length is invalid.
            ValueError: If verification fails.
        """
        maclen = len(mac)
        if maclen not in (16, 32):
            raise TypeError("mac length must be 16 or 32")

        cloned = self.clone()
        rc = _lib.aegis128x4_mac_verify(cloned._proxy.ptr, _ptr(mac), maclen)
        if rc != 0:
            raise ValueError("mac verification failed")


class Encryptor:
    """Incremental encryptor.

    - update(message[, into]) -> returns produced ciphertext bytes
    - final([into]) -> returns MAC tag
    """

    __slots__ = ("_state", "_maclen")

    def __init__(
        self,
        key: Buffer,
        nonce: Buffer,
        ad: Buffer | None = None,
        maclen: int = MACBYTES,
    ):
        """Create an incremental encryptor.

        Args:
            key: Secret key (generate with random_key()).
            nonce: Public nonce (generate with random_nonce()).
            ad: Associated data to bind to the encryption (optional).
            maclen: MAC length (16 or 32, default 16).

        Raises:
            TypeError: If key, nonce, or maclen are invalid.
        """
        if maclen not in (16, 32):
            raise TypeError("maclen must be 16 or 32")
        if len(key) != KEYBYTES:
            raise TypeError(f"key length must be {KEYBYTES}")
        if len(nonce) != NONCEBYTES:
            raise TypeError(f"nonce length must be {NONCEBYTES}")
        self._state = new_aligned_struct("aegis128x4_state", ALIGNMENT)
        _lib.aegis128x4_state_init(
            self._state.ptr,
            _ptr(ad) if ad is not None else ffi.NULL,
            0 if ad is None else len(ad),
            _ptr(nonce),
            _ptr(key),
        )
        self._maclen = maclen

    def update(
        self, message: Buffer, into: Buffer | None = None
    ) -> bytearray | memoryview:
        """Encrypt a chunk of the message.

        Args:
            message: Plaintext bytes to encrypt.
            into: Optional destination buffer; must be >= len(message).

        Returns:
            The ciphertext for this chunk as bytearray if into not provided, memoryview of into otherwise.

        Raises:
            TypeError: If destination buffer is too small.
            RuntimeError: If the C update call fails or if called after final().
        """
        if self._state is None:
            raise RuntimeError("Cannot call update() after final()")
        expected_out = len(message)
        out = into if into is not None else bytearray(expected_out)
        out_mv = memoryview(out)
        if len(out_mv) < expected_out:
            raise TypeError(
                "into length must be >= expected output size for this update"
            )
        written = ffi.new("size_t *")
        rc = _lib.aegis128x4_state_encrypt_update(
            self._state.ptr,
            ffi.from_buffer(out_mv),
            len(out_mv),
            written,
            _ptr(message),
            len(message),
        )
        if rc != 0:
            err_num = ffi.errno
            err_name = errno.errorcode.get(err_num, f"errno_{err_num}")
            raise RuntimeError(
                f"state encrypt update failed: {err_name} written {written[0]}"
            )
        w = int(written[0])
        assert w == expected_out
        return out if into is None else memoryview(out)[:w]  # type: ignore

    def final(self, into: Buffer | None = None) -> bytearray | memoryview:
        """Finalize encryption and return the authentication tag.

        Args:
            into: Optional destination buffer for the tag.

        Returns:
            The authentication tag as bytearray if into not provided, memoryview of into otherwise.

        Raises:
            RuntimeError: If the C final call fails or if called after final().
        """
        if self._state is None:
            raise RuntimeError("Cannot call final() after final()")
        maclen = self._maclen
        # Only the authentication tag is produced here; allocate exactly maclen
        out = into if into is not None else bytearray(maclen)
        written = ffi.new("size_t *")
        rc = _lib.aegis128x4_state_encrypt_final(
            self._state.ptr,
            ffi.from_buffer(out),
            len(out),
            written,
            maclen,
        )
        if rc != 0:
            err_num = ffi.errno
            err_name = errno.errorcode.get(err_num, f"errno_{err_num}")
            raise RuntimeError(f"state encrypt final failed: {err_name}")
        w = int(written[0])
        if into is None:
            # Only the tag bytes are returned when we allocate the buffer
            assert w == maclen
        self._state = None
        return out if into is None else memoryview(out)[:w]  # type: ignore


class Decryptor:
    """Incremental decryptor.

    - update(ciphertext[, into]) -> returns plaintext bytes
    - final(mac) -> verifies the MAC tag
    """

    __slots__ = ("_state", "_maclen")

    def __init__(
        self,
        key: Buffer,
        nonce: Buffer,
        ad: Buffer | None = None,
        maclen: int = MACBYTES,
    ):
        """Create an incremental decryptor for detached tags.

        Args:
            key: Secret key (same key used during encryption).
            nonce: Public nonce (same nonce used during encryption).
            ad: Associated data used during encryption (optional).
            maclen: MAC length (16 or 32, default 16).

        Raises:
            TypeError: If key, nonce, or maclen are invalid.
        """
        if maclen not in (16, 32):
            raise TypeError("maclen must be 16 or 32")
        if len(key) != KEYBYTES:
            raise TypeError(f"key length must be {KEYBYTES}")
        if len(nonce) != NONCEBYTES:
            raise TypeError(f"nonce length must be {NONCEBYTES}")
        self._state = new_aligned_struct("aegis128x4_state", ALIGNMENT)
        _lib.aegis128x4_state_init(
            self._state.ptr,
            _ptr(ad) if ad is not None else ffi.NULL,
            0 if ad is None else len(ad),
            _ptr(nonce),
            _ptr(key),
        )
        self._maclen = maclen

    def update(self, ct: Buffer, into: Buffer | None = None) -> bytearray | memoryview:
        """Process a chunk of ciphertext.

        Args:
            ct: Ciphertext bytes (without MAC).
            into: Optional destination buffer; must be >= len(ciphertext).

        Returns:
            A memoryview of the decrypted bytes for this chunk if into provided, bytearray otherwise.

        Raises:
            TypeError: If destination buffer is too small.
            RuntimeError: If the C update call fails or if called after final().
        """
        if self._state is None:
            raise RuntimeError("Cannot call update() after final()")
        expected_out = len(ct)
        out = into if into is not None else bytearray(expected_out)
        out_mv = memoryview(out)
        if len(out_mv) < expected_out:
            raise TypeError("into length must be >= required capacity for this update")
        written = ffi.new("size_t *")
        rc = _lib.aegis128x4_state_decrypt_detached_update(
            self._state.ptr,
            ffi.from_buffer(out_mv),
            len(out_mv),
            written,
            _ptr(ct),
            len(ct),
        )
        if rc != 0:
            err_num = ffi.errno
            err_name = errno.errorcode.get(err_num, f"errno_{err_num}")
            raise RuntimeError(f"state decrypt update failed: {err_name}")
        w = int(written[0])
        assert w == expected_out, f"got {w}, expected {expected_out}, len(ct)={len(ct)}"
        return out if into is None else memoryview(out)[:w]  # type: ignore

    def final(self, mac: Buffer) -> None:
        """Finalize decryption by verifying the MAC tag.

        Args:
            mac: Tag to verify.

        Raises:
            TypeError: If tag length doesn't match the expected maclen.
            ValueError: If authentication fails.
            RuntimeError: If called after final().
        """
        if self._state is None:
            raise RuntimeError("Cannot call final() after final()")
        maclen = self._maclen
        if len(mac) != maclen:
            raise TypeError(f"mac length must be {maclen}")
        rc = _lib.aegis128x4_state_decrypt_detached_final(
            self._state.ptr, ffi.NULL, 0, ffi.NULL, _ptr(mac), maclen
        )
        if rc != 0:
            raise ValueError("authentication failed")
        self._state = None


def new_state():
    """Allocate and return a new aegis128x4_state* with proper alignment."""
    return new_aligned_struct("aegis128x4_state", ALIGNMENT)


def new_mac_state():
    """Allocate and return a new aegis128x4_mac_state* with proper alignment."""
    return new_aligned_struct("aegis128x4_mac_state", ALIGNMENT)


__all__ = [
    # constants
    "NAME",
    "KEYBYTES",
    "NONCEBYTES",
    "MACBYTES",
    "MACBYTES_LONG",
    "ALIGNMENT",
    "RATE",
    # utility functions
    "random_key",
    "random_nonce",
    "nonce_increment",
    "wipe",
    # one-shot functions
    "encrypt_detached",
    "decrypt_detached",
    "encrypt",
    "decrypt",
    "stream",
    "encrypt_unauthenticated",
    "decrypt_unauthenticated",
    "mac",
    # incremental classes
    "Encryptor",
    "Decryptor",
    "Mac",
]
