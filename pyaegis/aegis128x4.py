"""AEGIS-128X4"""
# All modules are generated from aegis128x4.py by tools/gen_modules.py!
# DO NOT EDIT OTHER ALGORITHM FILES MANUALLY!

import errno
import secrets

from ._loader import ffi
from ._loader import lib as _lib
from .util import Buffer, new_aligned_struct

# Constants exposed as functions in C; mirror them as integers at module import time
KEYBYTES = _lib.aegis128x4_keybytes()
NPUBBYTES = _lib.aegis128x4_npubbytes()
ABYTES_MIN = _lib.aegis128x4_abytes_min()
ABYTES_MAX = _lib.aegis128x4_abytes_max()
TAILBYTES_MAX = _lib.aegis128x4_tailbytes_max()
ALIGNMENT = 64
RATE = 128


def random_key() -> bytes:
    """Generate a random key using cryptographically secure random bytes."""
    return secrets.token_bytes(KEYBYTES)


def random_nonce() -> bytes:
    """Generate a random nonce using cryptographically secure random bytes."""
    return secrets.token_bytes(NPUBBYTES)


def _ptr(buf):
    return ffi.NULL if buf is None else ffi.from_buffer(buf)


def encrypt_detached(
    key: Buffer,
    nonce: Buffer,
    message: Buffer,
    ad: Buffer | None = None,
    *,
    maclen: int = ABYTES_MIN,
    ct_into: Buffer | None = None,
    mac_into: Buffer | None = None,
) -> tuple[bytearray | memoryview, bytearray | memoryview]:
    f"""Encrypt message with associated data, returning ciphertext and MAC separately.

    Args:
        key: Key ({KEYBYTES=}).
        nonce: Nonce ({NPUBBYTES=}).
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
    if len(nonce) != NPUBBYTES:
        raise TypeError(f"nonce length must be {NPUBBYTES}")

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
    f"""Decrypt ciphertext with detached MAC and associated data.

    Args:
        key: Key ({KEYBYTES=}).
        nonce: Nonce ({NPUBBYTES=}).
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
    if len(nonce) != NPUBBYTES:
        raise TypeError(f"nonce length must be {NPUBBYTES}")
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
    maclen: int = ABYTES_MIN,
    into: Buffer | None = None,
) -> bytearray | memoryview:
    f"""Encrypt message with associated data, returning ciphertext with appended MAC.

    Args:
        key: Key ({KEYBYTES=}).
        nonce: Nonce ({NPUBBYTES=}).
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
    if len(nonce) != NPUBBYTES:
        raise TypeError(f"nonce length must be {NPUBBYTES}")
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
    maclen: int = ABYTES_MIN,
    into: Buffer | None = None,
) -> bytearray | memoryview:
    f"""Decrypt ciphertext with appended MAC and associated data.

    Args:
        key: Key ({KEYBYTES=}).
        nonce: Nonce ({NPUBBYTES=}).
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
    if len(nonce) != NPUBBYTES:
        raise TypeError(f"nonce length must be {NPUBBYTES}")
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
    f"""Generate a stream of pseudorandom bytes.

    Args:
        key: Key ({KEYBYTES=}).
        nonce: Nonce ({NPUBBYTES=}, uses zeroes for nonce if None).
        length: Number of bytes to generate (required if into is None).
        into: Buffer to write stream into (default: bytearray created).

    Returns:
        Pseudorandom bytes as bytearray, or into returned directly.

    Raises:
        TypeError: If lengths are invalid or neither length nor into provided.
    """
    if len(key) != KEYBYTES:
        raise TypeError(f"key length must be {KEYBYTES}")
    if nonce is not None and len(nonce) != NPUBBYTES:
        raise TypeError(f"nonce length must be {NPUBBYTES}")
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
    f"""Encrypt message without authentication (for testing/debugging).

    Args:
        key: Key ({KEYBYTES=}).
        nonce: Nonce ({NPUBBYTES=}).
        message: The plaintext message to encrypt.
        into: Buffer to write ciphertext into (default: bytearray created).

    Returns:
        Ciphertext as bytearray if into not provided, memoryview of into otherwise.

    Raises:
        TypeError: If lengths are invalid.
    """
    if len(key) != KEYBYTES:
        raise TypeError(f"key length must be {KEYBYTES}")
    if len(nonce) != NPUBBYTES:
        raise TypeError(f"nonce length must be {NPUBBYTES}")
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
    f"""Decrypt ciphertext without authentication (for testing/debugging).

    Args:
        key: Key ({KEYBYTES=}).
        nonce: Nonce ({NPUBBYTES=}).
        ct: The ciphertext to decrypt.
        into: Buffer to write plaintext into (default: bytearray created).

    Returns:
        Plaintext as bytearray if into not provided, memoryview of into otherwise.

    Raises:
        TypeError: If lengths are invalid.
    """
    if len(key) != KEYBYTES:
        raise TypeError(f"key length must be {KEYBYTES}")
    if len(nonce) != NPUBBYTES:
        raise TypeError(f"nonce length must be {NPUBBYTES}")
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
    maclen: int = ABYTES_MIN,
    into: Buffer | None = None,
) -> bytearray | memoryview:
    f"""Compute a MAC for the given data in one shot.

    Args:
        key: Key ({KEYBYTES=})
        nonce: Nonce ({NPUBBYTES=})
        data: Data to MAC
        maclen: MAC length (16 or 32, default 16)
        into: Buffer to write MAC into (default: bytearray created)

    Returns:
        MAC bytes as bytearray if into not provided, memoryview of into otherwise
    """
    mac_state = Mac(key, nonce)
    mac_state.update(data)
    return mac_state.final(maclen, into)


class Mac:
    """AEGIS-128X4 MAC state wrapper.

    Usage:
        mac = Mac(key, nonce)
        mac.update(data)
        tag = mac.final()  # defaults to 16-byte MAC
        # or verify:
        mac2 = Mac(key, nonce); mac2.update(data); mac2.verify(tag)
    """

    __slots__ = ("_st", "_owner")

    def __init__(
        self,
        key: Buffer,
        nonce: Buffer,
        _other=None,
    ) -> None:
        f"""Initialize a MAC state with a nonce and key.

        Args:
            key: Key ({KEYBYTES=}).
            nonce: Nonce ({NPUBBYTES=}).

        Raises:
            TypeError: If key or nonce lengths are invalid.
        """
        st, owner = new_aligned_struct("aegis128x4_mac_state", ALIGNMENT)
        self._st = st
        self._owner = owner
        if _other is not None:  # clone path
            _lib.aegis128x4_mac_state_clone(self._st, _other._st)
            return
        # Normal init path
        if len(key) != KEYBYTES:
            raise TypeError(f"key length must be {KEYBYTES}")
        if len(nonce) != NPUBBYTES:
            raise TypeError(f"nonce length must be {NPUBBYTES}")
        _lib.aegis128x4_mac_init(self._st, _ptr(key), _ptr(nonce))

    def __deepcopy__(self) -> "Mac":
        """Return a clone of current MAC state."""
        return Mac(b"", b"", _other=self)

    clone = __deepcopy__

    def reset(self) -> None:
        """Reset the MAC state so it can be reused with the same nonce and key."""
        _lib.aegis128x4_mac_reset(self._st)

    def update(self, data: Buffer) -> None:
        """Absorb data into the MAC state.

        Args:
            data: Bytes-like object to authenticate.

        Raises:
            RuntimeError: If the underlying C function reports an error.
        """
        rc = _lib.aegis128x4_mac_update(self._st, _ptr(data), len(data))
        if rc != 0:
            err_num = ffi.errno
            err_name = errno.errorcode.get(err_num, f"errno_{err_num}")
            raise RuntimeError(f"mac update failed: {err_name}")

    def final(
        self,
        maclen: int = ABYTES_MIN,
        into: Buffer | None = None,
    ) -> bytearray | memoryview:
        """Finalize and return the MAC tag.

        Args:
            maclen: Tag length in bytes (16 or 32). Defaults to 16.
            into: Optional buffer to write the tag into (default: bytearray created).

        Returns:
            The tag as bytearray if into not provided, memoryview of into otherwise.

        Raises:
            TypeError: If lengths are invalid.
            RuntimeError: If finalization fails in the C library.
        """
        if maclen not in (16, 32):
            raise TypeError("maclen must be 16 or 32")
        if into is None:
            out = bytearray(maclen)
        else:
            if len(into) < maclen:
                raise TypeError("into length must be at least maclen")
            out = into
        out_mv = memoryview(out)
        rc = _lib.aegis128x4_mac_final(self._st, ffi.from_buffer(out_mv), maclen)
        if rc != 0:
            err_num = ffi.errno
            err_name = errno.errorcode.get(err_num, f"errno_{err_num}")
            raise RuntimeError(f"mac final failed: {err_name}")
        return out if into is None else memoryview(out)[:maclen]  # type: ignore

    def verify(self, mac: Buffer):
        """Verify a tag for the current MAC state.

        Args:
            mac: The tag to verify (16 or 32 bytes).

        Returns:
            Only if verification succeeds.

        Raises:
            TypeError: If tag length is invalid.
            ValueError: If verification fails.
        """
        maclen = len(mac)
        if maclen not in (16, 32):
            raise TypeError("mac length must be 16 or 32")
        rc = _lib.aegis128x4_mac_verify(self._st, _ptr(mac), maclen)
        if rc != 0:
            raise ValueError("mac verification failed")


class Encryptor:
    """Incremental encryptor.

    - update(message[, into]) -> returns produced ciphertext bytes
    - final([into], maclen=16) -> returns tail+tag bytes
    - final_detached([ct_into], [mac_into], maclen=16) -> returns (tail_bytes, mac)
    """

    __slots__ = ("_st", "_owner", "_bytes_in", "_bytes_out")

    def __init__(self, key: Buffer, nonce: Buffer, ad: Buffer | None = None):
        f"""Create an incremental encryptor.

        Args:
            key: Key ({KEYBYTES=}).
            nonce: Nonce ({NPUBBYTES=}).
            ad: Associated data to bind to the encryption (optional).

        Raises:
            TypeError: If key or nonce lengths are invalid.
        """
        if len(key) != KEYBYTES:
            raise TypeError(f"key length must be {KEYBYTES}")
        if len(nonce) != NPUBBYTES:
            raise TypeError(f"nonce length must be {NPUBBYTES}")
        st, owner = new_aligned_struct("aegis128x4_state", ALIGNMENT)
        _lib.aegis128x4_state_init(
            st,
            _ptr(ad) if ad is not None else ffi.NULL,
            0 if ad is None else len(ad),
            _ptr(nonce),
            _ptr(key),
        )
        self._st = st
        self._owner = owner
        self._bytes_in = 0
        self._bytes_out = 0

    @property
    def bytes_in(self) -> int:
        """Total plaintext bytes fed to update() so far."""
        return self._bytes_in

    @property
    def bytes_out(self) -> int:
        """Total ciphertext bytes produced so far.

        Includes update() and final() output.
        """
        return self._bytes_out

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
            RuntimeError: If the C update call fails.
        """
        expected_out = len(message)
        out = into if into is not None else bytearray(expected_out)
        out_mv = memoryview(out)
        if len(out_mv) < expected_out:
            raise TypeError(
                "into length must be >= expected output size for this update"
            )
        written = ffi.new("size_t *")
        rc = _lib.aegis128x4_state_encrypt_update(
            self._st,
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
        self._bytes_in += len(message)
        self._bytes_out += w
        return out if into is None else memoryview(out)[:w]  # type: ignore

    def final(
        self, into: Buffer | None = None, maclen: int = ABYTES_MIN
    ) -> bytearray | memoryview:
        """Finalize encryption, writing any remaining bytes and the tag.

        Args:
            into: Optional destination buffer for the tail and tag.
            maclen: Tag length (16 or 32). Defaults to 16.

        Returns:
            A memoryview of the produced bytes (tail + tag) if into provided, bytearray slice otherwise.

        Raises:
            TypeError: If maclen is invalid.
            RuntimeError: If the C final call fails.
        """
        if maclen not in (16, 32):
            raise TypeError("maclen must be 16 or 32")
        # Only the authentication tag is produced here; allocate exactly maclen
        out = into if into is not None else bytearray(maclen)
        written = ffi.new("size_t *")
        rc = _lib.aegis128x4_state_encrypt_final(
            self._st,
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
        self._bytes_out += w
        return out if into is None else memoryview(out)[:w]  # type: ignore


class Decryptor:
    """Incremental decryptor.

    - update(ciphertext[, into]) -> returns plaintext bytes
    - final(mac) -> verifies the MAC tag
    """

    __slots__ = ("_st", "_owner", "_bytes_in", "_bytes_out")

    def __init__(self, key: Buffer, nonce: Buffer, ad: Buffer | None = None):
        f"""Create an incremental decryptor for detached tags.

        Args:
            key: Key ({KEYBYTES=}).
            nonce: Nonce ({NPUBBYTES=}).
            ad: Associated data used during encryption (optional).

        Raises:
            TypeError: If key or nonce lengths are invalid.
        """
        if len(key) != KEYBYTES:
            raise TypeError(f"key length must be {KEYBYTES}")
        if len(nonce) != NPUBBYTES:
            raise TypeError(f"nonce length must be {NPUBBYTES}")
        st, owner = new_aligned_struct("aegis128x4_state", ALIGNMENT)
        _lib.aegis128x4_state_init(
            st,
            _ptr(ad) if ad is not None else ffi.NULL,
            0 if ad is None else len(ad),
            _ptr(nonce),
            _ptr(key),
        )
        self._st = st
        self._owner = owner
        self._bytes_in = 0
        self._bytes_out = 0

    @property
    def bytes_in(self) -> int:
        """Total ciphertext bytes fed to update() so far."""
        return self._bytes_in

    @property
    def bytes_out(self) -> int:
        """Total plaintext bytes produced so far."""
        return self._bytes_out

    def update(self, ct: Buffer, into: Buffer | None = None) -> bytearray | memoryview:
        """Process a chunk of ciphertext.

        Args:
            ct: Ciphertext bytes (without MAC).
            into: Optional destination buffer; must be >= len(ciphertext).

        Returns:
            A memoryview of the decrypted bytes for this chunk if into provided, bytearray otherwise.

        Raises:
            TypeError: If destination buffer is too small.
            RuntimeError: If the C update call fails.
        """
        expected_out = len(ct)
        out = into if into is not None else bytearray(expected_out)
        out_mv = memoryview(out)
        if len(out_mv) < expected_out:
            raise TypeError("into length must be >= required capacity for this update")
        written = ffi.new("size_t *")
        rc = _lib.aegis128x4_state_decrypt_detached_update(
            self._st,
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
        self._bytes_in += len(ct)
        self._bytes_out += w
        return out if into is None else memoryview(out)[:w]  # type: ignore

    def final(self, mac: Buffer) -> None:
        """Finalize decryption by verifying the MAC tag.

        Args:
            mac: Tag to verify (16 or 32 bytes).

        Raises:
            TypeError: If tag length is invalid.
            ValueError: If authentication fails.
        """
        maclen = len(mac)
        if maclen not in (16, 32):
            raise TypeError("mac length must be 16 or 32")
        rc = _lib.aegis128x4_state_decrypt_detached_final(
            self._st, ffi.NULL, 0, ffi.NULL, _ptr(mac), maclen
        )
        if rc != 0:
            raise ValueError("authentication failed")


def new_state():
    """Allocate and return a new aegis128x4_state* with proper alignment."""
    return new_aligned_struct("aegis128x4_state", ALIGNMENT)


def new_mac_state():
    """Allocate and return a new aegis128x4_mac_state* with proper alignment."""
    return new_aligned_struct("aegis128x4_mac_state", ALIGNMENT)


__all__ = [
    # constants
    "KEYBYTES",
    "NPUBBYTES",
    "ABYTES_MIN",
    "ABYTES_MAX",
    "TAILBYTES_MAX",
    "ALIGNMENT",
    "RATE",
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
