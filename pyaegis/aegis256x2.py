"""aegis256x2 Python submodule.

Simplified API: single functions can return newly allocated buffers or write
into user-provided buffers via optional `into=` (and `mac_into=` for detached).

Error return codes from the C library raise ValueError.
"""

import errno
from collections.abc import Buffer

from ._loader import alloc_aligned, ffi, libc
from ._loader import lib as _lib

# Constants exposed as functions in C; mirror them as integers at module import time
KEYBYTES = _lib.aegis256x2_keybytes()
NPUBBYTES = _lib.aegis256x2_npubbytes()
ABYTES_MIN = _lib.aegis256x2_abytes_min()
ABYTES_MAX = _lib.aegis256x2_abytes_max()
TAILBYTES_MAX = _lib.aegis256x2_tailbytes_max()
ALIGNMENT = 32
RATE = 32


def calc_update_output_size(bytes_in: int, bytes_next: int) -> int:
    """Calculate the number of bytes output by the next incremental update.

    Args:
        bytes_in: Total number of bytes passed to update so far.
        bytes_next: Length of the next input chunk.

    Returns:
        Number of bytes that the next update will write.
    """
    return (((bytes_in % RATE) + bytes_next) // RATE) * RATE


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
) -> tuple[memoryview, memoryview]:
    """Encrypt message with associated data, returning ciphertext and MAC separately.

    Args:
        key: Key (32 bytes).
        nonce: Nonce (32 bytes).
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
    nonce = memoryview(nonce)
    key = memoryview(key)
    message = memoryview(message)
    ad = memoryview(ad) if ad is not None else None
    ct_into = memoryview(ct_into) if ct_into is not None else None
    mac_into = memoryview(mac_into) if mac_into is not None else None

    if maclen not in (16, 32):
        raise TypeError("maclen must be 16 or 32")
    if key.nbytes != KEYBYTES:
        raise TypeError(f"key length must be {KEYBYTES}")
    if nonce.nbytes != NPUBBYTES:
        raise TypeError(f"nonce length must be {NPUBBYTES}")

    c = ct_into if ct_into is not None else memoryview(bytearray(message.nbytes))
    mac = mac_into if mac_into is not None else memoryview(bytearray(maclen))
    if c.nbytes != message.nbytes:
        raise TypeError("into length must equal len(message)")
    if mac.nbytes != maclen:
        raise TypeError("mac_into length must equal maclen")

    rc = _lib.aegis256x2_encrypt_detached(
        ffi.from_buffer(c),
        ffi.from_buffer(mac),
        maclen,
        _ptr(message),
        message.nbytes,
        _ptr(ad),
        0 if ad is None else ad.nbytes,
        _ptr(nonce),
        _ptr(key),
    )
    if rc != 0:
        err_num = ffi.errno
        err_name = errno.errorcode.get(err_num, f"errno_{err_num}")
        raise RuntimeError(f"encrypt detached failed: {err_name}")
    return c, mac


def decrypt_detached(
    key: Buffer,
    nonce: Buffer,
    ct: Buffer,
    mac: Buffer,
    ad: Buffer | None = None,
    *,
    into: Buffer | None = None,
) -> memoryview:
    """Decrypt ciphertext with detached MAC and associated data.

    Args:
        key: Key (32 bytes).
        nonce: Nonce (32 bytes).
        ct: The ciphertext to decrypt.
        mac: The MAC to verify.
        ad: Associated data (optional).
        into: Buffer to write plaintext into (default: bytearray created).

    Returns:
        Plaintext as bytearray if into not provided.

    Raises:
        TypeError: If lengths are invalid.
        ValueError: If authentication fails.
    """
    nonce = memoryview(nonce)
    key = memoryview(key)
    ct = memoryview(ct)
    mac = memoryview(mac)
    ad = memoryview(ad) if ad is not None else None
    into = memoryview(into) if into is not None else None

    if key.nbytes != KEYBYTES:
        raise TypeError(f"key length must be {KEYBYTES}")
    if nonce.nbytes != NPUBBYTES:
        raise TypeError(f"nonce length must be {NPUBBYTES}")
    maclen = mac.nbytes
    if maclen not in (16, 32):
        raise TypeError("mac length must be 16 or 32")
    m_out = into if into is not None else memoryview(bytearray(ct.nbytes))
    if m_out.nbytes != ct.nbytes:
        raise TypeError("into length must equal len(ciphertext)")

    rc = _lib.aegis256x2_decrypt_detached(
        ffi.from_buffer(m_out),
        _ptr(ct),
        ct.nbytes,
        _ptr(mac),
        maclen,
        _ptr(ad),
        0 if ad is None else ad.nbytes,
        _ptr(nonce),
        _ptr(key),
    )
    if rc != 0:
        raise ValueError("authentication failed")
    return memoryview(m_out)


def encrypt(
    key: Buffer,
    nonce: Buffer,
    message: Buffer,
    ad: Buffer | None = None,
    *,
    maclen: int = ABYTES_MIN,
    into: Buffer | None = None,
) -> memoryview:
    """Encrypt message with associated data, returning ciphertext with appended MAC.

    Args:
        key: Key (32 bytes).
        nonce: Nonce (32 bytes).
        message: The plaintext message to encrypt.
        ad: Associated data (optional).
        maclen: MAC length (16 or 32, default 16).
        into: Buffer to write ciphertext+MAC into (default: bytearray created).

    Returns:
        Ciphertext with appended MAC as bytearray if into not provided.

    Raises:
        TypeError: If lengths are invalid.
        RuntimeError: If encryption fails.
    """
    nonce = memoryview(nonce)
    key = memoryview(key)
    message = memoryview(message)
    ad = memoryview(ad) if ad is not None else None
    into = memoryview(into) if into is not None else None

    if maclen not in (16, 32):
        raise TypeError("maclen must be 16 or 32")
    if key.nbytes != KEYBYTES:
        raise TypeError(f"key length must be {KEYBYTES}")
    if nonce.nbytes != NPUBBYTES:
        raise TypeError(f"nonce length must be {NPUBBYTES}")
    out = into if into is not None else memoryview(bytearray(message.nbytes + maclen))
    if out.nbytes != message.nbytes + maclen:
        raise TypeError("into length must be len(message)+maclen")

    rc = _lib.aegis256x2_encrypt(
        ffi.from_buffer(out),
        maclen,
        _ptr(message),
        message.nbytes,
        _ptr(ad),
        0 if ad is None else ad.nbytes,
        _ptr(nonce),
        _ptr(key),
    )
    if rc != 0:
        err_num = ffi.errno
        err_name = errno.errorcode.get(err_num, f"errno_{err_num}")
        raise RuntimeError(f"encrypt failed: {err_name}")
    return out


def decrypt(
    key: Buffer,
    nonce: Buffer,
    ct: Buffer,
    ad: Buffer | None = None,
    *,
    maclen: int = ABYTES_MIN,
    into: Buffer | None = None,
) -> memoryview:
    """Decrypt ciphertext with appended MAC and associated data.

    Args:
        key: Key (32 bytes).
        nonce: Nonce (32 bytes).
        ct: The ciphertext with MAC to decrypt.
        ad: Associated data (optional).
        maclen: MAC length (16 or 32, default 16).
        into: Buffer to write plaintext into (default: bytearray created).

    Returns:
        Plaintext as bytearray if into not provided.

    Raises:
        TypeError: If lengths are invalid.
        ValueError: If authentication fails.
    """
    nonce = memoryview(nonce)
    key = memoryview(key)
    ct = memoryview(ct)
    ad = memoryview(ad) if ad is not None else None
    into = memoryview(into) if into is not None else None

    if maclen not in (16, 32):
        raise TypeError("maclen must be 16 or 32")
    if key.nbytes != KEYBYTES:
        raise TypeError(f"key length must be {KEYBYTES}")
    if nonce.nbytes != NPUBBYTES:
        raise TypeError(f"nonce length must be {NPUBBYTES}")
    if ct.nbytes < maclen:
        raise TypeError("ciphertext too short for tag")
    m_out = into if into is not None else memoryview(bytearray(ct.nbytes - maclen))
    if m_out.nbytes != ct.nbytes - maclen:
        raise TypeError("into length must be len(ciphertext_with_tag)-maclen")

    rc = _lib.aegis256x2_decrypt(
        ffi.from_buffer(m_out),
        _ptr(ct),
        ct.nbytes,
        maclen,
        _ptr(ad),
        0 if ad is None else ad.nbytes,
        _ptr(nonce),
        _ptr(key),
    )
    if rc != 0:
        raise ValueError("authentication failed")
    return m_out


def stream(
    key: Buffer,
    nonce: Buffer | None,
    length: int | None = None,
    *,
    into: Buffer | None = None,
) -> memoryview:
    """Generate a stream of pseudorandom bytes.

    Args:
        key: Key (32 bytes).
        nonce: Nonce (32 bytes, uses zeroes for nonce if None).
        length: Number of bytes to generate (required if into is None).
        into: Buffer to write stream into (default: bytearray created).

    Returns:
        Pseudorandom bytes as bytearray if into not provided.

    Raises:
        TypeError: If lengths are invalid or neither length nor into provided.
    """
    nonce = memoryview(nonce) if nonce is not None else None
    key = memoryview(key)
    into = memoryview(into) if into is not None else None

    if key.nbytes != KEYBYTES:
        raise TypeError(f"key length must be {KEYBYTES}")
    if nonce is not None and nonce.nbytes != NPUBBYTES:
        raise TypeError(f"nonce length must be {NPUBBYTES}")
    if into is None and length is None:
        raise TypeError("provide either into or length")
    out = into if into is not None else memoryview(bytearray(int(length or 0)))
    _lib.aegis256x2_stream(
        ffi.from_buffer(out),
        out.nbytes,
        _ptr(nonce),
        _ptr(key),
    )
    return out


def encrypt_unauthenticated(
    key: Buffer,
    nonce: Buffer,
    message: Buffer,
    *,
    into: Buffer | None = None,
) -> memoryview:
    """Encrypt message without authentication (for testing/debugging).

    Args:
        key: Key (32 bytes).
        nonce: Nonce (32 bytes).
        message: The plaintext message to encrypt.
        into: Buffer to write ciphertext into (default: bytearray created).

    Returns:
        Ciphertext as bytearray if into not provided.

    Raises:
        TypeError: If lengths are invalid.
    """
    message = memoryview(message)
    nonce = memoryview(nonce)
    key = memoryview(key)
    into = memoryview(into) if into is not None else None

    if key.nbytes != KEYBYTES:
        raise TypeError(f"key length must be {KEYBYTES}")
    if nonce.nbytes != NPUBBYTES:
        raise TypeError(f"nonce length must be {NPUBBYTES}")
    out = into if into is not None else memoryview(bytearray(message.nbytes))
    if out.nbytes != message.nbytes:
        raise TypeError("into length must equal len(message)")
    _lib.aegis256x2_encrypt_unauthenticated(
        ffi.from_buffer(out),
        _ptr(message),
        message.nbytes,
        _ptr(nonce),
        _ptr(key),
    )
    return out


def decrypt_unauthenticated(
    key: Buffer,
    nonce: Buffer,
    ct: Buffer,
    *,
    into: Buffer | None = None,
) -> memoryview:
    """Decrypt ciphertext without authentication (for testing/debugging).

    Args:
        key: Key (32 bytes).
        nonce: Nonce (32 bytes).
        ct: The ciphertext to decrypt.
        into: Buffer to write plaintext into (default: bytearray created).

    Returns:
        Plaintext as bytearray if into not provided.

    Raises:
        TypeError: If lengths are invalid.
    """
    ct = memoryview(ct)
    nonce = memoryview(nonce)
    key = memoryview(key)
    into = memoryview(into) if into is not None else None

    if key.nbytes != KEYBYTES:
        raise TypeError(f"key length must be {KEYBYTES}")
    if nonce.nbytes != NPUBBYTES:
        raise TypeError(f"nonce length must be {NPUBBYTES}")
    out = into if into is not None else memoryview(bytearray(ct.nbytes))
    if out.nbytes != ct.nbytes:
        raise TypeError("into length must equal len(ciphertext)")
    _lib.aegis256x2_decrypt_unauthenticated(
        ffi.from_buffer(out),
        _ptr(ct),
        ct.nbytes,
        _ptr(nonce),
        _ptr(key),
    )
    return out


# This is missing from C API but convenient to have here
def mac(
    key: Buffer,
    nonce: Buffer,
    data: Buffer,
    maclen: int = ABYTES_MIN,
) -> memoryview:
    """Compute a MAC for the given data in one shot.

    Args:
        key: Key (32 bytes)
        nonce: Nonce (32 bytes)
        data: Data to MAC
        maclen: MAC length (16 or 32, default 16)

    Returns:
        MAC bytes
    """
    mac_state = Mac(key, nonce)
    mac_state.update(data)
    return mac_state.final(maclen)


class Mac:
    """AEGIS-256X2 MAC state wrapper.

    Usage:
        mac = Mac(key, nonce)
        mac.update(data)
        tag = mac.final()  # defaults to 16-byte MAC
        # or verify:
        mac2 = Mac(key, nonce); mac2.update(data); mac2.verify(tag)
    """

    __slots__ = ("_st", "_nonce", "_key")

    def __init__(
        self,
        key: Buffer,
        nonce: Buffer,
        _other=None,
    ) -> None:
        """Initialize a MAC state with a nonce and key.

        Args:
            key: Key (32 bytes).
            nonce: Nonce (32 bytes).

        Raises:
            TypeError: If key or nonce lengths are invalid.
        """
        raw = alloc_aligned(ffi.sizeof("aegis256x2_mac_state"), ALIGNMENT)
        st = ffi.cast("aegis256x2_mac_state *", raw)
        self._st = ffi.gc(st, libc.free)
        if _other is not None:
            _lib.aegis256x2_mac_state_clone(self._st, _other._st)
            return
        # Normal init
        nonce = memoryview(nonce)
        key = memoryview(key)
        if key.nbytes != KEYBYTES:
            raise TypeError(f"key length must be {KEYBYTES=}")
        if nonce.nbytes != NPUBBYTES:
            raise TypeError(f"nonce length must be {NPUBBYTES=}")
        _lib.aegis256x2_mac_init(self._st, _ptr(key), _ptr(nonce))

    def __deepcopy__(self) -> "Mac":
        """Return a clone of current MAC state."""
        return Mac(b"", b"", _other=self)

    clone = __deepcopy__

    def reset(self) -> None:
        """Reset the MAC state so it can be reused with the same nonce and key."""
        _lib.aegis256x2_mac_reset(self._st)

    def update(self, data: Buffer) -> None:
        """Absorb data into the MAC state.

        Args:
            data: Bytes-like object to authenticate.

        Raises:
            RuntimeError: If the underlying C function reports an error.
        """
        data = memoryview(data)
        rc = _lib.aegis256x2_mac_update(self._st, _ptr(data), data.nbytes)
        if rc != 0:
            err_num = ffi.errno
            err_name = errno.errorcode.get(err_num, f"errno_{err_num}")
            raise RuntimeError(f"mac update failed: {err_name}")

    def final(
        self,
        maclen: int = ABYTES_MIN,
        into: Buffer | None = None,
    ) -> memoryview:
        """Finalize and return the MAC tag.

        Args:
            maclen: Tag length in bytes (16 or 32). Defaults to 16.
            into: Optional buffer to write the tag into (default: bytearray created).

        Returns:
            The tag as a memoryview; if ``into`` is provided, it views that buffer.

        Raises:
            TypeError: If lengths are invalid.
            RuntimeError: If finalization fails in the C library.
        """
        if maclen not in (16, 32):
            raise TypeError("maclen must be 16 or 32")
        out = into if into is not None else bytearray(maclen)
        out = memoryview(out)
        if out.nbytes != maclen:
            raise TypeError("into length must equal maclen")
        rc = _lib.aegis256x2_mac_final(self._st, ffi.from_buffer(out), maclen)
        if rc != 0:
            err_num = ffi.errno
            err_name = errno.errorcode.get(err_num, f"errno_{err_num}")
            raise RuntimeError(f"mac final failed: {err_name}")
        return out

    def verify(self, mac: Buffer) -> bool:
        """Verify a tag for the current MAC state.

        Args:
            mac: The tag to verify (16 or 32 bytes).

        Returns:
            True if verification succeeds.

        Raises:
            TypeError: If tag length is invalid.
            ValueError: If verification fails.
        """
        mac = memoryview(mac)
        maclen = mac.nbytes
        if maclen not in (16, 32):
            raise TypeError("mac length must be 16 or 32")
        rc = _lib.aegis256x2_mac_verify(self._st, _ptr(mac), maclen)
        if rc != 0:
            raise ValueError("mac verification failed")
        return True


class Encryptor:
    """Incremental encryptor.

    - update(message[, into]) -> returns produced ciphertext bytes
    - final([into], maclen=16) -> returns tail+tag bytes
    - final_detached([ct_into], [mac_into], maclen=16) -> returns (tail_bytes, mac)
    """

    __slots__ = ("_st", "_bytes_in", "_bytes_out")

    def __init__(self, key: Buffer, nonce: Buffer, ad: Buffer | None = None):
        """Create an incremental encryptor.

        Args:
            key: Key (32 bytes).
            nonce: Nonce (32 bytes).
            ad: Associated data to bind to the encryption (optional).

        Raises:
            TypeError: If key or nonce lengths are invalid.
        """
        key = memoryview(key)
        nonce = memoryview(nonce)
        if key.nbytes != KEYBYTES:
            raise TypeError(f"key length must be {KEYBYTES}")
        if nonce.nbytes != NPUBBYTES:
            raise TypeError(f"nonce length must be {NPUBBYTES}")
        raw = alloc_aligned(ffi.sizeof("aegis256x2_state"), ALIGNMENT)
        st = ffi.cast("aegis256x2_state *", raw)
        st = ffi.gc(st, libc.free)
        _lib.aegis256x2_state_init(
            st,
            _ptr(ad) if ad is not None else ffi.NULL,
            0 if ad is None else memoryview(ad).nbytes,
            _ptr(nonce),
            _ptr(key),
        )
        self._st = st
        # Track total plaintext bytes passed through update() so far
        self._bytes_in = 0
        self._bytes_out = 0

    @property
    def bytes_in(self) -> int:
        """Total plaintext bytes fed to update() so far."""
        return self._bytes_in

    @property
    def bytes_out(self) -> int:
        """Total ciphertext bytes produced so far.

        Includes update() and final()/final_detached() output, also MAC tag.
        """
        return self._bytes_out

    def update(self, message: Buffer, into: Buffer | None = None) -> memoryview:
        """Encrypt a chunk of the message.

        Args:
            message: Plaintext bytes to encrypt.
            into: Optional destination buffer; must be >= len(message).

        Returns:
            The ciphertext for this chunk as a memoryview; when ``into`` is
            provided, a view of that buffer up to the number of bytes written.

        Raises:
            TypeError: If destination buffer is too small.
            RuntimeError: If the C update call fails.
        """
        message = memoryview(message)
        # Compute exact number of bytes this update can emit (multiple of ALIGNMENT)
        expected_out = calc_update_output_size(self._bytes_in, message.nbytes)
        out = memoryview(into if into is not None else bytearray(expected_out))
        if out.nbytes < expected_out:
            raise TypeError(
                "into length must be >= expected output size for this update"
            )
        written = ffi.new("size_t *")
        rc = _lib.aegis256x2_state_encrypt_update(
            self._st,
            ffi.from_buffer(out),
            out.nbytes,
            written,
            _ptr(message),
            message.nbytes,
        )
        if rc != 0:
            err_num = ffi.errno
            err_name = errno.errorcode.get(err_num, f"errno_{err_num}")
            raise RuntimeError(
                f"state encrypt update failed: {err_name} written {written[0]}"
            )
        w = int(written[0])
        assert w == expected_out
        self._bytes_in += message.nbytes
        self._bytes_out += w
        return out[:w]

    def final(self, into: Buffer | None = None, maclen: int = ABYTES_MIN) -> memoryview:
        """Finalize encryption, writing any remaining bytes and the tag.

        Args:
            into: Optional destination buffer for the tail and tag.
            maclen: Tag length (16 or 32). Defaults to 16.

        Returns:
            A memoryview of the produced bytes (tail + tag). When ``into`` is
            provided, the returned view references that buffer up to the number
            of bytes written.

        Raises:
            TypeError: If maclen is invalid.
            RuntimeError: If the C final call fails.
        """
        if maclen not in (16, 32):
            raise TypeError("maclen must be 16 or 32")
        # Worst-case final length is leftover tail (<= TAILBYTES_MAX) plus tag
        out = into if into is not None else bytearray(TAILBYTES_MAX + maclen)
        out = memoryview(out)
        written = ffi.new("size_t *")
        rc = _lib.aegis256x2_state_encrypt_final(
            self._st,
            ffi.from_buffer(out),
            out.nbytes,
            written,
            maclen,
        )
        if rc != 0:
            err_num = ffi.errno
            err_name = errno.errorcode.get(err_num, f"errno_{err_num}")
            raise RuntimeError(f"state encrypt final failed: {err_name}")
        w = int(written[0])
        self._bytes_out += w
        return out[:w]

    def final_detached(
        self,
        ct_into: bytearray | None = None,
        mac_into: bytearray | None = None,
        maclen: int = ABYTES_MIN,
    ) -> tuple[bytearray, bytearray]:
        """Finalize encryption, producing detached tail bytes and tag.

        Args:
            ct_into: Optional destination for the remaining ciphertext tail.
            mac_into: Optional destination for the tag.
            maclen: Tag length (16 or 32). Defaults to 16.

        Returns:
            A tuple of (tail_bytes, mac). When destination buffers are provided,
            the first element is a slice of ``ct_into`` up to the number of bytes
            written, and the second is ``mac_into``.

        Raises:
            TypeError: If maclen is invalid or mac_into has the wrong length.
            RuntimeError: If the C final call fails.
        """
        if maclen not in (16, 32):
            raise TypeError("maclen must be 16 or 32")
        out = ct_into if ct_into is not None else bytearray(TAILBYTES_MAX)
        mac = mac_into if mac_into is not None else bytearray(maclen)
        if len(mac) != maclen:
            raise TypeError("mac_into length must equal maclen")
        written = ffi.new("size_t *")
        rc = _lib.aegis256x2_state_encrypt_detached_final(
            self._st,
            ffi.from_buffer(out),
            len(out),
            written,
            ffi.from_buffer(mac),
            maclen,
        )
        if rc != 0:
            err_num = ffi.errno
            err_name = errno.errorcode.get(err_num, f"errno_{err_num}")
            raise RuntimeError(f"state encrypt detached final failed: {err_name}")
        w = int(written[0])
        self._bytes_out += w + maclen
        return out[:w], mac


class Decryptor:
    """Incremental decryptor.

    - update(ciphertext[, into]) -> returns plaintext bytes
    - final(mac[, into]) -> returns any remaining plaintext bytes
    """

    __slots__ = ("_st", "_bytes_in", "_bytes_out")

    def __init__(self, key: Buffer, nonce: Buffer, ad: Buffer | None = None):
        """Create an incremental decryptor for detached tags.

        Args:
            key: Key (32 bytes).
            nonce: Nonce (32 bytes).
            ad: Associated data used during encryption (optional).

        Raises:
            TypeError: If key or nonce lengths are invalid.
        """
        key = memoryview(key)
        nonce = memoryview(nonce)
        if key.nbytes != KEYBYTES:
            raise TypeError(f"key length must be {KEYBYTES}")
        if nonce.nbytes != NPUBBYTES:
            raise TypeError(f"nonce length must be {NPUBBYTES}")
        raw = alloc_aligned(ffi.sizeof("aegis256x2_state"), ALIGNMENT)
        st = ffi.cast("aegis256x2_state *", raw)
        st = ffi.gc(st, libc.free)
        _lib.aegis256x2_state_init(
            st,
            _ptr(ad) if ad is not None else ffi.NULL,
            0 if ad is None else memoryview(ad).nbytes,
            _ptr(nonce),
            _ptr(key),
        )
        self._st = st
        # Track total ciphertext bytes passed through update() so far
        self._bytes_in = 0
        self._bytes_out = 0

    @property
    def bytes_in(self) -> int:
        """Total ciphertext bytes fed to update() so far."""
        return self._bytes_in

    @property
    def bytes_out(self) -> int:
        """Total plaintext bytes produced so far.

        Includes bytes written by update() and by final().
        """
        return self._bytes_out

    def update(self, ct: Buffer, into: Buffer | None = None) -> memoryview:
        """Process a chunk of ciphertext.

        Args:
            ct: Ciphertext bytes (without MAC).
            into: Optional destination buffer; must be >= len(ciphertext).

        Returns:
            A memoryview of the decrypted bytes for this chunk. When ``into`` is
            provided, the returned view references that buffer up to the number
            of bytes written.

        Raises:
            TypeError: If destination buffer is too small.
            RuntimeError: If the C update call fails.
        """
        ct = memoryview(ct)
        expected_out = calc_update_output_size(self._bytes_in, ct.nbytes)
        out = into if into is not None else bytearray(expected_out)
        out = memoryview(out)
        if out.nbytes < expected_out:
            raise TypeError("into length must be >= required capacity for this update")
        written = ffi.new("size_t *")
        rc = _lib.aegis256x2_state_decrypt_detached_update(
            self._st,
            ffi.from_buffer(out),
            out.nbytes,
            written,
            _ptr(ct),
            ct.nbytes,
        )
        if rc != 0:
            err_num = ffi.errno
            err_name = errno.errorcode.get(err_num, f"errno_{err_num}")
            raise RuntimeError(f"state decrypt update failed: {err_name}")
        w = int(written[0])
        assert w == expected_out
        self._bytes_in += ct.nbytes
        self._bytes_out += w
        return out[:w]

    def final(self, mac: Buffer, into: Buffer | None = None) -> memoryview:
        """Finalize decryption by verifying tag and flushing remaining bytes.

        Args:
            mac: Tag to verify (16 or 32 bytes).
            into: Optional destination buffer for the remaining plaintext bytes.

        Returns:
            A memoryview of the remaining plaintext bytes. When ``into`` is
            provided, the returned view references that buffer up to the number
            of bytes written.

        Raises:
            TypeError: If tag length is invalid.
            ValueError: If authentication fails.
        """
        mac = memoryview(mac)
        maclen = mac.nbytes
        if maclen not in (16, 32):
            raise TypeError("mac length must be 16 or 32")
        out = into if into is not None else bytearray(TAILBYTES_MAX)
        out = memoryview(out)
        written = ffi.new("size_t *")
        rc = _lib.aegis256x2_state_decrypt_detached_final(
            self._st,
            ffi.from_buffer(out),
            out.nbytes,
            written,
            _ptr(mac),
            maclen,
        )
        if rc != 0:
            raise ValueError("authentication failed")
        w = int(written[0])
        self._bytes_out += w
        return out[:w]


def new_state():
    """Allocate and return a new aegis256x2_state* with proper alignment.

    The returned object is an ffi cdata pointer with automatic finalizer.
    """
    # Allocate with required alignment using libc.posix_memalign
    raw = alloc_aligned(ffi.sizeof("aegis256x2_state"), ALIGNMENT)
    ptr = ffi.cast("aegis256x2_state *", raw)
    return ffi.gc(ptr, libc.free)


def new_mac_state():
    """Allocate and return a new aegis256x2_mac_state* with proper alignment."""
    raw = alloc_aligned(ffi.sizeof("aegis256x2_mac_state"), ALIGNMENT)
    ptr = ffi.cast("aegis256x2_mac_state *", raw)
    return ffi.gc(ptr, libc.free)


__all__ = [
    # constants
    "KEYBYTES",
    "NPUBBYTES",
    "ABYTES_MIN",
    "ABYTES_MAX",
    "TAILBYTES_MAX",
    "ALIGNMENT",
    "RATE",
    # helpers
    "calc_update_output_size",
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
