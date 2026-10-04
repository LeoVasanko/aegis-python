"""RAF (random-access encrypted file) high-level API.

Provides pread/pwrite-style access to encrypted files. Files are divided into
fixed-size chunks, each independently encrypted with a fresh nonce, enabling
efficient random access without decrypting the whole file.

Use create() / open() with a cipher module (from aeg.cipher()) and a path,
an io.BytesIO, or a Storage instance.

Portions of the storage/callback/Merkle/file-like machinery are adapted from
pyaegis (https://github.com/jedisct1/pyaegis) by Frank Denis, MIT license.
"""

from __future__ import annotations

import errno as errno_module
import hashlib
import io as io_module
import os
import threading
from typing import NamedTuple, Protocol, Self, runtime_checkable

from . import cipher as _cipher_for_name
from . import random as _random
from ._loader import ffi, lib
from ._typing import Cipher
from .util import Buffer

__all__ = [
    "CHUNK_MIN",
    "CHUNK_MAX",
    "HEADER_SIZE",
    "SCRATCH_ALIGN",
    "Storage",
    "FileStorage",
    "BytesIOStorage",
    "StreamStorage",
    "MerkleHasher",
    "SHA256MerkleHasher",
    "RafInfo",
    "Raf",
    "create",
    "open",
    "probe",
    "derive_master_key",
]

CHUNK_MIN = int(lib.aegis_raf_chunk_min())  #: Minimum chunk size in bytes
CHUNK_MAX = int(lib.aegis_raf_chunk_max())  #: Maximum chunk size in bytes
HEADER_SIZE = int(lib.aegis_raf_header_size())  #: Encrypted file header size
SCRATCH_ALIGN = int(lib.aegis_raf_scratch_align())  #: Required scratch buffer alignment

# From aegis_raf.h (preprocessor macros, not available through cdef)
_FLAG_CREATE = 0x01
_FLAG_TRUNCATE = 0x02
_MERKLE_HASH_MIN = 8
_MERKLE_HASH_MAX = 64


@runtime_checkable
class Storage(Protocol):
    """Backing storage for RAF files. Operations must complete fully or raise OSError."""

    def read_at(self, buf: bytearray, offset: int) -> None:
        """Read exactly len(buf) bytes at offset into buf."""
        ...

    def write_at(self, data: bytes, offset: int) -> None:
        """Write exactly len(data) bytes at offset."""
        ...

    def get_size(self) -> int:
        """Return current storage size in bytes."""
        ...

    def set_size(self, size: int) -> None:
        """Resize storage (truncate or extend)."""
        ...

    def sync(self) -> None:
        """Flush writes to durable storage. May be a no-op."""
        ...


class FileStorage:
    """File-based storage.

    Uses os.pread/os.pwrite where available (Unix); otherwise falls back to
    a lock plus os.lseek/os.read/os.write (e.g. on Windows).
    """

    def __init__(self, path: str | os.PathLike, mode: str = "r+b"):
        """Open a file for RAF storage.

        Args:
            path: Path to the file.
            mode: "r+b" to open existing, "w+b" or "x+b" to create.
        """
        if mode == "r+b":
            flags = os.O_RDWR
        elif mode == "w+b":
            flags = os.O_RDWR | os.O_CREAT | os.O_TRUNC
        elif mode == "x+b":
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        else:
            raise ValueError(f"Unsupported mode: {mode}")
        # O_BINARY (Windows only): keep the CRT from translating \r\n in
        # binary data, which corrupts ciphertext and shifts offsets
        flags |= getattr(os, "O_BINARY", 0)
        self._fd = os.open(path, flags, 0o644)
        self._closed = False
        self._lock = threading.Lock()
        self._positional = hasattr(os, "pread") and hasattr(os, "pwrite")

    def read_at(self, buf: bytearray, offset: int) -> None:
        """Read exactly len(buf) bytes. Raises OSError on short read."""
        view = memoryview(buf)
        if self._positional:
            done = 0
            while done < len(view):
                chunk = os.pread(self._fd, len(view) - done, offset + done)
                if not chunk:
                    raise OSError(f"Short read: expected {len(view)}, got {done}")
                view[done : done + len(chunk)] = chunk
                done += len(chunk)
        else:
            with self._lock:
                os.lseek(self._fd, offset, os.SEEK_SET)
                done = 0
                while done < len(view):
                    chunk = os.read(self._fd, len(view) - done)
                    if not chunk:
                        raise OSError(f"Short read: expected {len(view)}, got {done}")
                    view[done : done + len(chunk)] = chunk
                    done += len(chunk)

    def write_at(self, data: bytes, offset: int) -> None:
        """Write exactly len(data) bytes."""
        view = memoryview(data)
        if self._positional:
            done = 0
            while done < len(view):
                done += os.pwrite(self._fd, view[done:], offset + done)
        else:
            with self._lock:
                os.lseek(self._fd, offset, os.SEEK_SET)
                done = 0
                while done < len(view):
                    done += os.write(self._fd, view[done:])

    def get_size(self) -> int:
        """Return current file size."""
        return os.fstat(self._fd).st_size

    def set_size(self, size: int) -> None:
        """Truncate or extend the file to the given size."""
        os.ftruncate(self._fd, size)

    def sync(self) -> None:
        """Flush file data to disk."""
        os.fsync(self._fd)

    def close(self) -> None:
        """Close the underlying file descriptor."""
        if not self._closed:
            os.close(self._fd)
            self._closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args) -> None:
        self.close()


class BytesIOStorage:
    """In-memory storage backed by a bytearray. Useful for tests."""

    def __init__(self, initial: bytes = b""):
        self._data = bytearray(initial)

    def read_at(self, buf: bytearray, offset: int) -> None:
        """Read exactly len(buf) bytes at offset into buf."""
        end = offset + len(buf)
        if end > len(self._data):
            raise OSError(
                f"Read past EOF: offset={offset}, len={len(buf)}, size={len(self._data)}"
            )
        buf[:] = self._data[offset:end]

    def write_at(self, data: bytes, offset: int) -> None:
        """Write exactly len(data) bytes at offset."""
        if not data:
            return
        end = offset + len(data)
        if end > len(self._data):
            self._data.extend(b"\x00" * (end - len(self._data)))
        self._data[offset:end] = data

    def get_size(self) -> int:
        """Return current buffer size."""
        return len(self._data)

    def set_size(self, size: int) -> None:
        """Resize the buffer (truncate or extend with zeros)."""
        current = len(self._data)
        if size < current:
            del self._data[size:]
        elif size > current:
            self._data.extend(b"\x00" * (size - current))

    def sync(self) -> None:
        """No-op for in-memory storage."""

    def getvalue(self) -> bytes:
        """Return the entire buffer contents."""
        return bytes(self._data)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args) -> None:
        pass


class StreamStorage:
    """Storage adapter for seek-based file-like objects (io.BytesIO, open files).

    Uses a lock plus seek/read/write, mirroring FileStorage's fallback path
    for platforms without os.pread/os.pwrite. The stream is not closed by
    Raf; closing it remains the caller's responsibility.
    """

    def __init__(self, stream):
        self._stream = stream
        self._lock = threading.Lock()

    def read_at(self, buf: bytearray, offset: int) -> None:
        """Read exactly len(buf) bytes at offset into buf."""
        with self._lock:
            self._stream.seek(offset)
            view = memoryview(buf)
            done = 0
            while done < len(view):
                chunk = self._stream.read(len(view) - done)
                if not chunk:
                    raise OSError(f"Short read: expected {len(view)}, got {done}")
                view[done : done + len(chunk)] = chunk
                done += len(chunk)

    def write_at(self, data: bytes, offset: int) -> None:
        """Write exactly len(data) bytes at offset."""
        with self._lock:
            self._stream.seek(offset)
            view = memoryview(data)
            done = 0
            while done < len(view):
                done += self._stream.write(view[done:])

    def get_size(self) -> int:
        """Return current stream size."""
        with self._lock:
            pos = self._stream.tell()
            try:
                return self._stream.seek(0, os.SEEK_END)
            finally:
                self._stream.seek(pos)

    def set_size(self, size: int) -> None:
        """Resize the stream (truncate or extend with zeros)."""
        self._stream.truncate(size)

    def sync(self) -> None:
        """Flush the stream if it supports flushing."""
        if hasattr(self._stream, "flush"):
            self._stream.flush()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args) -> None:
        pass


@runtime_checkable
class MerkleHasher(Protocol):
    """Protocol for Merkle tree hash functions."""

    @property
    def hash_len(self) -> int: ...

    def hash_leaf(self, chunk: bytes, chunk_len: int, chunk_idx: int) -> bytes: ...
    def hash_parent(
        self, left: bytes, right: bytes, level: int, node_idx: int
    ) -> bytes: ...
    def hash_empty(self, level: int, node_idx: int) -> bytes: ...
    def hash_commitment(
        self, structural_root: bytes, ctx: bytes, file_size: int
    ) -> bytes: ...


class SHA256MerkleHasher:
    """Default Merkle hasher using SHA-256 with domain-separated prefixes."""

    hash_len = 32

    def hash_leaf(self, chunk: bytes, chunk_len: int, chunk_idx: int) -> bytes:
        h = hashlib.sha256()
        h.update(b"\x00")
        h.update(chunk_idx.to_bytes(8, "little"))
        h.update(chunk[:chunk_len])
        return h.digest()

    def hash_parent(
        self, left: bytes, right: bytes, level: int, node_idx: int
    ) -> bytes:
        h = hashlib.sha256()
        h.update(b"\x01")
        h.update(level.to_bytes(4, "little"))
        h.update(node_idx.to_bytes(8, "little"))
        h.update(left)
        h.update(right)
        return h.digest()

    def hash_empty(self, level: int, node_idx: int) -> bytes:
        h = hashlib.sha256()
        h.update(b"\x02")
        h.update(level.to_bytes(4, "little"))
        h.update(node_idx.to_bytes(8, "little"))
        return h.digest()

    def hash_commitment(
        self, structural_root: bytes, ctx: bytes, file_size: int
    ) -> bytes:
        h = hashlib.sha256()
        h.update(b"\x03")
        h.update(structural_root)
        h.update(ctx)
        h.update(file_size.to_bytes(8, "little"))
        return h.digest()


# CFFI callbacks (module-level so they stay alive)


@ffi.callback("int(void*, uint8_t*, size_t, uint64_t)")
def _read_at_callback(user, buf, length, offset):
    try:
        storage = ffi.from_handle(user)
        temp = bytearray(length)
        storage.read_at(temp, offset)
        ffi.buffer(buf, length)[:] = temp
        return 0
    except Exception:
        ffi.errno = errno_module.EIO
        return -1


@ffi.callback("int(void*, const uint8_t*, size_t, uint64_t)")
def _write_at_callback(user, buf, length, offset):
    try:
        storage = ffi.from_handle(user)
        storage.write_at(bytes(ffi.buffer(buf, length)), offset)
        return 0
    except Exception:
        ffi.errno = errno_module.EIO
        return -1


@ffi.callback("int(void*, uint64_t*)")
def _get_size_callback(user, size_ptr):
    try:
        size_ptr[0] = ffi.from_handle(user).get_size()
        return 0
    except Exception:
        ffi.errno = errno_module.EIO
        return -1


@ffi.callback("int(void*, uint64_t)")
def _set_size_callback(user, size):
    try:
        ffi.from_handle(user).set_size(size)
        return 0
    except Exception:
        ffi.errno = errno_module.EIO
        return -1


@ffi.callback("int(void*)")
def _sync_callback(user):
    try:
        ffi.from_handle(user).sync()
        return 0
    except Exception:
        ffi.errno = errno_module.EIO
        return -1


@ffi.callback("int(void*, uint8_t*, size_t, const uint8_t*, size_t, uint64_t)")
def _hash_leaf_callback(user, out, out_len, chunk, chunk_len, chunk_idx):
    try:
        hasher = ffi.from_handle(user)
        digest = hasher.hash_leaf(
            bytes(ffi.buffer(chunk, chunk_len)), chunk_len, chunk_idx
        )
        if len(digest) != out_len:
            ffi.errno = errno_module.EINVAL
            return -1
        ffi.memmove(out, digest, out_len)
        return 0
    except Exception:
        ffi.errno = errno_module.EINVAL
        return -1


@ffi.callback(
    "int(void*, uint8_t*, size_t, const uint8_t*, const uint8_t*, uint32_t, uint64_t)"
)
def _hash_parent_callback(user, out, out_len, left, right, level, node_idx):
    try:
        hasher = ffi.from_handle(user)
        digest = hasher.hash_parent(
            bytes(ffi.buffer(left, out_len)),
            bytes(ffi.buffer(right, out_len)),
            level,
            node_idx,
        )
        if len(digest) != out_len:
            ffi.errno = errno_module.EINVAL
            return -1
        ffi.memmove(out, digest, out_len)
        return 0
    except Exception:
        ffi.errno = errno_module.EINVAL
        return -1


@ffi.callback("int(void*, uint8_t*, size_t, uint32_t, uint64_t)")
def _hash_empty_callback(user, out, out_len, level, node_idx):
    try:
        hasher = ffi.from_handle(user)
        digest = hasher.hash_empty(level, node_idx)
        if len(digest) != out_len:
            ffi.errno = errno_module.EINVAL
            return -1
        ffi.memmove(out, digest, out_len)
        return 0
    except Exception:
        ffi.errno = errno_module.EINVAL
        return -1


@ffi.callback(
    "int(void*, uint8_t*, size_t, const uint8_t*, const uint8_t*, size_t, uint64_t)"
)
def _hash_commitment_callback(
    user, out, out_len, structural_root, ctx, ctx_len, file_size
):
    try:
        hasher = ffi.from_handle(user)
        root_bytes = bytes(ffi.buffer(structural_root, out_len))
        ctx_bytes = bytes(ffi.buffer(ctx, ctx_len)) if ctx != ffi.NULL else b""
        digest = hasher.hash_commitment(root_bytes, ctx_bytes, file_size)
        if len(digest) != out_len:
            ffi.errno = errno_module.EINVAL
            return -1
        ffi.memmove(out, digest, out_len)
        return 0
    except Exception:
        ffi.errno = errno_module.EINVAL
        return -1


def _make_io(storage: Storage):
    """Build an aegis_raf_io* cdata for a Storage. Returns (io, handle)."""
    handle = ffi.new_handle(storage)
    io = ffi.new("aegis_raf_io*")
    io.user = handle
    io.read_at = _read_at_callback
    io.write_at = _write_at_callback
    io.get_size = _get_size_callback
    io.set_size = _set_size_callback
    io.sync = _sync_callback
    return io, handle


def _allocate_scratch(cipher: Cipher, chunk_size: int):
    """Allocate an aligned aegis_raf_scratch*. Returns (raw, scratch)."""
    size = cipher.raf_scratch_size(chunk_size)
    raw = bytearray(size + SCRATCH_ALIGN)
    raw_ptr = ffi.from_buffer(raw)
    offset = (-int(ffi.cast("uintptr_t", raw_ptr))) & (SCRATCH_ALIGN - 1)
    scratch = ffi.new("aegis_raf_scratch*")
    scratch.buf = ffi.cast("uint8_t*", raw_ptr) + offset
    scratch.len = size
    return raw, scratch


def derive_master_key(master_key: Buffer, context: Buffer = b"") -> bytes:
    """Derive a context-bound RAF master key from an application master key.

    Args:
        master_key: A 16-byte or 32-byte application master key.
        context: A public identifier for a file or file family
                 (at most 120 bytes for 16-byte keys, 72 for 32-byte keys).

    Returns:
        A RAF-scoped key of the same length as master_key.

    Raises:
        ValueError: If the key or context length is invalid.
        RuntimeError: If the C KDF rejects validated inputs.
    """
    master_key = memoryview(master_key)
    context = memoryview(context)
    key_size = master_key.nbytes
    if key_size not in (16, 32):
        raise ValueError(f"master_key must be 16 or 32 bytes, got {key_size}")
    max_context = 120 if key_size == 16 else 72
    if context.nbytes > max_context:
        raise ValueError(
            f"context must be at most {max_context} bytes for a {key_size}-byte key"
        )
    out = bytearray(key_size)
    rc = lib.aegis_raf_derive_master_key(
        ffi.from_buffer(out),
        key_size,
        bytes(master_key),
        key_size,
        bytes(context),
        context.nbytes,
    )
    if rc != 0:
        err_num = ffi.errno
        err_name = errno_module.errorcode.get(err_num, f"errno_{err_num}")
        raise RuntimeError(f"derive master key failed: {err_name}")
    return bytes(out)


class RafInfo(NamedTuple):
    """Unverified file metadata from probe()."""

    alg_id: int
    chunk_size: int
    file_size: int


def probe(storage: Storage) -> RafInfo:
    """Probe an encrypted file to determine its parameters.

    WARNING: the returned values are read from the header WITHOUT
    cryptographic verification. Only use them for scratch sizing and
    algorithm selection; open() verifies the header MAC with the key.

    Returns:
        RafInfo(alg_id, chunk_size, file_size).

    Raises:
        RuntimeError: Invalid header or I/O failure.
    """
    io, _handle = _make_io(storage)
    info = ffi.new("aegis_raf_info*")
    if lib.aegis_raf_probe(io, info) != 0:
        err_num = ffi.errno
        err_name = errno_module.errorcode.get(err_num, f"errno_{err_num}")
        raise RuntimeError(f"probe failed: {err_name}")
    return RafInfo(int(info.alg_id), int(info.chunk_size), int(info.file_size))


def _as_storage(storage_or_path, mode: str) -> tuple[Storage, bool]:
    if isinstance(storage_or_path, (str, bytes, os.PathLike)):
        return FileStorage(storage_or_path, mode), True
    if isinstance(storage_or_path, io_module.BytesIO):
        return StreamStorage(storage_or_path), False
    return storage_or_path, False


def _resolve_cipher(cipher) -> Cipher:
    if isinstance(cipher, str):
        return _cipher_for_name(cipher)
    return cipher


def create(
    storage_or_path,
    key: Buffer,
    cipher,
    *,
    chunk_size: int = 65536,
    truncate: bool = False,
    merkle: bool | MerkleHasher = False,
    merkle_max_chunks: int = 16384,
    rng: _random.RandomSource | None = None,
) -> Raf:
    """Create a new encrypted file.

    Args:
        storage_or_path: A Storage instance or a path (opened "x+b", or "w+b"
                         when truncate=True).
        key: Master key (cipher.KEYBYTES bytes).
        cipher: A cipher module (from aeg.cipher()) or algorithm name.
        chunk_size: Plaintext bytes per chunk (CHUNK_MIN..CHUNK_MAX, multiple of 16).
        truncate: Overwrite an existing file.
        merkle: Enable Merkle tree. True uses SHA256MerkleHasher, or pass a
                custom MerkleHasher instance.
        merkle_max_chunks: Maximum number of chunks the Merkle tree can track.
        rng: Random source (see aeg.random). Default: a fresh aeg.random.Random
            seeded for the same cipher module passed as cipher=; any callable(n)
            returning bytes overrides.

    Raises:
        TypeError: If the key length is invalid.
        ValueError: If chunk_size or merkle parameters are invalid.
        FileExistsError: If the file exists and truncate is False.
        RuntimeError: If creation fails.
    """
    cipher = _resolve_cipher(cipher)
    if not (CHUNK_MIN <= chunk_size <= CHUNK_MAX):
        raise ValueError(
            f"chunk_size must be {CHUNK_MIN}-{CHUNK_MAX}, got {chunk_size}"
        )
    if chunk_size % 16 != 0:
        raise ValueError(f"chunk_size must be a multiple of 16, got {chunk_size}")
    storage, owns = _as_storage(storage_or_path, "w+b" if truncate else "x+b")
    return Raf(
        storage,
        key,
        cipher,
        owns_storage=owns,
        creating=True,
        chunk_size=chunk_size,
        truncate=truncate,
        merkle=merkle,
        merkle_max_chunks=merkle_max_chunks,
        rng=rng,
    )


def open(
    storage_or_path,
    key: Buffer,
    cipher,
    *,
    merkle: bool | MerkleHasher = False,
    merkle_max_chunks: int = 16384,
    rng: _random.RandomSource | None = None,
) -> Raf:
    """Open an existing encrypted file.

    The header is probed to size internal buffers and its alg_id is checked
    against cipher.RAF_ALG_ID; a mismatch raises ValueError (the algorithm is
    never switched silently).

    Args:
        storage_or_path: A Storage instance or a path (opened "r+b").
        key: Master key (cipher.KEYBYTES bytes).
        cipher: A cipher module (from aeg.cipher()) or algorithm name.
        merkle: Enable Merkle tree (call merkle_rebuild() before use).
        merkle_max_chunks: Maximum number of chunks the Merkle tree can track.
        rng: Random source (see aeg.random). Default: a fresh aeg.random.Random
            seeded for the same cipher module passed as cipher=; any callable(n)
            returning bytes overrides.

    Raises:
        TypeError: If the key length is invalid.
        ValueError: If the algorithm doesn't match cipher or authentication fails.
        FileNotFoundError: If the file does not exist.
        RuntimeError: If opening fails.
    """
    cipher = _resolve_cipher(cipher)
    storage, owns = _as_storage(storage_or_path, "r+b")
    info = probe(storage)
    if info.alg_id != cipher.RAF_ALG_ID:
        raise ValueError(
            f"file uses algorithm id {info.alg_id}, "
            f"expected {cipher.RAF_ALG_ID} ({cipher.NAME})"
        )
    return Raf(
        storage,
        key,
        cipher,
        owns_storage=owns,
        creating=False,
        chunk_size=info.chunk_size,
        truncate=False,
        merkle=merkle,
        merkle_max_chunks=merkle_max_chunks,
        rng=rng,
    )


class Raf:
    """File-like random-access encrypted file. Use raf.create() / raf.open()."""

    def __init__(
        self,
        storage: Storage,
        key: Buffer,
        cipher: Cipher,
        *,
        owns_storage: bool,
        creating: bool,
        chunk_size: int,
        truncate: bool,
        merkle: bool | MerkleHasher,
        merkle_max_chunks: int,
        rng,
    ):
        self._cipher = cipher
        self._storage = storage
        self._owns_storage = owns_storage
        self._closed = False
        self._position = 0

        self._ctx = cipher.new_raf_ctx()
        self._io, self._storage_handle = _make_io(storage)
        if rng is None:
            rng = _random.Random(cipher)
        self._rng, self._rng_keepalive = _random.as_raf_rng(rng)
        self._raw_scratch, self._scratch = _allocate_scratch(cipher, chunk_size)

        self._config = ffi.new("aegis_raf_config*")
        self._config.scratch = self._scratch
        self._config.chunk_size = chunk_size
        flags = 0
        if creating:
            flags |= _FLAG_CREATE
            if truncate:
                flags |= _FLAG_TRUNCATE
        self._config.flags = flags
        self._config.merkle = ffi.NULL

        self._merkle_hasher = None
        self._merkle_cfg = None
        self._merkle_buf = None
        self._merkle_hasher_handle = None
        if merkle:
            hasher = SHA256MerkleHasher() if merkle is True else merkle
            if merkle_max_chunks <= 0:
                raise ValueError("merkle_max_chunks must be > 0")
            if not (_MERKLE_HASH_MIN <= hasher.hash_len <= _MERKLE_HASH_MAX):
                raise ValueError(
                    f"hash_len must be between {_MERKLE_HASH_MIN} and "
                    f"{_MERKLE_HASH_MAX}, got {hasher.hash_len}"
                )
            mcfg = ffi.new("aegis_raf_merkle_config*")
            mcfg.hash_len = hasher.hash_len
            mcfg.max_chunks = merkle_max_chunks
            buf_size = lib.aegis_raf_merkle_buffer_size(mcfg)
            if buf_size == 0 or buf_size >= int(ffi.cast("size_t", -1)):
                raise ValueError("Merkle tree buffer size overflow")
            self._merkle_buf = bytearray(buf_size)
            self._merkle_hasher_handle = ffi.new_handle(hasher)
            mcfg.hash_leaf = _hash_leaf_callback
            mcfg.hash_parent = _hash_parent_callback
            mcfg.hash_empty = _hash_empty_callback
            mcfg.hash_commitment = _hash_commitment_callback
            mcfg.user = self._merkle_hasher_handle
            mcfg.buf = ffi.from_buffer(self._merkle_buf)
            mcfg.len = buf_size
            self._merkle_hasher = hasher
            self._merkle_cfg = mcfg
            self._config.merkle = mcfg

        if creating:
            cipher.raf_create(key, self._ctx, self._io, self._rng, self._config)
        else:
            cipher.raf_open(key, self._ctx, self._io, self._rng, self._config)

    def _check_open(self) -> None:
        if self._closed:
            raise ValueError("I/O operation on closed file")

    def read(self, size: int = -1, offset: int | None = None) -> bytes:
        """Read and decrypt bytes, advancing the current position.

        Args:
            size: Number of bytes to read (-1 for all remaining).
            offset: Position to read from (None uses current position).

        Returns:
            Decrypted bytes (fewer than requested at EOF).

        Raises:
            ValueError: If authentication fails (corruption or tampering).
            RuntimeError: If the read fails.
        """
        self._check_open()
        if offset is None:
            offset = self._position
        elif offset < 0:
            raise ValueError(f"offset must be non-negative, got {offset}")
        if size < 0:
            size = max(0, self.size - offset)
        if size == 0:
            return b""
        out = self._cipher.raf_read(self._ctx, size, offset)
        self._position = offset + len(out)
        return bytes(out)

    def pread(self, size: int, offset: int) -> bytes:
        """Read at offset without updating the position (like os.pread)."""
        self._check_open()
        if offset < 0:
            raise ValueError(f"offset must be non-negative, got {offset}")
        if size < 0:
            raise ValueError(f"size must be non-negative, got {size}")
        if size == 0:
            return b""
        return bytes(self._cipher.raf_read(self._ctx, size, offset))

    def read_into(self, buf: Buffer, offset: int | None = None) -> int:
        """Read and decrypt into buf, advancing the position.

        Returns:
            Number of bytes actually read.
        """
        self._check_open()
        buf = memoryview(buf)
        if offset is None:
            offset = self._position
        elif offset < 0:
            raise ValueError(f"offset must be non-negative, got {offset}")
        if buf.nbytes == 0:
            return 0
        out = self._cipher.raf_read(self._ctx, buf.nbytes, offset, into=buf)
        n = len(out)
        self._position = offset + n
        return n

    def write(self, data: Buffer, offset: int | None = None) -> int:
        """Encrypt and write bytes, advancing the current position.

        Returns:
            Number of bytes written (always len(data) on success).

        Raises:
            ValueError: If the write exceeds merkle_max_chunks.
            RuntimeError: If the write fails.
        """
        self._check_open()
        data = memoryview(data)
        if offset is None:
            offset = self._position
        elif offset < 0:
            raise ValueError(f"offset must be non-negative, got {offset}")
        if data.nbytes == 0:
            return 0
        try:
            n = self._cipher.raf_write(self._ctx, data, offset)
        except RuntimeError as e:
            if "EOVERFLOW" in str(e) and self._merkle_cfg is not None:
                new_end = offset + data.nbytes
                if new_end <= 0xFFFFFFFFFFFFFFFF:
                    chunk_size = self._config.chunk_size
                    new_chunks = (new_end + chunk_size - 1) // chunk_size
                    if new_chunks > self._merkle_cfg.max_chunks:
                        raise ValueError(
                            f"write exceeds merkle_max_chunks "
                            f"({self._merkle_cfg.max_chunks}); "
                            "open the file with a larger merkle_max_chunks"
                        ) from e
            raise
        self._position = offset + n
        return n

    def pwrite(self, data: Buffer, offset: int) -> int:
        """Write at offset without updating the position (like os.pwrite)."""
        pos = self._position
        try:
            return self.write(data, offset)
        finally:
            self._position = pos

    def truncate(self, size: int | None = None) -> int:
        """Resize the file (default: current position). Returns the new size."""
        self._check_open()
        if size is None:
            size = self._position
        self._cipher.raf_truncate(self._ctx, size)
        return size

    def seek(self, offset: int, whence: int = 0) -> int:
        """Move the file position (whence: 0=absolute, 1=relative, 2=from end)."""
        self._check_open()
        if whence == 0:
            new_pos = offset
        elif whence == 1:
            new_pos = self._position + offset
        elif whence == 2:
            new_pos = self.size + offset
        else:
            raise ValueError(f"invalid whence: {whence}")
        if new_pos < 0:
            raise ValueError(f"negative seek position: {new_pos}")
        self._position = new_pos
        return new_pos

    def tell(self) -> int:
        """Return the current position."""
        return self._position

    @property
    def size(self) -> int:
        """Logical plaintext file size."""
        self._check_open()
        return self._cipher.raf_size(self._ctx)

    def sync(self) -> None:
        """Flush writes to backing storage."""
        self._check_open()
        self._cipher.raf_sync(self._ctx)

    def close(self) -> None:
        """Close the file, syncing and zeroizing key material."""
        if not self._closed:
            self._closed = True
            self._cipher.raf_close(self._ctx)
            if self._owns_storage and hasattr(self._storage, "close"):
                self._storage.close()

    @property
    def closed(self) -> bool:
        """True if the file has been closed."""
        return self._closed

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def _check_merkle_enabled(self) -> None:
        if self._merkle_cfg is None:
            raise ValueError("Merkle tree is not enabled on this file")

    def merkle_rebuild(self) -> None:
        """Rebuild the Merkle tree by reading and re-hashing every chunk.

        Must be called after opening an existing file with merkle enabled.
        """
        self._check_open()
        self._check_merkle_enabled()
        self._cipher.raf_merkle_rebuild(self._ctx)

    def merkle_verify(self) -> int | None:
        """Verify every chunk's hash against the Merkle tree.

        Returns:
            None if all chunks match, otherwise the index of the first
            corrupted chunk.
        """
        self._check_open()
        self._check_merkle_enabled()
        return self._cipher.raf_merkle_verify(self._ctx)

    @property
    def root_hash(self) -> bytes | None:
        """Current Merkle root commitment hash, or None if Merkle is not enabled."""
        self._check_open()
        if self._merkle_cfg is None:
            return None
        return self._cipher.raf_merkle_commitment(
            self._ctx, self._merkle_hasher.hash_len
        )

    def verify_root(self, expected: Buffer) -> None:
        """Rebuild the Merkle tree and verify the root matches expected.

        Raises:
            ValueError: If the root mismatches or expected has the wrong length.
        """
        self._check_open()
        self._check_merkle_enabled()
        expected = memoryview(expected)
        if expected.nbytes != self._merkle_hasher.hash_len:
            raise ValueError(
                f"expected must be {self._merkle_hasher.hash_len} bytes, "
                f"got {expected.nbytes}"
            )
        self.merkle_rebuild()
        if self.root_hash != bytes(expected):
            raise ValueError("authentication failed: merkle root mismatch")
