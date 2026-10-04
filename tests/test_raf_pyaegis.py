"""Tests for RAF (Random Access Format) encrypted file API.

Adapted from pyaegis (github.com/jedisct1/pyaegis) tests by Frank Denis.

Exception mapping from pyaegis: RAFAuthenticationError -> ValueError,
RAFConfigError -> ValueError/TypeError, RAFError/RAFIOError -> RuntimeError.
Their auto-detect raf_open() does not apply: our raf.open() requires the
cipher explicitly and validates it against the probed header.
"""

import hashlib

import pytest

from aeg import aegis128l, aegis128x2, aegis128x4, aegis256, aegis256x2, aegis256x4, raf
from aeg.raf import (
    BytesIOStorage,
    FileStorage,
    MerkleHasher,
    SHA256MerkleHasher,
)

CIPHERS = [aegis128l, aegis128x2, aegis128x4, aegis256, aegis256x2, aegis256x4]


def cipher_id(c):
    return c.NAME


class TestRafDeriveMasterKey:
    """Tests for context-bound RAF key derivation."""

    def test_128_bit_known_answer(self):
        master_key = bytes(range(16))

        derived = raf.derive_master_key(master_key, b"test-context")

        assert derived == bytes.fromhex("fb80072c5a6f1cddc6e97b35ed1f3bf3")

    def test_256_bit_known_answer(self):
        master_key = bytes(range(32))

        derived = raf.derive_master_key(master_key, b"test-context")

        assert derived == bytes.fromhex(
            "fee2d3cc58c69d8f43fd7b4e33eaec0053539685c7e284e6e12ee9c4f423d136"
        )

    def test_empty_context_is_domain_separated(self):
        master_key = bytes(range(16))

        derived = raf.derive_master_key(master_key)

        assert derived == bytes.fromhex("9b8e6ddb09c9eb0137888ca2a366fdd0")
        assert derived != master_key

    @pytest.mark.parametrize(("key_size", "max_context_size"), [(16, 120), (32, 72)])
    def test_context_length_limits(self, key_size, max_context_size):
        master_key = bytes(range(key_size))

        assert (
            len(raf.derive_master_key(master_key, b"x" * max_context_size)) == key_size
        )
        with pytest.raises(ValueError, match=f"at most {max_context_size} bytes"):
            raf.derive_master_key(master_key, b"x" * (max_context_size + 1))

    @pytest.mark.parametrize("key_size", [0, 15, 17, 31, 33])
    def test_invalid_key_length(self, key_size):
        with pytest.raises(ValueError, match="master_key must be 16 or 32 bytes"):
            raf.derive_master_key(b"x" * key_size)

    @pytest.mark.parametrize(
        ("master_key", "context"),
        [("not-bytes", b"context"), (b"x" * 16, "not-bytes")],
    )
    def test_requires_bytes(self, master_key, context):
        # pyaegis checked types explicitly; we raise TypeError from memoryview()
        with pytest.raises(TypeError):
            raf.derive_master_key(master_key, context)

    def test_derived_key_opens_only_with_same_context(self):
        storage = BytesIOStorage()
        master_key = bytes(range(16))
        key = raf.derive_master_key(master_key, b"context-a")

        with raf.create(storage, key, cipher="AEGIS-128L") as f:
            f.write(b"context-bound data")

        same_key = raf.derive_master_key(master_key, b"context-a")
        with raf.open(storage, same_key, cipher="AEGIS-128L") as f:
            assert f.read() == b"context-bound data"

        wrong_key = raf.derive_master_key(master_key, b"context-b")
        with pytest.raises(ValueError, match="authentication failed"):
            raf.open(storage, wrong_key, cipher="AEGIS-128L")


class TestBytesIOStorage:
    """Tests for BytesIOStorage backend."""

    def test_read_write_basic(self):
        """Test basic read/write operations."""
        storage = BytesIOStorage()
        storage.write_at(b"hello", 0)
        buf = bytearray(5)
        storage.read_at(buf, 0)
        assert buf == b"hello"

    def test_read_past_eof_raises(self):
        """Test that reading past EOF raises IOError."""
        storage = BytesIOStorage(b"short")
        buf = bytearray(10)
        with pytest.raises(IOError):
            storage.read_at(buf, 0)

    def test_write_extends_buffer(self):
        """Test that writing past end extends the buffer."""
        storage = BytesIOStorage()
        storage.write_at(b"hello", 10)
        assert storage.get_size() == 15
        assert storage.getvalue()[:10] == b"\x00" * 10
        assert storage.getvalue()[10:] == b"hello"

    def test_set_size_truncate(self):
        """Test truncating via set_size."""
        storage = BytesIOStorage(b"hello world")
        storage.set_size(5)
        assert storage.getvalue() == b"hello"

    def test_set_size_extend(self):
        """Test extending via set_size."""
        storage = BytesIOStorage(b"hi")
        storage.set_size(5)
        assert storage.getvalue() == b"hi\x00\x00\x00"

    def test_context_manager(self):
        """Test context manager support."""
        with BytesIOStorage(b"test") as storage:
            buf = bytearray(4)
            storage.read_at(buf, 0)
            assert buf == b"test"

    def test_getvalue_returns_bytes(self):
        """getvalue() returns immutable bytes, not bytearray."""
        storage = BytesIOStorage(b"test")
        result = storage.getvalue()
        assert isinstance(result, bytes)
        assert not isinstance(result, bytearray)

    def test_initial_data_is_copied(self):
        """Mutating initial_data after construction has no effect."""
        data = bytearray(b"hello")
        storage = BytesIOStorage(data)
        data[0] = 0xFF
        assert storage.getvalue() == b"hello"

    def test_read_write_at_exact_boundary(self):
        """Write then read at the exact end of existing data."""
        storage = BytesIOStorage(b"hello")
        storage.write_at(b"world", 5)
        assert storage.get_size() == 10
        buf = bytearray(5)
        storage.read_at(buf, 5)
        assert buf == b"world"

    def test_overwrite_same_region(self):
        """Repeatedly overwriting the same region keeps final value."""
        storage = BytesIOStorage(b"\x00" * 10)
        for i in range(100):
            storage.write_at(bytes([i % 256]), 5)
        assert storage.get_size() == 10
        buf = bytearray(1)
        storage.read_at(buf, 5)
        assert buf[0] == 99

    def test_overwrite_preserves_surrounding(self):
        """Overwriting a middle region doesn't corrupt surrounding data."""
        storage = BytesIOStorage(b"AABBBBCC")
        storage.write_at(b"XXXX", 2)
        assert storage.getvalue() == b"AAXXXXCC"

    def test_zero_length_read(self):
        """Reading zero bytes succeeds even on empty storage."""
        storage = BytesIOStorage()
        buf = bytearray(0)
        storage.read_at(buf, 0)
        assert buf == b""

    def test_zero_length_write(self):
        """Writing zero bytes doesn't change size."""
        storage = BytesIOStorage()
        storage.write_at(b"", 0)
        assert storage.get_size() == 0

    def test_zero_length_write_at_offset(self):
        """Writing zero bytes at an offset doesn't extend."""
        storage = BytesIOStorage(b"hi")
        storage.write_at(b"", 100)
        assert storage.get_size() == 2

    def test_set_size_to_zero(self):
        """Truncating to zero clears everything."""
        storage = BytesIOStorage(b"X" * 10000)
        storage.set_size(0)
        assert storage.get_size() == 0
        assert storage.getvalue() == b""

    def test_set_size_same(self):
        """set_size to current size is a no-op."""
        storage = BytesIOStorage(b"hello")
        storage.set_size(5)
        assert storage.getvalue() == b"hello"

    def test_sparse_write_large_gap(self):
        """Writing past a large gap fills with zeros."""
        storage = BytesIOStorage()
        storage.write_at(b"end", 10000)
        assert storage.get_size() == 10003
        assert storage.getvalue()[:10000] == b"\x00" * 10000
        assert storage.getvalue()[10000:] == b"end"

    def test_read_past_eof_various(self):
        """Read past EOF at different positions."""
        storage = BytesIOStorage(b"abc")
        with pytest.raises(OSError):
            storage.read_at(bytearray(1), 3)
        with pytest.raises(OSError):
            storage.read_at(bytearray(4), 0)
        with pytest.raises(OSError):
            storage.read_at(bytearray(2), 2)

    def test_read_at_offset_zero_on_empty(self):
        """Reading any bytes from empty storage raises."""
        storage = BytesIOStorage()
        with pytest.raises(OSError):
            storage.read_at(bytearray(1), 0)

    def test_sync_is_noop(self):
        """sync() doesn't raise or modify data."""
        storage = BytesIOStorage(b"data")
        storage.sync()
        storage.sync()
        assert storage.getvalue() == b"data"

    def test_truncate_then_extend_zeros(self):
        """Truncate then extend fills new region with zeros, not old data."""
        storage = BytesIOStorage(b"ABCDEFGHIJ")
        storage.set_size(3)
        storage.set_size(10)
        assert storage.getvalue() == b"ABC" + b"\x00" * 7

    def test_write_overlapping_existing(self):
        """Write that partially overlaps existing data and extends."""
        storage = BytesIOStorage(b"hello")
        storage.write_at(b"WORLD!", 3)
        assert storage.getvalue() == b"helWORLD!"
        assert storage.get_size() == 9

    def test_sequential_adjacent_writes(self):
        """Adjacent writes produce contiguous data."""
        storage = BytesIOStorage()
        storage.write_at(b"AAA", 0)
        storage.write_at(b"BBB", 3)
        storage.write_at(b"CCC", 6)
        assert storage.getvalue() == b"AAABBBCCC"

    def test_get_size_empty(self):
        """Empty storage has size 0."""
        assert BytesIOStorage().get_size() == 0

    def test_get_size_with_initial_data(self):
        """Size matches initial data length."""
        assert BytesIOStorage(b"hello").get_size() == 5


class TestFileStorage:
    """Tests for FileStorage backend."""

    def test_read_write_basic(self, tmp_path):
        """Test basic file read/write operations."""
        path = tmp_path / "test.bin"
        with FileStorage(path, "w+b") as storage:
            storage.write_at(b"hello", 0)
            buf = bytearray(5)
            storage.read_at(buf, 0)
            assert buf == b"hello"

    def test_read_short_raises(self, tmp_path):
        """Test that short read raises IOError."""
        path = tmp_path / "test.bin"
        with FileStorage(path, "w+b") as storage:
            storage.write_at(b"hi", 0)
            buf = bytearray(10)
            with pytest.raises(IOError, match="Short read"):
                storage.read_at(buf, 0)

    def test_file_size(self, tmp_path):
        """Test get_size and set_size."""
        path = tmp_path / "test.bin"
        with FileStorage(path, "w+b") as storage:
            storage.write_at(b"hello world", 0)
            assert storage.get_size() == 11
            storage.set_size(5)
            assert storage.get_size() == 5

    def test_invalid_mode_raises(self, tmp_path):
        """Test that invalid mode raises ValueError."""
        path = tmp_path / "test.bin"
        with pytest.raises(ValueError, match="Unsupported mode"):
            FileStorage(path, "rb")


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
class TestRafVariants:
    """Per-variant tests, merged from pyaegis's six AegisRaf* classes."""

    def test_create_write_read_basic(self, c):
        """Test creating a file, writing, closing, reopening, and reading."""
        storage = BytesIOStorage()
        key = c.random_key()

        with raf.create(storage, key, cipher=c) as f:
            f.write(b"Hello, World!")

        with raf.open(storage, key, cipher=c) as f:
            assert f.read() == b"Hello, World!"

    def test_create_with_file_storage(self, c, tmp_path):
        """Test with FileStorage backend."""
        path = tmp_path / "test.raf"
        key = c.random_key()

        with FileStorage(path, "w+b") as storage:
            with raf.create(storage, key, cipher=c) as f:
                f.write(b"Hello, World!")

        with FileStorage(path, "r+b") as storage:
            with raf.open(storage, key, cipher=c) as f:
                assert f.read() == b"Hello, World!"

    def test_random_access(self, c):
        """Test random access read/write."""
        storage = BytesIOStorage()
        key = c.random_key()

        with raf.create(storage, key, cipher=c) as f:
            f.write(b"AAAAAAAAAA")
            f.seek(5)
            f.write(b"BBBBB")
            f.seek(0)
            assert f.read() == b"AAAAABBBBB"

    def test_pread_pwrite(self, c):
        """Test pread/pwrite don't update position."""
        storage = BytesIOStorage()
        key = c.random_key()

        with raf.create(storage, key, cipher=c) as f:
            f.write(b"0123456789")
            assert f.tell() == 10

            # pread doesn't update position
            assert f.pread(3, 0) == b"012"
            assert f.tell() == 10

            # pwrite doesn't update position and preserves existing data
            f.pwrite(b"ABC", 5)
            assert f.tell() == 10

            f.seek(0)
            assert f.read() == b"01234ABC89"

    def test_read_into(self, c):
        """Test read_into with pre-allocated buffer."""
        storage = BytesIOStorage()
        key = c.random_key()

        with raf.create(storage, key, cipher=c) as f:
            f.write(b"Hello, World!")

        with raf.open(storage, key, cipher=c) as f:
            buf = bytearray(5)
            n = f.read_into(buf)
            assert n == 5
            assert buf == b"Hello"
            assert f.tell() == 5

    def test_seek_operations(self, c):
        """Test seek with different whence values."""
        storage = BytesIOStorage()
        key = c.random_key()

        with raf.create(storage, key, cipher=c) as f:
            f.write(b"0123456789")

            assert f.seek(0) == 0
            assert f.seek(5, 0) == 5
            assert f.seek(2, 1) == 7
            assert f.seek(-3, 2) == 7
            assert f.seek(0, 2) == 10

    def test_truncate(self, c):
        """Test file truncation."""
        storage = BytesIOStorage()
        key = c.random_key()

        with raf.create(storage, key, cipher=c) as f:
            f.write(b"Hello, World!")
            assert f.size == 13
            f.truncate(5)
            assert f.size == 5
            f.seek(0)
            assert f.read() == b"Hello"

    def test_truncate_uses_position(self, c):
        """Test truncate with no argument uses current position."""
        storage = BytesIOStorage()
        key = c.random_key()

        with raf.create(storage, key, cipher=c) as f:
            f.write(b"Hello, World!")
            f.seek(5)
            f.truncate()
            assert f.size == 5

    def test_wrong_key_fails(self, c):
        """Test that wrong key fails authentication."""
        storage = BytesIOStorage()
        key1 = c.random_key()
        key2 = c.random_key()

        with raf.create(storage, key1, cipher=c) as f:
            f.write(b"secret")

        with pytest.raises(ValueError, match="authentication failed"):
            raf.open(storage, key2, cipher=c)

    def test_invalid_key_size_rejected(self, c):
        """Test that invalid key size is rejected."""
        storage = BytesIOStorage()

        with pytest.raises(TypeError, match="key length"):
            raf.create(storage, b"short", cipher=c)

    def test_invalid_chunk_size_rejected(self, c):
        """Test invalid chunk_size is rejected."""
        storage = BytesIOStorage()
        key = c.random_key()

        with pytest.raises(ValueError, match="chunk_size must be"):
            raf.create(storage, key, cipher=c, chunk_size=100)

        with pytest.raises(ValueError, match="multiple of 16"):
            raf.create(BytesIOStorage(), key, cipher=c, chunk_size=1025)

    def test_truncate_overwrite(self, c):
        """Test create with truncate=True overwrites existing file."""
        storage = BytesIOStorage()
        key = c.random_key()

        with raf.create(storage, key, cipher=c) as f:
            f.write(b"original content")

        with raf.create(storage, key, cipher=c, truncate=True) as f:
            f.write(b"new")

        with raf.open(storage, key, cipher=c) as f:
            assert f.read() == b"new"

    def test_empty_file(self, c):
        """Test empty file operations."""
        storage = BytesIOStorage()
        key = c.random_key()

        with raf.create(storage, key, cipher=c) as f:
            assert f.size == 0
            assert f.read() == b""

    def test_single_byte(self, c):
        """Test single byte read/write."""
        storage = BytesIOStorage()
        key = c.random_key()

        with raf.create(storage, key, cipher=c) as f:
            f.write(b"X")
            f.seek(0)
            assert f.read() == b"X"

    def test_large_file(self, c):
        """Test large file operations."""
        storage = BytesIOStorage()
        key = c.random_key()
        data = b"X" * 100000

        with raf.create(storage, key, cipher=c) as f:
            f.write(data)

        with raf.open(storage, key, cipher=c) as f:
            assert f.read() == data

    def test_custom_chunk_size(self, c):
        """Test with custom chunk size."""
        storage = BytesIOStorage()
        key = c.random_key()
        chunk_size = 4096

        with raf.create(storage, key, cipher=c, chunk_size=chunk_size) as f:
            data = b"A" * (chunk_size * 2 + 100)
            f.write(data)

        with raf.open(storage, key, cipher=c) as f:
            assert f.read() == data

    def test_negative_offset_rejected(self, c):
        """Test that negative offsets raise ValueError."""
        storage = BytesIOStorage()
        key = c.random_key()

        with raf.create(storage, key, cipher=c) as f:
            f.write(b"test")

            with pytest.raises(ValueError, match="non-negative"):
                f.read(10, offset=-1)
            with pytest.raises(ValueError, match="non-negative"):
                f.pread(10, -1)
            with pytest.raises(ValueError, match="non-negative"):
                f.read_into(bytearray(10), offset=-1)
            with pytest.raises(ValueError, match="non-negative"):
                f.write(b"x", offset=-1)
            with pytest.raises(ValueError, match="non-negative"):
                f.pwrite(b"x", -1)

    def test_negative_size_rejected(self, c):
        """Test that negative size in pread raises ValueError."""
        storage = BytesIOStorage()
        key = c.random_key()

        with raf.create(storage, key, cipher=c) as f:
            f.write(b"test")
            with pytest.raises(ValueError, match="non-negative"):
                f.pread(-5, 0)

    def test_context_manager(self, c):
        """Test context manager properly closes file."""
        storage = BytesIOStorage()
        key = c.random_key()

        with raf.create(storage, key, cipher=c) as f:
            f.write(b"test")
            assert not f.closed

        assert f.closed

    def test_operations_on_closed_file_fail(self, c):
        """Test that operations on closed file raise ValueError."""
        storage = BytesIOStorage()
        key = c.random_key()

        f = raf.create(storage, key, cipher=c)
        f.write(b"test")
        f.close()

        with pytest.raises(ValueError, match="closed"):
            f.read()
        with pytest.raises(ValueError, match="closed"):
            f.write(b"x")
        with pytest.raises(ValueError, match="closed"):
            f.seek(0)
        with pytest.raises(ValueError, match="closed"):
            _ = f.size

    def test_key_sizes(self, c):
        """Test that key sizes are correct."""
        expected = 16 if "128" in c.NAME else 32
        assert c.KEYBYTES == expected
        assert c.NONCEBYTES == expected


class TestRafProbe:
    """Tests for raf.probe function."""

    def test_probe_default_chunk_size(self):
        """Test probing an AEGIS-128L file."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with raf.create(storage, key, cipher=aegis128l) as f:
            f.write(b"test data")

        alg_id, chunk_size, file_size = raf.probe(storage)
        assert alg_id == aegis128l.RAF_ALG_ID
        assert chunk_size == 65536
        assert file_size == 9

    def test_probe_custom_chunk_size(self):
        """Test probing an AEGIS-256 file with custom chunk size."""
        storage = BytesIOStorage()
        key = aegis256.random_key()

        with raf.create(storage, key, cipher=aegis256, chunk_size=4096) as f:
            f.write(b"hello")

        alg_id, chunk_size, _ = raf.probe(storage)
        assert alg_id == aegis256.RAF_ALG_ID
        assert chunk_size == 4096

    def test_probe_invalid_file_fails(self):
        """Test that probing invalid file fails."""
        storage = BytesIOStorage(b"not a valid RAF file")

        with pytest.raises(RuntimeError, match="probe failed"):
            raf.probe(storage)


class TestRafOpen:
    """Tests for raf.open with explicit cipher (pyaegis auto-detect doesn't apply)."""

    @pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
    def test_probe_reports_cipher_and_open_reads(self, c):
        """probe() reports the cipher's alg_id; open() with that cipher reads."""
        storage = BytesIOStorage()
        key = c.random_key()

        with raf.create(storage, key, cipher=c) as f:
            f.write(b"test variant")

        info = raf.probe(storage)
        assert info.alg_id == c.RAF_ALG_ID

        with raf.open(storage, key, cipher=c) as f:
            assert f.read() == b"test variant"

    def test_wrong_key_fails(self):
        """Test raf.open with wrong key fails."""
        storage = BytesIOStorage()
        key1 = aegis128l.random_key()
        key2 = aegis128l.random_key()

        with raf.create(storage, key1, cipher=aegis128l) as f:
            f.write(b"secret")

        with pytest.raises(ValueError, match="authentication failed"):
            raf.open(storage, key2, cipher=aegis128l)


class TestAlgorithmMismatch:
    """Test opening file with wrong cipher."""

    def test_wrong_cipher_rejected(self):
        """Test that opening with the wrong cipher is rejected."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with raf.create(storage, key, cipher=aegis128l) as f:
            f.write(b"test")

        with pytest.raises(ValueError, match="uses algorithm"):
            raf.open(storage, aegis256.random_key(), cipher=aegis256)


class TestChunkBoundary:
    """Tests for operations at chunk boundaries."""

    def test_exact_chunk_write(self):
        """Test writing exactly one chunk."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()
        chunk_size = 4096

        with raf.create(storage, key, cipher=aegis128l, chunk_size=chunk_size) as f:
            data = b"X" * chunk_size
            f.write(data)

        with raf.open(storage, key, cipher=aegis128l) as f:
            assert f.read() == data

    def test_cross_chunk_read(self):
        """Test read spanning multiple chunks."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()
        chunk_size = 4096

        with raf.create(storage, key, cipher=aegis128l, chunk_size=chunk_size) as f:
            data = b"ABCD" * chunk_size
            f.write(data)

        with raf.open(storage, key, cipher=aegis128l) as f:
            # Read spanning chunk boundary
            partial = f.pread(100, chunk_size - 50)
            assert len(partial) == 100

    def test_cross_chunk_write(self):
        """Test write spanning multiple chunks (overwriting)."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()
        chunk_size = 4096

        with raf.create(storage, key, cipher=aegis128l, chunk_size=chunk_size) as f:
            # Write initial data spanning two chunks
            f.write(b"0" * (chunk_size + 100))
            # Overwrite across chunk boundary
            f.pwrite(b"X" * 100, chunk_size - 50)

        with raf.open(storage, key, cipher=aegis128l) as f:
            data = f.read()
            assert len(data) == chunk_size + 100
            # First part unchanged
            assert data[: chunk_size - 50] == b"0" * (chunk_size - 50)
            # Overwritten part
            assert data[chunk_size - 50 : chunk_size + 50] == b"X" * 100
            # Trailing part unchanged
            assert data[chunk_size + 50 :] == b"0" * 50


class TestSync:
    """Tests for sync operation."""

    def test_sync_basic(self, tmp_path):
        """Test sync flushes to storage."""
        path = tmp_path / "test.raf"
        key = aegis128l.random_key()

        with FileStorage(path, "w+b") as storage:
            with raf.create(storage, key, cipher=aegis128l) as f:
                f.write(b"data to sync")
                f.sync()


class TestReadAtEOF:
    """Tests for reading at/past EOF."""

    def test_read_at_eof_returns_empty(self):
        """Test reading at EOF returns empty bytes."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with raf.create(storage, key, cipher=aegis128l) as f:
            f.write(b"hello")

        with raf.open(storage, key, cipher=aegis128l) as f:
            f.seek(0, 2)
            assert f.read() == b""

    def test_read_partial_at_eof(self):
        """Test reading more bytes than available returns partial."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with raf.create(storage, key, cipher=aegis128l) as f:
            f.write(b"hello")

        with raf.open(storage, key, cipher=aegis128l) as f:
            data = f.pread(100, 0)
            assert data == b"hello"


class Blake2bMerkleHasher:
    """Custom Merkle hasher using BLAKE2b for testing."""

    hash_len = 32

    def hash_leaf(self, chunk: bytes, chunk_len: int, chunk_idx: int) -> bytes:
        h = hashlib.blake2b(digest_size=32)
        h.update(b"\x00")
        h.update(chunk_idx.to_bytes(8, "little"))
        h.update(chunk[:chunk_len])
        return h.digest()

    def hash_parent(
        self, left: bytes, right: bytes, level: int, node_idx: int
    ) -> bytes:
        h = hashlib.blake2b(digest_size=32)
        h.update(b"\x01")
        h.update(level.to_bytes(4, "little"))
        h.update(node_idx.to_bytes(8, "little"))
        h.update(left)
        h.update(right)
        return h.digest()

    def hash_empty(self, level: int, node_idx: int) -> bytes:
        h = hashlib.blake2b(digest_size=32)
        h.update(b"\x02")
        h.update(level.to_bytes(4, "little"))
        h.update(node_idx.to_bytes(8, "little"))
        return h.digest()

    def hash_commitment(
        self, structural_root: bytes, ctx: bytes, file_size: int
    ) -> bytes:
        h = hashlib.blake2b(digest_size=32)
        h.update(b"\x03")
        h.update(structural_root)
        h.update(ctx)
        h.update(file_size.to_bytes(8, "little"))
        return h.digest()


class TestMerkle:
    """Tests for Merkle tree support in RAF."""

    def test_merkle_true_roundtrip(self):
        """merkle=True round-trip: root_hash is 32 bytes."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with raf.create(storage, key, cipher=aegis128l, merkle=True) as f:
            f.write(b"Hello, Merkle!")
            root = f.root_hash
            assert root is not None
            assert len(root) == 32

    def test_root_hash_changes_on_write(self):
        """Root hash changes after additional write."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with raf.create(storage, key, cipher=aegis128l, merkle=True) as f:
            f.write(b"first")
            root1 = f.root_hash
            f.write(b"second")
            root2 = f.root_hash
            assert root1 != root2

    def test_root_hash_deterministic(self):
        """Same file rewritten with same data produces same root commitment."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()
        data = b"deterministic content"

        with raf.create(storage, key, cipher=aegis128l, merkle=True) as f:
            f.write(data)
            root1 = f.root_hash

        with raf.open(storage, key, cipher=aegis128l, merkle=True) as f:
            f.merkle_rebuild()
            root2 = f.root_hash

        assert root1 == root2

    def test_rebuild_reproduces_root(self):
        """Close and reopen: rebuild reproduces the same root hash."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with raf.create(storage, key, cipher=aegis128l, merkle=True) as f:
            f.write(b"data for rebuild test")
            original_root = f.root_hash

        with raf.open(storage, key, cipher=aegis128l, merkle=True) as f:
            f.merkle_rebuild()
            assert f.root_hash == original_root

    def test_verify_clean_file(self):
        """Verify returns None for an untampered file."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with raf.create(storage, key, cipher=aegis128l, merkle=True) as f:
            f.write(b"clean data")

        with raf.open(storage, key, cipher=aegis128l, merkle=True) as f:
            f.merkle_rebuild()
            assert f.merkle_verify() is None

    def test_verify_root_happy_path(self):
        """verify_root succeeds with correct root."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with raf.create(storage, key, cipher=aegis128l, merkle=True) as f:
            f.write(b"verify root test")
            root = f.root_hash

        with raf.open(storage, key, cipher=aegis128l, merkle=True) as f:
            f.verify_root(root)

    def test_verify_root_wrong_root(self):
        """verify_root raises ValueError with wrong root."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with raf.create(storage, key, cipher=aegis128l, merkle=True) as f:
            f.write(b"some data")

        with raf.open(storage, key, cipher=aegis128l, merkle=True) as f:
            with pytest.raises(ValueError, match="merkle root mismatch"):
                f.verify_root(b"\x00" * 32)

    def test_rebuild_fails_on_tampered_ciphertext(self):
        """Tamper with raw storage; rebuild fails authentication."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with raf.create(storage, key, cipher=aegis128l, merkle=True) as f:
            f.write(b"X" * 1000)

        raw = storage._data
        tamper_offset = 100
        if tamper_offset < len(raw):
            raw[tamper_offset] ^= 0xFF

        with raf.open(storage, key, cipher=aegis128l, merkle=True) as f:
            with pytest.raises((ValueError, RuntimeError)):
                f.merkle_rebuild()

    def test_verify_detects_hash_mismatch(self):
        """Corrupt in-memory tree buffer; verify returns chunk index."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with raf.create(storage, key, cipher=aegis128l, merkle=True) as f:
            f.write(b"data to verify")
            f._merkle_buf[0] ^= 0xFF
            result = f.merkle_verify()
            assert result is not None
            assert isinstance(result, int)

    def test_merkle_max_chunks_zero_rejected(self):
        """merkle_max_chunks=0 raises ValueError."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with pytest.raises(ValueError, match="must be > 0"):
            raf.create(storage, key, cipher=aegis128l, merkle=True, merkle_max_chunks=0)

    def test_overflow_protection(self):
        """Absurdly large merkle_max_chunks raises ValueError."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with pytest.raises(ValueError, match="overflow"):
            raf.create(
                storage, key, cipher=aegis128l, merkle=True, merkle_max_chunks=2**62
            )

    def test_rebuild_without_merkle_raises(self):
        """merkle_rebuild on non-merkle file raises ValueError."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with raf.create(storage, key, cipher=aegis128l) as f:
            with pytest.raises(ValueError, match="not enabled"):
                f.merkle_rebuild()

    def test_verify_without_merkle_raises(self):
        """merkle_verify on non-merkle file raises ValueError."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with raf.create(storage, key, cipher=aegis128l) as f:
            with pytest.raises(ValueError, match="not enabled"):
                f.merkle_verify()

    def test_root_hash_none_without_merkle(self):
        """root_hash returns None when merkle is not enabled."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with raf.create(storage, key, cipher=aegis128l) as f:
            assert f.root_hash is None

    def test_custom_hasher_wrong_digest_length(self):
        """Hasher returning wrong digest length causes write to fail."""

        class BadHasher:
            hash_len = 32

            def hash_leaf(self, chunk, chunk_len, chunk_idx):
                return b"\x00" * 16  # Wrong: 16 instead of 32

            def hash_parent(self, left, right, level, node_idx):
                return b"\x00" * 16

            def hash_empty(self, level, node_idx):
                return b"\x00" * 16

            def hash_commitment(self, structural_root, ctx, file_size):
                return b"\x00" * 16

        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with pytest.raises((RuntimeError, ValueError)):
            with raf.create(storage, key, cipher=aegis128l, merkle=BadHasher()) as f:
                f.write(b"test data")

    def test_merkle_eoverflow_suggests_fix(self):
        """Writing past merkle_max_chunks raises ValueError with hint."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()
        chunk_size = 1024

        with raf.create(
            storage,
            key,
            cipher=aegis128l,
            chunk_size=chunk_size,
            merkle=True,
            merkle_max_chunks=2,
        ) as f:
            data = b"X" * (chunk_size * 3)
            with pytest.raises(ValueError, match="merkle_max_chunks"):
                f.write(data)

    @pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
    def test_merkle_all_variants_roundtrip(self, c):
        """merkle=True works with all 6 RAF variants."""
        storage = BytesIOStorage()
        key = c.random_key()

        with raf.create(storage, key, cipher=c, merkle=True) as f:
            f.write(b"variant test data")
            root = f.root_hash
            assert root is not None
            assert len(root) == 32

    @pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
    def test_merkle_all_variants_rebuild(self, c):
        """merkle_rebuild reproduces root across all variants."""
        storage = BytesIOStorage()
        key = c.random_key()

        with raf.create(storage, key, cipher=c, merkle=True) as f:
            f.write(b"rebuild variant test")
            original_root = f.root_hash

        with raf.open(storage, key, cipher=c, merkle=True) as f:
            f.merkle_rebuild()
            assert f.root_hash == original_root

    @pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
    def test_merkle_all_variants_verify(self, c):
        """merkle_verify returns None for clean file across all variants."""
        storage = BytesIOStorage()
        key = c.random_key()

        with raf.create(storage, key, cipher=c, merkle=True) as f:
            f.write(b"verify variant test")

        with raf.open(storage, key, cipher=c, merkle=True) as f:
            f.merkle_rebuild()
            assert f.merkle_verify() is None

    def test_custom_hasher_blake2b(self):
        """Custom BLAKE2b hasher works correctly."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()
        hasher = Blake2bMerkleHasher()

        with raf.create(storage, key, cipher=aegis128l, merkle=hasher) as f:
            f.write(b"blake2b test data")
            root = f.root_hash
            assert root is not None
            assert len(root) == 32

        with raf.open(storage, key, cipher=aegis128l, merkle=hasher) as f:
            f.merkle_rebuild()
            assert f.root_hash == root
            assert f.merkle_verify() is None

    def test_verify_root_wrong_length(self):
        """verify_root with wrong length raises ValueError."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with raf.create(storage, key, cipher=aegis128l, merkle=True) as f:
            f.write(b"test")
            with pytest.raises(ValueError, match="must be 32 bytes"):
                f.verify_root(b"\x00" * 16)

    def test_raf_open_with_merkle(self):
        """raf.open passes merkle params correctly."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with raf.create(storage, key, cipher=aegis128l, merkle=True) as f:
            f.write(b"raf_open merkle test")
            root = f.root_hash

        with raf.open(storage, key, cipher=aegis128l, merkle=True) as f:
            f.verify_root(root)

    def test_sha256_merkle_hasher_is_merkle_hasher(self):
        """SHA256MerkleHasher satisfies MerkleHasher protocol."""
        assert isinstance(SHA256MerkleHasher(), MerkleHasher)

    def test_merkle_methods_on_closed_file(self):
        """All merkle methods raise ValueError on closed file."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        f = raf.create(storage, key, cipher=aegis128l, merkle=True)
        f.write(b"test data")
        f.close()

        with pytest.raises(ValueError, match="closed"):
            f.merkle_rebuild()
        with pytest.raises(ValueError, match="closed"):
            f.merkle_verify()
        with pytest.raises(ValueError, match="closed"):
            f.verify_root(b"\x00" * 32)
        with pytest.raises(ValueError, match="closed"):
            _ = f.root_hash

    def test_eoverflow_with_absurd_offset_no_merkle_hint(self):
        """EOVERFLOW from absurd offset doesn't mention merkle_max_chunks."""
        storage = BytesIOStorage()
        key = aegis128l.random_key()

        with raf.create(storage, key, cipher=aegis128l, merkle=True) as f:
            with pytest.raises(RuntimeError, match="EOVERFLOW"):
                f.write(b"x", offset=2**64 - 1)
