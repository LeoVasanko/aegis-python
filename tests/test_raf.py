import pytest

from aeg import aegis128l, aegis128x2, aegis128x4, aegis256, aegis256x2, aegis256x4
from aeg import raf
from aeg import random as aeg_random

CIPHERS = [aegis128l, aegis128x2, aegis128x4, aegis256, aegis256x2, aegis256x4]

CHUNK = 1024


def cipher_id(c):
    return c.NAME


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_roundtrip_bytesio(c):
    key = c.random_key()
    data = bytes(range(256)) * 20  # spans multiple chunks
    st = raf.BytesIOStorage()
    with raf.create(st, key, c, chunk_size=CHUNK) as f:
        assert f.write(data) == len(data)
        assert f.size == len(data)
    with raf.open(st, key, c) as f:
        assert f.read() == data


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_roundtrip_filestorage(c, tmp_path):
    key = c.random_key()
    data = b"file-backed" * 500
    path = tmp_path / "test.raf"
    with raf.create(path, key, c, chunk_size=CHUNK) as f:
        f.write(data)
    with raf.open(path, key, c) as f:
        assert f.read() == data


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_random_access(c):
    key = c.random_key()
    st = raf.BytesIOStorage()
    data = bytearray(4097)
    with raf.create(st, key, c, chunk_size=CHUNK) as f:
        f.write(data)
        # unaligned writes across chunk boundaries
        f.pwrite(b"ABCDEF", 1000)  # crosses chunk 0/1 boundary at 1024
        f.pwrite(b"z", 4096)  # last byte
        data[1000:1006] = b"ABCDEF"
        data[4096:4097] = b"z"
        assert f.pread(6, 1000) == b"ABCDEF"
        assert f.pread(4097, 0) == bytes(data)
        assert f.tell() == len(data)  # pwrite/pread don't move the position


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_seek_tell_read_into(c):
    key = c.random_key()
    st = raf.BytesIOStorage()
    data = b"0123456789" * 100
    with raf.create(st, key, c, chunk_size=CHUNK) as f:
        f.write(data)
        assert f.tell() == len(data)
        assert f.seek(10) == 10
        assert f.read(5) == data[10:15]
        assert f.tell() == 15
        assert f.seek(-5, 1) == 10
        assert f.seek(0, 2) == len(data)
        buf = bytearray(20)
        assert f.read_into(buf, 100) == 20
        assert bytes(buf) == data[100:120]
        with pytest.raises(ValueError):
            f.seek(-1)


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_truncate(c):
    key = c.random_key()
    st = raf.BytesIOStorage()
    with raf.create(st, key, c, chunk_size=CHUNK) as f:
        f.write(b"x" * 3000)
        assert f.truncate(1500) == 1500
        assert f.size == 1500
        assert f.pread(1500, 0) == b"x" * 1500
        f.truncate(2500)  # grow, zero-filled
        assert f.size == 2500
        assert f.pread(1000, 1500) == b"\x00" * 1000


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_wrong_key(c):
    key = c.random_key()
    st = raf.BytesIOStorage()
    with raf.create(st, key, c, chunk_size=CHUNK) as f:
        f.write(b"secret")
    with pytest.raises(ValueError, match="authentication failed"):
        raf.open(st, c.random_key(), c)


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_tampered_chunk(c):
    key = c.random_key()
    st = raf.BytesIOStorage()
    with raf.create(st, key, c, chunk_size=CHUNK) as f:
        f.write(b"y" * 2048)
    # flip a ciphertext byte inside the first chunk record (after the nonce)
    st._data[raf.HEADER_SIZE + c.NONCEBYTES + 10] ^= 1
    with raf.open(st, key, c) as f:
        with pytest.raises(ValueError, match="authentication failed"):
            f.read()


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_probe_and_cipher_mismatch(c):
    key = c.random_key()
    st = raf.BytesIOStorage()
    with raf.create(st, key, c, chunk_size=CHUNK) as f:
        f.write(b"data")
    info = raf.probe(st)
    assert info.alg_id == c.RAF_ALG_ID
    assert info.chunk_size == CHUNK
    assert info.file_size == 4
    other = aegis256 if c is not aegis256 else aegis128l
    with pytest.raises(ValueError, match="algorithm id"):
        raf.open(st, key, other)


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_create_existing(c, tmp_path):
    key = c.random_key()
    path = tmp_path / "exists.raf"
    raf.create(path, key, c, chunk_size=CHUNK).close()
    with pytest.raises(FileExistsError):
        raf.create(path, key, c, chunk_size=CHUNK)
    with raf.create(path, key, c, chunk_size=CHUNK, truncate=True) as f:
        assert f.size == 0


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_open_missing(c, tmp_path):
    with pytest.raises(FileNotFoundError):
        raf.open(tmp_path / "missing.raf", c.random_key(), c)


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_merkle(c):
    key = c.random_key()
    st = raf.BytesIOStorage()
    data = b"m" * 5000
    with raf.create(st, key, c, chunk_size=CHUNK, merkle=True) as f:
        f.write(data)
        root1 = f.root_hash
        assert root1 is not None and len(root1) == 32
        assert f.merkle_verify() is None
        f.pwrite(b"X", 0)
        root2 = f.root_hash
        assert root1 != root2
        assert f.merkle_verify() is None
    with raf.open(st, key, c, merkle=True) as f:
        f.verify_root(root2)  # rebuilds and compares
        assert f.root_hash == root2
        with pytest.raises(ValueError, match="authentication failed"):
            f.verify_root(root1)
        with pytest.raises(ValueError):
            f.verify_root(b"short")


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_merkle_detects_corruption(c):
    key = c.random_key()
    st = raf.BytesIOStorage()
    with raf.create(st, key, c, chunk_size=CHUNK, merkle=True) as f:
        f.write(b"z" * 3000)
        f.merkle_rebuild()
        record = c.NONCEBYTES + CHUNK + 16
        # corrupt chunk 2's ciphertext in the backing store
        st._data[raf.HEADER_SIZE + 2 * record + c.NONCEBYTES + 5] ^= 1
        assert f.merkle_verify() == 2


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_merkle_overflow(c):
    key = c.random_key()
    st = raf.BytesIOStorage()
    with raf.create(
        st, key, c, chunk_size=CHUNK, merkle=True, merkle_max_chunks=2
    ) as f:
        f.write(b"a" * 2048)
        with pytest.raises(ValueError, match="merkle_max_chunks"):
            f.write(b"b")


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_merkle_disabled(c):
    key = c.random_key()
    st = raf.BytesIOStorage()
    with raf.create(st, key, c, chunk_size=CHUNK) as f:
        assert f.root_hash is None
        with pytest.raises(ValueError, match="not enabled"):
            f.merkle_verify()


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_custom_rng(c):
    counter = 0

    def deterministic(n: int) -> bytes:
        nonlocal counter
        out = bytes((counter + i) % 256 for i in range(n))
        counter += n
        return out

    key = c.random_key()
    st = raf.BytesIOStorage()
    with raf.create(st, key, c, chunk_size=CHUNK, rng=deterministic) as f:
        f.write(b"rng test")
    with raf.open(st, key, c) as f:
        assert f.read() == b"rng test"
    assert counter > 0


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_default_rng_matches_cipher(c):
    """raf.create/open without rng use a Random seeded for the same cipher."""
    key = c.random_key()
    st = raf.BytesIOStorage()
    with raf.create(st, key, c, chunk_size=CHUNK) as f:
        assert f._rng_keepalive[0]  # handle alive
        f.write(b"default rng")
    with raf.open(st, key, c) as f:
        assert f.read() == b"default rng"


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_random_per_cipher(c):
    """Random can be constructed with each cipher module."""
    r1 = aeg_random.Random(c)
    r2 = c.random()
    out = r1.bytes(100)
    assert len(out) == 100
    assert any(out)  # not all zeros
    assert len(r2.bytes(50)) == 50
    # Random instance satisfies the RandomSource callable protocol
    assert callable(r1)
    rng_cdata, keepalive = aeg_random.as_raf_rng(r1)
    assert rng_cdata.random is not None and keepalive


def test_random_determinism_with_seed():
    """Two Random instances seeded identically produce identical output."""
    c = aegis256x4
    seed = bytes(range(c.NONCEBYTES + c.KEYBYTES))
    r1 = aeg_random.Random(c, seed=seed)
    r2 = aeg_random.Random(c, seed=seed)
    assert r1.bytes(64) == r2.bytes(64)
    assert r1.bytes(1000) == r2.bytes(1000)
    with pytest.raises(TypeError, match="seed length"):
        aeg_random.Random(c, seed=b"short")


def test_random_into_equivalence():
    """into() fills in place and matches bytes() from an identically-seeded RNG."""
    c = aegis256x4
    seed = bytes(c.NONCEBYTES + c.KEYBYTES)
    r1 = aeg_random.Random(c, seed=seed)
    r2 = aeg_random.Random(c, seed=seed)
    buf = bytearray(128)
    r1.into(buf)
    assert bytes(buf) == bytes(r2.bytes(128))
    # buffers of other buffer-protocol types work too
    import array

    arr = array.array("b", bytes(32))
    r1.into(arr)
    assert any(arr.tobytes())


def test_random_no_repeat():
    """Successive calls never repeat a block (nonce increments)."""
    r = aeg_random.Random(aegis128x2)
    blocks = {bytes(r.bytes(64)) for _ in range(1000)}
    assert len(blocks) == 1000


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_cipher_module_random_helper(c):
    """Each cipher module provides a random() helper bound to itself."""
    r = c.random()
    assert isinstance(r, aeg_random.Random)
    assert r._cipher is c
    assert len(r.bytes(32)) == 32
    buf = bytearray(48)
    r.into(buf)
    assert any(buf)


def test_random_module():
    assert len(aeg_random.system_random(16)) == 16
    # any callable source can be bridged to the C RNG struct
    rng, keepalive = aeg_random.as_raf_rng(aeg_random.system_random)
    assert rng.random is not None and keepalive

    def bad(n: int) -> bytes:
        return b"too short"

    rng2, _ = aeg_random.as_raf_rng(bad)
    out = aeg_random.ffi.new("uint8_t[8]")
    assert rng2.random(rng2.user, out, 8) == -1


def test_derive_master_key():
    mk16 = bytes(range(16))
    mk32 = bytes(range(32))
    assert len(raf.derive_master_key(mk16)) == 16
    assert len(raf.derive_master_key(mk32)) == 32
    # context-bound: different contexts give different keys
    assert raf.derive_master_key(mk32, b"a") != raf.derive_master_key(mk32, b"b")
    # empty context still derives a scoped subkey
    assert raf.derive_master_key(mk32) != mk32
    with pytest.raises(ValueError):
        raf.derive_master_key(b"\x00" * 24)
    with pytest.raises(ValueError):
        raf.derive_master_key(mk16, b"c" * 121)
    with pytest.raises(ValueError):
        raf.derive_master_key(mk32, b"c" * 73)
    # derived keys work end-to-end
    c = aegis256x4
    key = raf.derive_master_key(mk32, b"my-file")
    st = raf.BytesIOStorage()
    with raf.create(st, key, c, chunk_size=CHUNK) as f:
        f.write(b"derived")
    with raf.open(st, key, c) as f:
        assert f.read() == b"derived"


def test_invalid_chunk_size():
    c = aegis256x4
    with pytest.raises(ValueError, match="chunk_size"):
        raf.create(raf.BytesIOStorage(), c.random_key(), c, chunk_size=512)
    with pytest.raises(ValueError, match="multiple of 16"):
        raf.create(raf.BytesIOStorage(), c.random_key(), c, chunk_size=1032)


def test_bad_key_length():
    c = aegis256x4
    with pytest.raises(TypeError, match="key length"):
        raf.create(raf.BytesIOStorage(), b"\x00" * 16, c, chunk_size=CHUNK)


def test_closed_file():
    c = aegis256x4
    st = raf.BytesIOStorage()
    f = raf.create(st, c.random_key(), c, chunk_size=CHUNK)
    f.close()
    assert f.closed
    with pytest.raises(ValueError, match="closed"):
        f.read()
    f.close()  # idempotent
