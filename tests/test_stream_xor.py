import pytest

from aeg import aegis128l, aegis128x2, aegis128x4, aegis256, aegis256x2, aegis256x4

CIPHERS = [aegis128l, aegis128x2, aegis128x4, aegis256, aegis256x2, aegis256x4]


def cipher_id(c):
    return c.NAME


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_stream_xor_roundtrip(c):
    key, nonce = c.random_key(), c.random_nonce()
    msg = b"stream cipher test" * 100  # spans multiple blocks, unaligned tail
    ct = c.stream_xor(key, nonce, msg)
    assert isinstance(ct, bytearray)
    assert len(ct) == len(msg)
    assert ct != msg
    # the same function decrypts
    assert c.stream_xor(key, nonce, ct) == msg


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_stream_xor_is_stream_xor(c):
    """Output equals data XOR stream(key, nonce) keystream."""
    key, nonce = c.random_key(), c.random_nonce()
    msg = b"\x5a" * 500
    ks = c.stream(key, nonce, len(msg))
    ct = c.stream_xor(key, nonce, msg)
    assert bytes(ct) == bytes(m ^ k for m, k in zip(msg, ks))


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_stream_xor_into(c):
    key, nonce = c.random_key(), c.random_nonce()
    msg = b"into target" * 10
    buf = bytearray(len(msg) + 10)
    out = c.stream_xor(key, nonce, msg, into=buf)
    assert len(out) == len(msg)
    assert bytes(out) == bytes(c.stream_xor(key, nonce, msg))


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_unauthenticated_deprecated(c):
    key, nonce = c.random_key(), c.random_nonce()
    msg = b"legacy format" * 20  # longer than one block: absorbing mode diverges
    with pytest.warns(DeprecationWarning):
        ct = c.encrypt_unauthenticated(key, nonce, msg)
    with pytest.warns(DeprecationWarning):
        pt = c.decrypt_unauthenticated(key, nonce, ct)
    assert pt == msg
    # deprecated pair is NOT compatible with stream_xor beyond the first block
    assert bytes(ct) != bytes(c.stream_xor(key, nonce, msg))
