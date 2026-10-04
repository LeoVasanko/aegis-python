import threading

import pytest

from aeg import aegis128l, aegis128x2, aegis128x4, aegis256, aegis256x2, aegis256x4

CIPHERS = [aegis128l, aegis128x2, aegis128x4, aegis256, aegis256x2, aegis256x4]


def cipher_id(c):
    return c.NAME


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_random_is_per_thread_singleton(c):
    assert c.random() is c.random()
    other = []
    t = threading.Thread(target=lambda: other.append(c.random()))
    t.start()
    t.join()
    assert other[0] is not c.random()


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_random_key_nonce_from_csprng(c):
    assert len(c.random_key()) == c.KEYBYTES
    assert len(c.random_nonce()) == c.NONCEBYTES
    # successive outputs never repeat
    assert c.random_key() != c.random_key()
    assert c.random_nonce() != c.random_nonce()


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_threads_get_independent_streams(c):
    results = [None] * 2

    def work(i):
        results[i] = bytes(c.random_key())

    threads = [threading.Thread(target=work, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results[0] != results[1]


@pytest.mark.parametrize("c", CIPHERS, ids=cipher_id)
def test_bytes_into_callable(c):
    rng = c.random()
    a = rng.bytes(64)
    buf = bytearray(64)
    rng.into(buf)
    b = rng(64)
    assert len(a) == len(b) == 64
    assert a != bytes(buf) != b  # three consecutive blocks differ
