"""Tests for aeg.securebuf.SecureBuffer.

CPython-only assumptions: reference counting frees memoryviews as soon as
they are del'd; live exported views would make mmap.close() fail with
BufferError.
"""

import pytest

from aeg import aegis128l
from aeg.securebuf import SecureBuffer
from aeg.util import wipe


def test_buffer_protocol_read_write():
    with SecureBuffer(32) as sb:
        assert len(sb) == 32
        mv = memoryview(sb)
        assert len(mv) == 32
        assert not mv.readonly
        mv[:4] = b"abcd"
        assert mv[:4] == b"abcd"
        del mv
    assert sb.closed


def test_not_convertible_to_bytes():
    with SecureBuffer(16) as sb, pytest.raises(TypeError, match="cannot be converted"):
        bytes(sb)


def test_invalid_size():
    for size in (0, -1):
        with pytest.raises(ValueError):
            SecureBuffer(size)


def test_close_is_idempotent_and_blocks_access():
    sb = SecureBuffer(16)
    sb.close()
    assert sb.closed
    with pytest.raises(ValueError):
        memoryview(sb)
    sb.close()
    assert sb.closed


def test_context_manager_closes_on_exception():
    with pytest.raises(RuntimeError), SecureBuffer(16) as sb:
        raise RuntimeError("boom")
    assert sb.closed


def test_del_closes():
    import gc

    sb = SecureBuffer(16)
    ref = sb._mmap
    del sb
    gc.collect()
    assert ref.closed


def test_getitem_returns_memoryview():
    with SecureBuffer(16) as sb:
        sb[:4] = b"abcd"
        view = sb[2:8]
        assert isinstance(view, memoryview)
        assert view.tobytes() == b"cd\x00\x00\x00\x00"
        del view


def test_wipe_fills_ff():
    sb = SecureBuffer(16)
    sb[:] = b"A" * 16
    wipe(sb)
    mv = memoryview(sb)
    assert mv.tobytes() == b"\xff" * 16
    del mv
    sb.close()


def test_roundtrip_as_key_and_into_target():
    """SecureBuffer works as key input and as an `into` target."""
    c = aegis128l
    with SecureBuffer(c.KEYBYTES) as key, SecureBuffer(c.NONCEBYTES) as nonce:
        key[:] = bytes(range(c.KEYBYTES))
        nonce[:] = bytes(c.NONCEBYTES)
        msg = b"hello secure world"
        ct, mac = c.encrypt_detached(key, nonce, msg)
        with SecureBuffer(len(msg)) as pt:
            out = c.decrypt_detached(key, nonce, ct, mac, into=pt)
            assert len(out) == len(msg)
            view = pt[:]
            assert view.tobytes() == msg
            del out, view


def test_stream_into():
    c = aegis128l
    key, nonce = c.random_key(), c.random_nonce()
    with SecureBuffer(64) as buf:
        c.stream(key, nonce, into=buf)
        view = buf[:]
        assert view.tobytes() == bytes(c.stream(key, nonce, 64))
        del view
