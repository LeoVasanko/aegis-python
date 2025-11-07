# pyaegis

[![PyPI version](https://badge.fury.io/py/pyaegis.svg)](https://badge.fury.io/py/pyaegis)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/LeoVasanko/pyaegis/blob/main/libaegis/LICENSE)

Fast, safe Python bindings for the AEGIS family of authenticated encryption algorithms (via libaegis).

## Install

- PyPI (recommended):

```bash
pip install pyaegis
```

For development builds, see BUILD.md.

## Variants

All submodules expose the same API; pick one for your key/nonce size and platform:

- aegis128l (16-byte key, 16-byte nonce)
- aegis256 (32-byte key, 32-byte nonce)
- aegis128x2 / aegis128x4 (multi-lane 128-bit; best throughput on SIMD-capable CPUs)
- aegis256x2 / aegis256x4 (multi-lane 256-bit)

## Quick start

```python
from pyaegis import aegis128x4 as ciph

key = ciph.random_key()
nonce = ciph.random_nonce()
msg = b"hello"

ct = ciph.encrypt(key, nonce, msg)
pt = ciph.decrypt(key, nonce, ct)
assert pt == msg
```

## API overview

Common parameters and returns (applies to all items below):

- key: bytes of length a.KEYBYTES
- nonce: bytes of length a.NPUBBYTES (must be unique per (key, message))
- message/ct: plain text or ciphertext
- ad: optional associated data (authenticated, not encrypted)
- into: optional output buffer (see below)
- maclen: MAC tag length 16 or 32 bytes (default 16)

Only the first few can be positional arguments that are always provided in this order. All arguments can be passed as kwargs.

Most functions return a buffer of bytes. By default a `bytearray` of the correct size is returned. An existing buffer can be provided by `into` argument, in which case the bytes of it that were written to are returned as a memoryview.


- random_key() -> bytes (correct length for the module)
- random_nonce() -> bytes (correct length for the module)

Constants (per module): KEYBYTES, NPUBBYTES, ABYTES_MIN, ABYTES_MAX, RATE, ALIGNMENT

### One-shot AEAD:

Encrypt and decrypt messages with built-in authentication:
- encrypt(key, nonce, message, ad=None, maclen=16, into=None) -> ct_with_mac
- decrypt(key, nonce, ct_with_mac, ad=None, maclen=16, into=None) -> plaintext

The MAC tag is handled separately of ciphertext:
- encrypt_detached(key, nonce, message, ad=None, maclen=16, ct_into=None, mac_into=None) -> (ct, mac)
- decrypt_detached(key, nonce, ct, mac, ad=None, into=None) -> plaintext

No MAC tag, vulnerable to alterations:
- encrypt_unauthenticated(key, nonce, message, into=None) -> ciphertext  (testing only)
- decrypt_unauthenticated(key, nonce, ct, into=None) -> plaintext        (testing only)

### Incremental AEAD:

Stateful classes that can be used for processing the data in separate chunks:
- Encryptor(key, nonce, ad=None)
    - update(message[, into]) -> ciphertext_chunk
    - final([into], maclen=16) -> mac_tag
- Decryptor(key, nonce, ad=None)
    - update(ct_chunk[, into]) -> plaintext_chunk
    - final(mac) -> None (raises ValueError on failure)

### Message Authentication Code:

No encryption, but prevents changes to the data without the correct key.

- mac(key, nonce, data, maclen=16, into=None) -> mac
- Mac(key, nonce)
    - update(data)
    - final(maclen=16[, into]) -> mac
    - verify(mac) -> bool (True on success; raises ValueError on failure)

### Keystream generation:

Useful for creating pseudo random bytes as rapidly as possible. Reuse of the same (key, nonce) creates identical output.

- stream(key, nonce=None, length=None, into=None) -> pseudorandom bytes (for tests/PRNG-like use)


## Examples

Detached tag (ct, mac)

```python
from pyaegis import aegis256x4 as a
key, nonce = a.random_key(), a.random_nonce()
ct, mac = a.encrypt_detached(key, nonce, b"secret", ad=b"hdr", maclen=32)
pt = a.decrypt_detached(key, nonce, ct, mac, ad=b"hdr")
```

Incremental:

```python
from pyaegis import aegis256x4 as a
key, nonce = a.random_key(), a.random_nonce()

enc = a.Encryptor(key, nonce, ad=b"hdr")
c1 = enc.update(b"chunk1")
c2 = enc.update(b"chunk2")
mac = enc.final(maclen=16)   # returns only the tag

dec = a.Decryptor(key, nonce, ad=b"hdr")
p1 = dec.update(c1)
p2 = dec.update(c2)
dec.final(mac)               # raises ValueError on failure
```

MAC-only:

```python
from pyaegis import aegis256x4 as a
key, nonce = a.random_key(), a.random_nonce()

mac = a.mac(key, nonce, b"data", maclen=32)

st = a.Mac(key, nonce)
st.update(b"data")
st.update(b"more data")
st.verify(mac)  # True or raises ValueError
```

Pre-allocated buffers (avoid allocations):

```python
from pyaegis import aegis256x4 as a
key, nonce = a.random_key(), a.random_nonce()
msg = b"data"

out = bytearray(len(msg) + 16)
view = a.encrypt(key, nonce, msg, into=out)
assert bytes(view) == bytes(out)
```

In-place (same buffer for input and into):

```python
from pyaegis import aegis256x4 as a
key, nonce = a.random_key(), a.random_nonce()

# Attached tag: place plaintext at the start of a buffer that has room for the tag
msg = b"secret"
maclen = 16
buf = bytearray(len(msg) + maclen)
buf[: len(msg)] = msg
m = memoryview(buf)[: len(msg)]

# Encrypt in-place (ciphertext written back into buf, tag appended)
a.encrypt(key, nonce, m, into=buf)

# Decrypt back in-place (plaintext written over the start region)
a.decrypt(key, nonce, buf, into=m)  # uses default maclen=16
assert bytes(m) == msg

# Detached mode: ciphertext written back to the same buffer
buf2 = bytearray(len(msg))
buf2[:] = msg
m2 = memoryview(buf2)
ct_view, mac = a.encrypt_detached(key, nonce, m2, ct_into=buf2)
a.decrypt_detached(key, nonce, ct_view, mac, into=m2)
assert bytes(m2) == msg
```

## Performance

Runtime CPU feature detection selects optimized code paths (AES-NI, ARM Crypto, AVX2/AVX-512). Multi-lane variants (x2/x4) offer higher throughput on suitable CPUs.

Run the built-in benchmark to see which variant is fastest on your machine:

```fish
python -m pyaegis.benchmark
```

## Errors

- Authentication failures raise ValueError.
- Invalid sizes/types raise TypeError.
- Unexpected errors from libaegis raise RuntimeError.

## Security notes

- Never reuse a nonce with the same key. Prefer a.random_nonce() per message.
- Keep keys secret; use a.random_key() to get correctly sized keys.
- AAD (ad=...) is authenticated but not encrypted.
- Do not use stream() or unauthenticated helpers for real data protection; they are for testing and specialized cases.
