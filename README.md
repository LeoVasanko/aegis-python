# pyaegis

[![PyPI version](https://badge.fury.io/py/pyaegis.svg)](https://badge.fury.io/py/pyaegis)

Safe Python bindings for the AEGIS family of very fast authenticated encryption algorithms (via libaegis).

## Install

Using [uv](https://docs.astral.sh/uv/getting-started/installation/):
```fish
uv pip install git+https://github.com/LeoVasanko/pyaegis.git
```

For development builds, see BUILD.md.

## Variants

All submodules expose the same API; pick one for your key/nonce size and platform:

- aegis128l (16-byte key, 16-byte nonce)
- aegis256 (32-byte key, 32-byte nonce)
- aegis128x2 / aegis128x4 (multi-lane 128-bit; best throughput on SIMD-capable CPUs)
- aegis256x2 / aegis256x4 (multi-lane 256-bit)

## Quick start

Normal authenticated encryption using the AEGIS-128X4 algorithm:

```python
from pyaegis import aegis128x4 as ciph

key = ciph.random_key()      # Secret key (stored securely)
nonce = ciph.random_nonce()  # Public nonce (recreated for each message)
msg = b"hello"

ct = ciph.encrypt(key, nonce, msg)
pt = ciph.decrypt(key, nonce, ct)   # Raises ValueError if anything was tampered with
assert pt == msg
```

## API overview

Common parameters and returns (applies to all items below):

- key: bytes of length ciph.KEYBYTES
- nonce: bytes of length ciph.NONCEBYTES (must be unique per message)
- message/ct: plain text or ciphertext
- ad: optional associated data (authenticated, not encrypted)
- into: optional output buffer (see below)
- maclen: MAC tag length 16 or 32 bytes (default 16)

Only the first few can be positional arguments that are always provided in this order. All arguments can be passed as kwargs. The inputs can be any Buffer supporting len() (e.g. `bytes`, `bytearray`, `memoryview`).

Most functions return a buffer of bytes. By default a `bytearray` of the correct size is returned. An existing buffer can be provided by `into` argument, in which case the bytes of it that were written to are returned as a memoryview.

### One-shot AEAD

Encrypt and decrypt messages with built-in authentication:
- encrypt(key, nonce, message, ad=None, maclen=16, into=None) -> ct_with_mac
- decrypt(key, nonce, ct_with_mac, ad=None, maclen=16, into=None) -> plaintext

The MAC tag is handled separately of ciphertext:
- encrypt_detached(key, nonce, message, ad=None, maclen=16, ct_into=None, mac_into=None) -> (ct, mac)
- decrypt_detached(key, nonce, ct, mac, ad=None, into=None) -> plaintext

No MAC tag, vulnerable to alterations:
- encrypt_unauthenticated(key, nonce, message, into=None) -> ciphertext  (testing only)
- decrypt_unauthenticated(key, nonce, ct, into=None) -> plaintext        (testing only)

### Incremental AEAD

Stateful classes that can be used for processing the data in separate chunks:
- Encryptor(key, nonce, ad=None)
    - update(message[, into]) -> ciphertext_chunk
    - final([into], maclen=16) -> mac_tag
- Decryptor(key, nonce, ad=None)
    - update(ct_chunk[, into]) -> plaintext_chunk
    - final(mac) -> None (raises ValueError on failure)

### Message Authentication Code

No encryption, but prevents changes to the data without the correct key.

- mac(key, nonce, data, maclen=16, into=None) -> mac
- Mac(key, nonce)
    - update(data)
    - final(maclen=16[, into]) -> mac
    - verify(mac) -> bool (True on success; raises ValueError on failure)

### Keystream generation

Useful for creating pseudo random bytes as rapidly as possible. Reuse of the same (key, nonce) creates identical output.

- stream(key, nonce=None, length=None, into=None) -> randombytes

### Miscellaneous

Constants (per module): KEYBYTES, NONCEBYTES, MACBYTES, MACBYTES_LONG, RATE, ALIGNMENT

- random_key() -> bytearray (length KEYBYTES)
- random_nonce() -> bytearray (length NONCEBYTES)
- nonce_increment(nonce)
- wipe(buffer)

### Exceptions

- Authentication failures raise ValueError.
- Invalid sizes/types raise TypeError.
- Unexpected errors from libaegis raise RuntimeError.


## Examples

### Authentication only

A cryptographically secure keyed hash is produced. The example uses all zeroes for the nonce to always produce the same hash for the same key:
```python
from pyaegis import aegis256x4 as ciph
key, nonce = ciph.random_key(), bytes(ciph.NONCEBYTES)

mac = ciph.mac(key, nonce, b"message", maclen=32)
print(mac)

st = ciph.Mac(key, nonce)
st.update(b"message")
st.update(b"Mallory Says Hello!")
st.verify(mac)  # Raises ValueError
```

### Detached mode encryption and decryption

Keeping the ciphertext, mac and ad separate. The ad represents a file header that needs to be tamper proofed.

```python
from pyaegis import aegis256x4 as ciph
key, nonce = ciph.random_key(), ciph.random_nonce()

ct, mac = ciph.encrypt_detached(key, nonce, b"secret", ad=b"header")
pt = ciph.decrypt_detached(key, nonce, ct, mac, ad=b"header")
print(ct, mac, pt)

ciph.wipe(key)  # Zero out sensitive buffers after use (recommended)
ciph.wipe(pt)
```

### Incremental updates

Class-based interface for incremental updates is an alternative to the one-shot functions. Not to be confused with separately verified ciphertext frames (see the next example).

```python
from pyaegis import aegis256x4 as ciph
key, nonce = ciph.random_key(), ciph.random_nonce()

enc = ciph.Encryptor(key, nonce, ad=b"header")
c1 = enc.update(b"chunk1")
c2 = enc.update(b"chunk2")
mac = enc.final(maclen=16)

dec = ciph.Decryptor(key, nonce, ad=b"header")
p1 = dec.update(c1)
p2 = dec.update(c2)
dec.final(mac)               # raises ValueError on failure
```

### Large data AEAD encryption/decryption

It is often practical to split larger messages into frames that can be individually decrypted and verified. Because every frame needs a different key, we employ the `nonce_increment` utility function to produce sequential nonces for each frame. As for the AEGIS algorithm, each frame is a completely independent invocation. The program will each time produce a completely different random-looking encrypted.bin file.

```python
from pyaegis import aegis128x4 as ciph

message = bytearray(30 * b"Attack at dawn! ")
key = b"sixteenbyte key!"  # 16 bytes secret key for aegis128* algorithms
nonce = ciph.random_nonce()
framebytes = 80  # In real applications 1 MiB or more is practical
maclen = ciph.MACBYTES  # 16

with open("encrypted.bin", "wb") as f:
    f.write(nonce)  # Public initial nonce sent with the ciphertext
    while message:
        chunk = message[:framebytes - maclen]
        del message[:len(chunk)]
        ct = ciph.encrypt(key, nonce, chunk, maclen=maclen)
        ciph.nonce_increment(nonce)
        f.write(ct)
```

```python
from pyaegis import aegis128x4 as ciph

# Decryption needs same values as encryption
key = b"sixteenbyte key!"
framebytes = 80
maclen = ciph.MACBYTES

with open("encrypted.bin", "rb") as f:
    nonce = bytearray(f.read(ciph.NONCEBYTES))
    while True:
        frame = f.read(framebytes)
        if not frame:
            break
        pt = ciph.decrypt(key, nonce, frame, maclen=maclen)
        ciph.nonce_increment(nonce)
        print(pt)
```

### Preallocated output buffers (into=)

For advanced use cases, the output buffer can be supplied with `into` kwarg. Any type of writable buffer with len() >= space required can be used. This includes bytearrays, memoryviews, mmap files, numpy.getbuffer etc.

A `TypeError` is raised if the buffer is too small. For convenience, the functions return a memoryview showing only the bytes actually written.

In-place operations are supported when the input and the output point to the same location in memory. When using attached MAC tag, the input buffer needs to be sliced to correct length:

```python
from pyaegis import aegis256x4 as ciph
key, nonce = ciph.random_key(), ciph.random_nonce()
buf = memoryview(bytearray(1000))  # memoryview[:len] is still in the same buffer (no copy)
buf[:7] = b"message"

# Each function returns a memoryview capped to correct length
ct = ciph.encrypt(key, nonce, buf[:7], into=buf)
pt = ciph.decrypt(key, nonce, ct, into=buf)

print(bytes(pt))
```

Detached and unauthenticated modes can use same size input and output (no MAC added to ciphertext). Detached encryption instead of `into` takes `ct_into` and `mac_into` separately and returns memoryviews to both.

## Performance

Runtime CPU feature detection selects optimized code paths (AES-NI, ARM Crypto, AVX2/AVX-512). Multi-lane variants (x2/x4) offer higher throughput on suitable CPUs.

Run the built-in benchmark to see which variant is fastest on your machine:

```fish
uv run -m pyaegis.benchmark
```

Benchmarks of the Python module and the C library run on Intel i7-14700, linux, single core (the software is not multithreaded). Note that the results are in megabits per second, not bytes. The CPU lacks AVX-512 that makes the X4 variants faster on AMD hardware.

```fish
$ python -m pyaegis.benchmark
AEGIS-256        107666.56 Mb/s
AEGIS-256X2      191314.53 Mb/s
AEGIS-256X4      211537.44 Mb/s
AEGIS-128L       159074.08 Mb/s
AEGIS-128X2      307332.53 Mb/s
AEGIS-128X4      230106.70 Mb/s
AEGIS-128L MAC   206082.24 Mb/s
AEGIS-128X2 MAC  366401.20 Mb/s
AEGIS-128X4 MAC  375011.51 Mb/s
AEGIS-256 MAC    110187.03 Mb/s
AEGIS-256X2 MAC  210063.51 Mb/s
AEGIS-256X4 MAC  347406.96 Mb/s
```

The Python library performance is similar to that of the C library:
```fish
$ ./libaegis/zig-out/bin/benchmark
AEGIS-256        107820.86 Mb/s
AEGIS-256X2      205025.57 Mb/s
AEGIS-256X4      223361.81 Mb/s
AEGIS-128L       187530.77 Mb/s
AEGIS-128X2      354003.14 Mb/s
AEGIS-128X4      218596.59 Mb/s
AEGIS-128L MAC   224276.49 Mb/s
AEGIS-128X2 MAC  417741.65 Mb/s
AEGIS-128X4 MAC  410454.05 Mb/s
AEGIS-256 MAC    116776.62 Mb/s
AEGIS-256X2 MAC  224150.04 Mb/s
AEGIS-256X4 MAC  392088.05 Mb/s
```
