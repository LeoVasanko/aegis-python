# pyaegis

[![PyPI version](https://badge.fury.io/py/pyaegis.svg)](https://badge.fury.io/py/pyaegis)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/LeoVasanko/pyaegis/blob/main/libaegis/LICENSE)

Python bindings for libaegis - high-performance AEGIS authenticated encryption.

## Overview

pyaegis provides Python bindings to the AEGIS family of authenticated encryption algorithms implemented in the libaegis C library.

AEGIS is a high-performance authenticated cipher that provides both confidentiality and authenticity guarantees.

### Variant selection

The following submodules are available:

- **aegis128l**: 16-byte key, 16-byte nonce
- **aegis256**: 32-byte key, 32-byte nonce
- **aegis128x2**: 16-byte key, 16-byte nonce (recommended on most platforms)
- **aegis128x4**: 16-byte key, 16-byte nonce (recommended on high-end Intel CPUs)
- **aegis256x2**: 32-byte key, 32-byte nonce
- **aegis256x4**: 32-byte key, 32-byte nonce (recommended if a 256-bit nonce is required)

```python
from pyaegis import aegis128x4
```

### One-shot Functions

- `encrypt(key, nonce, message, ad=None, maclen=16)` - Encrypt with attached MAC
- `decrypt(key, nonce, ciphertext, ad=None, maclen=16)` - Decrypt with attached MAC  
- `encrypt_detached(key, nonce, message, ad=None, maclen=16)` - Encrypt with detached MAC
- `decrypt_detached(key, nonce, ciphertext, mac, ad=None, maclen=16)` - Decrypt with detached MAC
- `stream(key, nonce, length)` - Generate pseudo-random bytes
- `encrypt_unauthenticated(key, nonce, message)` - Encrypt without authentication (insecure)
- `decrypt_unauthenticated(key, nonce, ciphertext)` - Decrypt without authentication (insecure)

**Note**: Functions that return buffers (like `encrypt`, `decrypt`, `stream`) return `memoryview` objects. Callers can optionally supply their own buffer via the `into=` keyword argument to avoid memory allocations.

### Incremental Classes

- `Encryptor(key, nonce, ad=None)` - For streaming encryption
- `Decryptor(key, nonce, ad=None)` - For streaming decryption

## Installation

### From PyPI

Using [uv](https://docs.astral.sh/uv/):

```bash
uv pip install pyaegis
```

Or using pip:

```bash
pip install pyaegis
```

### From Source

The package compiles the C library automatically using any installed C compiler:

```bash
# Clone the repository
git clone https://github.com/LeoVasanko/pyaegis.git
cd pyaegis

# Install with uv (compiles C sources automatically)
uv pip install .

# Or for development
uv pip install -e .
```

Alternatively with pip:

```bash
pip install .
# Or for development
pip install -e .
```

### Building a Distribution

```bash
# With uv
uv run python -m build

# Or with pip
python -m build
```

This creates both source and wheel distributions in the `dist/` directory. The C sources are bundled in the package and compiled during installation.

## Usage

All modules (`aegis128l`, `aegis256`, `aegis128x2`, `aegis128x4`, `aegis256x2`, `aegis256x4`) provide the exact same API.

### Basic Encryption/Decryption

```python
import pyaegis.aegis128l as a

key = b"K" * a.KEYBYTES    # 16 bytes for aegis128l
nonce = b"N" * a.NPUBBYTES # 16 bytes for aegis128l
plaintext = b"Hello, World!"

ciphertext = a.encrypt(key, nonce, plaintext)
decrypted = a.decrypt(key, nonce, ciphertext)
assert decrypted == plaintext
```

### With Additional Authenticated Data (AAD)

```python
ciphertext = a.encrypt(key, nonce, plaintext, ad=b"metadata")
plaintext = a.decrypt(key, nonce, ciphertext, ad=b"metadata")
```

### Detached Tag Mode

```python
ciphertext, mac = a.encrypt_detached(key, nonce, b"secret")
plaintext = a.decrypt_detached(key, nonce, ciphertext, mac)
```

### Custom MAC Length

Use 16 or 32-byte MACs (default 16):

```python
ciphertext, mac = a.encrypt_detached(key, nonce, message, maclen=32)
plaintext = a.decrypt_detached(key, nonce, ciphertext, mac, maclen=32)
```

### In-Place Operations

```python
buffer = bytearray(b"secret message")
mac = a.encrypt_unauthenticated_into(key, nonce, buffer)
# buffer now contains ciphertext

a.decrypt_unauthenticated_into(key, nonce, buffer, mac)
# buffer now contains plaintext again
```

### Using Pre-allocated Buffers

```python
# Pre-allocate output buffer
output = bytearray(len(plaintext) + 16)  # +16 for MAC
result = a.encrypt(key, nonce, plaintext, into=output)
# result is a memoryview of the output buffer
```

### Stream Generation

Generate pseudo-random bytes:

```python
random_bytes = a.stream(key, nonce, 1024)
```

### Incremental Encryption

```python
encryptor = a.Encryptor(key, nonce, ad=b"header")
ciphertext1 = encryptor.update(b"chunk1")
ciphertext2 = encryptor.update(b"chunk2") 
final_bytes = encryptor.final()  # includes MAC
```

## Performance

The library automatically detects CPU features at runtime and uses the most optimized implementation available:

- AES-NI on Intel/AMD processors
- ARM Crypto Extensions on ARM processors  
- AVX2 and AVX-512 for multi-lane variants
- Software fallback for other platforms

Multi-lane variants (X2, X4) provide higher throughput on systems with appropriate SIMD support.

See `examples/benchmark.py` for performance measurements.

## Error Handling

Functions that can fail raise `ValueError` with descriptive messages:

```python
import pyaegis.aegis128l as a

key = b"K" * a.KEYBYTES
nonce = b"N" * a.NPUBBYTES

try:
    # This will raise ValueError if authentication fails
    plaintext = a.decrypt(key, nonce, tampered_ciphertext)
except ValueError as e:
    print(f"Decryption failed: {e}")
```

## Performance

The library automatically detects CPU features at runtime and uses the most optimized implementation available:

- AES-NI on Intel/AMD processors
- ARM Crypto Extensions on ARM processors
- AVX2 and AVX-512 for multi-lane variants
- Software fallback for other platforms

Multi-lane variants (X2, X4) provide higher throughput on systems with appropriate SIMD support.

## Security Considerations

- **Nonce Uniqueness**: Never reuse a nonce with the same key. If you can't maintain a counter, generate random nonces for each message.
- **Key Management**: Generate cryptographically secure keys. Keep keys secret.
- **AAD**: Additional authenticated data is not encrypted but is protected against tampering.
- **MAC vs AEAD**: Use AEAD for encryption needs. MAC-only variants are for authentication without confidentiality.
