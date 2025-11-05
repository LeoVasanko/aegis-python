"""Dynamic loader for libaegis using CFFI (ABI mode).

This module avoids compiling any C shim. It loads the shared library built by
the project (e.g., build-shared/libaegis.so) or a system-installed libaegis.

Environment variables:
- AEGIS_LIB_PATH: full path to the libaegis shared library to load
- AEGIS_LIB_DIR: directory containing the shared library (libaegis.so)

Exports:
- ffi: a cffi.FFI instance with the libaegis API declared
- lib: the loaded libaegis shared library (ffi.dlopen)
- libc: the C runtime (for posix_memalign/free on POSIX)
- alloc_aligned(size, alignment): return (void*) pointer with requested alignment
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Iterable

from cffi import FFI

try:
    # ctypes is only used to resolve libc reliably across platforms
    import ctypes.util as _ctypes_util  # type: ignore
except Exception:  # pragma: no cover - very unlikely to happen
    _ctypes_util = None  # type: ignore[assignment]


ffi = FFI()

# Public API from headers (aegis.h and all aegis variant headers). Keep it macro-free.
ffi.cdef(
    r"""
    typedef unsigned char uint8_t;
    typedef unsigned long size_t;

    /* aegis.h */
    int aegis_init(void);
    int aegis_verify_16(const uint8_t *x, const uint8_t *y);
    int aegis_verify_32(const uint8_t *x, const uint8_t *y);

    /* aegis128l.h */
    typedef struct {
        /* CRYPTO_ALIGN(32) */ uint8_t opaque[256];
    } aegis128l_state;

    typedef struct {
        /* CRYPTO_ALIGN(32) */ uint8_t opaque[384];
    } aegis128l_mac_state;

    size_t aegis128l_keybytes(void);
    size_t aegis128l_npubbytes(void);
    size_t aegis128l_abytes_min(void);
    size_t aegis128l_abytes_max(void);
    size_t aegis128l_tailbytes_max(void);

    int aegis128l_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                                   size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                   const uint8_t *k);

    int aegis128l_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                                   size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                   const uint8_t *k);

    int aegis128l_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                          size_t adlen, const uint8_t *npub, const uint8_t *k);

    int aegis128l_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                          size_t adlen, const uint8_t *npub, const uint8_t *k);

    void aegis128l_state_init(aegis128l_state *st_, const uint8_t *ad, size_t adlen,
                              const uint8_t *npub, const uint8_t *k);

    int aegis128l_state_encrypt_update(aegis128l_state *st_, uint8_t *c, size_t clen_max,
                                       size_t *written, const uint8_t *m, size_t mlen);

    int aegis128l_state_encrypt_detached_final(aegis128l_state *st_, uint8_t *c, size_t clen_max,
                                               size_t *written, uint8_t *mac, size_t maclen);

    int aegis128l_state_encrypt_final(aegis128l_state *st_, uint8_t *c, size_t clen_max,
                                      size_t *written, size_t maclen);

    int aegis128l_state_decrypt_detached_update(aegis128l_state *st_, uint8_t *m, size_t mlen_max,
                                                size_t *written, const uint8_t *c, size_t clen);

    int aegis128l_state_decrypt_detached_final(aegis128l_state *st_, uint8_t *m, size_t mlen_max,
                                               size_t *written, const uint8_t *mac, size_t maclen);

    void aegis128l_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);
    void aegis128l_encrypt_unauthenticated(uint8_t *c, const uint8_t *m, size_t mlen,
                                           const uint8_t *npub, const uint8_t *k);
    void aegis128l_decrypt_unauthenticated(uint8_t *m, const uint8_t *c, size_t clen,
                                           const uint8_t *npub, const uint8_t *k);

    void aegis128l_mac_init(aegis128l_mac_state *st_, const uint8_t *k, const uint8_t *npub);
    int aegis128l_mac_update(aegis128l_mac_state *st_, const uint8_t *m, size_t mlen);
    int aegis128l_mac_final(aegis128l_mac_state *st_, uint8_t *mac, size_t maclen);
    int aegis128l_mac_verify(aegis128l_mac_state *st_, const uint8_t *mac, size_t maclen);
    void aegis128l_mac_reset(aegis128l_mac_state *st_);
    void aegis128l_mac_state_clone(aegis128l_mac_state *dst, const aegis128l_mac_state *src);

    /* aegis128x2.h */
    typedef struct {
        /* CRYPTO_ALIGN(64) */ uint8_t opaque[448];
    } aegis128x2_state;

    typedef struct {
        /* CRYPTO_ALIGN(64) */ uint8_t opaque[704];
    } aegis128x2_mac_state;

    size_t aegis128x2_keybytes(void);
    size_t aegis128x2_npubbytes(void);
    size_t aegis128x2_abytes_min(void);
    size_t aegis128x2_abytes_max(void);
    size_t aegis128x2_tailbytes_max(void);

    int aegis128x2_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                                    size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                    const uint8_t *k);

    int aegis128x2_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                                    size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                    const uint8_t *k);

    int aegis128x2_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                           size_t adlen, const uint8_t *npub, const uint8_t *k);

    int aegis128x2_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                           size_t adlen, const uint8_t *npub, const uint8_t *k);

    void aegis128x2_state_init(aegis128x2_state *st_, const uint8_t *ad, size_t adlen,
                               const uint8_t *npub, const uint8_t *k);

    int aegis128x2_state_encrypt_update(aegis128x2_state *st_, uint8_t *c, size_t clen_max,
                                        size_t *written, const uint8_t *m, size_t mlen);

    int aegis128x2_state_encrypt_detached_final(aegis128x2_state *st_, uint8_t *c, size_t clen_max,
                                                size_t *written, uint8_t *mac, size_t maclen);

    int aegis128x2_state_encrypt_final(aegis128x2_state *st_, uint8_t *c, size_t clen_max,
                                       size_t *written, size_t maclen);

    int aegis128x2_state_decrypt_detached_update(aegis128x2_state *st_, uint8_t *m, size_t mlen_max,
                                                 size_t *written, const uint8_t *c, size_t clen);

    int aegis128x2_state_decrypt_detached_final(aegis128x2_state *st_, uint8_t *m, size_t mlen_max,
                                                size_t *written, const uint8_t *mac, size_t maclen);

    void aegis128x2_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);
    void aegis128x2_encrypt_unauthenticated(uint8_t *c, const uint8_t *m, size_t mlen,
                                            const uint8_t *npub, const uint8_t *k);
    void aegis128x2_decrypt_unauthenticated(uint8_t *m, const uint8_t *c, size_t clen,
                                            const uint8_t *npub, const uint8_t *k);

    void aegis128x2_mac_init(aegis128x2_mac_state *st_, const uint8_t *k, const uint8_t *npub);
    int aegis128x2_mac_update(aegis128x2_mac_state *st_, const uint8_t *m, size_t mlen);
    int aegis128x2_mac_final(aegis128x2_mac_state *st_, uint8_t *mac, size_t maclen);
    int aegis128x2_mac_verify(aegis128x2_mac_state *st_, const uint8_t *mac, size_t maclen);
    void aegis128x2_mac_reset(aegis128x2_mac_state *st_);
    void aegis128x2_mac_state_clone(aegis128x2_mac_state *dst, const aegis128x2_mac_state *src);

    /* aegis128x4.h */
    typedef struct {
        /* CRYPTO_ALIGN(64) */ uint8_t opaque[832];
    } aegis128x4_state;

    typedef struct {
        /* CRYPTO_ALIGN(64) */ uint8_t opaque[1344];
    } aegis128x4_mac_state;

    size_t aegis128x4_keybytes(void);
    size_t aegis128x4_npubbytes(void);
    size_t aegis128x4_abytes_min(void);
    size_t aegis128x4_abytes_max(void);
    size_t aegis128x4_tailbytes_max(void);

    int aegis128x4_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                                    size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                    const uint8_t *k);

    int aegis128x4_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                                    size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                    const uint8_t *k);

    int aegis128x4_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                           size_t adlen, const uint8_t *npub, const uint8_t *k);

    int aegis128x4_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                           size_t adlen, const uint8_t *npub, const uint8_t *k);

    void aegis128x4_state_init(aegis128x4_state *st_, const uint8_t *ad, size_t adlen,
                               const uint8_t *npub, const uint8_t *k);

    int aegis128x4_state_encrypt_update(aegis128x4_state *st_, uint8_t *c, size_t clen_max,
                                        size_t *written, const uint8_t *m, size_t mlen);

    int aegis128x4_state_encrypt_detached_final(aegis128x4_state *st_, uint8_t *c, size_t clen_max,
                                                size_t *written, uint8_t *mac, size_t maclen);

    int aegis128x4_state_encrypt_final(aegis128x4_state *st_, uint8_t *c, size_t clen_max,
                                       size_t *written, size_t maclen);

    int aegis128x4_state_decrypt_detached_update(aegis128x4_state *st_, uint8_t *m, size_t mlen_max,
                                                 size_t *written, const uint8_t *c, size_t clen);

    int aegis128x4_state_decrypt_detached_final(aegis128x4_state *st_, uint8_t *m, size_t mlen_max,
                                                size_t *written, const uint8_t *mac, size_t maclen);

    void aegis128x4_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);
    void aegis128x4_encrypt_unauthenticated(uint8_t *c, const uint8_t *m, size_t mlen,
                                            const uint8_t *npub, const uint8_t *k);
    void aegis128x4_decrypt_unauthenticated(uint8_t *m, const uint8_t *c, size_t clen,
                                            const uint8_t *npub, const uint8_t *k);

    void aegis128x4_mac_init(aegis128x4_mac_state *st_, const uint8_t *k, const uint8_t *npub);
    int aegis128x4_mac_update(aegis128x4_mac_state *st_, const uint8_t *m, size_t mlen);
    int aegis128x4_mac_final(aegis128x4_mac_state *st_, uint8_t *mac, size_t maclen);
    int aegis128x4_mac_verify(aegis128x4_mac_state *st_, const uint8_t *mac, size_t maclen);
    void aegis128x4_mac_reset(aegis128x4_mac_state *st_);
    void aegis128x4_mac_state_clone(aegis128x4_mac_state *dst, const aegis128x4_mac_state *src);

    /* aegis256.h */
    typedef struct {
        /* CRYPTO_ALIGN(16) */ uint8_t opaque[192];
    } aegis256_state;

    typedef struct {
        /* CRYPTO_ALIGN(16) */ uint8_t opaque[288];
    } aegis256_mac_state;

    size_t aegis256_keybytes(void);
    size_t aegis256_npubbytes(void);
    size_t aegis256_abytes_min(void);
    size_t aegis256_abytes_max(void);
    size_t aegis256_tailbytes_max(void);

    int aegis256_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                                  size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                  const uint8_t *k);

    int aegis256_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                                  size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                  const uint8_t *k);

    int aegis256_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                         size_t adlen, const uint8_t *npub, const uint8_t *k);

    int aegis256_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                         size_t adlen, const uint8_t *npub, const uint8_t *k);

    void aegis256_state_init(aegis256_state *st_, const uint8_t *ad, size_t adlen,
                             const uint8_t *npub, const uint8_t *k);

    int aegis256_state_encrypt_update(aegis256_state *st_, uint8_t *c, size_t clen_max,
                                      size_t *written, const uint8_t *m, size_t mlen);

    int aegis256_state_encrypt_detached_final(aegis256_state *st_, uint8_t *c, size_t clen_max,
                                              size_t *written, uint8_t *mac, size_t maclen);

    int aegis256_state_encrypt_final(aegis256_state *st_, uint8_t *c, size_t clen_max,
                                     size_t *written, size_t maclen);

    int aegis256_state_decrypt_detached_update(aegis256_state *st_, uint8_t *m, size_t mlen_max,
                                               size_t *written, const uint8_t *c, size_t clen);

    int aegis256_state_decrypt_detached_final(aegis256_state *st_, uint8_t *m, size_t mlen_max,
                                              size_t *written, const uint8_t *mac, size_t maclen);

    void aegis256_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);
    void aegis256_encrypt_unauthenticated(uint8_t *c, const uint8_t *m, size_t mlen,
                                          const uint8_t *npub, const uint8_t *k);
    void aegis256_decrypt_unauthenticated(uint8_t *m, const uint8_t *c, size_t clen,
                                          const uint8_t *npub, const uint8_t *k);

    void aegis256_mac_init(aegis256_mac_state *st_, const uint8_t *k, const uint8_t *npub);
    int aegis256_mac_update(aegis256_mac_state *st_, const uint8_t *m, size_t mlen);
    int aegis256_mac_final(aegis256_mac_state *st_, uint8_t *mac, size_t maclen);
    int aegis256_mac_verify(aegis256_mac_state *st_, const uint8_t *mac, size_t maclen);
    void aegis256_mac_reset(aegis256_mac_state *st_);
    void aegis256_mac_state_clone(aegis256_mac_state *dst, const aegis256_mac_state *src);

    /* aegis256x2.h */
    typedef struct {
        /* CRYPTO_ALIGN(32) */ uint8_t opaque[320];
    } aegis256x2_state;

    typedef struct {
        /* CRYPTO_ALIGN(32) */ uint8_t opaque[512];
    } aegis256x2_mac_state;

    size_t aegis256x2_keybytes(void);
    size_t aegis256x2_npubbytes(void);
    size_t aegis256x2_abytes_min(void);
    size_t aegis256x2_abytes_max(void);
    size_t aegis256x2_tailbytes_max(void);

    int aegis256x2_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                                    size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                    const uint8_t *k);

    int aegis256x2_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                                    size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                    const uint8_t *k);

    int aegis256x2_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                           size_t adlen, const uint8_t *npub, const uint8_t *k);

    int aegis256x2_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                           size_t adlen, const uint8_t *npub, const uint8_t *k);

    void aegis256x2_state_init(aegis256x2_state *st_, const uint8_t *ad, size_t adlen,
                               const uint8_t *npub, const uint8_t *k);

    int aegis256x2_state_encrypt_update(aegis256x2_state *st_, uint8_t *c, size_t clen_max,
                                        size_t *written, const uint8_t *m, size_t mlen);

    int aegis256x2_state_encrypt_detached_final(aegis256x2_state *st_, uint8_t *c, size_t clen_max,
                                                size_t *written, uint8_t *mac, size_t maclen);

    int aegis256x2_state_encrypt_final(aegis256x2_state *st_, uint8_t *c, size_t clen_max,
                                       size_t *written, size_t maclen);

    int aegis256x2_state_decrypt_detached_update(aegis256x2_state *st_, uint8_t *m, size_t mlen_max,
                                                 size_t *written, const uint8_t *c, size_t clen);

    int aegis256x2_state_decrypt_detached_final(aegis256x2_state *st_, uint8_t *m, size_t mlen_max,
                                                size_t *written, const uint8_t *mac, size_t maclen);

    void aegis256x2_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);
    void aegis256x2_encrypt_unauthenticated(uint8_t *c, const uint8_t *m, size_t mlen,
                                            const uint8_t *npub, const uint8_t *k);
    void aegis256x2_decrypt_unauthenticated(uint8_t *m, const uint8_t *c, size_t clen,
                                            const uint8_t *npub, const uint8_t *k);

    void aegis256x2_mac_init(aegis256x2_mac_state *st_, const uint8_t *k, const uint8_t *npub);
    int aegis256x2_mac_update(aegis256x2_mac_state *st_, const uint8_t *m, size_t mlen);
    int aegis256x2_mac_final(aegis256x2_mac_state *st_, uint8_t *mac, size_t maclen);
    int aegis256x2_mac_verify(aegis256x2_mac_state *st_, const uint8_t *mac, size_t maclen);
    void aegis256x2_mac_reset(aegis256x2_mac_state *st_);
    void aegis256x2_mac_state_clone(aegis256x2_mac_state *dst, const aegis256x2_mac_state *src);

    /* aegis256x4.h */
    typedef struct {
        /* CRYPTO_ALIGN(64) */ uint8_t opaque[576];
    } aegis256x4_state;

    typedef struct {
        /* CRYPTO_ALIGN(64) */ uint8_t opaque[960];
    } aegis256x4_mac_state;

    size_t aegis256x4_keybytes(void);
    size_t aegis256x4_npubbytes(void);
    size_t aegis256x4_abytes_min(void);
    size_t aegis256x4_abytes_max(void);
    size_t aegis256x4_tailbytes_max(void);

    int aegis256x4_encrypt_detached(uint8_t *c, uint8_t *mac, size_t maclen, const uint8_t *m,
                                    size_t mlen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                    const uint8_t *k);

    int aegis256x4_decrypt_detached(uint8_t *m, const uint8_t *c, size_t clen, const uint8_t *mac,
                                    size_t maclen, const uint8_t *ad, size_t adlen, const uint8_t *npub,
                                    const uint8_t *k);

    int aegis256x4_encrypt(uint8_t *c, size_t maclen, const uint8_t *m, size_t mlen, const uint8_t *ad,
                           size_t adlen, const uint8_t *npub, const uint8_t *k);

    int aegis256x4_decrypt(uint8_t *m, const uint8_t *c, size_t clen, size_t maclen, const uint8_t *ad,
                           size_t adlen, const uint8_t *npub, const uint8_t *k);

    void aegis256x4_state_init(aegis256x4_state *st_, const uint8_t *ad, size_t adlen,
                               const uint8_t *npub, const uint8_t *k);

    int aegis256x4_state_encrypt_update(aegis256x4_state *st_, uint8_t *c, size_t clen_max,
                                        size_t *written, const uint8_t *m, size_t mlen);

    int aegis256x4_state_encrypt_detached_final(aegis256x4_state *st_, uint8_t *c, size_t clen_max,
                                                size_t *written, uint8_t *mac, size_t maclen);

    int aegis256x4_state_encrypt_final(aegis256x4_state *st_, uint8_t *c, size_t clen_max,
                                       size_t *written, size_t maclen);

    int aegis256x4_state_decrypt_detached_update(aegis256x4_state *st_, uint8_t *m, size_t mlen_max,
                                                 size_t *written, const uint8_t *c, size_t clen);

    int aegis256x4_state_decrypt_detached_final(aegis256x4_state *st_, uint8_t *m, size_t mlen_max,
                                                size_t *written, const uint8_t *mac, size_t maclen);

    void aegis256x4_stream(uint8_t *out, size_t len, const uint8_t *npub, const uint8_t *k);
    void aegis256x4_encrypt_unauthenticated(uint8_t *c, const uint8_t *m, size_t mlen,
                                            const uint8_t *npub, const uint8_t *k);
    void aegis256x4_decrypt_unauthenticated(uint8_t *m, const uint8_t *c, size_t clen,
                                            const uint8_t *npub, const uint8_t *k);

    void aegis256x4_mac_init(aegis256x4_mac_state *st_, const uint8_t *k, const uint8_t *npub);
    int aegis256x4_mac_update(aegis256x4_mac_state *st_, const uint8_t *m, size_t mlen);
    int aegis256x4_mac_final(aegis256x4_mac_state *st_, uint8_t *mac, size_t maclen);
    int aegis256x4_mac_verify(aegis256x4_mac_state *st_, const uint8_t *mac, size_t maclen);
    void aegis256x4_mac_reset(aegis256x4_mac_state *st_);
    void aegis256x4_mac_state_clone(aegis256x4_mac_state *dst, const aegis256x4_mac_state *src);

    /* libc bits for aligned allocation on POSIX */
    int posix_memalign(void **memptr, size_t alignment, size_t size);
    void free(void *ptr);
    """
)


def _candidate_paths() -> Iterable[str]:
    # 1) Explicit override
    p = os.environ.get("AEGIS_LIB_PATH")
    if p:
        yield p

    # 2) Directory override
    d = os.environ.get("AEGIS_LIB_DIR")
    if d:
        yield str(Path(d) / _platform_lib_name())

    # 3) Local builds relative to this file
    here = Path(__file__).resolve()
    repo_root = here.parents[2]  # python/aegis/_loader.py -> repo root
    for rel in (
        "build-shared-clang/libaegis.so",
        "build-shared/libaegis.so",
        "build/libaegis.so",
        "zig-out/lib/libaegis.so",
    ):
        path = repo_root / rel
        if path.exists():
            yield str(path)

    # 4) Let the dynamic loader search system paths
    yield _platform_lib_name()  # e.g. "libaegis.so" or "aegis"


def _platform_lib_name() -> str:
    if sys.platform.startswith("linux"):
        return "libaegis.so"
    if sys.platform == "darwin":
        return "libaegis.dylib"
    if os.name == "nt":
        return "aegis.dll"
    return "libaegis.so"


def _load_libaegis():
    last_err: Exception | None = None
    for cand in _candidate_paths():
        try:
            lib = ffi.dlopen(str(cand))
            return lib
        except Exception as e:  # try next candidate
            last_err = e
            continue
    # If we get here, we couldn't load the library
    hint = (
        "Set AEGIS_LIB_PATH to the full path of libaegis or AEGIS_LIB_DIR to the folder "
        "containing it, or install libaegis system-wide."
    )
    raise OSError(f"Could not load libaegis: {last_err}\n{hint}")


def _load_libc():
    # Use ctypes.util to find a usable libc name; fallback to None-dlopen on POSIX
    if _ctypes_util is not None:
        libc_name = _ctypes_util.find_library("c")  # type: ignore[attr-defined]
        if libc_name:
            try:
                return ffi.dlopen(libc_name)
            except Exception:
                pass
    # Fallback: try process globals (works on many Unix platforms)
    try:
        return ffi.dlopen(None)
    except Exception as e:
        raise OSError(f"Unable to load libc for aligned allocation: {e}")


lib: Any = _load_libaegis()
libc: Any = _load_libc()

# Initialize CPU feature selection (recommended by the library)
try:
    lib.aegis_init()
except Exception:
    # Non-fatal; functions will still work, maybe slower
    pass


def alloc_aligned(size: int, alignment: int = 64):
    """Allocate aligned memory via posix_memalign(); returns a void* cdata.

    The returned pointer must be freed with libc.free(). Attach a GC finalizer
    at call sites using ffi.gc(ptr, libc.free) after casting to the target type.
    """
    memptr = ffi.new("void **")
    rc = libc.posix_memalign(memptr, alignment, size)
    if rc != 0 or memptr[0] == ffi.NULL:
        raise MemoryError(f"posix_memalign({alignment}, {size}) failed with rc={rc}")
    return memptr[0]
