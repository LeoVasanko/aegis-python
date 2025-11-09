#!/usr/bin/env python3
"""
Python benchmark matching src/test/benchmark.zig for all supported Aegis algorithms.

It performs two benchmarks with the same parameters as the Zig version:
- AEGIS encrypt (attached tag, maclen = MACBYTES)
- AEGIS MAC (clone state pattern)

Output format and throughput units mirror the Zig benchmark (Mb/s).
"""

import os
import time

from pyaegis import aegis128l, aegis128x2, aegis128x4, aegis256, aegis256x2, aegis256x4

MSG_LEN = 16384000  # 16 000 KiB
ITERATIONS = 100


def _random_bytes(n: int) -> bytes:
    return os.urandom(n)


def bench_encrypt(ciph) -> None:
    key = _random_bytes(ciph.KEYBYTES)
    nonce = _random_bytes(ciph.NONCEBYTES)

    # Single buffer, as in Zig: c_out == m buffer, with tag appended
    maclen = ciph.MACBYTES
    buf = bytearray(MSG_LEN + maclen)
    # Initialize buffer with random data
    buf[:] = _random_bytes(len(buf))

    mview = memoryview(buf)[:MSG_LEN]

    t0 = time.perf_counter()
    for _ in range(ITERATIONS):
        ciph.encrypt(key, nonce, mview, None, maclen=maclen, into=buf)
    t1 = time.perf_counter()

    # Prevent any unrealistic optimization assumptions
    _ = buf[0]

    bits = MSG_LEN * ITERATIONS * 8
    elapsed_s = t1 - t0
    throughput_mbps = (
        (bits / (elapsed_s * 1_000_000)) if elapsed_s > 0 else float("inf")
    )
    print(f"{ciph.NAME}\t{throughput_mbps:10.2f} Mb/s")


def bench_mac(ciph) -> None:
    key = _random_bytes(ciph.KEYBYTES)
    nonce = _random_bytes(ciph.NONCEBYTES)

    buf = bytearray(MSG_LEN)
    buf[:] = _random_bytes(len(buf))

    mac0 = ciph.Mac(key, nonce)
    mac_out = bytearray(ciph.MACBYTES_LONG)

    t0 = time.perf_counter()
    for _ in range(ITERATIONS):
        mac = mac0.clone()
        mac.update(buf)
        mac.final(maclen=ciph.MACBYTES_LONG, into=mac_out)
    t1 = time.perf_counter()

    _ = mac_out[0]

    bits = MSG_LEN * ITERATIONS * 8
    elapsed_s = t1 - t0
    throughput_mbps = (
        (bits / (elapsed_s * 1_000_000)) if elapsed_s > 0 else float("inf")
    )
    print(f"{ciph.NAME} MAC\t{throughput_mbps:10.2f} Mb/s")


if __name__ == "__main__":
    # aegis_init() is called in the loader at import time already
    # Run encrypt benchmarks in order: 256, 256x2, 256x4, 128l, 128x2, 128x4
    bench_encrypt(aegis256)
    bench_encrypt(aegis256x2)
    bench_encrypt(aegis256x4)
    bench_encrypt(aegis128l)
    bench_encrypt(aegis128x2)
    bench_encrypt(aegis128x4)

    # Run MAC benchmarks in order: 128l, 128x2, 128x4, 256, 256x2, 256x4
    bench_mac(aegis128l)
    bench_mac(aegis128x2)
    bench_mac(aegis128x4)
    bench_mac(aegis256)
    bench_mac(aegis256x2)
    bench_mac(aegis256x4)
