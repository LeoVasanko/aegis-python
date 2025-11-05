"""Demonstration script for aegis.aegis256x4

Covers:
- encrypt_detached / decrypt_detached
- encrypt / decrypt (attached tag)
- stream_into
- encrypt_unauthenticated_into / decrypt_unauthenticated_into
- MAC (mac_init/update/final/verify)
"""

import time

from aegis import aegis256x4 as a


def hx(b, limit: int | None = None) -> str:
    data = bytes(b)
    if limit is not None:
        data = data[:limit]
    return data.hex()


def demo():
    print("KEYBYTES:", a.KEYBYTES, "NPUBBYTES:", a.NPUBBYTES)

    key = b"K" * a.KEYBYTES
    nonce = b"N" * a.NPUBBYTES
    message = b"hello world"
    associated_data = b"header"

    # Detached encrypt/decrypt
    ciphertext, mac = a.encrypt_detached(
        key, nonce, message, associated_data, maclen=16
    )
    plaintext = a.decrypt_detached(key, nonce, ciphertext, mac, associated_data)
    print(
        "detached enc: c=",
        hx(ciphertext),
        " mac=",
        hx(mac),
        " dec_ok=",
        plaintext == message,
    )

    # Attached encrypt/decrypt
    ciphertext_with_tag = a.encrypt(key, nonce, message, associated_data, maclen=32)
    plaintext2 = a.decrypt(key, nonce, ciphertext_with_tag, associated_data, maclen=32)
    print(
        "attached enc: ct=", hx(ciphertext_with_tag), " dec_ok=", plaintext2 == message
    )

    # Stream generation (None nonce allowed) -> deterministic for a given key
    stream = bytearray(64)
    a.stream(key, None, into=stream)
    print("stream (first 16 bytes):", hx(stream, 16))

    # Unauthenticated mode round-trip (INSECURE; compatibility only)
    c2 = bytearray(len(message))
    a.encrypt_unauthenticated(key, nonce, message, into=c2)
    m2 = bytearray(len(message))
    a.decrypt_unauthenticated(key, nonce, c2, into=m2)
    print("unauth round-trip ok:", bytes(m2) == message)

    # MAC: compute then verify
    mac_state = a.Mac(key, nonce)
    mac_state.update(message)
    mac32 = mac_state.final(32)

    mac_verify_state = a.Mac(key, nonce)
    mac_verify_state.update(message)
    try:
        mac_verify_state.verify(mac32)
        print("mac verify: ok", " mac=", hx(mac32))
    except ValueError:
        print("mac verify: failed")

    # Benchmark: unauthenticated encryption of 1 GiB as a single operation
    total_bytes = 1 << 30  # 1 GiB

    def bench_unauth_single(total: int):
        src = bytearray(total)
        dst = bytearray(total)
        t0 = time.perf_counter()
        a.encrypt_unauthenticated(key, nonce, src, into=dst)
        t1 = time.perf_counter()
        secs = t1 - t0
        gib = total / float(1 << 30)
        gbps = gib / secs if secs > 0 else float("inf")
        print(
            f"unauth 1GiB bench (single call): size={gib:.3f} GiB, time={secs:.3f} s, throughput={gbps:.2f} GiB/s"
        )

    bench_unauth_single(total_bytes)


if __name__ == "__main__":
    demo()
