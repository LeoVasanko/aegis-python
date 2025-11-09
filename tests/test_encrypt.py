import json
from pathlib import Path

import pytest

from pyaegis import aegis128l, aegis128x2, aegis128x4, aegis256, aegis256x2, aegis256x4

from .util import random_split_bytes


def load_encryption_test_vectors():
    """Load encryption test vectors from all algorithm-specific JSON files."""
    test_vectors_path = Path(__file__).parent / "test-vectors"
    vectors = []

    # Map filename to algorithm module
    algorithm_files = {
        "aegis-128l-test-vectors.json": aegis128l,
        "aegis-128x2-test-vectors.json": aegis128x2,
        "aegis-128x4-test-vectors.json": aegis128x4,
        "aegis-256-test-vectors.json": aegis256,
        "aegis-256x2-test-vectors.json": aegis256x2,
        "aegis-256x4-test-vectors.json": aegis256x4,
    }

    for filename, alg_module in algorithm_files.items():
        filepath = test_vectors_path / filename
        with open(filepath, "r") as f:
            file_vectors = json.load(f)
            # Filter and add algorithm info to testable vectors
            for vector in file_vectors:
                # Only include vectors that can be tested via the Python API
                if (
                    "key" in vector
                    and "nonce" in vector
                    and ("msg" in vector or "error" in vector)
                ):
                    vector["_algorithm"] = alg_module
                    vectors.append(vector)

    return vectors


def get_encryption_test_id(vector):
    """Generate a test ID from the vector name and algorithm."""
    alg_name = vector["_algorithm"].__name__.split(".")[
        -1
    ]  # e.g., "aegis256" -> "aegis256"
    vector_name = vector.get("name", "Unknown")
    return f"{alg_name}-{vector_name}"


@pytest.mark.parametrize(
    "vector", load_encryption_test_vectors(), ids=get_encryption_test_id
)
def test_encrypt_decrypt(vector):
    """Test encryption and decryption against test vectors."""
    alg = vector["_algorithm"]

    key = bytes.fromhex(vector["key"])
    nonce = bytes.fromhex(vector["nonce"])
    ad = bytes.fromhex(vector.get("ad", ""))

    if "msg" in vector:
        # Test encryption/decryption with valid message
        msg = bytes.fromhex(vector["msg"])

        # Test 128-bit MAC if present
        if "tag128" in vector:
            expected_tag128 = bytes.fromhex(vector["tag128"])
            ct, mac = alg.encrypt_detached(key, nonce, msg, ad, maclen=16)

            # Verify MAC
            assert bytes(mac) == expected_tag128, (
                f"128-bit MAC mismatch for {vector['name']}"
            )

            # Verify ciphertext if present
            if "ct" in vector:
                expected_ct = bytes.fromhex(vector["ct"])
                assert bytes(ct) == expected_ct, (
                    f"Ciphertext mismatch for {vector['name']}"
                )

            # Test successful decryption
            decrypted = alg.decrypt_detached(key, nonce, ct, expected_tag128, ad)
            assert bytes(decrypted) == msg, (
                f"Decryption failed for 128-bit MAC in {vector['name']}"
            )

        # Test 256-bit MAC if present
        if "tag256" in vector:
            expected_tag256 = bytes.fromhex(vector["tag256"])
            ct, mac = alg.encrypt_detached(key, nonce, msg, ad, maclen=32)

            # Verify MAC
            assert bytes(mac) == expected_tag256, (
                f"256-bit MAC mismatch for {vector['name']}"
            )

            # Verify ciphertext if present
            if "ct" in vector:
                expected_ct = bytes.fromhex(vector["ct"])
                assert bytes(ct) == expected_ct, (
                    f"Ciphertext mismatch for {vector['name']}"
                )

            # Test successful decryption
            decrypted = alg.decrypt_detached(key, nonce, ct, expected_tag256, ad)
            assert bytes(decrypted) == msg, (
                f"Decryption failed for 256-bit MAC in {vector['name']}"
            )

    elif "error" in vector:
        # Test decryption failure cases
        ct = bytes.fromhex(vector["ct"])

        # Test that decryption fails with the provided (invalid) MACs
        if "tag128" in vector:
            invalid_mac = bytes.fromhex(vector["tag128"])
            with pytest.raises(ValueError, match="authentication failed"):
                alg.decrypt_detached(key, nonce, ct, invalid_mac, ad)

        if "tag256" in vector:
            invalid_mac = bytes.fromhex(vector["tag256"])
            with pytest.raises(ValueError, match="authentication failed"):
                alg.decrypt_detached(key, nonce, ct, invalid_mac, ad)


@pytest.mark.parametrize(
    "vector", load_encryption_test_vectors(), ids=get_encryption_test_id
)
def test_encrypt_decrypt_incremental(vector):
    """Test incremental encryption and decryption using Encryptor/Decryptor classes."""
    alg = vector["_algorithm"]

    key = bytes.fromhex(vector["key"])
    nonce = bytes.fromhex(vector["nonce"])
    ad = bytes.fromhex(vector.get("ad", ""))

    if "msg" in vector:
        # Test incremental encryption/decryption with valid message
        msg = bytes.fromhex(vector["msg"])

        # Test 128-bit MAC if present
        if "tag128" in vector:
            expected_tag128 = bytes.fromhex(vector["tag128"])

            # Incremental encryption with random chunking
            encryptor = alg.Encryptor(key, nonce, ad, maclen=16)
            ct_chunks = []
            for chunk in random_split_bytes(msg):
                ct_result = encryptor.update(chunk)
                ct_chunks.append(bytes(ct_result))
            computed_mac = bytes(encryptor.final())

            # Combine ciphertext chunks
            computed_ct = b"".join(ct_chunks)

            # Verify against expected values
            assert bytes(computed_mac) == expected_tag128, (
                f"128-bit MAC mismatch for {vector['name']}"
            )
            if "ct" in vector:
                expected_ct = bytes.fromhex(vector["ct"])
                assert computed_ct == expected_ct, (
                    f"Ciphertext mismatch for {vector['name']}"
                )

            # Incremental decryption with different random chunking
            decryptor = alg.Decryptor(key, nonce, ad, maclen=16)
            pt_chunks = []
            for chunk in random_split_bytes(computed_ct):
                pt_chunks.append(bytes(decryptor.update(chunk)))
            decryptor.final(expected_tag128)

            # Combine plaintext chunks
            computed_pt = b"".join(pt_chunks)
            assert computed_pt == msg, (
                f"Decryption failed for 128-bit MAC in {vector['name']}"
            )

        # Test 256-bit MAC if present
        if "tag256" in vector:
            expected_tag256 = bytes.fromhex(vector["tag256"])

            # Incremental encryption with random chunking
            encryptor = alg.Encryptor(key, nonce, ad, maclen=32)
            ct_chunks = []
            for chunk in random_split_bytes(msg):
                ct_result = encryptor.update(chunk)
                ct_chunks.append(bytes(ct_result))
            computed_mac = bytes(encryptor.final())

            # Combine ciphertext chunks
            computed_ct = b"".join(ct_chunks)

            # Verify against expected values
            assert bytes(computed_mac) == expected_tag256, (
                f"256-bit MAC mismatch for {vector['name']}"
            )
            if "ct" in vector:
                expected_ct = bytes.fromhex(vector["ct"])
                assert computed_ct == expected_ct, (
                    f"Ciphertext mismatch for {vector['name']}"
                )

            # Incremental decryption with different random chunking
            decryptor = alg.Decryptor(key, nonce, ad, maclen=32)
            pt_chunks = []
            for chunk in random_split_bytes(computed_ct):
                pt_chunks.append(bytes(decryptor.update(chunk)))
            decryptor.final(expected_tag256)

            # Combine plaintext chunks
            computed_pt = b"".join(pt_chunks)
            assert computed_pt == msg, (
                f"Decryption failed for 256-bit MAC in {vector['name']}"
            )

    elif "error" in vector:
        # Test decryption failure cases with incremental API
        ct = bytes.fromhex(vector["ct"])

        # Test that incremental decryption fails with the provided (invalid) MACs
        if "tag128" in vector:
            invalid_mac = bytes.fromhex(vector["tag128"])
            decryptor = alg.Decryptor(key, nonce, ad, maclen=16)
            decryptor.update(ct)  # This should succeed
            with pytest.raises(ValueError, match="authentication failed"):
                decryptor.final(invalid_mac)

        if "tag256" in vector:
            invalid_mac = bytes.fromhex(vector["tag256"])
            decryptor = alg.Decryptor(key, nonce, ad, maclen=32)
            decryptor.update(ct)  # This should succeed
            with pytest.raises(ValueError, match="authentication failed"):
                decryptor.final(invalid_mac)
