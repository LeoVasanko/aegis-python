import json
from pathlib import Path

import pytest

from pyaegis import aegis128l, aegis128x2, aegis128x4, aegis256, aegis256x2, aegis256x4

from .util import random_split_bytes


def load_mac_test_vectors():
    """Load MAC test vectors from JSON file."""
    test_vectors_path = (
        Path(__file__).parent / "test-vectors" / "aegismac-test-vectors.json"
    )
    with open(test_vectors_path, "r") as f:
        return json.load(f)


def get_algorithm_module(name):
    """Map test vector name to algorithm module."""
    if "128L" in name:
        return aegis128l
    elif "128X2" in name:
        return aegis128x2
    elif "128X4" in name:
        return aegis128x4
    elif "256" in name and "256X2" not in name and "256X4" not in name:
        return aegis256
    elif "256X2" in name:
        return aegis256x2
    elif "256X4" in name:
        return aegis256x4
    else:
        raise ValueError(f"Unknown algorithm in test vector name: {name}")


def get_test_id(vector):
    """Generate a test ID from the vector name."""
    name = vector["name"]
    # Extract algorithm name, e.g., "AEGISMAC-128L Test Vector" -> "128L"
    if "AEGISMAC-" in name:
        return name.split("AEGISMAC-")[1].split(" ")[0]
    return name


@pytest.mark.parametrize("vector", load_mac_test_vectors(), ids=get_test_id)
def test_mac(vector):
    """Test MAC computation against test vectors."""
    alg = get_algorithm_module(vector["name"])

    key = bytes.fromhex(vector["key"])
    nonce = bytes.fromhex(vector["nonce"])
    data = bytes.fromhex(vector["data"])

    # Test 128-bit MAC if present
    if "tag128" in vector:
        expected_tag128 = bytes.fromhex(vector["tag128"])
        computed_tag128 = alg.mac(key, nonce, data, maclen=16)
        assert computed_tag128 == expected_tag128, (
            f"128-bit MAC mismatch for {vector['name']}"
        )

    # Test 256-bit MAC if present
    if "tag256" in vector:
        expected_tag256 = bytes.fromhex(vector["tag256"])
        computed_tag256 = alg.mac(key, nonce, data, maclen=32)
        assert computed_tag256 == expected_tag256, (
            f"256-bit MAC mismatch for {vector['name']}"
        )


@pytest.mark.parametrize("vector", load_mac_test_vectors(), ids=get_test_id)
def test_mac_class(vector):
    """Test MAC computation using the Mac class against test vectors."""
    alg = get_algorithm_module(vector["name"])

    key = bytes.fromhex(vector["key"])
    nonce = bytes.fromhex(vector["nonce"])
    data = bytes.fromhex(vector["data"])

    # Test 128-bit MAC if present
    if "tag128" in vector:
        expected_tag128 = bytes.fromhex(vector["tag128"])
        mac_state = alg.Mac(key, nonce, maclen=16)
        for chunk in random_split_bytes(data):
            mac_state.update(chunk)
        computed_tag128 = mac_state.final()
        assert computed_tag128 == expected_tag128, (
            f"128-bit MAC mismatch for {vector['name']}"
        )

    # Test 256-bit MAC if present
    if "tag256" in vector:
        expected_tag256 = bytes.fromhex(vector["tag256"])
        mac_state = alg.Mac(key, nonce, maclen=32)
        for chunk in random_split_bytes(data):
            mac_state.update(chunk)
        computed_tag256 = mac_state.final()
        assert computed_tag256 == expected_tag256, (
            f"256-bit MAC mismatch for {vector['name']}"
        )
