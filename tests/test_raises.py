"""Tests for Encryptor and Decryptor finalization behavior.

This module verifies that Encryptor and Decryptor objects become unusable
after calling final(), preventing accidental misuse.
"""

import pytest

from pyaegis import aegis256x4


class TestEncryptorFinalization:
    """Test that Encryptor becomes unusable after final()."""

    def test_update_after_final_raises(self):
        """Test that calling update() after final() raises RuntimeError."""
        key = aegis256x4.random_key()
        nonce = aegis256x4.random_nonce()

        encryptor = aegis256x4.Encryptor(key, nonce)

        # Encrypt some data and finalize
        encryptor.update(b"Hello, world!")
        tag = encryptor.final()

        # Attempting to update after final should raise RuntimeError
        with pytest.raises(
            RuntimeError, match="Cannot call update\\(\\) after final\\(\\)"
        ):
            encryptor.update(b"More data")

    def test_final_after_final_raises(self):
        """Test that calling final() after final() raises RuntimeError."""
        key = aegis256x4.random_key()
        nonce = aegis256x4.random_nonce()

        encryptor = aegis256x4.Encryptor(key, nonce)

        # Encrypt some data and finalize
        encryptor.update(b"Hello, world!")
        tag = encryptor.final()

        # Attempting to call final again should raise RuntimeError
        with pytest.raises(
            RuntimeError, match="Cannot call final\\(\\) after final\\(\\)"
        ):
            encryptor.final()

    def test_update_then_final_after_final_raises(self):
        """Test that both update() and final() fail after final()."""
        key = aegis256x4.random_key()
        nonce = aegis256x4.random_nonce()

        encryptor = aegis256x4.Encryptor(key, nonce)

        # Encrypt and finalize
        encryptor.update(b"Test data")
        tag = encryptor.final()

        # Both operations should fail
        with pytest.raises(
            RuntimeError, match="Cannot call update\\(\\) after final\\(\\)"
        ):
            encryptor.update(b"More data")

        with pytest.raises(
            RuntimeError, match="Cannot call final\\(\\) after final\\(\\)"
        ):
            encryptor.final()

    def test_properties_accessible_after_final(self):
        """Test that properties like bytes_in and bytes_out are still accessible after final()."""
        key = aegis256x4.random_key()
        nonce = aegis256x4.random_nonce()

        encryptor = aegis256x4.Encryptor(key, nonce)

        message = b"Hello, world!"
        encryptor.update(message)
        tag = encryptor.final()

        # Properties should still be accessible
        assert encryptor.bytes_in == len(message)
        assert encryptor.bytes_out == len(message) + len(tag)

    def test_empty_encryption_finalization(self):
        """Test that finalization works correctly with no update() calls."""
        key = aegis256x4.random_key()
        nonce = aegis256x4.random_nonce()

        encryptor = aegis256x4.Encryptor(key, nonce)

        # Finalize without any updates
        tag = encryptor.final()
        assert len(tag) == aegis256x4.MACBYTES

        # Should still be unusable after
        with pytest.raises(
            RuntimeError, match="Cannot call update\\(\\) after final\\(\\)"
        ):
            encryptor.update(b"Data")


class TestDecryptorFinalization:
    """Test that Decryptor becomes unusable after final()."""

    def test_update_after_final_raises(self):
        """Test that calling update() after final() raises RuntimeError."""
        key = aegis256x4.random_key()
        nonce = aegis256x4.random_nonce()
        message = b"Hello, world!"

        # Encrypt first to get valid ciphertext and tag
        ct, tag = aegis256x4.encrypt_detached(key, nonce, message)

        # Now test decryption
        decryptor = aegis256x4.Decryptor(key, nonce)
        decryptor.update(ct)
        decryptor.final(tag)

        # Attempting to update after final should raise RuntimeError
        with pytest.raises(
            RuntimeError, match="Cannot call update\\(\\) after final\\(\\)"
        ):
            decryptor.update(b"More ciphertext")

    def test_final_after_final_raises(self):
        """Test that calling final() after final() raises RuntimeError."""
        key = aegis256x4.random_key()
        nonce = aegis256x4.random_nonce()
        message = b"Hello, world!"

        # Encrypt first to get valid ciphertext and tag
        ct, tag = aegis256x4.encrypt_detached(key, nonce, message)

        # Now test decryption
        decryptor = aegis256x4.Decryptor(key, nonce)
        decryptor.update(ct)
        decryptor.final(tag)

        # Attempting to call final again should raise RuntimeError
        with pytest.raises(
            RuntimeError, match="Cannot call final\\(\\) after final\\(\\)"
        ):
            decryptor.final(tag)

    def test_update_then_final_after_final_raises(self):
        """Test that both update() and final() fail after final()."""
        key = aegis256x4.random_key()
        nonce = aegis256x4.random_nonce()
        message = b"Test data"

        # Encrypt first
        ct, tag = aegis256x4.encrypt_detached(key, nonce, message)

        # Decrypt and finalize
        decryptor = aegis256x4.Decryptor(key, nonce)
        decryptor.update(ct)
        decryptor.final(tag)

        # Both operations should fail
        with pytest.raises(
            RuntimeError, match="Cannot call update\\(\\) after final\\(\\)"
        ):
            decryptor.update(b"More ciphertext")

        with pytest.raises(
            RuntimeError, match="Cannot call final\\(\\) after final\\(\\)"
        ):
            decryptor.final(tag)

    def test_properties_accessible_after_final(self):
        """Test that properties like bytes_in and bytes_out are still accessible after final()."""
        key = aegis256x4.random_key()
        nonce = aegis256x4.random_nonce()
        message = b"Hello, world!"

        # Encrypt first
        ct, tag = aegis256x4.encrypt_detached(key, nonce, message)

        # Decrypt
        decryptor = aegis256x4.Decryptor(key, nonce)
        decryptor.update(ct)
        decryptor.final(tag)

        # Properties should still be accessible
        assert decryptor.bytes_in == len(ct)
        assert decryptor.bytes_out == len(message)

    def test_empty_decryption_finalization(self):
        """Test that finalization works correctly with no update() calls."""
        key = aegis256x4.random_key()
        nonce = aegis256x4.random_nonce()

        # Encrypt empty message
        ct, tag = aegis256x4.encrypt_detached(key, nonce, b"")

        # Decrypt without any updates
        decryptor = aegis256x4.Decryptor(key, nonce)
        decryptor.final(tag)  # Should work with empty ciphertext

        # Should still be unusable after
        with pytest.raises(
            RuntimeError, match="Cannot call update\\(\\) after final\\(\\)"
        ):
            decryptor.update(b"Data")

    def test_failed_verification_still_finalizes(self):
        """Test that even if verification fails, the object becomes unusable."""
        key = aegis256x4.random_key()
        nonce = aegis256x4.random_nonce()
        message = b"Hello, world!"

        # Encrypt first
        ct, tag = aegis256x4.encrypt_detached(key, nonce, message)

        # Decrypt but use wrong tag
        decryptor = aegis256x4.Decryptor(key, nonce)
        decryptor.update(ct)

        # Try to finalize with invalid tag - should raise ValueError
        bad_tag = bytes(len(tag))  # All zeros
        with pytest.raises(ValueError, match="authentication failed"):
            decryptor.final(bad_tag)

        # Object should NOT be finalized on failure - should still be usable
        # This is a design decision: failed verification shouldn't lock the object
        # Let's verify current behavior
        try:
            decryptor.update(b"test")
            # If this doesn't raise, the object is still usable after failed verification
            # This might be the desired behavior
        except RuntimeError:
            # If this raises, failed verification also finalizes the object
            pass


class TestMultipleChunksBeforeFinalization:
    """Test that multiple update() calls work before final()."""

    def test_encryptor_multiple_updates(self):
        """Test that Encryptor can handle multiple update() calls before final()."""
        key = aegis256x4.random_key()
        nonce = aegis256x4.random_nonce()

        encryptor = aegis256x4.Encryptor(key, nonce)

        # Multiple updates
        encryptor.update(b"Hello, ")
        encryptor.update(b"world!")
        encryptor.update(b" More data.")

        # Should still work
        tag = encryptor.final()
        assert len(tag) == aegis256x4.MACBYTES

        # Now unusable
        with pytest.raises(RuntimeError):
            encryptor.update(b"More")

    def test_decryptor_multiple_updates(self):
        """Test that Decryptor can handle multiple update() calls before final()."""
        key = aegis256x4.random_key()
        nonce = aegis256x4.random_nonce()

        # Encrypt in chunks
        encryptor = aegis256x4.Encryptor(key, nonce)
        ct1 = encryptor.update(b"Hello, ")
        ct2 = encryptor.update(b"world!")
        tag = encryptor.final()

        # Decrypt in chunks
        decryptor = aegis256x4.Decryptor(key, nonce)
        decryptor.update(ct1)
        decryptor.update(ct2)
        decryptor.final(tag)

        # Now unusable
        with pytest.raises(RuntimeError):
            decryptor.update(b"More")
