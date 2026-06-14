"""
test_hmac.py - Validate SHA-256 and HMAC-SHA256 implementations from scratch.

Run with: python test_hmac.py

Expects all assertions to pass (no output on success).
Prints summary on completion.
"""

import sys
import os
import unittest
# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auth.hmac_auth import (
    sha256_hash,
    hmac_sha256,
    compute_tag,
    verify_tag,
    _rotr,
    _shr,
)


class TestSHA256(unittest.TestCase):
    """Tests for SHA-256 hash function."""

    def test_empty_message(self):
        """SHA-256 of empty string is a well-known constant."""
        result = sha256_hash(b"")
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertEqual(result.hex(), expected)

    def test_known_message(self):
        """SHA-256 of 'abc' is a well-known constant."""
        result = sha256_hash(b"abc")
        expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        self.assertEqual(result.hex(), expected)

    def test_known_message_long(self):
        """SHA-256 of 'The quick brown fox jumps over the lazy dog'."""
        msg = b"The quick brown fox jumps over the lazy dog"
        result = sha256_hash(msg)
        expected = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        self.assertEqual(result.hex(), expected)

    def test_different_messages_different_hashes(self):
        """Different messages must produce different hashes."""
        h1 = sha256_hash(b"hello")
        h2 = sha256_hash(b"world")
        self.assertNotEqual(h1, h2)

    def test_deterministic(self):
        """Same message always produces same hash."""
        h1 = sha256_hash(b"deterministic test")
        h2 = sha256_hash(b"deterministic test")
        self.assertEqual(h1, h2)

    def test_output_size(self):
        """SHA-256 output must be exactly 32 bytes."""
        for msg in [b"", b"a", b"x" * 1000, b"\xff" * 256]:
            self.assertEqual(len(sha256_hash(msg)), 32)

    def test_avalanche_effect(self):
        """Changing one bit should drastically change the hash."""
        h1 = sha256_hash(b"aaaaaaaa")
        h2 = sha256_hash(b"aaaaaaaX")
        diffs = sum(1 for a, b in zip(h1, h2) if a != b)
        # At least 60% of bytes should differ (avalanche criterion)
        self.assertGreater(diffs, 19)


class TestHMACSHA256(unittest.TestCase):
    """Tests for HMAC-SHA256 message authentication."""

    def test_hmac_with_empty_message(self):
        """HMAC-SHA256 with empty message should produce a valid tag."""
        key = b"key"
        tag = hmac_sha256(key, b"")
        self.assertEqual(len(tag), 32)

    def test_hmac_with_known_key_and_message(self):
        """HMAC-SHA256 produces consistent output for given key and message."""
        key = b"secret-key"
        msg = b"hello world"
        tag1 = hmac_sha256(key, msg)
        tag2 = hmac_sha256(key, msg)
        self.assertEqual(tag1, tag2)

    def test_different_keys_different_tags(self):
        """Different keys must produce different HMAC tags."""
        msg = b"same message"
        tag1 = hmac_sha256(b"key1", msg)
        tag2 = hmac_sha256(b"key2", msg)
        self.assertNotEqual(tag1, tag2)

    def test_different_messages_different_tags(self):
        """Different messages must produce different HMAC tags."""
        key = b"shared-key"
        tag1 = hmac_sha256(key, b"message1")
        tag2 = hmac_sha256(key, b"message2")
        self.assertNotEqual(tag1, tag2)

    def test_tampered_message_rejected(self):
        """Modifying the message should change the HMAC tag."""
        key = b"test-key"
        msg = b"original message"
        tag = hmac_sha256(key, msg)
        tampered_tag = hmac_sha256(key, b"tamp ered message")
        self.assertNotEqual(tag, tampered_tag)

    def test_long_key(self):
        """HMAC should work with keys longer than block size (64 bytes)."""
        key = b"A" * 100  # > 64 bytes
        msg = b"test message"
        tag = hmac_sha256(key, msg)
        self.assertEqual(len(tag), 32)

    def test_binary_message(self):
        """HMAC should work with arbitrary binary messages."""
        key = b"key"
        msg = bytes(range(256))
        tag = hmac_sha256(key, msg)
        self.assertEqual(len(tag), 32)

    def test_unicode_message(self):
        """HMAC should work with UTF-8 encoded messages."""
        key = b"key"
        msg = "你好世界".encode("utf-8")
        tag = hmac_sha256(key, msg)
        self.assertEqual(len(tag), 32)


class TestComputeTag(unittest.TestCase):
    """Tests for compute_tag convenience function."""

    def test_returns_hex_string(self):
        """compute_tag should return a hex string."""
        result = compute_tag(b"key", b"msg")
        self.assertIsInstance(result, str)
        self.assertEqual(len(result), 64)  # 32 bytes = 64 hex chars

    def test_valid_hex(self):
        """Returned string should be valid hex."""
        result = compute_tag(b"key", b"msg")
        int(result, 16)  # raises if invalid hex


class TestVerifyTag(unittest.TestCase):
    """Tests for verify_tag function."""

    def test_valid_tag_returns_true(self):
        """Verifying a correct tag should return True."""
        key = b"secret"
        msg = b"authenticated message"
        tag = hmac_sha256(key, msg)
        self.assertTrue(verify_tag(key, msg, tag.hex()))

    def test_wrong_tag_returns_false(self):
        """Verifying a wrong tag should return False."""
        key = b"secret"
        msg = b"authenticated message"
        self.assertFalse(verify_tag(key, msg, "a" * 64))

    def test_tampered_message_returns_false(self):
        """Verifying a tampered message should return False."""
        key = b"secret"
        msg = b"original"
        tag = hmac_sha256(key, msg)
        self.assertFalse(verify_tag(key, b"tampered", tag.hex()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
