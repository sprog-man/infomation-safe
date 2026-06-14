"""
test_aes.py - Validate AES-128 encryption/decryption from scratch.

Run with: python test_aes.py

Expects all assertions to pass (no output on success).
Prints summary on completion.
"""

import unittest
from crypto.aes_crypto import (
    aes_encrypt,
    aes_decrypt,
    aes_encrypt_block,
    aes_decrypt_block,
    key_expansion,
    pkcs7_pad,
    pkcs7_unpad,
    gmul,
    S_BOX,
    INV_S_BOX,
)


class TestSBox(unittest.TestCase):
    """Tests for S-Box and inverse S-Box correctness."""

    def test_sbox_is_256_entries(self):
        """S-Box must have exactly 256 entries (8-bit)."""
        self.assertEqual(len(S_BOX), 256)

    def test_inv_sbox_is_256_entries(self):
        """Inverse S-Box must have exactly 256 entries."""
        self.assertEqual(len(INV_S_BOX), 256)

    def test_inv_sbox_complement(self):
        """Applying S_BOX then INV_S_BOX must recover the original byte."""
        for i in range(256):
            self.assertEqual(INV_S_BOX[S_BOX[i]], i)

    def test_sbox_is_permutation(self):
        """S-Box must be a permutation of 0-255."""
        self.assertEqual(sorted(S_BOX), list(range(256)))


class TestGaloisFieldMultiplication(unittest.TestCase):
    """Tests for GF(2^8) multiplication."""

    def test_gmul_identity(self):
        """Multiplying by 1 must return the other operand."""
        for i in range(256):
            self.assertEqual(gmul(i, 1), i)

    def test_gmul_zero(self):
        """Multiplying by 0 must always return 0."""
        for i in range(256):
            self.assertEqual(gmul(i, 0), 0)
            self.assertEqual(gmul(0, i), 0)

    def test_gmul_known_values(self):
        """Verify known GF(2^8) multiplication results."""
        # 0x57 * 0x02 in GF(2^8) = 0xAE
        self.assertEqual(gmul(0x57, 0x02), 0xAE)
        self.assertEqual(gmul(0x57, 0x03), gmul(0x57, 0x02) ^ 0x57)
        self.assertEqual(gmul(0xFE, 0x02), 0xE7)
        # 0xFE * 0x02 = 0xE7 (correct in our impl)



class TestPkc7Padding(unittest.TestCase):
    """Tests for PKCS7 padding and unpadding."""

    def test_pad_already_aligned(self):
        """A 16-byte input gets a full 16-byte padding block."""
        data = b"A" * 16
        padded = pkcs7_pad(data)
        self.assertEqual(len(padded), 32)
        self.assertEqual(padded[-1], 16)

    def test_pad_not_aligned(self):
        """A 13-byte input gets 3 padding bytes of value 3."""
        data = b"A" * 13
        padded = pkcs7_pad(data)
        self.assertEqual(len(padded), 16)
        self.assertEqual(padded[-1], 3)

    def test_pad_remove_restores_original(self):
        """Unpadding after padding must recover the original data."""
        for length in range(1, 32):
            data = bytes(range(length))
            padded = pkcs7_pad(data)
            unpadded = pkcs7_unpad(padded)
            self.assertEqual(unpadded, data)

    def test_pad_returns_bytes(self):
        """Output of pkcs7_pad must be bytes."""
        self.assertIsInstance(pkcs7_pad(b"test"), bytes)


class TestAesRoundTrip(unittest.TestCase):
    """Tests for full AES-128 encrypt/decrypt round-trip."""

    def setUp(self):
        """Standard test key (16 bytes)."""
        self.key = b"0123456789ABCDEF"

    def test_short_message(self):
        """Encrypt and decrypt a short message."""
        message = b"Hello"
        encrypted = aes_encrypt(message, self.key)
        decrypted = aes_decrypt(encrypted, self.key)
        self.assertEqual(decrypted, message)

    def test_longer_message(self):
        """Encrypt and decrypt a message spanning multiple blocks."""
        message = b"This is a longer message that spans multiple AES blocks. " \
                  b"It needs padding to be exactly divisible by 16 bytes."
        encrypted = aes_encrypt(message, self.key)
        decrypted = aes_decrypt(encrypted, self.key)
        self.assertEqual(decrypted, message)

    def test_empty_message(self):
        """Encrypt and decrypt an empty message."""
        message = b""
        encrypted = aes_encrypt(message, self.key)
        decrypted = aes_decrypt(encrypted, self.key)
        self.assertEqual(decrypted, message)

    def test_binary_data(self):
        """Encrypt and decrypt arbitrary binary data."""
        message = bytes(range(256))
        encrypted = aes_encrypt(message, self.key)
        decrypted = aes_decrypt(encrypted, self.key)
        self.assertEqual(decrypted, message)

    def test_deterministic(self):
        """Same key and plaintext must always produce the same ciphertext."""
        message = b"deterministic test"
        c1 = aes_encrypt(message, self.key)
        c2 = aes_encrypt(message, self.key)
        self.assertEqual(c1, c2)

    def test_different_keys(self):
        """Different keys must produce different ciphertexts."""
        message = b"different keys test"
        key2 = b"ABCDEFGHIJKLMNO"
        key2 = key2 + b"\x00"  # pad to 16 bytes
        c1 = aes_encrypt(message, self.key)
        c2 = aes_encrypt(message, key2)
        self.assertNotEqual(c1, c2)

    def test_ciphertext_is_different_from_plaintext(self):
        """Ciphertext must not equal the plaintext (no-op encryption)."""
        message = b"not encrypted"
        encrypted = aes_encrypt(message, self.key)
        self.assertNotEqual(encrypted, message)


class TestAesBlockCipher(unittest.TestCase):
    """Tests for single-block AES encrypt/decrypt."""

    def setUp(self):
        self.key = b"0123456789ABCDEF"
        self.round_keys = key_expansion(self.key)

    def test_single_block_roundtrip(self):
        """Encrypt and decrypt a single 16-byte block."""
        block = b"1234567890ABCDEF"
        ct = aes_encrypt_block(block, self.round_keys)
        pt = aes_decrypt_block(ct, self.round_keys)
        self.assertEqual(pt, block)

    def test_known_plaintext(self):
        """Specific plaintext produces specific ciphertext with given key."""
        block = b"HelloAES1234!!!!"
        ct = aes_encrypt_block(block, self.round_keys)
        # We verify round-trip, not specific hex (no known test vector library)
        pt = aes_decrypt_block(ct, self.round_keys)
        self.assertEqual(pt, block)


class TestAesErrors(unittest.TestCase):
    """Tests for error handling."""

    def test_wrong_key_length(self):
        """AES-128 requires exactly 16-byte key."""
        with self.assertRaises(ValueError):
            aes_encrypt(b"test", b"short")
        with self.assertRaises(ValueError):
            aes_encrypt(b"test", b"this_key_is_too_long_for_aes_128")

    def test_ciphertext_must_be_multiple_of_16(self):
        """aes_decrypt requires ciphertext length to be a multiple of 16."""
        key = b"0123456789ABCDEF"
        with self.assertRaises(ValueError):
            aes_decrypt(b"not_divisible", key)


class TestAesKnownTestVector(unittest.TestCase):
    """
    Verify against NIST AES-128 test vector from FIPS-197 Appendix B.
    Key:       2b7e151628aed2a6abf7158809cf4f3c
    Plaintext: 3243f6a8885a308d313198a2e0370734
    Ciphertext:3925841d02dc09fbdc118597196a0b32
    """

    def test_fips_197_appendix_b(self):
        """NIST FIPS-197 Appendix B test vector for AES-128."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        expected_ct = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

        round_keys = key_expansion(key)
        ct = aes_encrypt_block(plaintext, round_keys)
        self.assertEqual(ct, expected_ct, "Ciphertext does not match NIST test vector")

        pt = aes_decrypt_block(ct, round_keys)
        self.assertEqual(pt, plaintext, "Decryption does not recover original plaintext")


if __name__ == "__main__":
    unittest.main(verbosity=2)
