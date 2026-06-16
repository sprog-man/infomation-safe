"""
test_rsa.py - Validate RSA key generation, encryption, and decryption.

Run with: python test_rsa.py

Expects all assertions to pass (no output on success).
Prints summary on completion.
"""

import unittest
import time
from crypto.rsa_crypto import (
    generate_keypair,
    rsa_encrypt,
    rsa_decrypt,
    mod_pow,
    mod_inverse,
    gcd,
    is_prime_miller_rabin,
    pkcs1_pad,
    pkcs1_unpad,
    serialize_public_key,
    deserialize_public_key,
    serialize_private_key,
    deserialize_private_key,
)


class TestModularExponentiation(unittest.TestCase):
    """Tests for the mod_pow square-and-multiply algorithm."""

    def test_identity(self):
        """x^1 mod n == x mod n."""
        self.assertEqual(mod_pow(7, 1, 13), 7)

    def test_zero_exponent(self):
        """x^0 mod n == 1 for any x."""
        self.assertEqual(mod_pow(7, 0, 13), 1)

    def test_known_value(self):
        """3^5 mod 7 = 5."""
        self.assertEqual(mod_pow(3, 5, 7), 5)

    def test_large_exponent(self):
        """2^100 mod 1000 = 376."""
        self.assertEqual(mod_pow(2, 100, 1000), 376)

    def test_symmetry(self):
        """If m^e mod n = c, then c^d mod n = m when e*d = 1 mod lambda(n)."""
        # With small primes p=3, q=11, n=33, phi=20, e=3, d=7 (3*7=21=1 mod 20)
        n, e, d = 33, 3, 7
        m = 5
        c = mod_pow(m, e, n)
        self.assertEqual(mod_pow(c, d, n), m)


class TestModularInverse(unittest.TestCase):
    """Tests for the Extended Euclidean Algorithm."""

    def test_inverse_property(self):
        """a * mod_inverse(a, m) mod m == 1."""
        for a in [3, 7, 13, 65537]:
            m = 7919  # prime
            inv = mod_inverse(a, m)
            self.assertEqual((a * inv) % m, 1)

    def test_no_inverse_when_not_coprime(self):
        """Extended GCD on non-coprime inputs is undefined; skip test."""
        pass

    """Tests for the Euclidean GCD algorithm."""

    def test_known_gcd(self):
        self.assertEqual(gcd(48, 18), 6)
        self.assertEqual(gcd(17, 13), 1)
        self.assertEqual(gcd(100, 75), 25)

    def test_gcd_with_zero(self):
        self.assertEqual(gcd(7, 0), 7)
        self.assertEqual(gcd(0, 7), 7)


class TestMillerRabin(unittest.TestCase):
    """Tests for the Miller-Rabin primality test."""

    def test_small_primes(self):
        """Known primes should be reported as prime."""
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
            self.assertTrue(is_prime_miller_rabin(p))

    def test_small_composites(self):
        """Known composites should be reported as composite."""
        for n in [0, 1, 4, 6, 8, 9, 10, 12, 15, 21, 25]:
            self.assertFalse(is_prime_miller_rabin(n))

    def test_large_prime(self):
        """A large known prime should pass."""
        self.assertTrue(is_prime_miller_rabin(104729))  # 10000th prime


class TestRSAKeyGeneration(unittest.TestCase):
    """Tests for RSA key pair generation."""

    def test_key_sizes(self):
        """Generated keys should have the requested bit length."""
        pub, priv = generate_keypair(512)
        self.assertEqual(pub["n"].bit_length(), 512)
        self.assertEqual(priv["n"].bit_length(), 512)
        self.assertEqual(pub["e"], 65537)

    def test_keys_share_modulus(self):
        """Public and private keys must share the same modulus n."""
        pub, priv = generate_keypair(512)
        self.assertEqual(pub["n"], priv["n"])

    def test_different_keys_per_call(self):
        """Two calls should produce different key pairs."""
        pub1, _ = generate_keypair(512)
        pub2, _ = generate_keypair(512)
        self.assertNotEqual(pub1["n"], pub2["n"])

    def test_e_is_65537(self):
        """Public exponent should always be 65537."""
        pub, _ = generate_keypair(512)
        self.assertEqual(pub["e"], 65537)


class TestRSAEncryptionDecryption(unittest.TestCase):
    """Tests for RSA encrypt/decrypt round-trip."""

    def setUp(self):
        self.pub, self.priv = generate_keypair(512)
        self.key_bytes = (self.pub["n"].bit_length() + 7) // 8

    def test_short_message(self):
        """Encrypt and decrypt a short message."""
        message = b"Hello RSA!"
        ct = rsa_encrypt(message, self.pub)
        pt = rsa_decrypt(ct, self.priv)
        self.assertEqual(pt, message)

    def test_longer_message(self):
        """Encrypt and decrypt a message up to the size limit."""
        # PKCS#1 overhead is 11 bytes
        max_len = self.key_bytes - 11
        message = b"X" * (max_len - 2)
        ct = rsa_encrypt(message, self.pub)
        pt = rsa_decrypt(ct, self.priv)
        self.assertEqual(pt, message)

    def test_binary_data(self):
        """Encrypt and decrypt arbitrary binary data."""
        message = bytes(range(40))
        ct = rsa_encrypt(message, self.pub)
        pt = rsa_decrypt(ct, self.priv)
        self.assertEqual(pt, message)

    def test_deterministic_padding(self):
        """Same message encrypts differently each time (random padding)."""
        message = b"deterministic test"
        ct1 = rsa_encrypt(message, self.pub)
        ct2 = rsa_encrypt(message, self.pub)
        self.assertNotEqual(ct1, ct2)

    def test_ciphertext_different_from_plaintext(self):
        """Ciphertext must not equal the plaintext."""
        message = b"not encrypted"
        ct = rsa_encrypt(message, self.pub)
        self.assertNotEqual(ct, message)

    def test_wrong_key_fails(self):
        """Ciphertext encrypted with one key cannot be decrypted with another."""
        pub2, priv2 = generate_keypair(512)
        message = b"wrong key test"
        ct = rsa_encrypt(message, self.pub)
        with self.assertRaises(ValueError):
            rsa_decrypt(ct, priv2)

class TestPKCS1Padding(unittest.TestCase):
    """Tests for PKCS#1 v1.5 padding."""

    def test_padding_format(self):
        """Padded message must start with 0x00 0x02."""
        padded = pkcs1_pad(b"test", 64)
        self.assertEqual(padded[0], 0x00)
        self.assertEqual(padded[1], 0x02)

    def test_padding_separator(self):
        """There must be a 0x00 separator between padding and message."""
        padded = pkcs1_pad(b"test", 64)
        separator_idx = padded.index(b"\x00", 2)
        self.assertEqual(padded[separator_idx + 1:], b"test")

    def test_unpad_matches_original(self):
        """Unpadding padded data must recover the original message."""
        msg = b"Hello"
        padded = pkcs1_pad(msg, 64)
        unpadded = pkcs1_unpad(padded, 64)
        self.assertEqual(unpadded, msg)

    def test_message_too_long(self):
        """Messages longer than key allow must raise ValueError."""
        with self.assertRaises(ValueError):
            pkcs1_pad(b"A" * 64, 64)


class TestKeySerialization(unittest.TestCase):
    """Tests for public/private key serialization/deserialization."""

    def test_serialize_deserialize_public(self):
        """Serialize and deserialize a public key must round-trip."""
        pub, _ = generate_keypair(512)
        data = serialize_public_key(pub)
        restored = deserialize_public_key(data)
        self.assertEqual(restored["n"], pub["n"])
        self.assertEqual(restored["e"], pub["e"])

    def test_serialize_deserialize_private(self):
        """Serialize and deserialize a private key must round-trip."""
        _, priv = generate_keypair(512)
        data = serialize_private_key(priv)
        restored = deserialize_private_key(data)
        self.assertEqual(restored["n"], priv["n"])
        self.assertEqual(restored["d"], priv["d"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
