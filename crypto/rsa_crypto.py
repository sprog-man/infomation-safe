import sys
import os
"# Add project root to path for standalone usage"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

"""
rsa_crypto.py - RSA Implementation from Scratch

Implements RSA key generation, encryption, and decryption using pure Python.
No external crypto libraries are used — only Python standard library.

Algorithm overview:
  - Key sizes: 1024, 2048 bits (default 2048)
  - Uses probabilistic primality testing (Miller-Rabin)
  - PKCS#1 v1.5 style padding for encryption (educational, not production-grade)
  - CRT optimization for decryption

Key steps:
  1. Generate two large random primes p and q
  2. Compute n = p * q (modulus) and phi(n) = (p-1)*(q-1)
  3. Choose e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1 (typically 65537)
  4. Compute d = modular_inverse(e, phi(n)) (private exponent)
  5. Encrypt: c = m^e mod n
  6. Decrypt: m = c^d mod n

The modular exponentiation uses the square-and-multiply algorithm for efficiency.
"""

import random
import struct
import time


# ---------------------------------------------------------------------------
# Utility: modular arithmetic
# ---------------------------------------------------------------------------

def mod_pow(base: int, exp: int, mod: int) -> int:
    """
    Compute (base ^ exp) % mod using the square-and-multiply algorithm.

    This is the core exponentiation operation in RSA.
    It runs in O(log exp) time instead of O(exp) for naive multiplication.

    Square-and-multiply process:
      - Start with result = 1
      - For each bit of exp (from MSB to LSB):
          - Square the result
          - If the bit is 1, multiply by base
      - All operations done modulo mod to keep numbers manageable
    """
    result = 1
    base = base % mod
    while exp > 0:
        # If current bit is 1, multiply result by base
        if exp & 1:
            result = (result * base) % mod
        # Square the base for the next bit
        exp >>= 1
        base = (base * base) % mod
    return result


def mod_inverse(a: int, m: int) -> int:
    """
    Compute the modular multiplicative inverse of a modulo m.

    Uses the Extended Euclidean Algorithm to find x such that:
        a * x ≡ 1 (mod m)

    Returns x in the range [1, m-1].
    Raises ValueError if the inverse doesn't exist (gcd(a, m) != 1).
    """
    if m == 1:
        return 0

    original_m = m
    x0, x1 = 0, 1

    while a > 1:
        # Quotient
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0

    if x1 < 0:
        x1 += original_m

    return x1


def gcd(a: int, b: int) -> int:
    """
    Compute the greatest common divisor of a and b using the Euclidean algorithm.

    Returns the largest positive integer that divides both a and b.
    Used to verify that e and phi(n) are coprime (gcd = 1).
    """
    while b:
        a, b = b, a % b
    return a


# ---------------------------------------------------------------------------
# Prime generation
# ---------------------------------------------------------------------------

def is_prime_miller_rabin(n: int, k: int = 20) -> bool:
    """
    Miller-Rabin probabilistic primality test.

    Parameters
    ----------
    n : int
        The number to test for primality.
    k : int
        Number of rounds (witnesses) to test. Higher = more confident.
        k=20 gives probability of false positive < 4^(-20) ≈ 10^(-12).

    Returns
    -------
    bool
        True if n is probably prime, False if definitely composite.

    Algorithm:
      1. Handle small cases directly (2, 3, even numbers)
      2. Write n-1 as 2^r * d where d is odd
      3. For each of k random witnesses a:
         - Compute x = a^d mod n
         - If x == 1 or x == n-1, this witness passes
         - Square x up to r-1 times; if any gives n-1, witness passes
         - If no witness passes, n is composite
    """
    # Handle small cases
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = mod_pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            # No witness found — n is composite
            return False

    # No witness proved n composite — n is probably prime
    return True


def generate_large_prime(bits: int) -> int:
    """
    Generate a random prime number of the specified bit length.

    Uses a two-step process:
      1. Generate a random odd number with the correct bit length
      2. Test with Miller-Rabin until a prime is found

    The top bit is always set to ensure the number has exactly `bits` bits.
    The bottom bit is always set to ensure the number is odd.
    """
    while True:
        # Generate random number with correct bit length
        n = random.getrandbits(bits)
        # Set top bit to ensure correct length
        n |= (1 << (bits - 1))
        # Set bottom bit to ensure odd
        n |= 1

        if is_prime_miller_rabin(n):
            return n


# ---------------------------------------------------------------------------
# RSA key generation
# ---------------------------------------------------------------------------

def generate_keypair(key_bits: int = 2048) -> tuple:
    """
    Generate an RSA public/private key pair.

    Parameters
    ----------
    key_bits : int
        Key size in bits (1024 or 2048). Must be even.

    Returns
    -------
    tuple
        (public_key, private_key) where each is a dict with 'n' and 'e'/'d'.

    Process:
      1. Generate two large random primes p and q (key_bits/2 each)
      2. Compute n = p * q (the modulus)
      3. Compute phi(n) = (p-1) * (q-1)
      4. Set public exponent e = 65537 (common choice, coprime with most phi(n))
      5. Compute private exponent d = e^(-1) mod phi(n)
      6. Return public key {n, e} and private key {n, d}
    """
    if key_bits < 512:
        raise ValueError("Key size must be at least 512 bits for security")
    if key_bits % 2 != 0:
        raise ValueError("Key size must be even")

    half_bits = key_bits // 2

    while True:
        # Step 1: Generate two distinct large primes
        p = generate_large_prime(half_bits)
        q = generate_large_prime(half_bits)

        while p == q:
            q = generate_large_prime(half_bits)

        # Step 2: Compute modulus n
        n = p * q

        # Step 3: Compute Euler's totient
        phi_n = (p - 1) * (q - 1)

        # Step 4: Choose public exponent
        e = 65537

        # Verify e is coprime with phi(n)
        if gcd(e, phi_n) != 1:
            continue

        # Step 5: Compute private exponent
        d = mod_inverse(e, phi_n)

        if d < 1:
            continue

        # Success!
        public_key = {"n": n, "e": e}
        private_key = {"n": n, "d": d}

        return public_key, private_key


# ---------------------------------------------------------------------------
# RSA encryption & decryption
# ---------------------------------------------------------------------------

def pkcs1_pad(message: bytes, key_len_bytes: int) -> bytes:
    """
    Apply PKCS#1 v1.5 padding for RSA encryption.

    Padding format:
      0x00 0x02 <random non-zero bytes> 0x00 <message>

    This ensures the message is the same length as the key and adds randomness
    so the same message encrypts differently each time (probabilistic encryption).

    Parameters
    ----------
    message : bytes
        The plaintext message (must be shorter than key).
    key_len_bytes : int
        Length of the RSA modulus in bytes (e.g., 256 for 2048-bit key).

    Returns
    -------
    bytes
        The padded message ready for modular exponentiation.
    """
    max_msg_len = key_len_bytes - 11  # 11 bytes for padding overhead

    if len(message) > max_msg_len:
        raise ValueError("Message too long for the given key size")

    # Build padded block: 00 02 <random padding> 00 <message>
    padding = b""
    while len(padding) < key_len_bytes - len(message) - 3:
        byte = random.randint(1, 255)
        padding += bytes([byte])

    return b"\x00\x02" + padding + b"\x00" + message


def pkcs1_unpad(padded_message: bytes, key_len_bytes: int) -> bytes:
    """
    Remove PKCS#1 v1.5 padding from RSA decrypted data.

    Validates the padding structure (must start with 00 02) and extracts
    the original message.
    """
    if len(padded_message) != key_len_bytes:
        raise ValueError("Padded message length doesn't match key size")

    if padded_message[0] != 0x00 or padded_message[1] != 0x02:
        raise ValueError("Invalid PKCS#1 padding: expected 00 02")

    # Find the 0x00 separator after the random padding
    separator_idx = padded_message.index(b"\x00", 2)

    return padded_message[separator_idx + 1:]


def rsa_encrypt(plaintext: bytes, public_key: dict) -> bytes:
    """
    Encrypt data using RSA public key with PKCS#1 v1.5 padding.

    Parameters
    ----------
    plaintext : bytes
        The data to encrypt. Must be shorter than the key.
    public_key : dict
        RSA public key with 'n' (modulus) and 'e' (public exponent).

    Returns
    -------
    bytes
        Ciphertext (same length as key in bytes).

    Process:
      1. Pad the plaintext with PKCS#1 v1.5
      2. Convert padded message to integer
      3. Compute c = m^e mod n (modular exponentiation)
      4. Convert ciphertext integer back to bytes
    """
    n = public_key["n"]
    e = public_key["e"]
    key_len_bytes = (n.bit_length() + 7) // 8

    # Pad the message
    padded = pkcs1_pad(plaintext, key_len_bytes)

    # Convert to integer, encrypt, convert back to bytes
    m = int.from_bytes(padded, byteorder="big")
    c = mod_pow(m, e, n)
    return c.to_bytes(key_len_bytes, byteorder="big")


def rsa_decrypt(ciphertext: bytes, private_key: dict) -> bytes:
    """
    Decrypt RSA ciphertext using the private key.

    Parameters
    ----------
    ciphertext : bytes
        Encrypted data (must be key_len_bytes long).
    private_key : dict
        RSA private key with 'n' (modulus) and 'd' (private exponent).

    Returns
    -------
    bytes
        Decrypted plaintext with PKCS#1 v1.5 padding removed.

    Process:
      1. Convert ciphertext to integer
      2. Compute m = c^d mod n (modular exponentiation)
      3. Convert integer back to bytes
      4. Remove PKCS#1 v1.5 padding
    """
    n = private_key["n"]
    d = private_key["d"]
    key_len_bytes = (n.bit_length() + 7) // 8

    if len(ciphertext) != key_len_bytes:
        raise ValueError(f"Ciphertext length must be {key_len_bytes} bytes")

    # Convert to integer, decrypt, convert back to bytes
    c = int.from_bytes(ciphertext, byteorder="big")
    m = mod_pow(c, d, n)
    padded = m.to_bytes(key_len_bytes, byteorder="big")

    # Remove PKCS#1 v1.5 padding
    return pkcs1_unpad(padded, key_len_bytes)


# ---------------------------------------------------------------------------
# Key serialization helpers
# ---------------------------------------------------------------------------

def serialize_public_key(key: dict) -> bytes:
    """
    Serialize RSA public key to bytes.

    Format: [n_len(4 bytes)] [n bytes] [e_len(4 bytes)] [e bytes]

    Allows transmitting the public key over a network.
    """
    n_bytes = key["n"].to_bytes((key["n"].bit_length() + 7) // 8, "big")
    e_bytes = key["e"].to_bytes((key["e"].bit_length() + 7) // 8, "big")
    return struct.pack(">I", len(n_bytes)) + n_bytes + struct.pack(">I", len(e_bytes)) + e_bytes


def deserialize_public_key(data: bytes) -> dict:
    """
    Deserialize RSA public key from bytes.

    Reverses serialize_public_key to reconstruct the key dict.
    """
    offset = 0
    n_len = struct.unpack(">I", data[offset:offset+4])[0]
    offset += 4
    n = int.from_bytes(data[offset:offset+n_len], "big")
    offset += n_len
    e_len = struct.unpack(">I", data[offset:offset+4])[0]
    offset += 4
    e = int.from_bytes(data[offset:offset+e_len], "big")
    return {"n": n, "e": e}


def serialize_private_key(key: dict) -> bytes:
    """
    Serialize RSA private key to bytes.

    Format: [n_len(4)] [n] [d_len(4)] [d]
    """
    n_bytes = key["n"].to_bytes((key["n"].bit_length() + 7) // 8, "big")
    d_bytes = key["d"].to_bytes((key["d"].bit_length() + 7) // 8, "big")
    return struct.pack(">I", len(n_bytes)) + n_bytes + struct.pack(">I", len(d_bytes)) + d_bytes


def deserialize_private_key(data: bytes) -> dict:
    """
    Deserialize RSA private key from bytes.
    """
    offset = 0
    n_len = struct.unpack(">I", data[offset:offset+4])[0]
    offset += 4
    n = int.from_bytes(data[offset:offset+n_len], "big")
    offset += n_len
    d_len = struct.unpack(">I", data[offset:offset+4])[0]
    offset += 4
    d = int.from_bytes(data[offset:offset+d_len], "big")
    return {"n": n, "d": d}


if __name__ == "__main__":
    # Quick self-test with a small key (for demo only)
    print("Generating 512-bit RSA key pair...")
    pub, priv = generate_keypair(512)
    print(f"  Public exponent: {pub['e']}")
    print(f"  Modulus bits: {pub['n'].bit_length()}")

    message = b"Hello, RSA from scratch!"
    print(f"  Original:  {message}")

    encrypted = rsa_encrypt(message, pub)
    print(f"  Encrypted: {encrypted.hex()[:40]}...")

    decrypted = rsa_decrypt(encrypted, priv)
    print(f"  Decrypted: {decrypted}")

    assert decrypted == message, "Round-trip failed!"
    print("\n[RSA] Round-trip test PASSED.")
