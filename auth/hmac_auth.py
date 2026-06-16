import sys
import os
"# Add project root to path for standalone usage"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

"""
hmac_auth.py - HMAC-SHA256 Message Authentication from Scratch

Implements SHA-256 hash and HMAC-SHA256 authentication using pure Python.
No external crypto libraries are used — only Python standard library.

Algorithm overview:
  SHA-256:
    - Processes message in 512-bit (64-byte) blocks
    - Maintains 8 state variables (32-bit each)
    - 64 rounds of compression with constants derived from fractional parts of
      cube roots of first 64 primes
    - Output: 256-bit (32-byte) hash

  HMAC (RFC 2104):
    - HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
    - K' = hash(K) if key > block_size, else key padded with zeros
    - ipad = 0x36 repeated, opad = 0x5c repeated
    - block_size for SHA-256 = 64 bytes
"""

import struct


# ---------------------------------------------------------------------------
# SHA-256 constants
# ---------------------------------------------------------------------------

# First 32 bits of the fractional parts of the cube roots of the first 64 primes
_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# SHA-256 initial hash values (first 32 bits of the fractional parts of
# the square roots of the first 8 primes)
_H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

_BLOCK_SIZE = 64   # SHA-256 block size in bytes
_HASH_SIZE = 32    # SHA-256 output size in bytes


# ---------------------------------------------------------------------------
# Bit manipulation helpers
# ---------------------------------------------------------------------------

def _rotr(x: int, n: int) -> int:
    """Right rotate a 32-bit integer x by n bits."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _shr(x: int, n: int) -> int:
    """Right shift a 32-bit integer x by n bits."""
    return x >> n


# ---------------------------------------------------------------------------
# SHA-256 compression
# ---------------------------------------------------------------------------

def sha256_hash(message: bytes) -> bytes:
    """
    Compute the SHA-256 hash of a message.

    Parameters
    ----------
    message : bytes
        Input data to hash.

    Returns
    -------
    bytes
        32-byte SHA-256 digest.

    Process:
      1. Pre-process: append bit '1' then zeros, then 64-bit message length
      2. Process each 512-bit block through the compression function
      3. Concatenate the 8 state variables to produce the final hash
    """
    # Step 1: Pre-processing — append padding
    msg_len = len(message)
    bit_len = msg_len * 8

    # Append bit 1 (0x80) then zeros, then 64-bit big-endian bit length
    message += b"\x80"
    # Pad to 56 mod 64 bytes (so that after appending 8-byte length, total is 64-byte aligned)
    while len(message) % _BLOCK_SIZE != 56:
        message += b"\x00"
    # Append original length in bits as 64-bit big-endian
    message += struct.pack(">Q", bit_len)

    # Step 2: Initialize hash values
    h0, h1, h2, h3, h4, h5, h6, h7 = _H_INIT

    # Step 3: Process each 512-bit (64-byte) block
    for offset in range(0, len(message), _BLOCK_SIZE):
        block = message[offset:offset + _BLOCK_SIZE]
        h0, h1, h2, h3, h4, h5, h6, h7 = _compress(block, h0, h1, h2, h3, h4, h5, h6, h7)

    # Step 4: Produce final hash
    return struct.pack(">8I", h0, h1, h2, h3, h4, h5, h6, h7)


def _compress(block: bytes, h0: int, h1: int, h2: int, h3: int,
              h4: int, h5: int, h6: int, h7: int) -> tuple:
    """
    SHA-256 compression function for a single 512-bit block.

    Parameters
    ----------
    block : bytes
        Exactly 64 bytes of message block.
    h0..h7 : int
        Current hash state (8 × 32-bit words).

    Returns
    -------
    tuple
        Updated hash state (h0..h7).

    Process:
      1. Prepare the message schedule W[0..63]:
         - W[0..15] = the block itself (split into 4-byte words)
         - W[16..63] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
      2. 64 rounds of compression:
         T1 = h + EP1(h) + Ch(h,e,f) + K[i] + W[i]
         T2 = EP0(a) + Maj(a,b,c)
         Rotate state variables
      3. Add compressed chunk to current hash value
    """
    # Prepare message schedule
    W = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        s0 = _rotr(W[i - 15], 7) ^ _rotr(W[i - 15], 18) ^ _shr(W[i - 15], 3)
        s1 = _rotr(W[i - 2], 17) ^ _rotr(W[i - 2], 19) ^ _shr(W[i - 2], 10)
        W.append((W[i - 16] + s0 + W[i - 7] + s1) & 0xFFFFFFFF)

    # Initialize working variables
    a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

    # 64 rounds
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ (~e & g) & 0xFFFFFFFF
        t1 = (h + S1 + ch + _K[i] + W[i]) & 0xFFFFFFFF
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & 0xFFFFFFFF

        h = g
        g = f
        f = e
        e = (d + t1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (t1 + t2) & 0xFFFFFFFF

    # Add compressed chunk to hash
    return (
        (h0 + a) & 0xFFFFFFFF,
        (h1 + b) & 0xFFFFFFFF,
        (h2 + c) & 0xFFFFFFFF,
        (h3 + d) & 0xFFFFFFFF,
        (h4 + e) & 0xFFFFFFFF,
        (h5 + f) & 0xFFFFFFFF,
        (h6 + g) & 0xFFFFFFFF,
        (h7 + h) & 0xFFFFFFFF,
    )


# ---------------------------------------------------------------------------
# HMAC-SHA256
# ---------------------------------------------------------------------------

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """
    Compute HMAC-SHA256 authentication tag.

    Parameters
    ----------
    key : bytes
        The secret key (any length).
    message : bytes
        The message to authenticate.

    Returns
    -------
    bytes
        32-byte HMAC tag.

    Algorithm (RFC 2104):
      HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))

      Where:
        - K' = H(K) if len(K) > block_size, else K || zeros
        - ipad = 0x36 repeated 64 times
        - opad = 0x5c repeated 64 times
        - || denotes concatenation
        - H is SHA-256
    """
    if not key:
        key = b""

    # Step 1: Derive the block-sized key K'
    if len(key) > _BLOCK_SIZE:
        key = sha256_hash(key)
    if len(key) < _BLOCK_SIZE:
        key = key + b"\x00" * (_BLOCK_SIZE - len(key))

    # Step 2: Create inner and outer padded keys
    ipad = bytes(k ^ 0x36 for k in key)
    opad = bytes(k ^ 0x5c for k in key)

    # Step 3: HMAC = H(opad || H(ipad || message))
    inner_hash = sha256_hash(ipad + message)
    return sha256_hash(opad + inner_hash)


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------

def compute_tag(key: bytes, message: bytes) -> str:
    """
    Compute HMAC-SHA256 tag and return as hex string.

    Parameters
    ----------
    key : bytes
        Secret key.
    message : bytes
        Message to authenticate.

    Returns
    -------
    str
        Hex-encoded HMAC tag (64 hex characters).
    """
    return hmac_sha256(key, message).hex()


def verify_tag(key: bytes, message: bytes, expected_tag: str) -> bool:
    """
    Verify an HMAC-SHA256 tag using constant-time comparison.

    Parameters
    ----------
    key : bytes
        Secret key.
    message : bytes
        Message to verify.
    expected_tag : str
        Expected hex-encoded tag.

    Returns
    -------
    bool
        True if the tag matches, False otherwise.

    Uses hmac.compare_digest for timing-attack resistance.
    """
    import hmac
    actual_tag = hmac_sha256(key, message)
    return hmac.compare_digest(actual_tag, bytes.fromhex(expected_tag))


if __name__ == "__main__":
    # Quick self-test
    key = b"secret-key"
    message = b"The quick brown fox jumps over the lazy dog"

    # SHA-256
    digest = sha256_hash(message)
    print(f"SHA-256:  {digest.hex()}")

    # HMAC-SHA256
    tag = hmac_sha256(key, message)
    print(f"HMAC:     {tag.hex()}")

    # Verify
    print(f"Valid:    {verify_tag(key, message, tag.hex())}")
    print(f"Tampered: {verify_tag(key, b'TAMPERED', tag.hex())}")
