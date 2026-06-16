import sys
import os
"# Add project root to path for standalone usage"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

"""
aes_crypto.py - AES (Advanced Encryption Standard) Implementation from Scratch

Supports AES-128 encryption and decryption using pure Python.
No external crypto libraries are used.

Algorithm overview:
  - Key size: 128 bits (16 bytes)
  - Block size: 128 bits (16 bytes)
  - Number of rounds: 10
  - Modes: ECB (with PKCS7 padding)

Core operations per round:
  1. SubBytes  - non-linear substitution using S-Box
  2. ShiftRows - cyclic shift of row elements
  3. MixColumns - mixing of column bytes via Galois Field multiplication
  4. AddRoundKey - XOR with round key

The first and last rounds omit MixColumns (first) or SubBytes+ShiftRows+MixColumns (last omits MixColumns).

Comments throughout explain the math and logic.
"""

# ---------------------------------------------------------------------------
# S-Box: Substitution box for SubBytes operation
# ---------------------------------------------------------------------------
# The S-Box is a 16x16 lookup table derived from the inverse affine
# transformation over GF(2^8). It provides the non-linear substitution
# step in AES, making the cipher resistant to linear cryptanalysis.

S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

# Inverse S-Box for decryption
INV_S_BOX = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]

# Round constants for key expansion (Rcon)
# These are used in the key schedule to provide each round with a unique key.
# Rcon[i] = 2^(i-1) in GF(2^8) represented as a 4-byte word with the first byte non-zero.
RCON = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
]


# ---------------------------------------------------------------------------
# Galois Field (GF(2^8)) arithmetic
# ---------------------------------------------------------------------------
# AES operates over the finite field GF(2^8), with the irreducible polynomial
# m(x) = x^8 + x^4 + x^3 + x + 1 = 0x11B.
# All additions are XOR operations. Multiplication uses Russian Peasant
# multiplication with reduction modulo m(x).

def gmul(a: int, b: int) -> int:
    """
    Multiply two numbers in GF(2^8) with irreducible polynomial 0x11B.

    Uses the Russian Peasant (also called "peasant multiplication" or
    "ancient Egyptian multiplication") method:
      - If the low bit of b is 1, XOR the result with a
      - Double a (left shift, with reduction if >= 0x100)
      - Halve b (right shift)
      - Repeat for 8 bits

    This is the core multiplication used in MixColumns.
    """
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        # Double a: left shift by 1
        a <<= 1
        # Reduce modulo 0x11B if the high bit overflowed
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return result


# ---------------------------------------------------------------------------
# State representation
# ---------------------------------------------------------------------------
# The AES state is a 4x4 byte matrix arranged in column-major order.
# Internally we use a flat list of 16 bytes for simplicity.
# Index mapping: state[row][col] -> flat index = row + 4*col

def bytes_to_state(data: bytes) -> list:
    """
    Convert a byte string (16 bytes) to the AES state matrix.

    The input is read column by column: the first 4 bytes fill column 0,
    the next 4 fill column 1, etc. This is column-major layout.

    Returns a list of 16 integers (0-255).
    """
    return list(data)


def state_to_bytes(state: list) -> bytes:
    """
    Convert the AES state matrix back to a byte string.

    Reads the state column by column to reconstruct the original order.
    """
    return bytes(state)


# ---------------------------------------------------------------------------
# Core AES operations
# ---------------------------------------------------------------------------

def sub_bytes(state: list) -> None:
    """
    Apply the SubBytes transformation to the state.

    Each byte in the state is replaced by looking up the S-Box table.
    This is the only non-linear operation in AES and provides confusion.
    Modifies the state list in-place.
    """
    for i in range(16):
        state[i] = S_BOX[state[i]]


def inv_sub_bytes(state: list) -> None:
    """
    Apply the inverse SubBytes transformation during decryption.

    Each byte is replaced using the inverse S-Box table.
    """
    for i in range(16):
        state[i] = INV_S_BOX[state[i]]


def shift_rows(state: list) -> None:
    """
    Apply the ShiftRows transformation.

    Each row of the 4x4 state matrix is shifted cyclically:
      - Row 0: no shift
      - Row 1: shift left by 1 position
      - Row 2: shift left by 2 positions
      - Row 3: shift left by 3 positions

    The state is stored in column-major order, so we use the formula:
      state[row + 4*col] -> state[row + 4*((col + shift) % 4)]
    """
    # Row 1: shift left by 1
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    # Row 2: shift left by 2
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    # Row 3: shift left by 3 (equivalent to shift right by 1)
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]


def inv_shift_rows(state: list) -> None:
    """
    Apply the inverse ShiftRows transformation during decryption.

    Reverse of shift_rows: shift RIGHT instead of left.
      - Row 1: shift right by 1
      - Row 2: shift right by 2
      - Row 3: shift right by 3 (equivalent to shift left by 1)
    """
    # Row 1: shift right by 1
    state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
    # Row 2: shift right by 2
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    # Row 3: shift right by 3 (shift left by 1)
    state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]


def mix_columns(state: list) -> None:
    """
    Apply the MixColumns transformation.

    Each column is treated as a polynomial over GF(2^8) and multiplied
    modulo (x^4 + 1) with a fixed polynomial c(x) = {03}x^3 + {01}x^2 +
    {01}x + {03}.

    In matrix form:
      |02 03 01 01|   |s0|
      |01 02 03 01| * |s1|
      |01 01 02 03|   |s2|
      |03 01 01 02|   |s3|

    This provides diffusion by spreading bytes across columns.
    """
    for col in range(4):
        # Get the column as a list of 4 bytes
        s0 = state[col * 4 + 0]
        s1 = state[col * 4 + 1]
        s2 = state[col * 4 + 2]
        s3 = state[col * 4 + 3]

        # Multiply each row of the mixing matrix
        state[col * 4 + 0] = gmul(s0, 2) ^ gmul(s1, 3) ^ s2 ^ s3
        state[col * 4 + 1] = s0 ^ gmul(s1, 2) ^ gmul(s2, 3) ^ s3
        state[col * 4 + 2] = s0 ^ s1 ^ gmul(s2, 2) ^ gmul(s3, 3)
        state[col * 4 + 3] = gmul(s0, 3) ^ s1 ^ s2 ^ gmul(s3, 2)


def inv_mix_columns(state: list) -> None:
    """
    Apply the inverse MixColumns transformation during decryption.

    Uses the inverse mixing matrix with coefficients {0E}, {0B}, {0D}, {09}.
    These are the multiplicative inverses in GF(2^8) of the forward coefficients.
    """
    for col in range(4):
        s0 = state[col * 4 + 0]
        s1 = state[col * 4 + 1]
        s2 = state[col * 4 + 2]
        s3 = state[col * 4 + 3]

        state[col * 4 + 0] = gmul(s0, 14) ^ gmul(s1, 11) ^ gmul(s2, 13) ^ gmul(s3, 9)
        state[col * 4 + 1] = gmul(s0, 9) ^ gmul(s1, 14) ^ gmul(s2, 11) ^ gmul(s3, 13)
        state[col * 4 + 2] = gmul(s0, 13) ^ gmul(s1, 9) ^ gmul(s2, 14) ^ gmul(s3, 11)
        state[col * 4 + 3] = gmul(s0, 11) ^ gmul(s1, 13) ^ gmul(s2, 9) ^ gmul(s3, 14)


def add_round_key(state: list, round_key: list) -> None:
    """
    XOR the state with the round key.

    This is the only step where the secret key material enters the
    encryption process. It binds the ciphertext to the key.
    """
    for i in range(16):
        state[i] ^= round_key[i]


# ---------------------------------------------------------------------------
# Key expansion
# ---------------------------------------------------------------------------

def key_expansion(key: bytes) -> list:
    """
    Expand the 16-byte AES-128 key into 11 round keys (176 bytes total).

    The key schedule generates 44 32-bit words (W[0]..W[43]), grouped
    into 11 round keys of 16 bytes each.

    Algorithm:
      - The first 4 words are the original key.
      - For words 4-43:
          - If the index is a multiple of 4, apply a special transformation:
            1. RotWord: cyclically shift the 4 bytes left by 1
            2. SubWord: substitute each byte with the S-Box
            3. XOR with the round constant Rcon
          - XOR the result with the word 4 positions earlier
    """
    # The key schedule works on 32-bit words (4 bytes each)
    nk = 4  # Number of 32-bit words in the key (128 bits / 32)
    nr = 10 + 1  # Number of round keys = rounds + 1

    # Initialize the word array with the original key
    w = []
    for i in range(nk):
        w.append([key[4*i], key[4*i + 1], key[4*i + 2], key[4*i + 3]])

    # Generate the remaining words
    for i in range(nk, 4 * (nr)):
        temp = list(w[i - 1])
        if i % nk == 0:
            # RotWord: rotate bytes left by 1
            temp = [temp[1], temp[2], temp[3], temp[0]]
            # SubWord: apply S-Box to each byte
            temp = [S_BOX[b] for b in temp]
            # XOR with round constant
            temp[0] ^= RCON[i // nk]
        # XOR with the word nk positions earlier
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])

    # Group words into round keys (16 bytes each)
    round_keys = []
    for r in range(nr):
        rk = []
        for word_idx in range(4):
            rk.extend(w[r * 4 + word_idx])
        round_keys.append(rk)

    return round_keys


# ---------------------------------------------------------------------------
# AES block cipher
# ---------------------------------------------------------------------------

def aes_encrypt_block(plaintext_block: bytes, round_keys: list) -> bytes:
    """
    Encrypt a single 16-byte block using AES-128.

    Parameters
    ----------
    plaintext_block : bytes
        Exactly 16 bytes of plaintext.
    round_keys : list
        Pre-computed round keys from key_expansion.

    Returns
    -------
    bytes
        16 bytes of ciphertext.

    Process (for AES-128, 10 rounds):
      0. AddRoundKey (initial)
      Round 1-9:  SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
      Round 10:   SubBytes -> ShiftRows -> AddRoundKey (no MixColumns)
    """
    state = bytes_to_state(plaintext_block)

    # Initial AddRoundKey
    add_round_key(state, round_keys[0])

    # Rounds 1 through 9
    for r in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[r])

    # Final round 10 (no MixColumns)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])

    return state_to_bytes(state)


def aes_decrypt_block(ciphertext_block: bytes, round_keys: list) -> bytes:
    """
    Decrypt a single 16-byte block using AES-128.

    Parameters
    ----------
    ciphertext_block : bytes
        Exactly 16 bytes of ciphertext.
    round_keys : list
        Pre-computed round keys from key_expansion.

    Returns
    -------
    bytes
        16 bytes of plaintext.

    The decryption is the inverse of encryption:
      0. AddRoundKey (using the last round key)
      Round 1-9:  InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns
      Round 10:   InvShiftRows -> InvSubBytes -> AddRoundKey (no InvMixColumns)
    """
    state = bytes_to_state(ciphertext_block)

    # Initial AddRoundKey (reverse of last round)
    add_round_key(state, round_keys[10])

    # Rounds 9 through 1
    for r in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[r])
        inv_mix_columns(state)

    # Final round (reverse of initial AddRoundKey)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])

    return state_to_bytes(state)


# ---------------------------------------------------------------------------
# PKCS7 padding
# ---------------------------------------------------------------------------

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Apply PKCS7 padding to make data a multiple of block_size.

    PKCS7 pads with N bytes each having the value N, where N = block_size -
    (len(data) % block_size). If data is already aligned, a full block of
    padding (16 bytes of value 0x10) is added.

    This ensures the plaintext is always a valid multiple of the block size.
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """
    Remove PKCS7 padding from data.

    Reads the last byte to determine the number of padding bytes and
    validates them. Returns the unpadded data.
    """
    if len(data) == 0:
        raise ValueError("Cannot unpad empty data")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError(f"Invalid padding value: {pad_len}")
    # Verify all padding bytes have the same value
    for i in range(pad_len):
        if data[-(i + 1)] != pad_len:
            raise ValueError("Invalid PKCS7 padding")
    return data[:-pad_len]


# ---------------------------------------------------------------------------
# High-level AES interface (ECB mode)
# ---------------------------------------------------------------------------

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt arbitrary-length plaintext using AES-128 in ECB mode with PKCS7 padding.

    Parameters
    ----------
    plaintext : bytes
        Data to encrypt (any length).
    key : bytes
        16-byte encryption key.

    Returns
    -------
    bytes
        Encrypted ciphertext.

    Steps:
      1. Expand the key into round keys
      2. Pad the plaintext to a multiple of 16 bytes
      3. Encrypt each 16-byte block independently
    """
    if len(key) != 16:
        raise ValueError("Key must be exactly 16 bytes for AES-128")

    round_keys = key_expansion(key)
    padded = pkcs7_pad(plaintext)

    ciphertext = b""
    for i in range(0, len(padded), 16):
        block = padded[i:i + 16]
        ciphertext += aes_encrypt_block(block, round_keys)

    return ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-128 ECB ciphertext with PKCS7 padding.

    Parameters
    ----------
    ciphertext : bytes
        Encrypted data (must be a multiple of 16 bytes).
    key : bytes
        16-byte decryption key (same as encryption key).

    Returns
    -------
    bytes
        Decrypted plaintext with padding removed.

    Steps:
      1. Expand the key into round keys
      2. Decrypt each 16-byte block independently
      3. Remove PKCS7 padding
    """
    if len(key) != 16:
        raise ValueError("Key must be exactly 16 bytes for AES-128")
    if len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16 bytes")

    round_keys = key_expansion(key)
    plaintext = b""

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        plaintext += aes_decrypt_block(block, round_keys)

    return pkcs7_unpad(plaintext)


if __name__ == "__main__":
    # Quick self-test
    key = b"0123456789ABCDEF"  # 16-byte key
    message = b"Hello, AES from scratch!"
    print(f"Original:  {message}")

    encrypted = aes_encrypt(message, key)
    print(f"Encrypted: {encrypted.hex()}")

    decrypted = aes_decrypt(encrypted, key)
    print(f"Decrypted: {decrypted}")

    assert decrypted == message, "Round-trip failed!"
    print("\n[AES] Round-trip test PASSED.")
