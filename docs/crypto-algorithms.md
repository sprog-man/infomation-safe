# Crypto Algorithms

This document contains the algorithm principles needed for the experiment report.

---

## 一、AES-128 Encryption

### 1. Basic Principle

AES (Advanced Encryption Standard) is a symmetric block cipher with:
- **Block size**: 128 bits (16 bytes)
- **Key size**: 128 bits (16 bytes)
- **Rounds**: 10
- **Mode**: ECB (Educational purpose; not recommended for production)

### 2. Core Operations

| Operation | Description |
|-----------|-------------|
| **SubBytes** | Non-linear byte substitution using S-Box (GF(2^8) inverse + affine transform) |
| **ShiftRows** | Cyclic shift of row i by i positions |
| **MixColumns** | Linear mixing of each column using polynomial multiplication in GF(2^8) |
| **AddRoundKey** | XOR state with round key derived from key expansion |

### 3. Key Expansion

The 16-byte key is expanded into 11 round keys (176 bytes) using:
- RotWord: cyclic left shift of 4-byte word
- SubWord: S-Box substitution on each byte
- Rcon: round constant XOR (only for first byte of words at indices 4, 8, 12, 16)

### 4. PKCS7 Padding

Plaintext must be multiple of 16 bytes. Padding adds 1-16 bytes, each with value equal to padding length.

### 5. Implementation Files

- `crypto/aes_crypto.py` — Full implementation (~500 lines)
  - S-Box: lines 25-73
  - key_expansion: lines 273-319
  - sub_bytes: lines 149-158
  - shift_rows: lines 171-189
  - mix_columns: lines 209-236
  - add_round_key: lines 258-266
  - aes_encrypt: lines 449-481
  - aes_decrypt: lines 484-517

---

## 二、RSA Key Generation & Encryption

### 1. Basic Principle

RSA is an asymmetric public-key cryptosystem based on integer factorization difficulty.

### 2. Key Generation Steps

1. Generate two large prime numbers p and q (512 bits each → 1024-bit key, or 1024 bits each → 2048-bit key)
2. Compute n = p × q (modulus)
3. Compute φ(n) = (p-1) × (q-1) (Euler's totient)
4. Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1 (commonly e = 65537)
5. Compute d = e^(-1) mod φ(n) (modular multiplicative inverse)
6. Public key: (e, n), Private key: (d, n)

### 3. Encryption / Decryption

- **Encrypt**: c = m^e mod n
- **Decrypt**: m = c^d mod n

Uses PKCS#1 v1.5 padding for security against chosen ciphertext attacks.

### 4. Implementation Files

- `crypto/rsa_crypto.py` — Full implementation (~400 lines)
  - generate_keypair: lines 195-255
  - rsa_encrypt / rsa_decrypt: lines 317-387

---

## 三、HMAC-SHA256 Message Authentication

### 1. SHA-256 Basic Principle

SHA-256 is a cryptographic hash function producing a 256-bit (32-byte) digest.

**Algorithm steps:**
1. **Padding**: Append bit '1' then '0's until message length ≡ 448 mod 512
2. **Append length**: Add 64-bit big-endian representation of original message length
3. **Initialize**: Set 8 hash values (H0-H7) to fractional parts of square roots of first 8 primes
4. **Process blocks**: For each 512-bit block, perform 64 rounds of compression with constants K[0..63]
5. **Output**: Concatenate H0-H7 → 256-bit digest

### 2. HMAC Construction

HMAC(K, m) = H((K' ⊕ op) || H((K' ⊕ ip) || m))

Where:
- K' = H(K) if key longer than block size (64 bytes for SHA-256), else K padded with zeros
- op = 0x5c repeated (outer pad)
- ip = 0x36 repeated (inner pad)
- H = SHA-256

### 3. Implementation Files

- `auth/hmac_auth.py` — Full implementation (~250 lines)
  - SHA-256: lines 83-123
  - HMAC-SHA256: lines 198-239
  - compute_tag / verify_tag: lines 246-236

---

## 四、Overall Security Architecture

```
Sensor JSON ──[AES-128 Encrypt]──→ Ciphertext
                                    │
Session Key ──[RSA-2048 Encrypt]──→ Encrypted Key  ──┐
                                                      ├─→ TCP Transmission
HMAC-SHA256(Ciphertext, Key) ──→ Auth Tag ───────────┘
                                                      │
Server receives ──[HMAC Verify]──→ Accept/Reject ──┐
                                                    ├─→ Decrypt
                                                    │     [RSA Decrypt Key] → AES Key
                                                    │     [AES-128 Decrypt] → Original JSON
```

**Threat model covered:**
- Eavesdropping: AES encryption protects payload confidentiality
- Key exchange: RSA protects session key transmission
- Tampering: HMAC detects any modification of ciphertext
- Replay: Batch ID + timestamp provide basic replay protection
