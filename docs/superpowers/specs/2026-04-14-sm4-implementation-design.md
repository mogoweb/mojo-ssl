# SM4 Implementation Design

## Overview

Implement SM4 symmetric block cipher (GB/T 32907-2016) in BoringSSL, following the hybrid approach: port Tongsuo's core algorithm while using BoringSSL's EVP cipher patterns.

## Goals

- Provide SM4 core API: `SM4_set_key`, `SM4_encrypt`, `SM4_decrypt`
- Support 5 cipher modes via EVP: ECB, CBC, CTR, OFB, CFB
- Use test-driven development with GM/T 32907-2016 test vectors
- Software-only implementation (no hardware acceleration)

## Non-Goals

- Hardware acceleration (ARMv8 SM4 instructions)
- Authenticated encryption modes (GCM, CCM)
- White-box SM4 implementations

## File Structure

```
crypto/sm4/
├── sm4.cc              # Core algorithm implementation
├── sm4_test.cc         # GTest unit tests
└── sm4_tests.txt       # Test vectors (not in build.json)

include/openssl/
└── sm4.h               # Public API header

crypto/cipher/
└── e_sm4.cc            # EVP_CIPHER integration

Files to modify:
- build.json            # Add new source files
- include/openssl/cipher.h  # Add EVP_sm4_* declarations
```

## Public API

### Core API (`include/openssl/sm4.h`)

```c
#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SCHEDULE 32

typedef struct SM4_KEY_st {
  uint32_t rk[SM4_KEY_SCHEDULE];
} SM4_KEY;

// Set encryption/decryption key (same function, same key schedule)
int SM4_set_key(const uint8_t *key, SM4_KEY *ks);

// Encrypt one 16-byte block
void SM4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);

// Decrypt one 16-byte block
void SM4_decrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);
```

### EVP Interface (`include/openssl/cipher.h`)

```c
OPENSSL_EXPORT const EVP_CIPHER *EVP_sm4_ecb(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_sm4_cbc(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_sm4_ctr(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_sm4_ofb(void);
OPENSSL_EXPORT const EVP_CIPHER *EVP_sm4_cfb(void);
```

## Core Algorithm Details

### SM4 Parameters

| Parameter | Value |
|-----------|-------|
| Key length | 128 bits (16 bytes) |
| Block size | 128 bits (16 bytes) |
| Rounds | 32 |
| Round key size | 32 × 32 bits |

### Implementation Components

1. **S-box (`SM4_S[256]`)** - Nonlinear substitution defined by GB/T 32907-2016

2. **Precomputed T-tables (`SM4_SBOX_T0-T3[256]`)** - Combines S-box substitution with linear transform L for fast middle rounds

3. **Slow T function (`SM4_T_slow`)** - Byte-wise S-box lookup, used for first/last 4 rounds to mitigate cache timing side channels

4. **Fast T function (`SM4_T`)** - Table lookup using precomputed tables, used for middle 24 rounds

5. **Key expansion** - Generates 32 round keys from 128-bit key using system parameters FK and constant keys CK

6. **Encryption** - 32-round unbalanced Feistel structure

7. **Decryption** - Same structure as encryption, using round keys in reverse order

### Side-Channel Mitigation

Following Tongsuo's approach:
- First 4 rounds and last 4 rounds use `SM4_T_slow` (byte-wise S-box)
- Middle 24 rounds use `SM4_T` (fast table lookup)
- This reduces cache timing leakage on inputs/outputs

## EVP Mode Implementation

Following BoringSSL's existing cipher patterns in `crypto/cipher/e_aes*.cc`:

### ECB Mode
- Simplest: direct block cipher calls
- Block size: 16, IV length: 0, Key length: 16
- No padding in BoringSSL (caller handles)

### CBC Mode
- Uses `CRYPTO_cbc128_encrypt` / `CRYPTO_cbc128_decrypt` helpers
- Block size: 16, IV length: 16, Key length: 16

### CTR Mode
- Uses `CRYPTO_ctr128_encrypt_ctr32` helper
- Treated as stream cipher (block size 1 for API purposes)
- IV length: 16, Key length: 16

### OFB Mode
- Uses `CRYPTO_ofb128_encrypt` helper
- Treated as stream cipher
- IV length: 16, Key length: 16

### CFB Mode
- Uses `CRYPTO_cfb128_encrypt` helper
- Treated as stream cipher
- IV length: 16, Key length: 16

## Testing

### Test Vectors

Using GM/T 32907-2016 standard test vectors:

**Example 1 (single encryption):**
```
Key:        0123456789ABCDEFFEDCBA9876543210
Plaintext:  0123456789ABCDEFFEDCBA9876543210
Ciphertext: 681EDF34D206965E86B3E94F536E4246
```

**Example 2 (1 million iterations):**
```
Key:        0123456789ABCDEFFEDCBA9876543210
Plaintext:  0123456789ABCDEFFEDCBA9876543210
After 1M encryptions:
Ciphertext: 595298C7C6FD271F0402F804C33D3F66
```

### Test Cases

1. **Core algorithm tests** (`sm4_test.cc`)
   - Example 1: Single encryption/decryption
   - Example 2: 1 million iteration test
   - Streaming API verification

2. **EVP mode tests**
   - Each mode (ECB, CBC, CTR, OFB, CFB) encrypt/decrypt round-trip
   - Multi-block test
   - IV handling verification

## Build System Integration

### build.json additions

```json
{
  "srcs": [
    "crypto/sm4/sm4.cc",
    "crypto/cipher/e_sm4.cc"
  ],
  "hdrs": [
    "include/openssl/sm4.h"
  ],
  "crypto_test_srcs": [
    "crypto/sm4/sm4_test.cc"
  ]
}
```

Note: `sm4_tests.txt` is NOT added to build.json (test data file read at runtime)

### Build steps

1. Edit `build.json` to add new files
2. Run `go run ./util/pregenerate` to regenerate `gen/sources.*`
3. Rebuild: `cmake -GNinja -B build && ninja -C build`

## TDD Implementation Order

1. **Create header** - `include/openssl/sm4.h` with API declarations
2. **Write tests** - `crypto/sm4/sm4_test.cc` (will fail to compile)
3. **Implement core** - `crypto/sm4/sm4.cc` (tests should pass)
4. **Implement EVP** - `crypto/cipher/e_sm4.cc`
5. **Update build** - Edit `build.json`, run pregenerate
6. **Verify** - Run `ninja -C build run_tests`

## References

- GB/T 32907-2016 - SM4 block cipher standard (Chinese national standard)
- Tongsuo implementation: `../Tongsuo/crypto/sm4/sm4.c`
- Tongsuo documentation: `docs/tongsuo/sm4.md`
- BoringSSL AES pattern: `crypto/fipsmodule/aes/`
- BoringSSL cipher pattern: `crypto/cipher/e_aes*.cc`
- Existing SM3 pattern: `crypto/sm3/`
