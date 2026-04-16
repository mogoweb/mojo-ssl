# SM2 Signature Algorithm Implementation

## Summary

Implement SM2 digital signature algorithm (GM/T 0003-2012) in BoringSSL, including core signature functions, simple API wrappers, and EVP integration. Follow TDD (Test-Driven Development) approach.

## Background

SM2 is a Chinese national cryptographic standard for elliptic curve digital signatures. BoringSSL already has SM2 encryption/decryption (`SM2_encrypt`/`SM2_decrypt`) but lacks signature functionality. Tongsuo (Alibaba's OpenSSL fork) has a complete implementation that can serve as reference.

## Design Decisions

1. **API Style**: Both simple C functions and EVP integration
2. **User ID**: Optional parameter with default value (`SM2_DEFAULT_USER_ID = "1234567812345678"`)
3. **Signature Format**: DER-encoded (ECDSA style: `SEQUENCE { r INTEGER, s INTEGER }`)

## Implementation Phases

### Phase 1: Core Algorithm Functions

Implement internal functions in `crypto/sm2/sm2_sign.cc`:

- `SM2_compute_z_digest()` - Compute Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
- `sm2_compute_msg_hash()` - Compute e = SM3(Z || M), return as BIGNUM
- `sm2_sig_gen()` - Generate signature following GM/T 0003 steps A3-A7
- `sm2_sig_verify()` - Verify signature following GM/T 0003 steps B1-B7

### Phase 2: Public API

Add to `include/openssl/sm2.h`:

```c
// SM2 signature with user ID
OPENSSL_EXPORT int SM2_sign_with_id(const EC_KEY *key,
                                    const uint8_t *id, size_t id_len,
                                    const uint8_t *msg, size_t msg_len,
                                    uint8_t *sig, size_t *sig_len);

OPENSSL_EXPORT int SM2_verify_with_id(const EC_KEY *key,
                                      const uint8_t *id, size_t id_len,
                                      const uint8_t *msg, size_t msg_len,
                                      const uint8_t *sig, size_t sig_len);

// SM2 signature with default user ID
OPENSSL_EXPORT int SM2_sign(const EC_KEY *key,
                            const uint8_t *msg, size_t msg_len,
                            uint8_t *sig, size_t *sig_len);

OPENSSL_EXPORT int SM2_verify(const EC_KEY *key,
                              const uint8_t *msg, size_t msg_len,
                              const uint8_t *sig, size_t sig_len);

// Signature size helper
OPENSSL_EXPORT size_t SM2_signature_size(void);
```

### Phase 3: EVP Integration

Create `crypto/evp/p_sm2.cc` for EVP_PKEY_METHOD:

- Register `EVP_PKEY_SM2` method
- Implement `pkey_sm2_sign`, `pkey_sm2_verify`, `pkey_sm2_digestsign`, `pkey_sm2_digestverify`
- Enable usage with `EVP_DigestSignInit`/`EVP_DigestVerifyInit`

## Algorithm Details

### Z Value Computation (GM/T 0003)

```
Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
```

Where:
- ENTL = 16-bit big-endian bit length of ID
- ID = User identifier string
- a, b = Curve parameters
- xG, yG = Generator point coordinates
- xA, yA = User public key coordinates

### Message Hash

```
e = SM3(Z || M)
```

Where M is the message to be signed.

### Signature Generation (GM/T 0003 A3-A7)

| Step | Operation | Description |
|------|-----------|-------------|
| A3 | `k = random(1, n-1)` | Generate random k |
| A4 | `(x1, y1) = k·G` | Compute point |
| A5 | `r = (e + x1) mod n` | If r=0 or r+k=n, retry |
| A6 | `s = (dA+1)⁻¹·(k - r·dA) mod n` | If s=0, retry |
| A7 | Output DER(r, s) | DER-encoded signature |

### Signature Verification (GM/T 0003 B1-B7)

| Step | Operation | Description |
|------|-----------|-------------|
| B1-B2 | Verify r, s ∈ [1, n-1] | Range check |
| B5 | `t = (r + s) mod n` | If t=0, fail |
| B6 | `(x1, y1) = s·G + t·PA` | Compute point |
| B7 | Verify r == (e + x1) mod n | Check signature |

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `crypto/sm2/sm2_sign.cc` | Create | Core signature implementation |
| `crypto/sm2/internal.h` | Modify | Internal declarations |
| `include/openssl/sm2.h` | Modify | Public API |
| `crypto/sm2/sm2_test.cc` | Modify | Unit tests |
| `crypto/evp/p_sm2.cc` | Create | EVP integration (Phase 3) |
| `crypto/evp/evp.cc` | Modify | Register SM2 method (Phase 3) |
| `include/openssl/evp.h` | Modify | Add EVP_PKEY_SM2 (Phase 3) |
| `crypto/obj/obj_xref.cc` | Already done | SM2-with-SM3 cross-reference |

## Error Codes

Add to `include/openssl/sm2.h`:

```c
#define SM2_R_INVALID_SIGNATURE 106
#define SM2_R_INVALID_ENCODING 107
#define SM2_R_RANDOM_FAILED 108
```

## Testing Strategy (TDD)

1. **Z Value Tests**: Verify Z computation against Tongsuo test vectors
2. **Hash Tests**: Verify e = SM3(Z || M) computation
3. **Signature Generation Tests**: Test signature creation and retry logic
4. **Signature Verification Tests**: Test verification of valid/invalid signatures
5. **Round-trip Tests**: Sign then verify with same key
6. **Interop Tests**: Verify signatures against Tongsuo test vectors
7. **Edge Cases**: r=0, s=0, t=0 scenarios
8. **EVP Tests**: EVP_DigestSign/EVP_DigestVerify integration tests

## References

- GM/T 0003-2012 (Chinese national standard)
- `docs/tongsuo/sm2_sign.md` - Tongsuo implementation reference
- Tongsuo source: `crypto/sm2/sm2_sign.c`
