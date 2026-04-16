# SM2 EVP Integration Design

## Summary

Implement SM2 as a separate EVP key type (`EVP_PKEY_SM2`) in BoringSSL, enabling `EVP_DigestSign`/`EVP_DigestVerify` API, key generation, import/export, and X.509 certificate integration.

## Background

BoringSSL already has SM2 signature functions (`SM2_sign`/`SM2_verify`) and treats SM2 curve as an EC variant. However, SM2 is **not ECDSA** - it requires Z value computation and uses a different signature algorithm (GM/T 0003-2012). The current EC EVP implementation calls ECDSA functions, which is incorrect for SM2 keys.

This design creates a dedicated SM2 EVP type that reuses EC_KEY internally but provides SM2-specific signing and verification.

## Design Decisions

1. **Separate key type**: `EVP_PKEY_SM2` with OID `1.2.156.10197.1.301`
2. **Internal storage**: Reuse `EC_KEY` structure for key material
3. **Digest**: SM3 only (enforced, GM/T 0003 standard)
4. **User ID**: Default `"1234567812345678"`, optional custom via `EVP_PKEY_CTX_set_sm2_user_id`
5. **Signature format**: DER-encoded (SEQUENCE { r INTEGER, s INTEGER })

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                     Public API (evp.h)                      │
│  EVP_PKEY_SM2, EVP_pkey_sm2(), EVP_DigestSign/Verify        │
├─────────────────────────────────────────────────────────────┤
│                  crypto/evp/p_sm2.cc                        │
│  ┌─────────────────────┐  ┌─────────────────────────────┐   │
│  │  sm2_asn1_meth      │  │  sm2_pkey_meth              │   │
│  │  - pub/priv encode  │  │  - keygen                   │   │
│  │  - pub/priv decode  │  │  - sign/verify              │   │
│  │  - OID: sm2         │  │  - digestsign/digestverify  │   │
│  └─────────────────────┘  └─────────────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                  crypto/sm2/sm2_sign.cc                     │
│  SM2_sign, SM2_verify, SM2_compute_z_digest                 │
│  (existing implementation)                                   │
├─────────────────────────────────────────────────────────────┤
│                  crypto/ec/*                                │
│  EC_KEY, EC_POINT, EC_GROUP                                 │
│  (reused for key storage)                                   │
└─────────────────────────────────────────────────────────────┘
```

### Key Type Definition

```c
// include/openssl/evp.h
#define EVP_PKEY_SM2 NID_sm2  // OID: 1.2.156.10197.1.301

OPENSSL_EXPORT const EVP_PKEY_ALG *EVP_pkey_sm2(void);

// Accessor functions (EC_KEY reused internally)
OPENSSL_EXPORT int EVP_PKEY_set1_SM2(EVP_PKEY *pkey, EC_KEY *key);
OPENSSL_EXPORT int EVP_PKEY_assign_SM2(EVP_PKEY *pkey, EC_KEY *key);
OPENSSL_EXPORT EC_KEY *EVP_PKEY_get0_SM2(const EVP_PKEY *pkey);
OPENSSL_EXPORT EC_KEY *EVP_PKEY_get1_SM2(const EVP_PKEY *pkey);

// User ID control
OPENSSL_EXPORT int EVP_PKEY_CTX_set_sm2_user_id(EVP_PKEY_CTX *ctx,
                                                 const uint8_t *id, size_t id_len);
```

### ASN.1 Method

The `sm2_asn1_meth` handles key encoding/decoding:

| Method | Implementation |
|--------|----------------|
| `pub_decode` | Parse SEC1 uncompressed point, create EC_KEY with SM2 group |
| `pub_encode` | Encode EC_KEY public point as SEC1 uncompressed |
| `priv_decode` | Parse SEC1 private key, create EC_KEY with SM2 group |
| `priv_encode` | Encode EC_KEY private key as SEC1 |
| OID | `1.2.156.10197.1.301` (NID_sm2) |

### PKEY Method

The `sm2_pkey_meth` handles cryptographic operations:

| Method | Implementation |
|--------|----------------|
| `init` | Allocate SM2_PKEY_CTX (stores user_id, md_ctx) |
| `copy` | Copy SM2_PKEY_CTX state |
| `cleanup` | Free SM2_PKEY_CTX |
| `keygen` | Generate EC_KEY on SM2 curve via SM2_generate_key |
| `sign` | DER-encoded signature via SM2_sign |
| `verify` | Verify DER-encoded signature via SM2_verify |
| `digestsign_init` | Initialize SM3, flag Z not computed |
| `digestsign_update` | Compute Z on first call, feed to SM3 |
| `digestsign_final` | Finalize SM3, call SM2_sign |
| `digestverify_*` | Same flow, call SM2_verify at end |
| `ctrl` | Handle EVP_PKEY_CTRL_SM2_USER_ID |

## Data Flow

### Signing with EVP_DigestSign

```
EVP_DigestSignInit(pkey, EVP_sm3())
  │
  ▼
pkey_sm2_digestsign_init()
  ├─ Initialize SM3 context
  ├─ Set user_id = default or custom
  └─ Set flag: z_computed = false
  │
  ▼
EVP_DigestSignUpdate(data)
  │
  ▼
pkey_sm2_digestsign_update()
  ├─ if (!z_computed):
  │    ├─ Compute Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
  │    ├─ Feed Z to SM3 context
  │    └─ z_computed = true
  └─ Feed data to SM3 context
  │
  ▼
EVP_DigestSignFinal()
  │
  ▼
pkey_sm2_digestsign_final()
  ├─ Finalize SM3: e = SM3(Z || M)
  ├─ Generate signature: (r, s) via sm2_sig_gen()
  ├─ DER encode signature
  └─ Return signature bytes
```

### Verification with EVP_DigestVerify

```
EVP_DigestVerifyInit(pkey, EVP_sm3())
  │
  ▼
pkey_sm2_digestverify_init()
  ├─ Same as digestsign_init
  │
  ▼
EVP_DigestVerifyUpdate(data)
  │
  ▼
pkey_sm2_digestverify_update()
  ├─ Same as digestsign_update (compute Z, feed data)
  │
  ▼
EVP_DigestVerifyFinal(sig)
  │
  ▼
pkey_sm2_digestverify_final()
  ├─ Finalize SM3: e = SM3(Z || M)
  ├─ Parse DER signature to (r, s)
  ├─ Verify via sm2_sig_verify()
  └─ Return 1 on success, 0 on failure
```

## Files to Create/Modify

### New Files

| File | Purpose |
|------|---------|
| `crypto/evp/p_sm2.cc` | SM2 EVP implementation (ASN.1 + PKEY methods) |

### Modified Files

| File | Changes |
|------|---------|
| `include/openssl/evp.h` | Add EVP_PKEY_SM2, accessor functions, EVP_pkey_sm2() |
| `crypto/evp/internal.h` | Declare sm2_pkey_meth, sm2_asn1_meth |
| `crypto/evp/evp.cc` | Register SM2 method in lookup tables |
| `crypto/sm2/internal.h` | Expose SM2_DEFAULT_USER_ID if needed |
| `crypto/sm2/sm2_test.cc` | Add EVP integration tests |
| `build.json` | Add p_sm2.cc to crypto sources |

## Certificate Integration

SM2 certificates use the `SM2-with-SM3` signature algorithm (OID `1.2.156.10197.1.501`).

When verifying a certificate signed with SM2-with-SM3:
1. Parse certificate, extract public key as `EVP_PKEY_SM2`
2. Extract signature (DER-encoded)
3. Call `EVP_DigestVerify` with the certificate's tbsCertificate as message
4. SM3 hash and SM2 verification happen automatically

The existing `NID_SM2_with_SM3` in `obj_xref.cc` already maps to `(NID_sm3, NID_sm2)`.

## Error Handling

Add new error codes if needed:

```c
#define SM2_R_USER_ID_TOO_LARGE 110
#define SM2_R_DIGEST_NOT_ALLOWED 111  // If non-SM3 digest used
```

## Testing Strategy

### Unit Tests

1. **Key generation**: `EVP_PKEY_keygen` produces valid SM2 keys
2. **Sign/verify roundtrip**: Sign with private key, verify with public key
3. **Import/export**: DER-encoded keys roundtrip correctly
4. **Custom user ID**: `EVP_PKEY_CTX_set_sm2_user_id` affects signature
5. **Error cases**: Wrong key, tampered signature, wrong digest

### Interop Tests

1. Verify BoringSSL signatures against Tongsuo test vectors
2. Cross-verify: sign with EVP, verify with SM2_verify() and vice versa

### Test Vectors

Use existing SM2 test data and Tongsuo reference implementation at `../Tongsuo/`.

## Implementation Phases

### Phase 1: Core EVP Type
- Create `p_sm2.cc` with ASN.1 method skeleton
- Add `EVP_PKEY_SM2` define and `EVP_pkey_sm2()` function
- Implement pub/priv encode/decode (reuse EC functions)
- Register in `evp.cc`
- Basic tests: key import/export

### Phase 2: Sign/Verify Operations
- Implement PKEY method with sign/verify
- Implement digestsign/digestverify methods
- Z value computation integration
- Tests: sign/verify roundtrip

### Phase 3: Key Management
- Implement keygen method
- Implement user ID control
- Tests: key generation, custom user ID

### Phase 4: Certificate Integration
- Verify SM2 certificates work with X.509 verification
- Integration tests with TLCP

## References

- GM/T 0003-2012 (Chinese national standard)
- `docs/tongsuo/sm2_verify.md` - Tongsuo EVP implementation reference
- `docs/superpowers/plans/2026-04-16-sm2-signature.md` - Existing SM2 signature implementation
