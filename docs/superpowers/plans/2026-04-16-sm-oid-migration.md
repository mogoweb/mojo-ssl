# SM OID Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate all SM (Chinese cryptographic standard) OID definitions from Tongsuo to BoringSSL for TLCP support.

**Architecture:** Add hierarchical OID definitions to `objects.txt`, regenerate headers via `objects.go`, and manually add signature algorithm cross-reference to `obj_xref.cc`.

**Tech Stack:** Go (for OID generation), C++ (BoringSSL), CMake/Ninja (build)

---

## File Structure

| File | Responsibility |
|------|----------------|
| `crypto/obj/objects.txt` | Source OID definitions (human-readable) |
| `crypto/obj/obj_xref.cc` | Signature algorithm cross-reference table |
| `crypto/obj/obj_mac.num` | NID number assignments (generated) |
| `include/openssl/nid.h` | NID macros (generated) |
| `crypto/obj/obj_dat.h` | DER-encoded OID data (generated) |

---

### Task 1: Update objects.txt with SM OID Definitions

**Files:**
- Modify: `crypto/obj/objects.txt`

- [ ] **Step 1: Remove existing inline SM2 definition and add hierarchical SM OIDs**

Locate lines 111-113 in `crypto/obj/objects.txt`:
```
# SM2 curve (GM/T 0003-2012)
# OID: 1.2.156.10197.1.301
member-body 156 10197 1 301	: SM2			: sm2
```

Replace with the complete SM OID hierarchy:
```
# Chinese national cryptographic algorithms (GM/T series)
# OID root: 1.2.156.10197.1 (sm-scheme)
member-body 156         : ISO-CN        : ISO CN Member Body
ISO-CN 10197            : oscca
oscca 1                 : sm-scheme

# SM2 elliptic curve (GM/T 0003-2012)
# OID: 1.2.156.10197.1.301
sm-scheme 301           : SM2           : sm2

# SM3 hash algorithm (GM/T 0004-2012)
# OID: 1.2.156.10197.1.401
sm-scheme 401           : SM3           : sm3

# SM2-with-SM3 signature algorithm (GM/T 0003-2012)
# OID: 1.2.156.10197.1.501
sm-scheme 501           : SM2-SM3       : SM2-with-SM3

# SM4 symmetric cipher (GM/T 0002-2012)
# OID: 1.2.156.10197.1.104.x
sm-scheme 104 1         : SM4-ECB       : sm4-ecb
sm-scheme 104 2         : SM4-CBC       : sm4-cbc
!Cname sm4-ofb128
sm-scheme 104 3         : SM4-OFB       : sm4-ofb
!Cname sm4-cfb128
sm-scheme 104 4         : SM4-CFB       : sm4-cfb
sm-scheme 104 7         : SM4-CTR       : sm4-ctr
sm-scheme 104 8         : SM4-GCM       : sm4-gcm
sm-scheme 104 9         : SM4-CCM       : sm4-ccm

# RSA with SM3 signature algorithm
# OID: 1.2.156.10197.1.504
sm-scheme 504           : RSA-SM3       : sm3WithRSAEncryption

# HMAC with SM3
# OID: 1.2.156.10197.1.401.3.1
sm3 3 1                 :               : hmacWithSM3

# ZUC stream cipher (GM/T 0001-2012)
# OID: 1.2.156.10197.1.201
sm-scheme 201           : ZUC           : zuc

# ZUC-based algorithms for 4G LTE
# OID: 1.2.156.10197.1.801, 1.2.156.10197.1.802
sm-scheme 801           : ZUC-128-EEA3  : zuc-128-eea3
sm-scheme 802           : ZUC-128-EIA3  : zuc-128-eia3

# TLS key exchange and authentication methods for SM2
                        : KxSM2         : kx-sm2
                        : KxSM2DHE      : kx-sm2dhe
                        : AuthSM2       : auth-sm2
```

- [ ] **Step 2: Commit objects.txt changes**

```bash
git add crypto/obj/objects.txt
git commit -m "obj: add SM OID definitions for TLCP support

Add hierarchical OID definitions for Chinese national cryptographic
algorithms including SM2, SM3, SM4, ZUC, and related algorithms."
```

---

### Task 2: Regenerate OID Header Files

**Files:**
- Modify: `crypto/obj/obj_mac.num` (generated)
- Modify: `include/openssl/nid.h` (generated)
- Modify: `crypto/obj/obj_dat.h` (generated)

- [ ] **Step 1: Run the OID generation script**

```bash
cd crypto/obj && go run objects.go
```

Expected output: No errors. The script regenerates:
- `obj_mac.num` - NID assignments
- `../../include/openssl/nid.h` - NID macros
- `obj_dat.h` - DER-encoded OID data

- [ ] **Step 2: Verify generated NID macros exist**

Check that the following NIDs are defined in the generated `nid.h`:
```bash
grep -E "NID_sm2|NID_sm3|NID_SM2_with_SM3|NID_sm4" include/openssl/nid.h
```

Expected: Multiple lines showing NID definitions for sm2, sm3, SM2_with_SM3, sm4 variants.

- [ ] **Step 3: Commit generated files**

```bash
git add crypto/obj/obj_mac.num include/openssl/nid.h crypto/obj/obj_dat.h
git commit -m "obj: regenerate headers with SM OID definitions"
```

---

### Task 3: Add Signature Algorithm Cross-Reference

**Files:**
- Modify: `crypto/obj/obj_xref.cc`

- [ ] **Step 1: Add SM2-with-SM3 to kTriples array**

In `crypto/obj/obj_xref.cc`, locate the `kTriples` array (around line 26). Add the SM2-with-SM3 entry before the closing brace:

```cpp
static const nid_triple kTriples[] = {
    // RSA PKCS#1.
    {NID_md4WithRSAEncryption, NID_md4, NID_rsaEncryption},
    {NID_md5WithRSAEncryption, NID_md5, NID_rsaEncryption},
    {NID_sha1WithRSAEncryption, NID_sha1, NID_rsaEncryption},
    {NID_sha224WithRSAEncryption, NID_sha224, NID_rsaEncryption},
    {NID_sha256WithRSAEncryption, NID_sha256, NID_rsaEncryption},
    {NID_sha384WithRSAEncryption, NID_sha384, NID_rsaEncryption},
    {NID_sha512WithRSAEncryption, NID_sha512, NID_rsaEncryption},
    // DSA.
    {NID_dsaWithSHA1, NID_sha1, NID_dsa},
    {NID_dsaWithSHA1_2, NID_sha1, NID_dsa_2},
    {NID_dsa_with_SHA224, NID_sha224, NID_dsa},
    {NID_dsa_with_SHA256, NID_sha256, NID_dsa},
    // ECDSA.
    {NID_ecdsa_with_SHA1, NID_sha1, NID_X9_62_id_ecPublicKey},
    {NID_ecdsa_with_SHA224, NID_sha224, NID_X9_62_id_ecPublicKey},
    {NID_ecdsa_with_SHA256, NID_sha256, NID_X9_62_id_ecPublicKey},
    {NID_ecdsa_with_SHA384, NID_sha384, NID_X9_62_id_ecPublicKey},
    {NID_ecdsa_with_SHA512, NID_sha512, NID_X9_62_id_ecPublicKey},
    // The following algorithms use more complex (or simpler) parameters. The
    // digest "undef" indicates the caller should handle this explicitly.
    {NID_rsassaPss, NID_undef, NID_rsaEncryption},
    {NID_ED25519, NID_undef, NID_ED25519},
    {NID_ML_DSA_44, NID_undef, NID_ML_DSA_44},
    {NID_ML_DSA_65, NID_undef, NID_ML_DSA_65},
    {NID_ML_DSA_87, NID_undef, NID_ML_DSA_87},
    // SM2-with-SM3 signature algorithm (GM/T 0003-2012).
    {NID_SM2_with_SM3, NID_sm3, NID_sm2},
};
```

- [ ] **Step 2: Commit obj_xref.cc changes**

```bash
git add crypto/obj/obj_xref.cc
git commit -m "obj: add SM2-with-SM3 signature algorithm cross-reference

Add NID_SM2_with_SM3 mapping to kTriples for TLS certificate
verification in TLCP."
```

---

### Task 4: Build and Test

**Files:**
- Test: `build/crypto_test`

- [ ] **Step 1: Build the project**

```bash
cmake -GNinja -B build
ninja -C build
```

Expected: Build succeeds with no errors.

- [ ] **Step 2: Run OBJ tests**

```bash
./build/crypto_test --gtest_filter=ObjTest*
```

Expected: All tests pass.

- [ ] **Step 3: Verify SM OID lookups work**

Create a simple test program or use GDB to verify:

```bash
# Quick verification using crypto_test
./build/crypto_test --gtest_filter=ObjTest.ByShortName
./build/crypto_test --gtest_filter=ObjTest.ByLongName
```

Expected: Tests pass, SM OIDs are resolvable.

---

### Task 5: Final Verification and Documentation

**Files:**
- Modify: `docs/tongsuo/oid.md` (update to reflect migration)

- [ ] **Step 1: Verify all SM OIDs are defined**

```bash
# Check that all expected NIDs are in nid.h
grep -c "NID_sm" include/openssl/nid.h
```

Expected: Count should be 15+ (sm2, sm3, SM2_with_SM3, sm4 variants, zuc, etc.)

- [ ] **Step 2: Update documentation**

Update `docs/tongsuo/oid.md` to note that SM OIDs are now natively defined in BoringSSL.

- [ ] **Step 3: Final commit**

```bash
git add docs/tongsuo/oid.md
git commit -m "docs: update OID documentation for native SM OID support"
```

---

## Summary

After completing all tasks:
- SM OID hierarchy is defined in `objects.txt`
- NID macros are generated in `nid.h`
- DER encodings are in `obj_dat.h`
- SM2-with-SM3 signature cross-reference is in `obj_xref.cc`
- All tests pass
- TLCP support is enabled for OID resolution
