# SM2 Signature Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement SM2 digital signature algorithm (GM/T 0003-2012) in BoringSSL with TDD approach.

**Architecture:** Core algorithm functions first, then public API wrappers, finally EVP integration. Each phase produces testable code.

**Tech Stack:** C++ (BoringSSL), SM3 hash, EC operations on SM2 curve, DER encoding

---

## File Structure

| File | Purpose |
|------|---------|
| `crypto/sm2/sm2_sign.cc` | Core signature implementation |
| `crypto/sm2/internal.h` | Internal declarations (SM2_DEFAULT_USER_ID, etc.) |
| `include/openssl/sm2.h` | Public API declarations |
| `crypto/sm2/sm2_test.cc` | Unit tests |

---

## Phase 1: Core Algorithm Functions

### Task 1: Add SM2_DEFAULT_USER_ID and SM2_signature_size

**Files:**
- Modify: `crypto/sm2/internal.h`
- Modify: `include/openssl/sm2.h`

- [ ] **Step 1: Write failing test for SM2_signature_size**

Add to `crypto/sm2/sm2_test.cc`:

```cpp
// Test SM2 signature size (DER encoded)
TEST(SM2Test, SignatureSize) {
  // SM2 signature is DER-encoded SEQUENCE { r INTEGER, s INTEGER }
  // r and s are 32 bytes each, DER encoding adds ~8 bytes overhead
  EXPECT_GE(SM2_signature_size(), 70u);
  EXPECT_LE(SM2_signature_size(), 80u);
}
```

- [ ] **Step 2: Build and verify test fails**

```bash
ninja -C build
./build/crypto_test --gtest_filter=SM2Test.SignatureSize
```

Expected: Compilation error (SM2_signature_size undefined)

- [ ] **Step 3: Add SM2_DEFAULT_USER_ID to internal.h**

Add to `crypto/sm2/internal.h`:

```cpp
// SM2 default user ID (GM/T 0003-2012 standard)
#define SM2_DEFAULT_USER_ID "1234567812345678"
#define SM2_DEFAULT_USER_ID_LEN 16
```

- [ ] **Step 4: Add SM2_signature_size declaration to sm2.h**

Add to `include/openssl/sm2.h` after `SM2_decrypt`:

```cpp
// SM2 signature size returns the maximum size of a DER-encoded SM2 signature.
// The actual signature may be smaller.
OPENSSL_EXPORT size_t SM2_signature_size(void);
```

- [ ] **Step 5: Implement SM2_signature_size**

Add to `crypto/sm2/sm2.cc` (or create new file `crypto/sm2/sm2_sign.cc`):

```cpp
size_t SM2_signature_size(void) {
  // SM2 uses 256-bit curve, r and s are 32 bytes each
  // DER encoding: SEQUENCE { INTEGER r, INTEGER s }
  // Maximum: 4 (sequence) + 34 (r with tag) + 34 (s with tag) = 72
  return 72;
}
```

- [ ] **Step 6: Run test to verify it passes**

```bash
ninja -C build
./build/crypto_test --gtest_filter=SM2Test.SignatureSize
```

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add crypto/sm2/internal.h include/openssl/sm2.h crypto/sm2/sm2.cc crypto/sm2/sm2_test.cc
git commit -m "sm2: add SM2_DEFAULT_USER_ID and SM2_signature_size"
```

---

### Task 2: Implement SM2_compute_z_digest

**Files:**
- Modify: `crypto/sm2/internal.h`
- Modify: `include/openssl/sm2.h`
- Create: `crypto/sm2/sm2_sign.cc`
- Modify: `crypto/sm2/sm2_test.cc`

- [ ] **Step 1: Write failing test for SM2_compute_z_digest**

Add to `crypto/sm2/sm2_test.cc`:

```cpp
// Test SM2 Z value computation
// Reference: GM/T 0003-2012, test vector from Tongsuo
TEST(SM2Test, ComputeZDigest) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  // Test with default user ID
  uint8_t z[32];
  EXPECT_TRUE(SM2_compute_z_digest(z, key.get(), nullptr, 0));

  // Test with custom user ID
  const uint8_t id[] = "test_user_id";
  EXPECT_TRUE(SM2_compute_z_digest(z, key.get(), id, sizeof(id) - 1));

  // Z value should be 32 bytes (SM3 output)
  // Verify it's not all zeros
  bool all_zero = true;
  for (int i = 0; i < 32; i++) {
    if (z[i] != 0) {
      all_zero = false;
      break;
    }
  }
  EXPECT_FALSE(all_zero);
}
```

- [ ] **Step 2: Build and verify test fails**

```bash
ninja -C build
./build/crypto_test --gtest_filter=SM2Test.ComputeZDigest
```

Expected: Compilation error (SM2_compute_z_digest undefined)

- [ ] **Step 3: Add declaration to internal.h**

Add to `crypto/sm2/internal.h`:

```cpp
// SM2_compute_z_digest computes Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
// ENTL is 16-bit big-endian bit length of ID.
// If id is NULL, uses SM2_DEFAULT_USER_ID.
// Returns 1 on success, 0 on error.
OPENSSL_EXPORT int SM2_compute_z_digest(uint8_t *out, const EC_KEY *key,
                                        const uint8_t *id, size_t id_len);
```

- [ ] **Step 4: Add declaration to sm2.h**

Add to `include/openssl/sm2.h`:

```cpp
// SM2_compute_z_digest computes the Z value used in SM2 signature.
// Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
// If id is NULL, uses the default user ID "1234567812345678".
// Returns 1 on success, 0 on error.
OPENSSL_EXPORT int SM2_compute_z_digest(uint8_t *out, const EC_KEY *key,
                                        const uint8_t *id, size_t id_len);
```

- [ ] **Step 5: Implement SM2_compute_z_digest**

Create `crypto/sm2/sm2_sign.cc`:

```cpp
// Copyright 2026 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <openssl/sm2.h>

#include <openssl/bn.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/nid.h>

#include <string.h>

#include "../internal.h"
#include "internal.h"


using namespace bssl;

// SM2_compute_z_digest computes Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
int SM2_compute_z_digest(uint8_t *out, const EC_KEY *key,
                         const uint8_t *id, size_t id_len) {
  if (out == NULL || key == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  const EC_GROUP *group = EC_KEY_get0_group(key);
  const EC_POINT *pub_key = EC_KEY_get0_public_key(key);

  if (group == NULL || pub_key == NULL) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_PUBLIC_KEY);
    return 0;
  }

  // Use default ID if none provided
  if (id == NULL) {
    id = (const uint8_t *)SM2_DEFAULT_USER_ID;
    id_len = SM2_DEFAULT_USER_ID_LEN;
  }

  if (id_len >= (UINT16_MAX / 8)) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_ID_TOO_LARGE);
    return 0;
  }

  int ret = 0;
  BN_CTX *ctx = BN_CTX_new();
  EVP_MD_CTX md_ctx;
  EVP_MD_CTX_init(&md_ctx);
  BIGNUM *p = NULL, *a = NULL, *b = NULL;
  BIGNUM *xG = NULL, *yG = NULL, *xA = NULL, *yA = NULL;
  uint8_t *buf = NULL;
  int p_bytes = 0;
  uint16_t entl = (uint16_t)(8 * id_len);

  if (ctx == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
    goto done;
  }

  BN_CTX_start(ctx);
  p = BN_CTX_get(ctx);
  a = BN_CTX_get(ctx);
  b = BN_CTX_get(ctx);
  xG = BN_CTX_get(ctx);
  yG = BN_CTX_get(ctx);
  xA = BN_CTX_get(ctx);
  yA = BN_CTX_get(ctx);

  if (yA == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
    goto done;
  }

  // Initialize SM3 hash
  if (!EVP_DigestInit_ex(&md_ctx, EVP_sm3(), NULL)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
    goto done;
  }

  // Hash ENTL (2 bytes, big-endian)
  uint8_t entl_bytes[2] = {(uint8_t)(entl >> 8), (uint8_t)(entl & 0xFF)};
  if (!EVP_DigestUpdate(&md_ctx, entl_bytes, 2)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
    goto done;
  }

  // Hash ID
  if (id_len > 0 && !EVP_DigestUpdate(&md_ctx, id, id_len)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
    goto done;
  }

  // Get curve parameters
  if (!EC_GROUP_get_curve(group, p, a, b, ctx)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    goto done;
  }

  p_bytes = BN_num_bytes(p);
  buf = (uint8_t *)OPENSSL_zalloc(p_bytes);
  if (buf == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
    goto done;
  }

  // Hash a, b
  if (!BN_bn2bin_padded(buf, p_bytes, a) ||
      !EVP_DigestUpdate(&md_ctx, buf, p_bytes) ||
      !BN_bn2bin_padded(buf, p_bytes, b) ||
      !EVP_DigestUpdate(&md_ctx, buf, p_bytes)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto done;
  }

  // Hash xG, yG (generator point)
  if (!EC_POINT_get_affine_coordinates(group, EC_GROUP_get0_generator(group),
                                        xG, yG, ctx) ||
      !BN_bn2bin_padded(buf, p_bytes, xG) ||
      !EVP_DigestUpdate(&md_ctx, buf, p_bytes) ||
      !BN_bn2bin_padded(buf, p_bytes, yG) ||
      !EVP_DigestUpdate(&md_ctx, buf, p_bytes)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    goto done;
  }

  // Hash xA, yA (public key)
  if (!EC_POINT_get_affine_coordinates(group, pub_key, xA, yA, ctx) ||
      !BN_bn2bin_padded(buf, p_bytes, xA) ||
      !EVP_DigestUpdate(&md_ctx, buf, p_bytes) ||
      !BN_bn2bin_padded(buf, p_bytes, yA) ||
      !EVP_DigestUpdate(&md_ctx, buf, p_bytes)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    goto done;
  }

  // Finalize hash
  if (!EVP_DigestFinal_ex(&md_ctx, out, NULL)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
    goto done;
  }

  ret = 1;

done:
  OPENSSL_free(buf);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  EVP_MD_CTX_cleanup(&md_ctx);
  return ret;
}

size_t SM2_signature_size(void) {
  return 72;
}
```

- [ ] **Step 6: Update build.json**

Add `crypto/sm2/sm2_sign.cc` to build.json under crypto target, then run:

```bash
go run ./util/pregenerate
```

- [ ] **Step 7: Run test to verify it passes**

```bash
ninja -C build
./build/crypto_test --gtest_filter=SM2Test.ComputeZDigest
```

Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add crypto/sm2/sm2_sign.cc crypto/sm2/internal.h include/openssl/sm2.h crypto/sm2/sm2_test.cc build.json gen/sources.*
git commit -m "sm2: implement SM2_compute_z_digest for Z value computation"
```

---

### Task 3: Implement internal sm2_compute_msg_hash

**Files:**
- Modify: `crypto/sm2/internal.h`
- Modify: `crypto/sm2/sm2_sign.cc`
- Modify: `crypto/sm2/sm2_test.cc`

- [ ] **Step 1: Write failing test for sm2_compute_msg_hash**

Add to `crypto/sm2/sm2_test.cc`:

```cpp
// Test internal message hash computation
TEST(SM2Test, ComputeMsgHash) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  const char *msg = "Hello, SM2 Signature!";
  size_t msg_len = strlen(msg);

  // Compute e = SM3(Z || M)
  bssl::UniquePtr<BIGNUM> e(sm2_compute_msg_hash(key.get(), nullptr, 0,
                                                   (const uint8_t *)msg, msg_len));
  ASSERT_TRUE(e);

  // e should be non-zero
  EXPECT_FALSE(BN_is_zero(e.get()));
}
```

- [ ] **Step 2: Build and verify test fails**

```bash
ninja -C build
./build/crypto_test --gtest_filter=SM2Test.ComputeMsgHash
```

Expected: Compilation error

- [ ] **Step 3: Add declaration to internal.h**

Add to `crypto/sm2/internal.h`:

```cpp
// sm2_compute_msg_hash computes e = SM3(Z || msg) where Z is computed
// from the key and user ID. Caller must BN_free() the result.
// Returns NULL on error.
BIGNUM *sm2_compute_msg_hash(const EC_KEY *key,
                              const uint8_t *id, size_t id_len,
                              const uint8_t *msg, size_t msg_len);
```

- [ ] **Step 4: Implement sm2_compute_msg_hash**

Add to `crypto/sm2/sm2_sign.cc`:

```cpp
// sm2_compute_msg_hash computes e = SM3(Z || msg)
BIGNUM *sm2_compute_msg_hash(const EC_KEY *key,
                              const uint8_t *id, size_t id_len,
                              const uint8_t *msg, size_t msg_len) {
  if (key == NULL || msg == NULL) {
    return NULL;
  }

  BIGNUM *e = NULL;
  uint8_t *z = NULL;
  EVP_MD_CTX md_ctx;
  EVP_MD_CTX_init(&md_ctx);

  // Compute Z
  z = (uint8_t *)OPENSSL_malloc(32);  // SM3 output size
  if (z == NULL) {
    goto done;
  }

  if (!SM2_compute_z_digest(z, key, id, id_len)) {
    goto done;
  }

  // Compute e = SM3(Z || msg)
  if (!EVP_DigestInit_ex(&md_ctx, EVP_sm3(), NULL) ||
      !EVP_DigestUpdate(&md_ctx, z, 32) ||
      !EVP_DigestUpdate(&md_ctx, msg, msg_len) ||
      !EVP_DigestFinal_ex(&md_ctx, z, NULL)) {
    goto done;
  }

  // Convert to BIGNUM
  e = BN_bin2bn(z, 32, NULL);

done:
  OPENSSL_free(z);
  EVP_MD_CTX_cleanup(&md_ctx);
  return e;
}
```

- [ ] **Step 5: Run test to verify it passes**

```bash
ninja -C build
./build/crypto_test --gtest_filter=SM2Test.ComputeMsgHash
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crypto/sm2/internal.h crypto/sm2/sm2_sign.cc crypto/sm2/sm2_test.cc
git commit -m "sm2: implement internal sm2_compute_msg_hash"
```

---

### Task 4: Implement sm2_sig_gen (signature generation)

**Files:**
- Modify: `crypto/sm2/internal.h`
- Modify: `crypto/sm2/sm2_sign.cc`
- Modify: `crypto/sm2/sm2_test.cc`

- [ ] **Step 1: Write failing test for sm2_sig_gen**

Add to `crypto/sm2/sm2_test.cc`:

```cpp
// Test SM2 signature generation
TEST(SM2Test, SigGen) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  // Create a test hash value (e)
  bssl::UniquePtr<BIGNUM> e(BN_new());
  ASSERT_TRUE(e);
  BN_set_word(e.get(), 12345);

  // Generate signature
  bssl::UniquePtr<ECDSA_SIG> sig(sm2_sig_gen(key.get(), e.get()));
  ASSERT_TRUE(sig);

  // Verify r and s are not zero and in valid range
  const BIGNUM *r, *s;
  ECDSA_SIG_get0(sig.get(), &r, &s);
  EXPECT_FALSE(BN_is_zero(r));
  EXPECT_FALSE(BN_is_zero(s));

  // r and s should be less than curve order
  const EC_GROUP *group = EC_KEY_get0_group(key.get());
  bssl::UniquePtr<BIGNUM> order(BN_new());
  ASSERT_TRUE(EC_GROUP_get_order(group, order.get(), nullptr));
  EXPECT_LT(BN_cmp(r, order.get()), 0);
  EXPECT_LT(BN_cmp(s, order.get()), 0);
}
```

- [ ] **Step 2: Build and verify test fails**

```bash
ninja -C build
./build/crypto_test --gtest_filter=SM2Test.SigGen
```

Expected: Compilation error

- [ ] **Step 3: Add declaration to internal.h**

Add to `crypto/sm2/internal.h`:

```cpp
// sm2_sig_gen generates an SM2 signature for hash value e.
// Follows GM/T 0003-2012 steps A3-A7.
// Caller must ECDSA_SIG_free() the result.
// Returns NULL on error.
ECDSA_SIG *sm2_sig_gen(const EC_KEY *key, const BIGNUM *e);
```

- [ ] **Step 4: Implement sm2_sig_gen**

Add to `crypto/sm2/sm2_sign.cc`:

```cpp
// sm2_sig_gen generates SM2 signature following GM/T 0003 A3-A7
ECDSA_SIG *sm2_sig_gen(const EC_KEY *key, const BIGNUM *e) {
  if (key == NULL || e == NULL) {
    return NULL;
  }

  const BIGNUM *dA = EC_KEY_get0_private_key(key);
  const EC_GROUP *group = EC_KEY_get0_group(key);
  const BIGNUM *order = EC_GROUP_get0_order(group);

  if (dA == NULL || group == NULL || order == NULL) {
    return NULL;
  }

  ECDSA_SIG *sig = NULL;
  EC_POINT *kG = NULL;
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *k = NULL, *rk = NULL, *x1 = NULL, *tmp = NULL;
  BIGNUM *r = NULL, *s = NULL;

  if (ctx == NULL) {
    goto done;
  }

  kG = EC_POINT_new(group);
  if (kG == NULL) {
    goto done;
  }

  BN_CTX_start(ctx);
  k = BN_CTX_get(ctx);
  rk = BN_CTX_get(ctx);
  x1 = BN_CTX_get(ctx);
  tmp = BN_CTX_get(ctx);
  if (tmp == NULL) {
    goto done;
  }

  r = BN_new();
  s = BN_new();
  if (r == NULL || s == NULL) {
    goto done;
  }

  // Retry loop for signature generation
  for (;;) {
    // A3: Generate random k in [1, n-1]
    if (!BN_rand_range_ex(k, 1, order)) {
      goto done;
    }

    // A4: Compute (x1, y1) = k * G
    if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx) ||
        !EC_POINT_get_affine_coordinates(group, kG, x1, NULL, ctx)) {
      goto done;
    }

    // A5: r = (e + x1) mod n
    if (!BN_mod_add(r, e, x1, order, ctx)) {
      goto done;
    }

    // Retry if r == 0 or r + k == n
    if (BN_is_zero(r)) {
      continue;
    }

    if (!BN_add(rk, r, k)) {
      goto done;
    }
    if (BN_cmp(rk, order) == 0) {
      continue;
    }

    // A6: s = (dA + 1)^{-1} * (k - r * dA) mod n
    if (!BN_add(s, dA, BN_value_one())) {
      goto done;
    }
    // Compute modular inverse of (dA + 1)
    if (!BN_mod_inverse(s, s, order, ctx)) {
      goto done;
    }
    // tmp = r * dA mod n
    if (!BN_mod_mul(tmp, r, dA, order, ctx)) {
      goto done;
    }
    // tmp = k - r * dA
    if (!BN_sub(tmp, k, tmp)) {
      goto done;
    }
    // s = (dA + 1)^{-1} * (k - r * dA) mod n
    if (!BN_mod_mul(s, s, tmp, order, ctx)) {
      goto done;
    }

    // Retry if s == 0
    if (BN_is_zero(s)) {
      continue;
    }

    // A7: Create signature
    sig = ECDSA_SIG_new();
    if (sig == NULL) {
      goto done;
    }
    ECDSA_SIG_set0(sig, r, s);
    r = NULL;
    s = NULL;
    break;
  }

done:
  BN_free(r);
  BN_free(s);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  EC_POINT_free(kG);
  return sig;
}
```

- [ ] **Step 5: Run test to verify it passes**

```bash
ninja -C build
./build/crypto_test --gtest_filter=SM2Test.SigGen
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crypto/sm2/internal.h crypto/sm2/sm2_sign.cc crypto/sm2/sm2_test.cc
git commit -m "sm2: implement sm2_sig_gen for signature generation"
```

---

### Task 5: Implement sm2_sig_verify (signature verification)

**Files:**
- Modify: `crypto/sm2/internal.h`
- Modify: `crypto/sm2/sm2_sign.cc`
- Modify: `crypto/sm2/sm2_test.cc`

- [ ] **Step 1: Write failing test for sm2_sig_verify**

Add to `crypto/sm2/sm2_test.cc`:

```cpp
// Test SM2 signature verification
TEST(SM2Test, SigVerify) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  // Create a test hash value
  bssl::UniquePtr<BIGNUM> e(BN_new());
  ASSERT_TRUE(e);
  BN_set_word(e.get(), 12345);

  // Generate signature
  bssl::UniquePtr<ECDSA_SIG> sig(sm2_sig_gen(key.get(), e.get()));
  ASSERT_TRUE(sig);

  // Verify signature
  EXPECT_EQ(1, sm2_sig_verify(key.get(), sig.get(), e.get()));

  // Verify with wrong hash should fail
  bssl::UniquePtr<BIGNUM> wrong_e(BN_new());
  BN_set_word(wrong_e.get(), 54321);
  EXPECT_EQ(0, sm2_sig_verify(key.get(), sig.get(), wrong_e.get()));
}
```

- [ ] **Step 2: Build and verify test fails**

```bash
ninja -C build
./build/crypto_test --gtest_filter=SM2Test.SigVerify
```

Expected: Compilation error

- [ ] **Step 3: Add declaration to internal.h**

Add to `crypto/sm2/internal.h`:

```cpp
// sm2_sig_verify verifies SM2 signature.
// Follows GM/T 0003-2012 steps B1-B7.
// Returns 1 on success, 0 on failure.
int sm2_sig_verify(const EC_KEY *key, const ECDSA_SIG *sig, const BIGNUM *e);
```

- [ ] **Step 4: Implement sm2_sig_verify**

Add to `crypto/sm2/sm2_sign.cc`:

```cpp
// sm2_sig_verify verifies SM2 signature following GM/T 0003 B1-B7
int sm2_sig_verify(const EC_KEY *key, const ECDSA_SIG *sig, const BIGNUM *e) {
  if (key == NULL || sig == NULL || e == NULL) {
    return 0;
  }

  const EC_GROUP *group = EC_KEY_get0_group(key);
  const EC_POINT *pub_key = EC_KEY_get0_public_key(key);
  const BIGNUM *order = EC_GROUP_get0_order(group);

  if (group == NULL || pub_key == NULL || order == NULL) {
    return 0;
  }

  int ret = 0;
  BN_CTX *ctx = BN_CTX_new();
  EC_POINT *pt = NULL;
  BIGNUM *t = NULL, *x1 = NULL;
  const BIGNUM *r = NULL, *s = NULL;

  if (ctx == NULL) {
    goto done;
  }

  pt = EC_POINT_new(group);
  if (pt == NULL) {
    goto done;
  }

  BN_CTX_start(ctx);
  t = BN_CTX_get(ctx);
  x1 = BN_CTX_get(ctx);
  if (x1 == NULL) {
    goto done;
  }

  ECDSA_SIG_get0(sig, &r, &s);

  // B1-B2: Verify r, s in [1, n-1]
  if (BN_cmp(r, BN_value_one()) < 0 ||
      BN_cmp(s, BN_value_one()) < 0 ||
      BN_cmp(order, r) <= 0 ||
      BN_cmp(order, s) <= 0) {
    goto done;
  }

  // B5: t = (r + s) mod n
  if (!BN_mod_add(t, r, s, order, ctx)) {
    goto done;
  }

  // Fail if t == 0
  if (BN_is_zero(t)) {
    goto done;
  }

  // B6: (x1, y1) = s * G + t * PA
  if (!EC_POINT_mul(group, pt, s, pub_key, t, ctx) ||
      !EC_POINT_get_affine_coordinates(group, pt, x1, NULL, ctx)) {
    goto done;
  }

  // B7: Verify r == (e + x1) mod n
  if (!BN_mod_add(t, e, x1, order, ctx)) {
    goto done;
  }

  if (BN_cmp(r, t) == 0) {
    ret = 1;
  }

done:
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  EC_POINT_free(pt);
  return ret;
}
```

- [ ] **Step 5: Run test to verify it passes**

```bash
ninja -C build
./build/crypto_test --gtest_filter=SM2Test.SigVerify
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crypto/sm2/internal.h crypto/sm2/sm2_sign.cc crypto/sm2/sm2_test.cc
git commit -m "sm2: implement sm2_sig_verify for signature verification"
```

---

## Phase 2: Public API

### Task 6: Implement SM2_sign_with_id and SM2_verify_with_id

**Files:**
- Modify: `include/openssl/sm2.h`
- Modify: `crypto/sm2/sm2_sign.cc`
- Modify: `crypto/sm2/sm2_test.cc`

- [ ] **Step 1: Write failing test for SM2_sign_with_id**

Add to `crypto/sm2/sm2_test.cc`:

```cpp
// Test SM2 sign/verify with user ID
TEST(SM2Test, SignVerifyWithId) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  const char *msg = "Hello, SM2!";
  const uint8_t id[] = "test_id";

  // Sign
  uint8_t sig[72];
  size_t sig_len = sizeof(sig);
  ASSERT_TRUE(SM2_sign_with_id(key.get(), id, sizeof(id) - 1,
                                (const uint8_t *)msg, strlen(msg),
                                sig, &sig_len));

  // Verify
  EXPECT_TRUE(SM2_verify_with_id(key.get(), id, sizeof(id) - 1,
                                  (const uint8_t *)msg, strlen(msg),
                                  sig, sig_len));

  // Verify with wrong message should fail
  const char *wrong_msg = "Wrong message";
  EXPECT_FALSE(SM2_verify_with_id(key.get(), id, sizeof(id) - 1,
                                   (const uint8_t *)wrong_msg, strlen(wrong_msg),
                                   sig, sig_len));
}
```

- [ ] **Step 2: Build and verify test fails**

```bash
ninja -C build
./build/crypto_test --gtest_filter=SM2Test.SignVerifyWithId
```

Expected: Compilation error

- [ ] **Step 3: Add declarations to sm2.h**

Add to `include/openssl/sm2.h`:

```cpp
// SM2_sign_with_id signs |msg_len| bytes from |msg| using |key| and user ID |id|.
// The signature is written to |sig| and its length stored in |*sig_len|.
// The |sig| buffer must have at least |SM2_signature_size()| bytes.
// Returns 1 on success, 0 on error.
OPENSSL_EXPORT int SM2_sign_with_id(const EC_KEY *key,
                                    const uint8_t *id, size_t id_len,
                                    const uint8_t *msg, size_t msg_len,
                                    uint8_t *sig, size_t *sig_len);

// SM2_verify_with_id verifies |sig_len| bytes from |sig| using |key| and user ID |id|.
// Returns 1 on success, 0 on failure.
OPENSSL_EXPORT int SM2_verify_with_id(const EC_KEY *key,
                                      const uint8_t *id, size_t id_len,
                                      const uint8_t *msg, size_t msg_len,
                                      const uint8_t *sig, size_t sig_len);
```

- [ ] **Step 4: Implement SM2_sign_with_id and SM2_verify_with_id**

Add to `crypto/sm2/sm2_sign.cc`:

```cpp
int SM2_sign_with_id(const EC_KEY *key,
                     const uint8_t *id, size_t id_len,
                     const uint8_t *msg, size_t msg_len,
                     uint8_t *sig, size_t *sig_len) {
  if (key == NULL || msg == NULL || sig == NULL || sig_len == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  // Compute e = SM3(Z || msg)
  bssl::UniquePtr<BIGNUM> e(sm2_compute_msg_hash(key, id, id_len, msg, msg_len));
  if (!e) {
    return 0;
  }

  // Generate signature
  bssl::UniquePtr<ECDSA_SIG> sig_struct(sm2_sig_gen(key, e.get()));
  if (!sig_struct) {
    return 0;
  }

  // Encode as DER
  uint8_t *der = NULL;
  size_t der_len;
  if (!ECDSA_SIG_to_bytes(&der, &der_len, sig_struct.get())) {
    return 0;
  }

  if (der_len > *sig_len) {
    OPENSSL_free(der);
    OPENSSL_PUT_ERROR(SM2, SM2_R_BUFFER_TOO_SMALL);
    return 0;
  }

  OPENSSL_memcpy(sig, der, der_len);
  *sig_len = der_len;
  OPENSSL_free(der);
  return 1;
}

int SM2_verify_with_id(const EC_KEY *key,
                       const uint8_t *id, size_t id_len,
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t *sig, size_t sig_len) {
  if (key == NULL || msg == NULL || sig == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  // Parse DER signature
  CBS cbs;
  CBS_init(&cbs, sig, sig_len);
  bssl::UniquePtr<ECDSA_SIG> sig_struct(ECDSA_SIG_parse(&cbs));
  if (!sig_struct || CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_ENCODING);
    return 0;
  }

  // Compute e = SM3(Z || msg)
  bssl::UniquePtr<BIGNUM> e(sm2_compute_msg_hash(key, id, id_len, msg, msg_len));
  if (!e) {
    return 0;
  }

  // Verify signature
  return sm2_sig_verify(key, sig_struct.get(), e.get());
}
```

- [ ] **Step 5: Run test to verify it passes**

```bash
ninja -C build
./build/crypto_test --gtest_filter=SM2Test.SignVerifyWithId
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add include/openssl/sm2.h crypto/sm2/sm2_sign.cc crypto/sm2/sm2_test.cc
git commit -m "sm2: implement SM2_sign_with_id and SM2_verify_with_id"
```

---

### Task 7: Implement SM2_sign and SM2_verify (default ID)

**Files:**
- Modify: `include/openssl/sm2.h`
- Modify: `crypto/sm2/sm2_sign.cc`
- Modify: `crypto/sm2/sm2_test.cc`

- [ ] **Step 1: Write failing test for SM2_sign**

Add to `crypto/sm2/sm2_test.cc`:

```cpp
// Test SM2 sign/verify with default user ID
TEST(SM2Test, SignVerifyDefaultId) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  const char *msg = "Hello, SM2 with default ID!";

  // Sign with default ID
  uint8_t sig[72];
  size_t sig_len = sizeof(sig);
  ASSERT_TRUE(SM2_sign(key.get(),
                        (const uint8_t *)msg, strlen(msg),
                        sig, &sig_len));

  // Verify with default ID
  EXPECT_TRUE(SM2_verify(key.get(),
                          (const uint8_t *)msg, strlen(msg),
                          sig, sig_len));
}
```

- [ ] **Step 2: Build and verify test fails**

```bash
ninja -C build
./build/crypto_test --gtest_filter=SM2Test.SignVerifyDefaultId
```

Expected: Compilation error

- [ ] **Step 3: Add declarations to sm2.h**

Add to `include/openssl/sm2.h`:

```cpp
// SM2_sign signs |msg_len| bytes from |msg| using |key| with default user ID.
// The signature is written to |sig| and its length stored in |*sig_len|.
// Returns 1 on success, 0 on error.
OPENSSL_EXPORT int SM2_sign(const EC_KEY *key,
                            const uint8_t *msg, size_t msg_len,
                            uint8_t *sig, size_t *sig_len);

// SM2_verify verifies |sig_len| bytes from |sig| using |key| with default user ID.
// Returns 1 on success, 0 on failure.
OPENSSL_EXPORT int SM2_verify(const EC_KEY *key,
                              const uint8_t *msg, size_t msg_len,
                              const uint8_t *sig, size_t sig_len);
```

- [ ] **Step 4: Implement SM2_sign and SM2_verify**

Add to `crypto/sm2/sm2_sign.cc`:

```cpp
int SM2_sign(const EC_KEY *key,
             const uint8_t *msg, size_t msg_len,
             uint8_t *sig, size_t *sig_len) {
  return SM2_sign_with_id(key, NULL, 0, msg, msg_len, sig, sig_len);
}

int SM2_verify(const EC_KEY *key,
               const uint8_t *msg, size_t msg_len,
               const uint8_t *sig, size_t sig_len) {
  return SM2_verify_with_id(key, NULL, 0, msg, msg_len, sig, sig_len);
}
```

- [ ] **Step 5: Run test to verify it passes**

```bash
ninja -C build
./build/crypto_test --gtest_filter=SM2Test.SignVerifyDefaultId
```

Expected: PASS

- [ ] **Step 6: Run all SM2 tests**

```bash
./build/crypto_test --gtest_filter=SM2Test*
```

Expected: All tests pass

- [ ] **Step 7: Commit**

```bash
git add include/openssl/sm2.h crypto/sm2/sm2_sign.cc crypto/sm2/sm2_test.cc
git commit -m "sm2: implement SM2_sign and SM2_verify with default user ID"
```

---

### Task 8: Add error codes and update sm2.h

**Files:**
- Modify: `include/openssl/sm2.h`

- [ ] **Step 1: Add new error codes to sm2.h**

Update the error codes section in `include/openssl/sm2.h`:

```cpp
// Error codes for SM2 operations.
#define SM2_R_INVALID_PRIVATE_KEY 100
#define SM2_R_INVALID_PUBLIC_KEY 101
#define SM2_R_INVALID_CIPHERTEXT 102
#define SM2_R_ASN1_ERROR 103
#define SM2_R_DIGEST_MISMATCH 104
#define SM2_R_BUFFER_TOO_SMALL 105
#define SM2_R_INVALID_SIGNATURE 106
#define SM2_R_INVALID_ENCODING 107
#define SM2_R_RANDOM_FAILED 108
#define SM2_R_ID_TOO_LARGE 109
```

- [ ] **Step 2: Build and test**

```bash
ninja -C build
./build/crypto_test --gtest_filter=SM2Test*
```

Expected: All tests pass

- [ ] **Step 3: Commit**

```bash
git add include/openssl/sm2.h
git commit -m "sm2: add error codes for signature operations"
```

---

## Phase 3: EVP Integration (Optional/Future)

Phase 3 (EVP integration) is documented in the spec but can be implemented in a separate effort. The core functionality is complete after Phase 2.

---

## Summary

After completing all tasks:
- SM2 Z value computation implemented
- SM2 message hash computation implemented
- SM2 signature generation implemented (GM/T 0003 A3-A7)
- SM2 signature verification implemented (GM/T 0003 B1-B7)
- Public API: `SM2_sign`, `SM2_verify`, `SM2_sign_with_id`, `SM2_verify_with_id`
- All tests pass
- Ready for EVP integration (Phase 3) if needed
