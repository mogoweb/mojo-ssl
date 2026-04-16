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
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>

#include <string.h>

#include "../internal.h"
#include "internal.h"


// SM2_compute_z_digest computes Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
// per GM/T 0003-2012 section 5.5.
// ENTL is 16-bit big-endian bit length of ID.
// If id is NULL, uses SM2_DEFAULT_USER_ID.
// Returns 1 on success, 0 on error.
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

  // Use default user ID if not provided
  if (id == NULL) {
    id = reinterpret_cast<const uint8_t *>(SM2_DEFAULT_USER_ID);
    id_len = SM2_DEFAULT_USER_ID_LEN;
  }

  // Validate ID length to prevent overflow in entl computation
  // Max ID length: (2^16 - 1) / 8 bits = 8191 bytes
  if (id_len > 8191) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_ID_TOO_LARGE);
    return 0;
  }

  int ret = 0;
  BN_CTX *bn_ctx = BN_CTX_new();
  BIGNUM *a = BN_new();
  BIGNUM *b = BN_new();
  BIGNUM *xG = BN_new();
  BIGNUM *yG = BN_new();
  BIGNUM *xA = BN_new();
  BIGNUM *yA = BN_new();
  uint8_t *buf = NULL;
  const EC_POINT *generator = NULL;
  size_t field_size = 0;
  uint16_t entl;
  uint8_t entl_bytes[2];
  EVP_MD_CTX md_ctx;
  EVP_MD_CTX_init(&md_ctx);

  if (bn_ctx == NULL || a == NULL || b == NULL ||
      xG == NULL || yG == NULL || xA == NULL || yA == NULL) {
    goto err;
  }

  // Get curve parameters a and b
  if (!EC_GROUP_get_curve_GFp(group, NULL, a, b, bn_ctx)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    goto err;
  }

  // Get generator point coordinates (xG, yG)
  generator = EC_GROUP_get0_generator(group);
  if (generator == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto err;
  }
  if (!EC_POINT_get_affine_coordinates(group, generator, xG, yG, bn_ctx)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    goto err;
  }

  // Get public key coordinates (xA, yA)
  if (!EC_POINT_get_affine_coordinates(group, pub_key, xA, yA, bn_ctx)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    goto err;
  }

  // Determine field size for padding
  field_size = BN_num_bytes(a);  // a, b, xG, yG, xA, yA all have same size
  if (field_size == 0) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  // Allocate buffer for converting BIGNUMs to bytes
  buf = reinterpret_cast<uint8_t *>(OPENSSL_malloc(field_size));
  if (buf == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_MALLOC_FAILURE);
    goto err;
  }

  // Compute Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA)

  // Initialize SM3 hash
  if (!EVP_DigestInit_ex(&md_ctx, EVP_sm3(), NULL)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
    goto err;
  }

  // ENTL: 16-bit big-endian bit length of ID
  entl = (uint16_t)(id_len * 8);  // Bit length
  entl_bytes[0] = (uint8_t)(entl >> 8);
  entl_bytes[1] = (uint8_t)(entl & 0xFF);

  if (!EVP_DigestUpdate(&md_ctx, entl_bytes, 2)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
    goto err;
  }

  // ID
  if (id_len > 0 && !EVP_DigestUpdate(&md_ctx, id, id_len)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
    goto err;
  }

  // a
  if (!BN_bn2bin_padded(buf, field_size, a) ||
      !EVP_DigestUpdate(&md_ctx, buf, field_size)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  // b
  if (!BN_bn2bin_padded(buf, field_size, b) ||
      !EVP_DigestUpdate(&md_ctx, buf, field_size)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  // xG
  if (!BN_bn2bin_padded(buf, field_size, xG) ||
      !EVP_DigestUpdate(&md_ctx, buf, field_size)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  // yG
  if (!BN_bn2bin_padded(buf, field_size, yG) ||
      !EVP_DigestUpdate(&md_ctx, buf, field_size)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  // xA
  if (!BN_bn2bin_padded(buf, field_size, xA) ||
      !EVP_DigestUpdate(&md_ctx, buf, field_size)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  // yA
  if (!BN_bn2bin_padded(buf, field_size, yA) ||
      !EVP_DigestUpdate(&md_ctx, buf, field_size)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  // Finalize hash
  if (!EVP_DigestFinal_ex(&md_ctx, out, NULL)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EVP_LIB);
    goto err;
  }

  ret = 1;

err:
  EVP_MD_CTX_cleanup(&md_ctx);
  BN_CTX_free(bn_ctx);
  BN_free(a);
  BN_free(b);
  BN_free(xG);
  BN_free(yG);
  BN_free(xA);
  BN_free(yA);
  OPENSSL_free(buf);
  return ret;
}

// sm2_compute_msg_hash computes e = SM3(Z || msg)
BIGNUM *sm2_compute_msg_hash(const EC_KEY *key,
                              const uint8_t *id, size_t id_len,
                              const uint8_t *msg, size_t msg_len) {
  if (key == NULL || msg == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return NULL;
  }

  BIGNUM *e = NULL;
  uint8_t *z = NULL;
  EVP_MD_CTX md_ctx;
  EVP_MD_CTX_init(&md_ctx);

  // Compute Z
  z = reinterpret_cast<uint8_t *>(OPENSSL_malloc(32));  // SM3 output size
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

// sm2_sig_gen generates SM2 signature following GM/T 0003-2012 A3-A7
// A3: Generate random k in [1, n-1]
// A4: Compute (x1, y1) = k * G
// A5: r = (e + x1) mod n, retry if r=0 or r+k=n
// A6: s = (dA + 1)^{-1} * (k - r * dA) mod n, retry if s=0
// A7: Output (r, s)
ECDSA_SIG *sm2_sig_gen(const EC_KEY *key, const BIGNUM *e) {
  if (key == NULL || e == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return NULL;
  }

  const BIGNUM *dA = EC_KEY_get0_private_key(key);
  const EC_GROUP *group = EC_KEY_get0_group(key);

  if (dA == NULL || group == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return NULL;
  }

  // Get curve order first (must be before any goto)
  const BIGNUM *order = EC_GROUP_get0_order(group);
  if (order == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    return NULL;
  }

  ECDSA_SIG *sig = NULL;
  EC_POINT *kG = NULL;
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *k = NULL, *rk = NULL, *x1 = NULL, *tmp = NULL;
  BIGNUM *r = NULL, *s = NULL;
  int iterations = 0;

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
  static const int kMaxIterations = 32;
  for (;;) {
    if (++iterations > kMaxIterations) {
      OPENSSL_PUT_ERROR(SM2, SM2_R_TOO_MANY_ITERATIONS);
      goto done;
    }

    // A3: Generate random k in [1, n-1]
    // BN_rand_range generates in [0, n-1], so we retry if k=0
    if (!BN_rand_range(k, order)) {
      OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
      goto done;
    }
    // Ensure k is not zero
    if (BN_is_zero(k)) {
      continue;
    }

    // A4: Compute (x1, y1) = k * G
    if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx) ||
        !EC_POINT_get_affine_coordinates(group, kG, x1, NULL, ctx)) {
      OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
      goto done;
    }

    // A5: r = (e + x1) mod n
    if (!BN_mod_add(r, e, x1, order, ctx)) {
      OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
      goto done;
    }

    // Retry if r == 0 or r + k == n
    if (BN_is_zero(r)) {
      continue;
    }

    if (!BN_add(rk, r, k)) {
      OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
      goto done;
    }
    if (BN_cmp(rk, order) == 0) {
      continue;
    }

    // A6: s = (dA + 1)^{-1} * (k - r * dA) mod n
    // Compute (dA + 1)
    if (!BN_add(s, dA, BN_value_one())) {
      OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
      goto done;
    }
    // Compute modular inverse of (dA + 1)
    if (!BN_mod_inverse(s, s, order, ctx)) {
      // If inverse doesn't exist, retry with new k
      continue;
    }
    // tmp = r * dA mod n
    if (!BN_mod_mul(tmp, r, dA, order, ctx)) {
      OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
      goto done;
    }
    // tmp = k - r * dA (can be negative, handle with mod)
    if (!BN_sub(tmp, k, tmp)) {
      OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
      goto done;
    }
    // Ensure tmp is positive mod n
    if (BN_is_negative(tmp)) {
      if (!BN_add(tmp, tmp, order)) {
        OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
        goto done;
      }
    }
    // s = (dA + 1)^{-1} * (k - r * dA) mod n
    if (!BN_mod_mul(s, s, tmp, order, ctx)) {
      OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
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
    if (!ECDSA_SIG_set0(sig, r, s)) {
      goto done;
    }
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

// sm2_sig_verify verifies SM2 signature following GM/T 0003-2012 B1-B7
// B1-B2: Verify r, s in [1, n-1]
// B5: t = (r + s) mod n, fail if t == 0
// B6: (x1, y1) = s*G + t*PA
// B7: r == (e + x1) mod n
int sm2_sig_verify(const EC_KEY *key, const ECDSA_SIG *sig, const BIGNUM *e) {
  if (key == NULL || sig == NULL || e == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  const EC_GROUP *group = EC_KEY_get0_group(key);
  const EC_POINT *pub_key = EC_KEY_get0_public_key(key);

  if (group == NULL || pub_key == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  // Get curve order
  const BIGNUM *order = EC_GROUP_get0_order(group);
  if (order == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    return 0;
  }

  // B1-B2: Get r, s from signature and verify they are in [1, n-1]
  const BIGNUM *r, *s;
  ECDSA_SIG_get0(sig, &r, &s);

  // Verify r >= 1 and r < n
  if (BN_is_zero(r) || BN_cmp(r, order) >= 0) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_SIGNATURE);
    return 0;
  }

  // Verify s >= 1 and s < n
  if (BN_is_zero(s) || BN_cmp(s, order) >= 0) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_SIGNATURE);
    return 0;
  }

  int ret = 0;
  BN_CTX *ctx = BN_CTX_new();
  EC_POINT *pt = NULL;
  BIGNUM *t = NULL, *x1 = NULL, *v = NULL;

  if (ctx == NULL) {
    goto done;
  }

  BN_CTX_start(ctx);
  t = BN_CTX_get(ctx);
  x1 = BN_CTX_get(ctx);
  v = BN_CTX_get(ctx);
  if (v == NULL) {
    goto done;
  }

  // B5: t = (r + s) mod n
  if (!BN_mod_add(t, r, s, order, ctx)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
    goto done;
  }

  // Fail if t == 0
  if (BN_is_zero(t)) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_SIGNATURE);
    goto done;
  }

  // B6: (x1, y1) = s*G + t*PA
  pt = EC_POINT_new(group);
  if (pt == NULL) {
    goto done;
  }

  // Compute pt = s*G + t*pub_key
  if (!EC_POINT_mul(group, pt, s, pub_key, t, ctx)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    goto done;
  }

  // Get x1 coordinate
  if (!EC_POINT_get_affine_coordinates(group, pt, x1, NULL, ctx)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    goto done;
  }

  // B7: v = (e + x1) mod n
  if (!BN_mod_add(v, e, x1, order, ctx)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_BN_LIB);
    goto done;
  }

  // Verify r == v (constant-time comparison to prevent timing attacks)
  if (!BN_equal_consttime(r, v)) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_SIGNATURE);
    goto done;
  }

  ret = 1;

done:
  EC_POINT_free(pt);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return ret;
}
