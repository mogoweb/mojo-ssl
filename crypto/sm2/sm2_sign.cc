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
