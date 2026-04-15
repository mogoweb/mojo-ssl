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
#include <openssl/bytestring.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>

#include <string.h>

#include "../internal.h"
#include "internal.h"


using namespace bssl;

// SM2 encryption produces ciphertext in the following ASN.1 DER format:
// SM2Cipher ::= SEQUENCE {
//   C1x INTEGER,          -- x coordinate of C1 = k*G
//   C1y INTEGER,          -- y coordinate of C1 = k*G
//   C3 OCTET STRING,      -- SM3(x2 || M || y2)
//   C2 OCTET STRING       -- M XOR KDF(x2 || y2, len(M))
// }

// sm2_compute_c3 computes C3 = SM3(x2 || M || y2)
// where (x2, y2) are the coordinates of k*Ppub (encryption) or d*C1 (decryption)
static int sm2_compute_c3(uint8_t *out, const BIGNUM *x2, const BIGNUM *y2,
                          const uint8_t *message, size_t message_len) {
  // Convert coordinates to big-endian byte arrays
  const size_t field_size = BN_num_bytes(x2);  // x2 and y2 should have same size
  if (field_size == 0 || BN_num_bytes(y2) != field_size) {
    return 0;
  }

  uint8_t *x2_bytes = reinterpret_cast<uint8_t *>(OPENSSL_malloc(field_size));
  uint8_t *y2_bytes = reinterpret_cast<uint8_t *>(OPENSSL_malloc(field_size));

  if (x2_bytes == NULL || y2_bytes == NULL) {
    OPENSSL_free(x2_bytes);
    OPENSSL_free(y2_bytes);
    return 0;
  }

  int ret = 0;
  EVP_MD_CTX ctx;
  EVP_MD_CTX_init(&ctx);

  // Convert coordinates to bytes
  if (!BN_bn2bin_padded(x2_bytes, field_size, x2) ||
      !BN_bn2bin_padded(y2_bytes, field_size, y2)) {
    goto err;
  }

  // C3 = SM3(x2 || M || y2)
  if (!EVP_DigestInit_ex(&ctx, EVP_sm3(), NULL) ||
      !EVP_DigestUpdate(&ctx, x2_bytes, field_size) ||
      !EVP_DigestUpdate(&ctx, message, message_len) ||
      !EVP_DigestUpdate(&ctx, y2_bytes, field_size) ||
      !EVP_DigestFinal_ex(&ctx, out, NULL)) {
    goto err;
  }

  ret = 1;

err:
  EVP_MD_CTX_cleanup(&ctx);
  OPENSSL_free(x2_bytes);
  OPENSSL_free(y2_bytes);
  return ret;
}

int SM2_encrypt(const EC_KEY *key,
                const uint8_t *plaintext, size_t plaintext_len,
                uint8_t *ciphertext, size_t *ciphertext_len) {
  if (key == NULL || plaintext == NULL || ciphertext_len == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  // Empty plaintext is not supported
  if (plaintext_len == 0) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  const EC_GROUP *group = EC_KEY_get0_group(key);
  const EC_POINT *pub_key = EC_KEY_get0_public_key(key);

  if (group == NULL || pub_key == NULL) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_PUBLIC_KEY);
    return 0;
  }

  // Check buffer size
  size_t required_len = SM2_ciphertext_size(plaintext_len);
  if (ciphertext == NULL) {
    *ciphertext_len = required_len;
    return 1;
  }

  if (*ciphertext_len < required_len) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_BUFFER_TOO_SMALL);
    return 0;
  }

  int ret = 0;
  BN_CTX *bn_ctx = NULL;
  BIGNUM *k = NULL;
  BIGNUM *x1 = NULL;
  BIGNUM *y1 = NULL;
  BIGNUM *x2 = NULL;
  BIGNUM *y2 = NULL;
  EC_POINT *C1 = NULL;
  EC_POINT *kP = NULL;
  uint8_t *KDF_out = NULL;
  uint8_t *C2 = NULL;
  uint8_t *z = NULL;
  uint8_t C3[32];  // SM3 digest size is 32 bytes
  size_t field_size = 0;
  size_t z_len = 0;
  const BIGNUM *order = NULL;

  bn_ctx = BN_CTX_new();
  k = BN_new();
  x1 = BN_new();
  y1 = BN_new();
  x2 = BN_new();
  y2 = BN_new();
  C1 = EC_POINT_new(group);
  kP = EC_POINT_new(group);

  if (bn_ctx == NULL || k == NULL || x1 == NULL || y1 == NULL ||
      x2 == NULL || y2 == NULL || C1 == NULL || kP == NULL) {
    goto err;
  }

  // Step 1: Generate random k in [1, n-1)
  order = EC_GROUP_get0_order(group);

  // SM2 requires k in [1, n-1)
  // BN_rand_range gives [0, n-1], so we use BN_rand_range_ex with min=1
  if (!BN_rand_range_ex(k, 1, order)) {
    goto err;
  }

  // Step 2: C1 = k * G = (x1, y1)
  if (!EC_POINT_mul(group, C1, k, NULL, NULL, bn_ctx) ||
      !EC_POINT_get_affine_coordinates(group, C1, x1, y1, bn_ctx)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    goto err;
  }

  // Step 3: kP = k * P = (x2, y2), where P is the recipient's public key
  if (!EC_POINT_mul(group, kP, NULL, pub_key, k, bn_ctx) ||
      !EC_POINT_get_affine_coordinates(group, kP, x2, y2, bn_ctx)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    goto err;
  }

  // Step 4: t = KDF(x2 || y2, plaintext_len)
  field_size = BN_num_bytes(x2);
  if (field_size == 0 || BN_num_bytes(y2) != field_size) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  // Allocate buffer for x2 || y2
  z_len = 2 * field_size;
  z = reinterpret_cast<uint8_t *>(OPENSSL_malloc(z_len));
  if (z == NULL) {
    goto err;
  }

  if (!BN_bn2bin_padded(z, field_size, x2) ||
      !BN_bn2bin_padded(z + field_size, field_size, y2)) {
    OPENSSL_free(z);
    z = NULL;
    goto err;
  }

  // Allocate KDF output buffer
  KDF_out = reinterpret_cast<uint8_t *>(OPENSSL_malloc(plaintext_len));
  if (KDF_out == NULL) {
    OPENSSL_free(z);
    z = NULL;
    goto err;
  }

  // Compute KDF
  if (!sm2_kdf(KDF_out, plaintext_len, z, z_len, EVP_sm3())) {
    OPENSSL_cleanse(z, z_len);
    OPENSSL_free(z);
    z = NULL;
    OPENSSL_free(KDF_out);
    KDF_out = NULL;
    goto err;
  }
  OPENSSL_cleanse(z, z_len);
  OPENSSL_free(z);
  z = NULL;

  // Step 5: C2 = M XOR t
  C2 = reinterpret_cast<uint8_t *>(OPENSSL_malloc(plaintext_len));
  if (C2 == NULL) {
    goto err;
  }

  for (size_t i = 0; i < plaintext_len; i++) {
    C2[i] = plaintext[i] ^ KDF_out[i];
  }
  OPENSSL_free(KDF_out);
  KDF_out = NULL;

  // Step 6: C3 = SM3(x2 || M || y2)
  if (!sm2_compute_c3(C3, x2, y2, plaintext, plaintext_len)) {
    OPENSSL_free(C2);
    C2 = NULL;
    goto err;
  }

  // Step 7: Encode ciphertext as ASN.1 DER
  // SEQUENCE { C1x INTEGER, C1y INTEGER, C3 OCTET STRING, C2 OCTET STRING }
  CBB cbb, child;
  CBB_zero(&cbb);
  if (!CBB_init(&cbb, SM2_ciphertext_size(plaintext_len)) ||
      !CBB_add_asn1(&cbb, &child, CBS_ASN1_SEQUENCE) ||
      !BN_marshal_asn1(&child, x1) ||
      !BN_marshal_asn1(&child, y1) ||
      !CBB_add_asn1_octet_string(&child, C3, sizeof(C3)) ||
      !CBB_add_asn1_octet_string(&child, C2, plaintext_len) ||
      !CBB_finish(&cbb, &ciphertext, ciphertext_len)) {
    CBB_cleanup(&cbb);
    OPENSSL_PUT_ERROR(SM2, SM2_R_ASN1_ERROR);
    OPENSSL_free(C2);
    C2 = NULL;
    goto err;
  }

  OPENSSL_cleanse(C2, plaintext_len);
  OPENSSL_free(C2);
  C2 = NULL;
  ret = 1;

err:
  BN_CTX_free(bn_ctx);
  BN_free(k);
  BN_free(x1);
  BN_free(y1);
  BN_free(x2);
  BN_free(y2);
  EC_POINT_free(C1);
  EC_POINT_free(kP);
  OPENSSL_cleanse(C3, sizeof(C3));
  if (KDF_out != NULL) {
    OPENSSL_cleanse(KDF_out, plaintext_len);
    OPENSSL_free(KDF_out);
  }
  if (C2 != NULL) {
    OPENSSL_cleanse(C2, plaintext_len);
    OPENSSL_free(C2);
  }
  return ret;
}

int SM2_decrypt(const EC_KEY *key,
                const uint8_t *ciphertext, size_t ciphertext_len,
                uint8_t *plaintext, size_t *plaintext_len) {
  if (key == NULL || ciphertext == NULL || plaintext_len == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  const EC_GROUP *group = EC_KEY_get0_group(key);
  const BIGNUM *priv_key = EC_KEY_get0_private_key(key);

  if (group == NULL || priv_key == NULL) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_PRIVATE_KEY);
    return 0;
  }

  // Check buffer size
  if (plaintext == NULL) {
    *plaintext_len = SM2_plaintext_size(ciphertext_len);
    return 1;
  }

  int ret = 0;
  BN_CTX *bn_ctx = NULL;
  BIGNUM *x1 = NULL;
  BIGNUM *y1 = NULL;
  BIGNUM *x2 = NULL;
  BIGNUM *y2 = NULL;
  EC_POINT *C1 = NULL;
  uint8_t *KDF_out = NULL;
  uint8_t *M = NULL;
  uint8_t *z = NULL;
  uint8_t C3_computed[32];
  uint8_t *C3 = NULL;
  uint8_t *C2 = NULL;
  size_t C2_len = 0;
  size_t field_size = 0;
  size_t z_len = 0;
  size_t max_plaintext_len = 0;

  bn_ctx = BN_CTX_new();
  x1 = BN_new();
  y1 = BN_new();
  x2 = BN_new();
  y2 = BN_new();
  C1 = EC_POINT_new(group);

  if (bn_ctx == NULL || x1 == NULL || y1 == NULL || x2 == NULL ||
      y2 == NULL || C1 == NULL) {
    goto err;
  }

  // Step 1: Parse ASN.1 DER ciphertext
  // SEQUENCE { C1x INTEGER, C1y INTEGER, C3 OCTET STRING, C2 OCTET STRING }
  CBS cbs, child, c3_cbs, c2_cbs;
  CBS_init(&cbs, ciphertext, ciphertext_len);

  if (!CBS_get_asn1(&cbs, &child, CBS_ASN1_SEQUENCE) ||
      !BN_parse_asn1_unsigned(&child, x1) ||
      !BN_parse_asn1_unsigned(&child, y1) ||
      !CBS_get_asn1(&child, &c3_cbs, CBS_ASN1_OCTETSTRING) ||
      !CBS_get_asn1(&child, &c2_cbs, CBS_ASN1_OCTETSTRING) ||
      CBS_len(&child) != 0 || CBS_len(&cbs) != 0) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_ASN1_ERROR);
    goto err;
  }

  // Validate C3 length (SM3 digest is 32 bytes)
  if (CBS_len(&c3_cbs) != 32) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_CIPHERTEXT);
    goto err;
  }

  C3 = const_cast<uint8_t *>(CBS_data(&c3_cbs));
  C2 = const_cast<uint8_t *>(CBS_data(&c2_cbs));
  C2_len = CBS_len(&c2_cbs);

  // Check plaintext buffer size
  max_plaintext_len = *plaintext_len;
  if (max_plaintext_len < C2_len) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_BUFFER_TOO_SMALL);
    goto err;
  }

  // Step 2: Reconstruct point C1 = (x1, y1)
  if (!EC_POINT_set_affine_coordinates(group, C1, x1, y1, bn_ctx)) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_CIPHERTEXT);
    goto err;
  }

  // Verify C1 is on the curve
  if (!EC_POINT_is_on_curve(group, C1, bn_ctx)) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_CIPHERTEXT);
    goto err;
  }

  // Step 3: d * C1 = (x2, y2)
  if (!EC_POINT_mul(group, C1, NULL, C1, priv_key, bn_ctx) ||
      !EC_POINT_get_affine_coordinates(group, C1, x2, y2, bn_ctx)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    goto err;
  }

  // Step 4: t = KDF(x2 || y2, C2_len)
  field_size = BN_num_bytes(x2);
  if (field_size == 0 || BN_num_bytes(y2) != field_size) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto err;
  }

  z_len = 2 * field_size;
  z = reinterpret_cast<uint8_t *>(OPENSSL_malloc(z_len));
  if (z == NULL) {
    goto err;
  }

  if (!BN_bn2bin_padded(z, field_size, x2) ||
      !BN_bn2bin_padded(z + field_size, field_size, y2)) {
    OPENSSL_free(z);
    z = NULL;
    goto err;
  }

  KDF_out = reinterpret_cast<uint8_t *>(OPENSSL_malloc(C2_len));
  if (KDF_out == NULL) {
    OPENSSL_free(z);
    z = NULL;
    goto err;
  }

  if (!sm2_kdf(KDF_out, C2_len, z, z_len, EVP_sm3())) {
    OPENSSL_cleanse(z, z_len);
    OPENSSL_free(z);
    z = NULL;
    OPENSSL_free(KDF_out);
    KDF_out = NULL;
    goto err;
  }
  OPENSSL_cleanse(z, z_len);
  OPENSSL_free(z);
  z = NULL;

  // Step 5: M = C2 XOR t
  M = reinterpret_cast<uint8_t *>(OPENSSL_malloc(C2_len));
  if (M == NULL) {
    OPENSSL_free(KDF_out);
    KDF_out = NULL;
    goto err;
  }

  for (size_t i = 0; i < C2_len; i++) {
    M[i] = C2[i] ^ KDF_out[i];
  }
  OPENSSL_free(KDF_out);
  KDF_out = NULL;

  // Step 6: Verify C3 = SM3(x2 || M || y2)
  if (!sm2_compute_c3(C3_computed, x2, y2, M, C2_len)) {
    OPENSSL_free(M);
    M = NULL;
    goto err;
  }

  // Compare computed C3 with received C3 (constant-time comparison)
  if (CRYPTO_memcmp(C3_computed, C3, 32) != 0) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_DIGEST_MISMATCH);
    OPENSSL_cleanse(M, C2_len);
    OPENSSL_free(M);
    M = NULL;
    goto err;
  }

  // Step 7: Output plaintext
  OPENSSL_memcpy(plaintext, M, C2_len);
  *plaintext_len = C2_len;
  ret = 1;

  OPENSSL_cleanse(M, C2_len);
  OPENSSL_free(M);
  M = NULL;

err:
  BN_CTX_free(bn_ctx);
  BN_free(x1);
  BN_free(y1);
  BN_free(x2);
  BN_free(y2);
  EC_POINT_free(C1);
  OPENSSL_cleanse(C3_computed, sizeof(C3_computed));
  if (KDF_out != NULL) {
    OPENSSL_cleanse(KDF_out, C2_len);
    OPENSSL_free(KDF_out);
  }
  if (M != NULL) {
    OPENSSL_cleanse(M, C2_len);
    OPENSSL_free(M);
  }
  return ret;
}
