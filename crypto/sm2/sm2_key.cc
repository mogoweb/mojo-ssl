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
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/nid.h>

#include <string.h>

#include "../internal.h"
#include "../fipsmodule/ec/internal.h"


using namespace bssl;

size_t SM2_ciphertext_size(size_t plaintext_len) {
  // ASN.1 DER encoding overhead:
  // SEQUENCE header: ~4 bytes
  // C1x (INTEGER): ~35 bytes (32 bytes + 3 bytes header)
  // C1y (INTEGER): ~35 bytes
  // C3 (OCTET STRING): 34 bytes (32 bytes + 2 bytes header)
  // C2 (OCTET STRING): plaintext_len + 2 bytes header
  return 108 + plaintext_len + 10;  // Extra padding for safety
}

size_t SM2_plaintext_size(size_t ciphertext_len) {
  // Reverse estimate: subtract ASN.1 overhead
  // ASN.1 structure:
  // - SEQUENCE header: 2-4 bytes
  // - C1x INTEGER: 2 header + 32 data (+ 1 if high bit set for sign)
  // - C1y INTEGER: 2 header + 32 data (+ 1 if high bit set for sign)
  // - C3 OCTET STRING: 2 header + 32 data
  // - C2 OCTET STRING: 2 header + plaintext_len data
  //
  // Minimum overhead: 2 + 34 + 34 + 34 + 2 = 106 bytes
  // With potential sign bytes: up to 110 bytes
  // Use 110 bytes overhead to ensure buffer is large enough
  if (ciphertext_len <= 110) {
    return 0;
  }
  return ciphertext_len - 110;
}

int SM2_check_private_key(const EC_KEY *key) {
  if (key == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  const EC_GROUP *group = EC_KEY_get0_group(key);
  const BIGNUM *priv_key = EC_KEY_get0_private_key(key);

  if (group == NULL || priv_key == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  // SM2 private key must be in range [1, n-1)
  // where n is the curve order
  BIGNUM *n_minus_1 = BN_new();
  if (n_minus_1 == NULL) {
    return 0;
  }

  const BIGNUM *order = EC_GROUP_get0_order(group);
  int ret = 0;

  // n - 1
  if (!BN_sub(n_minus_1, order, BN_value_one())) {
    goto end;
  }

  // Check: 1 <= priv_key < n - 1
  if (BN_cmp(priv_key, BN_value_one()) < 0 ||
      BN_cmp(priv_key, n_minus_1) >= 0) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_PRIVATE_KEY);
    goto end;
  }

  ret = 1;

end:
  BN_free(n_minus_1);
  return ret;
}

int SM2_generate_key(EC_KEY *key) {
  if (key == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  const EC_GROUP *group = EC_KEY_get0_group(key);
  if (group == NULL) {
    // Set SM2 curve group if not set
    EC_GROUP *sm2_group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (sm2_group == NULL) {
      OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
      return 0;
    }
    if (!EC_KEY_set_group(key, sm2_group)) {
      EC_GROUP_free(sm2_group);
      return 0;
    }
    EC_GROUP_free(sm2_group);
    group = EC_KEY_get0_group(key);
  }

  // Generate key pair using standard EC key generation
  // Note: Standard EC key generation uses [1, n) range, same as SM2.
  // SM2 additionally excludes n-1, which is a single value with probability ~1/2^256.
  if (!EC_KEY_generate_key(key)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    return 0;
  }

  // Validate the generated key
  int attempts = 0;
  while (!SM2_check_private_key(key)) {
    // Retry if by chance we got n-1 (extremely rare, probability ~1/2^256)
    if (++attempts > 3 || !EC_KEY_generate_key(key)) {
      OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
      return 0;
    }
  }

  return 1;
}
