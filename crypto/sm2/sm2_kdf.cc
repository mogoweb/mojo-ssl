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

#include "internal.h"

#include <openssl/digest.h>
#include <openssl/mem.h>

#include <string.h>

#include "../internal.h"


// X9.63 KDF (equivalent to SM2 KDF)
// K = KDF(Z, klen)
// For i = 1 to ceil(klen / hashlen):
//   K_i = Hash(Z || i)
// K = K_1 || K_2 || ... || K_n (truncated to klen)
extern "C" int sm2_kdf(uint8_t *out, size_t out_len,
                       const uint8_t *z, size_t z_len,
                       const EVP_MD *md) {
  if (out == NULL || out_len == 0) {
    return 0;
  }

  if (z == NULL && z_len > 0) {
    return 0;
  }

  const size_t md_size = EVP_MD_size(md);
  if (md_size == 0) {
    return 0;
  }

  EVP_MD_CTX ctx;
  EVP_MD_CTX_init(&ctx);

  // Counter is 4 bytes (big-endian)
  uint8_t counter[4];
  uint8_t digest[EVP_MAX_MD_SIZE];

  size_t remaining = out_len;
  uint8_t *out_ptr = out;
  int ret = 0;

  for (uint32_t i = 1; remaining > 0; i++) {
    // Encode counter as big-endian 4 bytes
    counter[0] = (uint8_t)(i >> 24);
    counter[1] = (uint8_t)(i >> 16);
    counter[2] = (uint8_t)(i >> 8);
    counter[3] = (uint8_t)i;

    // Hash(Z || counter)
    if (!EVP_DigestInit_ex(&ctx, md, NULL) ||
        !EVP_DigestUpdate(&ctx, z, z_len) ||
        !EVP_DigestUpdate(&ctx, counter, 4) ||
        !EVP_DigestFinal_ex(&ctx, digest, NULL)) {
      OPENSSL_cleanse(out, out_len);
      goto err;
    }

    size_t copy_len = remaining < md_size ? remaining : md_size;
    memcpy(out_ptr, digest, copy_len);
    out_ptr += copy_len;
    remaining -= copy_len;
  }

  ret = 1;

err:
  EVP_MD_CTX_cleanup(&ctx);
  OPENSSL_cleanse(digest, sizeof(digest));
  return ret;
}
