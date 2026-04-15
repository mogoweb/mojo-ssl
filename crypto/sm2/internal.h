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

#ifndef OPENSSL_HEADER_CRYPTO_SM2_INTERNAL_H
#define OPENSSL_HEADER_CRYPTO_SM2_INTERNAL_H

#include <openssl/base.h>
#include <openssl/digest.h>

#if defined(__cplusplus)
extern "C" {
#endif


// sm2_kdf implements X9.63 KDF (equivalent to SM2 KDF).
// It derives |out_len| bytes from shared secret |z| of length |z_len|
// using hash function |md|. Returns 1 on success, 0 on failure.
OPENSSL_EXPORT int sm2_kdf(uint8_t *out, size_t out_len,
                           const uint8_t *z, size_t z_len,
                           const EVP_MD *md);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_CRYPTO_SM2_INTERNAL_H
