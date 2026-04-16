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


// SM2 default user ID (GM/T 0003-2012 standard)
#define SM2_DEFAULT_USER_ID "1234567812345678"
#define SM2_DEFAULT_USER_ID_LEN 16


// sm2_kdf implements X9.63 KDF (equivalent to SM2 KDF).
// It derives |out_len| bytes from shared secret |z| of length |z_len|
// using hash function |md|. Returns 1 on success, 0 on failure.
OPENSSL_EXPORT int sm2_kdf(uint8_t *out, size_t out_len,
                           const uint8_t *z, size_t z_len,
                           const EVP_MD *md);


// SM2_compute_z_digest computes Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA)
// ENTL is 16-bit big-endian bit length of ID.
// If id is NULL, uses SM2_DEFAULT_USER_ID.
// Returns 1 on success, 0 on error.
OPENSSL_EXPORT int SM2_compute_z_digest(uint8_t *out, const EC_KEY *key,
                                        const uint8_t *id, size_t id_len);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_CRYPTO_SM2_INTERNAL_H
