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

#ifndef OPENSSL_HEADER_SM4_H
#define OPENSSL_HEADER_SM4_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define SM4_ENCRYPT 1
#define SM4_DECRYPT 0

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SCHEDULE 32

typedef struct SM4_KEY_st {
  uint32_t rk[SM4_KEY_SCHEDULE];
} SM4_KEY;

// SM4_set_key configures |ks| to encrypt/decrypt with 128-bit |key|.
// Returns 1 on success.
OPENSSL_EXPORT int SM4_set_key(const uint8_t *key, SM4_KEY *ks);

// SM4_encrypt encrypts one 16-byte block from |in| to |out| using |ks|.
OPENSSL_EXPORT void SM4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);

// SM4_decrypt decrypts one 16-byte block from |in| to |out| using |ks|.
OPENSSL_EXPORT void SM4_decrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);

#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_SM4_H
