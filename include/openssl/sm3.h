// Copyright 2024 The BoringSSL Authors
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

#ifndef OPENSSL_HEADER_SM3_H
#define OPENSSL_HEADER_SM3_H

#include <openssl/base.h>  // IWYU pragma: export

#if defined(__cplusplus)
extern "C" {
#endif


// SM3 is a cryptographic hash function defined in GM/T 0004-2012.
// It produces a 256-bit (32-byte) digest.


// SM3_DIGEST_LENGTH is the length of an SM3 digest.
#define SM3_DIGEST_LENGTH 32

// SM3_CBLOCK is the block size of SM3.
#define SM3_CBLOCK 64


// SM3_CTX is the state for an SM3 digest operation.
struct sm3_state_st {
  uint32_t h[8];              // 8 state words (A-H)
  uint32_t Nl, Nh;            // message bit count
  uint8_t data[SM3_CBLOCK];   // data buffer
  unsigned num;               // bytes in buffer
} /* SM3_CTX */;


// SM3_Init initialises |ctx| for a fresh SM3 hash. It returns one.
OPENSSL_EXPORT int SM3_Init(SM3_CTX *ctx);

// SM3_Update adds |len| bytes from |data| to |ctx|. It returns one.
OPENSSL_EXPORT int SM3_Update(SM3_CTX *ctx, const void *data, size_t len);

// SM3_Final completes the hash and writes |SM3_DIGEST_LENGTH| bytes to |out|.
// It returns one.
OPENSSL_EXPORT int SM3_Final(uint8_t out[SM3_DIGEST_LENGTH], SM3_CTX *ctx);

// SM3 computes the SM3 hash of |len| bytes from |data| and writes the result
// to |out|.
OPENSSL_EXPORT void SM3(const uint8_t *data, size_t len,
                         uint8_t out[SM3_DIGEST_LENGTH]);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_SM3_H
