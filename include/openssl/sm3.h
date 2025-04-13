/*
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* This header can move into provider when legacy support is removed */
#ifndef OPENSSL_SM3_H
#define OPENSSL_SM3_H
#pragma once

#include <openssl/base.h>
#include <stddef.h>
#ifdef  __cplusplus
extern "C" {
#endif

#define SM3_DIGEST_LENGTH 32
#define SM3_WORD unsigned int

#define SM3_CBLOCK      64
#define SM3_LBLOCK      (SM3_CBLOCK/4)

typedef struct SM3state_st {
   SM3_WORD A, B, C, D, E, F, G, H;
   SM3_WORD Nl, Nh;
   SM3_WORD data[SM3_LBLOCK];
   unsigned int num;
} SM3_CTX;

OPENSSL_EXPORT int SM3_Init(SM3_CTX *c);
OPENSSL_EXPORT int SM3_Update(SM3_CTX *c, const void *data, size_t len);
OPENSSL_EXPORT int SM3_Final(unsigned char *md, SM3_CTX *c);
OPENSSL_EXPORT void SM3_Transform(SM3_CTX *c, const unsigned char *data);

// SM3 writes the digest of |len| bytes from |data| to |out| and returns |out|.
// There must be at least |SM3_DIGEST_LENGTH| bytes of space in |out|.
OPENSSL_EXPORT uint8_t *SM3(const uint8_t *data, size_t len,
                            uint8_t out[SM3_DIGEST_LENGTH]);

#ifdef  __cplusplus
}
#endif

#endif /* OPENSSL_SM3_H */
