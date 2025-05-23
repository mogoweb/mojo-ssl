/*
 * Copyright 2017-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_SM2_H
#define OSSL_CRYPTO_SM2_H
#pragma once

#include <openssl/opensslconf.h>

#include <openssl/ec.h>

#if defined(__cplusplus)
extern "C" {
#endif

int ossl_sm2_key_private_check(const EC_KEY *eckey);

/* The default user id as specified in GM/T 0009-2012 */
#define SM2_DEFAULT_USERID "1234567812345678"

OPENSSL_EXPORT int ossl_sm2_compute_z_digest(uint8_t *out,
                                             const EVP_MD *digest,
                                             const uint8_t *id,
                                             size_t id_len,
                                             const EC_KEY *key);

/*
 * SM2 signature operation. Computes Z and then signs H(Z || msg) using SM2
 */
ECDSA_SIG *ossl_sm2_do_sign(const EC_KEY *key,
                            const EVP_MD *digest,
                            const uint8_t *id,
                            const size_t id_len,
                            const uint8_t *msg, size_t msg_len);

int ossl_sm2_do_verify(const EC_KEY *key,
                       const EVP_MD *digest,
                       const ECDSA_SIG *signature,
                       const uint8_t *id,
                       const size_t id_len,
                       const uint8_t *msg, size_t msg_len);

/*
 * SM2 signature generation.
 */
int ossl_sm2_internal_sign(const unsigned char *dgst, int dgstlen,
                           unsigned char *sig, unsigned int *siglen,
                           EC_KEY *eckey);

/*
 * SM2 signature verification.
 */
int ossl_sm2_internal_verify(const unsigned char *dgst, int dgstlen,
                             const unsigned char *sig, int siglen,
                             const EC_KEY *eckey);

/*
 * SM2 encryption
 */
int ossl_sm2_ciphertext_size(const EC_KEY *key, const EVP_MD *digest,
                             size_t msg_len, size_t *ct_size);

int ossl_sm2_plaintext_size(const unsigned char *ct, size_t ct_size,
                            size_t *pt_size);

int ossl_sm2_encrypt(const EC_KEY *key,
                     const EVP_MD *digest,
                     const uint8_t *msg, size_t msg_len,
                     uint8_t *ciphertext_buf, size_t *ciphertext_len);

int ossl_sm2_decrypt(const EC_KEY *key,
                     const EVP_MD *digest,
                     const uint8_t *ciphertext, size_t ciphertext_len,
                     uint8_t *ptext_buf, size_t *ptext_len);

const unsigned char *ossl_sm2_algorithmidentifier_encoding(int md_nid,
                                                           size_t *len);

int SM2_compute_key(void *out, size_t outlen, int initiator,
                    const uint8_t *peer_id, size_t peer_id_len,
                    const uint8_t *self_id, size_t self_id_len,
                    const EC_KEY *peer_ecdhe_key, const EC_KEY *self_ecdhe_key,
                    const EC_KEY *peer_pub_key, const EC_KEY *self_eckey,
                    const EVP_MD *md, BN_CTX *libctx,
                    const char *propq);

BIGNUM *sm2_compute_msg_hash(const EVP_MD *digest,
                             const EC_KEY *key,
                             const uint8_t *id,
                             const size_t id_len,
                             const uint8_t *msg, size_t msg_len);
#if defined(__cplusplus)
}  // extern C
#endif

/*
 * SM2 reason codes.
 */
#define SM2_R_ASN1_ERROR                                 100
#define SM2_R_BAD_SIGNATURE                              101
#define SM2_R_BUFFER_TOO_SMALL                           107
#define SM2_R_DIST_ID_TOO_LARGE                          110
#define SM2_R_ID_NOT_SET                                 112
#define SM2_R_ID_TOO_LARGE                               111
#define SM2_R_INVALID_CURVE                              108
#define SM2_R_INVALID_DIGEST                             102
#define SM2_R_INVALID_DIGEST_TYPE                        103
#define SM2_R_INVALID_ENCODING                           104
#define SM2_R_INVALID_FIELD                              105
#define SM2_R_INVALID_PRIVATE_KEY                        113
#define SM2_R_NO_PARAMETERS_SET                          109
#define SM2_R_POINT_ARITHMETIC_FAILURE                   114
#define SM2_R_USER_ID_TOO_LARGE                          106
#endif
