// Copyright 2026 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0

#ifndef OPENSSL_HEADER_TLCP_H
#define OPENSSL_HEADER_TLCP_H

#include <openssl/base.h>

#if defined(__cplusplus)
extern "C" {
#endif

// TLCP_VERSION is the wire version for TLCP (GB/T 38636-2020).
// Note: This uses the same value as TLS 1.1 (0x0101) per the TLCP spec.
#define TLCP_VERSION 0x0101

// TLCP cipher suite identifiers.
#define TLCP_ECC_SM2_SM4_CBC_SM3 0x0001
#define TLCP_ECC_SM2_SM4_GCM_SM3 0x0002
#define TLCP_ECDHE_SM2_SM4_CBC_SM3 0x0003
#define TLCP_ECDHE_SM2_SM4_GCM_SM3 0x0004

// TLCP method functions.
OPENSSL_EXPORT const SSL_METHOD *TLCP_method(void);
OPENSSL_EXPORT const SSL_METHOD *TLCP_server_method(void);
OPENSSL_EXPORT const SSL_METHOD *TLCP_client_method(void);

// TLCP dual certificate functions.
// The signing certificate is used for authentication signatures.
// The encryption certificate is used for key exchange.
OPENSSL_EXPORT int SSL_CTX_use_tlcp_sign_certificate(SSL_CTX *ctx, X509 *x,
                                                      EVP_PKEY *pkey);
OPENSSL_EXPORT int SSL_CTX_use_tlcp_enc_certificate(SSL_CTX *ctx, X509 *x,
                                                     EVP_PKEY *pkey);
OPENSSL_EXPORT int SSL_use_tlcp_sign_certificate(SSL *ssl, X509 *x,
                                                  EVP_PKEY *pkey);
OPENSSL_EXPORT int SSL_use_tlcp_enc_certificate(SSL *ssl, X509 *x,
                                                 EVP_PKEY *pkey);

// SSL_is_tlcp returns one if |ssl| is using TLCP and zero otherwise.
OPENSSL_EXPORT int SSL_is_tlcp(const SSL *ssl);

// TLCP error codes.
// Note: These start at 500 to avoid conflicts with existing SSL_R_* codes.
#define TLCP_R_INVALID_DUAL_CERTIFICATE        500
#define TLCP_R_MISSING_ENCRYPTION_CERTIFICATE   501
#define TLCP_R_MISSING_SIGNING_CERTIFICATE      502
#define TLCP_R_INVALID_CERTIFICATE_USAGE        503
#define TLCP_R_SM2_ENCRYPTION_FAILED            504
#define TLCP_R_SM2_DECRYPTION_FAILED            505
#define TLCP_R_INVALID_PRE_MASTER_SECRET        506
#define TLCP_R_UNSUPPORTED_CIPHER_SUITE         507
#define TLCP_R_HANDSHAKE_FAILURE                508

#if defined(__cplusplus)
}
#endif

#endif  // OPENSSL_HEADER_TLCP_H
