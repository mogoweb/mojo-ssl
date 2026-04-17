// Copyright 2026 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0

#include <openssl/ssl.h>
#include <openssl/tlcp.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "../crypto/internal.h"
#include "internal.h"

BSSL_NAMESPACE_BEGIN

namespace {

// x509_to_buffer returns a |CRYPTO_BUFFER| that contains the serialised
// contents of |x509|.
UniquePtr<CRYPTO_BUFFER> x509_to_buffer(X509 *x509) {
  uint8_t *buf = nullptr;
  int cert_len = i2d_X509(x509, &buf);
  if (cert_len <= 0) {
    return nullptr;
  }

  UniquePtr<CRYPTO_BUFFER> buffer(CRYPTO_BUFFER_new(buf, cert_len, nullptr));
  OPENSSL_free(buf);

  return buffer;
}

// tlcp_validate_certificate checks that |x| is an SM2 certificate
// with the expected key usage.
bool tlcp_validate_certificate(X509 *x, EVP_PKEY *pkey, bool require_signing) {
  if (x == nullptr || pkey == nullptr) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_PASSED_NULL_PARAMETER);
    return false;
  }

  // Check that the key is SM2 (EVP_PKEY_SM2 or EVP_PKEY_EC with SM2 curve)
  int pkey_type = EVP_PKEY_id(pkey);
  if (pkey_type != EVP_PKEY_SM2 && pkey_type != EVP_PKEY_EC) {
    OPENSSL_PUT_ERROR(SSL, TLCP_R_INVALID_CERTIFICATE_USAGE);
    return false;
  }

  // TODO: Check key usage extension
  // - Signing cert should have digitalSignature
  // - Encryption cert should have keyEncipherment

  return true;
}

}  // namespace

int ssl_ctx_use_tlcp_certificate(SSL_CTX *ctx, X509 *x, EVP_PKEY *pkey,
                                 bool is_sign) {
  if (ctx == nullptr || ctx->cert == nullptr) {
    return 0;
  }

  if (!tlcp_validate_certificate(x, pkey, is_sign)) {
    return 0;
  }

  // Create a new credential for the certificate
  UniquePtr<SSL_CREDENTIAL> cred(SSL_CREDENTIAL_new_x509());
  if (!cred) {
    return 0;
  }

  // Set the private key
  if (!SSL_CREDENTIAL_set1_private_key(cred.get(), pkey)) {
    return 0;
  }

  // Convert X509 to CRYPTO_BUFFER and set up the certificate chain
  UniquePtr<CRYPTO_BUFFER> cert_buffer = x509_to_buffer(x);
  if (!cert_buffer) {
    return 0;
  }

  CRYPTO_BUFFER *certs[] = {cert_buffer.get()};
  if (!SSL_CREDENTIAL_set1_cert_chain(cred.get(), certs, 1)) {
    return 0;
  }

  if (is_sign) {
    ctx->cert->tlcp_sign = std::move(cred);
  } else {
    ctx->cert->tlcp_enc = std::move(cred);
  }

  return 1;
}

int ssl_use_tlcp_certificate(SSL *ssl, X509 *x, EVP_PKEY *pkey, bool is_sign) {
  if (ssl == nullptr || ssl->config == nullptr ||
      ssl->config->cert == nullptr) {
    return 0;
  }

  if (!tlcp_validate_certificate(x, pkey, is_sign)) {
    return 0;
  }

  // Create a new credential for the certificate
  UniquePtr<SSL_CREDENTIAL> cred(SSL_CREDENTIAL_new_x509());
  if (!cred) {
    return 0;
  }

  // Set the private key
  if (!SSL_CREDENTIAL_set1_private_key(cred.get(), pkey)) {
    return 0;
  }

  // Convert X509 to CRYPTO_BUFFER and set up the certificate chain
  UniquePtr<CRYPTO_BUFFER> cert_buffer = x509_to_buffer(x);
  if (!cert_buffer) {
    return 0;
  }

  CRYPTO_BUFFER *certs[] = {cert_buffer.get()};
  if (!SSL_CREDENTIAL_set1_cert_chain(cred.get(), certs, 1)) {
    return 0;
  }

  if (is_sign) {
    ssl->config->cert->tlcp_sign = std::move(cred);
  } else {
    ssl->config->cert->tlcp_enc = std::move(cred);
  }

  return 1;
}

BSSL_NAMESPACE_END

using namespace bssl;

int SSL_CTX_use_tlcp_sign_certificate(SSL_CTX *ctx, X509 *x, EVP_PKEY *pkey) {
  return ssl_ctx_use_tlcp_certificate(ctx, x, pkey, true);
}

int SSL_CTX_use_tlcp_enc_certificate(SSL_CTX *ctx, X509 *x, EVP_PKEY *pkey) {
  return ssl_ctx_use_tlcp_certificate(ctx, x, pkey, false);
}

int SSL_use_tlcp_sign_certificate(SSL *ssl, X509 *x, EVP_PKEY *pkey) {
  return ssl_use_tlcp_certificate(ssl, x, pkey, true);
}

int SSL_use_tlcp_enc_certificate(SSL *ssl, X509 *x, EVP_PKEY *pkey) {
  return ssl_use_tlcp_certificate(ssl, x, pkey, false);
}
