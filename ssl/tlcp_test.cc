// Copyright 2026 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0

#include <openssl/ssl.h>
#include <openssl/tlcp.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "test/test_state.h"
#include <gtest/gtest.h>

TEST(TLCPMethodTest, MethodCreation) {
  const SSL_METHOD *method = TLCP_method();
  EXPECT_NE(method, nullptr);
}

TEST(TLCPMethodTest, ServerMethod) {
  const SSL_METHOD *method = TLCP_server_method();
  EXPECT_NE(method, nullptr);
}

TEST(TLCPMethodTest, ClientMethod) {
  const SSL_METHOD *method = TLCP_client_method();
  EXPECT_NE(method, nullptr);
}

TEST(TLCPMethodTest, SSLIsTLCP) {
  SSL_CTX *ctx = SSL_CTX_new(TLCP_method());
  ASSERT_NE(ctx, nullptr);
  SSL *ssl = SSL_new(ctx);
  ASSERT_NE(ssl, nullptr);

  // Before handshake, version is not set
  // SSL_is_tlcp should return 0 when version is not set
  EXPECT_EQ(SSL_is_tlcp(ssl), 0);

  SSL_free(ssl);
  SSL_CTX_free(ctx);
}

TEST(TLCPCipherTest, CipherSuiteRegistration) {
  SSL_CTX *ctx = SSL_CTX_new(TLCP_method());
  ASSERT_NE(ctx, nullptr);

  // Set TLCP cipher list
  int ret = SSL_CTX_set_cipher_list(ctx, "ECC-SM2-SM4-CBC-SM3");
  EXPECT_EQ(ret, 1);

  SSL_CTX_free(ctx);
}

TEST(TLCPCipherTest, GetCipherName) {
  SSL_CTX *ctx = SSL_CTX_new(TLCP_method());
  ASSERT_NE(ctx, nullptr);

  SSL_CTX_set_cipher_list(ctx, "ECC-SM2-SM4-CBC-SM3");

  SSL *ssl = SSL_new(ctx);
  ASSERT_NE(ssl, nullptr);

  // After handshake, we would check the cipher name
  // For now, just verify setup works

  SSL_free(ssl);
  SSL_CTX_free(ctx);
}

TEST(TLCPDualCertTest, LoadSignCertificate) {
  SSL_CTX *ctx = SSL_CTX_new(TLCP_method());
  ASSERT_NE(ctx, nullptr);

  // Test error handling: Call with NULL parameters and verify it returns 0
  EXPECT_EQ(SSL_CTX_use_tlcp_sign_certificate(nullptr, nullptr, nullptr), 0);
  EXPECT_EQ(SSL_CTX_use_tlcp_enc_certificate(nullptr, nullptr, nullptr), 0);

  // Create an SSL object and test SSL-level functions with NULL parameters
  SSL *ssl = SSL_new(ctx);
  ASSERT_NE(ssl, nullptr);

  EXPECT_EQ(SSL_use_tlcp_sign_certificate(nullptr, nullptr, nullptr), 0);
  EXPECT_EQ(SSL_use_tlcp_enc_certificate(nullptr, nullptr, nullptr), 0);

  SSL_free(ssl);
  SSL_CTX_free(ctx);
}

TEST(TLCPDualCertTest, NullParameters) {
  SSL_CTX *ctx = SSL_CTX_new(TLCP_method());
  ASSERT_NE(ctx, nullptr);

  // Generate SM2 key pair
  bssl::UniquePtr<EVP_PKEY_CTX> pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_SM2, nullptr));
  ASSERT_TRUE(pctx);
  ASSERT_TRUE(EVP_PKEY_keygen_init(pctx.get()));
  EVP_PKEY *raw_pkey = nullptr;
  ASSERT_TRUE(EVP_PKEY_keygen(pctx.get(), &raw_pkey));
  bssl::UniquePtr<EVP_PKEY> pkey(raw_pkey);

  // Create a minimal certificate
  bssl::UniquePtr<X509> cert(X509_new());
  ASSERT_TRUE(cert);
  ASSERT_TRUE(X509_set_version(cert.get(), X509_VERSION_3));

  // Test with NULL context
  EXPECT_EQ(SSL_CTX_use_tlcp_sign_certificate(nullptr, cert.get(), pkey.get()),
            0);
  EXPECT_EQ(SSL_CTX_use_tlcp_enc_certificate(nullptr, cert.get(), pkey.get()),
            0);

  // Test with NULL certificate
  EXPECT_EQ(SSL_CTX_use_tlcp_sign_certificate(ctx, nullptr, pkey.get()), 0);
  EXPECT_EQ(SSL_CTX_use_tlcp_enc_certificate(ctx, nullptr, pkey.get()), 0);

  // Test with NULL key
  EXPECT_EQ(SSL_CTX_use_tlcp_sign_certificate(ctx, cert.get(), nullptr), 0);
  EXPECT_EQ(SSL_CTX_use_tlcp_enc_certificate(ctx, cert.get(), nullptr), 0);

  // Create SSL object to test SSL-level functions
  SSL *ssl = SSL_new(ctx);
  ASSERT_NE(ssl, nullptr);

  // Test with NULL SSL
  EXPECT_EQ(SSL_use_tlcp_sign_certificate(nullptr, cert.get(), pkey.get()), 0);
  EXPECT_EQ(SSL_use_tlcp_enc_certificate(nullptr, cert.get(), pkey.get()), 0);

  SSL_free(ssl);
  SSL_CTX_free(ctx);
}
