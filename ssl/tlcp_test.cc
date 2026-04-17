// Copyright 2026 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0

#include <openssl/ssl.h>
#include <openssl/tlcp.h>

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
