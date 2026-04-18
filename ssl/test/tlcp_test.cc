// Copyright 2026 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0

#include <gtest/gtest.h>
#include <openssl/ssl.h>
#include <openssl/tlcp.h>

#include "test_config.h"

class TLCPIntegrationTest : public testing::Test {
 protected:
  void SetUp() override {
    server_ctx_ = SSL_CTX_new(TLCP_server_method());
    client_ctx_ = SSL_CTX_new(TLCP_client_method());
    ASSERT_NE(server_ctx_, nullptr);
    ASSERT_NE(client_ctx_, nullptr);
  }

  void TearDown() override {
    SSL_CTX_free(server_ctx_);
    SSL_CTX_free(client_ctx_);
  }

  SSL_CTX *server_ctx_ = nullptr;
  SSL_CTX *client_ctx_ = nullptr;
};

TEST_F(TLCPIntegrationTest, ContextSetup) {
  // Verify both contexts are set up correctly
  EXPECT_NE(server_ctx_, nullptr);
  EXPECT_NE(client_ctx_, nullptr);
}

TEST_F(TLCPIntegrationTest, CipherSuiteSelection) {
  // Set cipher list
  int ret = SSL_CTX_set_cipher_list(server_ctx_, "ECC-SM2-SM4-CBC-SM3");
  EXPECT_EQ(ret, 1);

  ret = SSL_CTX_set_cipher_list(client_ctx_, "ECC-SM2-SM4-CBC-SM3");
  EXPECT_EQ(ret, 1);
}

// TODO: Add actual handshake test once state machine is complete
// TEST_F(TLCPIntegrationTest, BasicHandshake) { ... }
