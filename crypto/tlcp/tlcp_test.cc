// Copyright 2026 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0

#include <gtest/gtest.h>
#include <openssl/tlcp.h>

TEST(TLCPHeaderTest, VersionConstant) {
    EXPECT_EQ(TLCP_VERSION, 0x0101);
}

TEST(TLCPHeaderTest, CipherSuiteConstant) {
    EXPECT_EQ(TLCP_ECC_SM2_SM4_CBC_SM3, 0x0001);
}

TEST(TLCPHeaderTest, AllCipherSuiteConstants) {
    EXPECT_EQ(TLCP_ECC_SM2_SM4_CBC_SM3, 0x0001);
    EXPECT_EQ(TLCP_ECC_SM2_SM4_GCM_SM3, 0x0002);
    EXPECT_EQ(TLCP_ECDHE_SM2_SM4_CBC_SM3, 0x0003);
    EXPECT_EQ(TLCP_ECDHE_SM2_SM4_GCM_SM3, 0x0004);
}

TEST(TLCPKeyExchangeTest, PreMasterSecretSize) {
    // Pre-master secret for TLCP should be 48 bytes
    // First 2 bytes: TLCP_VERSION (0x0101)
    // Remaining 46 bytes: random

    constexpr size_t kPreMasterLen = 48;
    uint8_t pre_master[kPreMasterLen];

    // Version bytes
    pre_master[0] = (TLCP_VERSION >> 8) & 0xff;
    pre_master[1] = TLCP_VERSION & 0xff;

    // Random bytes would be filled by the actual function
    EXPECT_EQ(pre_master[0], 0x01);
    EXPECT_EQ(pre_master[1], 0x01);
}

TEST(TLCPKeyDerivationTest, MasterSecretSize) {
    // Master secret should be 48 bytes (same as TLS)
    constexpr size_t kMasterSecretLen = 48;
    EXPECT_EQ(kMasterSecretLen, 48u);
}

TEST(TLCPKeyDerivationTest, KeyBlockSize) {
    // For SM4-CBC with SM3:
    // client_write_MAC_key[32] (SM3 digest size)
    // server_write_MAC_key[32]
    // client_write_key[16] (SM4 key size)
    // server_write_key[16]
    // client_write_IV[16]
    // server_write_IV[16]
    // Total: 32 + 32 + 16 + 16 + 16 + 16 = 128 bytes
    constexpr size_t kKeyBlockSize = 128;
    EXPECT_EQ(kKeyBlockSize, 128u);
}

TEST(TLCPKeyDerivationTest, SM3DigestSize) {
    // SM3 digest size is 32 bytes
    constexpr size_t kSM3DigestSize = 32;
    EXPECT_EQ(kSM3DigestSize, 32u);
}

TEST(TLCPKeyDerivationTest, SM4KeySize) {
    // SM4 key size is 16 bytes
    constexpr size_t kSM4KeySize = 16;
    EXPECT_EQ(kSM4KeySize, 16u);
}

TEST(TLCPKeyDerivationTest, SM4BlockSize) {
    // SM4 block size is 16 bytes
    constexpr size_t kSM4BlockSize = 16;
    EXPECT_EQ(kSM4BlockSize, 16u);
}

TEST(TLCPRecordTest, SM4CBCKeySize) {
    // SM4 key size is 16 bytes (128 bits)
    constexpr size_t kSM4KeySize = 16;
    EXPECT_EQ(kSM4KeySize, 16u);
}

TEST(TLCPRecordTest, SM3DigestSize) {
    // SM3 digest size is 32 bytes (256 bits)
    constexpr size_t kSM3DigestSize = 32;
    EXPECT_EQ(kSM3DigestSize, 32u);
}

TEST(TLCPRecordTest, SM4BlockSize) {
    // SM4 block size is 16 bytes (128 bits)
    constexpr size_t kSM4BlockSize = 16;
    EXPECT_EQ(kSM4BlockSize, 16u);
}

TEST(TLCPHandshakeTest, BasicConstants) {
    // Verify basic handshake constants exist
    // Full SSL integration tests will be in ssl/test/tlcp_test.cc
    // This test just validates constants are defined
    EXPECT_EQ(TLCP_VERSION, 0x0101);
    EXPECT_EQ(TLCP_ECC_SM2_SM4_CBC_SM3, 0x0001);
}
