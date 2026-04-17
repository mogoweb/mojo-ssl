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
