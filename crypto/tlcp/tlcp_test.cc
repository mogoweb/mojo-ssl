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
