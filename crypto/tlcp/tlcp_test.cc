#include <gtest/gtest.h>
#include <openssl/tlcp.h>

TEST(TLCPHeaderTest, VersionConstant) {
    EXPECT_EQ(TLCP_VERSION, 0x0101);
}

TEST(TLCPHeaderTest, CipherSuiteConstant) {
    EXPECT_EQ(TLCP_ECC_SM2_SM4_CBC_SM3, 0x0001);
}
