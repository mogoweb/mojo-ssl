// Copyright 2026 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <openssl/sm4.h>

#include <gtest/gtest.h>

#include "../test/test_util.h"

BSSL_NAMESPACE_BEGIN
namespace {

// Test vector from GM/T 32907-2016 Example 1
TEST(SM4Test, Example1_SingleEncryption) {
  const uint8_t kKey[] = {
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
  };
  const uint8_t kPlaintext[] = {
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
  };
  const uint8_t kExpected[] = {
      0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
      0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
  };

  SM4_KEY key;
  ASSERT_TRUE(SM4_set_key(kKey, &key));

  uint8_t ciphertext[SM4_BLOCK_SIZE];
  SM4_encrypt(kPlaintext, ciphertext, &key);
  EXPECT_EQ(Bytes(kExpected), Bytes(ciphertext));

  uint8_t plaintext[SM4_BLOCK_SIZE];
  SM4_decrypt(ciphertext, plaintext, &key);
  EXPECT_EQ(Bytes(kPlaintext), Bytes(plaintext));
}

// Test vector from GM/T 32907-2016 Example 2 - 1 million iterations
TEST(SM4Test, Example2_MillionIterations) {
  const uint8_t kKey[] = {
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
  };
  const uint8_t kPlaintext[] = {
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
  };
  const uint8_t kExpected[] = {
      0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
      0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66
  };

  SM4_KEY key;
  ASSERT_TRUE(SM4_set_key(kKey, &key));

  uint8_t block[SM4_BLOCK_SIZE];
  OPENSSL_memcpy(block, kPlaintext, SM4_BLOCK_SIZE);

  // Encrypt 1,000,000 times
  for (int i = 0; i < 1000000; ++i) {
    SM4_encrypt(block, block, &key);
  }
  EXPECT_EQ(Bytes(kExpected), Bytes(block));

  // Decrypt 1,000,000 times (should return to original)
  for (int i = 0; i < 1000000; ++i) {
    SM4_decrypt(block, block, &key);
  }
  EXPECT_EQ(Bytes(kPlaintext), Bytes(block));
}

}  // namespace
BSSL_NAMESPACE_END
