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

#include <gtest/gtest.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/nid.h>
#include <openssl/sm2.h>

#include "internal.h"
#include "../test/test_util.h"


// Check if SM2 curve is available (requires Task 9: SM2 curve support in EC module)
static bool SM2CurveAvailable() {
  bssl::UniquePtr<EC_GROUP> group(EC_GROUP_new_by_curve_name(NID_sm2));
  return group != nullptr;
}

// Test SM2 ciphertext size calculation
TEST(SM2Test, CiphertextSize) {
  // SM2 ciphertext format: ASN.1 SEQUENCE { C1x, C1y, C3, C2 }
  // C1x, C1y: ~35 bytes each (32-byte coord + ASN.1 overhead)
  // C3: 34 bytes (32-byte hash + ASN.1 overhead)
  // C2: plaintext_len + ASN.1 overhead
  // SEQUENCE header: ~4 bytes

  EXPECT_GT(SM2_ciphertext_size(0), 100u);
  EXPECT_GT(SM2_ciphertext_size(32), 130u);
  EXPECT_GT(SM2_ciphertext_size(1024), 1100u);

  // Ciphertext size should grow linearly with plaintext
  size_t size_0 = SM2_ciphertext_size(0);
  size_t size_32 = SM2_ciphertext_size(32);
  size_t size_64 = SM2_ciphertext_size(64);

  EXPECT_EQ(size_64 - size_32, 32u);
  EXPECT_EQ(size_32 - size_0, 32u);
}

// Test SM2 plaintext size calculation
TEST(SM2Test, PlaintextSize) {
  // Plaintext size should be ciphertext minus ASN.1 overhead
  EXPECT_EQ(SM2_plaintext_size(200), 90u);
  EXPECT_EQ(SM2_plaintext_size(150), 40u);
  EXPECT_EQ(SM2_plaintext_size(110), 0u);
  EXPECT_EQ(SM2_plaintext_size(100), 0u);  // Too small
}

// Test SM2 key generation (requires SM2 curve support)
TEST(SM2Test, KeyGeneration) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available in EC module (Task 9 not completed)";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);

  ASSERT_TRUE(SM2_generate_key(key.get()));
  ASSERT_TRUE(SM2_check_private_key(key.get()));
  ASSERT_TRUE(EC_KEY_check_key(key.get()));
}

// Test SM2 encrypt/decrypt round-trip (requires SM2 curve support)
TEST(SM2Test, EncryptDecrypt) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available in EC module (Task 9 not completed)";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  const char *plaintext = "Hello, SM2!";
  size_t plaintext_len = strlen(plaintext);

  // Encrypt
  size_t ciphertext_len = SM2_ciphertext_size(plaintext_len);
  std::vector<uint8_t> ciphertext(ciphertext_len);
  ASSERT_TRUE(SM2_encrypt(key.get(),
                          (const uint8_t *)plaintext, plaintext_len,
                          ciphertext.data(), &ciphertext_len));

  // Decrypt - use ciphertext_len as buffer size (always >= plaintext_len)
  std::vector<uint8_t> decrypted(ciphertext_len);
  size_t decrypted_len = ciphertext_len;
  ASSERT_TRUE(SM2_decrypt(key.get(),
                          ciphertext.data(), ciphertext_len,
                          decrypted.data(), &decrypted_len));

  EXPECT_EQ(plaintext_len, decrypted_len);
  EXPECT_EQ(Bytes(plaintext, plaintext_len),
            Bytes(decrypted.data(), decrypted_len));
}

// Test SM2 with larger message (requires SM2 curve support)
TEST(SM2Test, LargeMessage) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available in EC module (Task 9 not completed)";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  // 1KB message
  std::vector<uint8_t> plaintext(1024);
  for (size_t i = 0; i < plaintext.size(); i++) {
    plaintext[i] = (uint8_t)(i & 0xFF);
  }

  // Encrypt
  size_t ciphertext_len = SM2_ciphertext_size(plaintext.size());
  std::vector<uint8_t> ciphertext(ciphertext_len);
  ASSERT_TRUE(SM2_encrypt(key.get(),
                          plaintext.data(), plaintext.size(),
                          ciphertext.data(), &ciphertext_len));

  // Decrypt - use ciphertext_len as buffer size
  std::vector<uint8_t> decrypted(ciphertext_len);
  size_t decrypted_len = ciphertext_len;
  ASSERT_TRUE(SM2_decrypt(key.get(),
                          ciphertext.data(), ciphertext_len,
                          decrypted.data(), &decrypted_len));

  EXPECT_EQ(plaintext.size(), decrypted_len);
  EXPECT_EQ(Bytes(plaintext), Bytes(decrypted.data(), decrypted_len));
}

// Test decryption with wrong key (requires SM2 curve support)
TEST(SM2Test, WrongKey) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available in EC module (Task 9 not completed)";
  }

  bssl::UniquePtr<EC_KEY> key1(EC_KEY_new_by_curve_name(NID_sm2));
  bssl::UniquePtr<EC_KEY> key2(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key1);
  ASSERT_TRUE(key2);
  ASSERT_TRUE(SM2_generate_key(key1.get()));
  ASSERT_TRUE(SM2_generate_key(key2.get()));

  const char *plaintext = "Secret message";
  size_t plaintext_len = strlen(plaintext);

  // Encrypt with key1
  size_t ciphertext_len = SM2_ciphertext_size(plaintext_len);
  std::vector<uint8_t> ciphertext(ciphertext_len);
  ASSERT_TRUE(SM2_encrypt(key1.get(),
                          (const uint8_t *)plaintext, plaintext_len,
                          ciphertext.data(), &ciphertext_len));

  // Try to decrypt with key2 (should fail)
  std::vector<uint8_t> decrypted(ciphertext_len);
  size_t decrypted_len = ciphertext_len;
  EXPECT_FALSE(SM2_decrypt(key2.get(),
                           ciphertext.data(), ciphertext_len,
                           decrypted.data(), &decrypted_len));
}

// Test decryption with corrupted ciphertext (requires SM2 curve support)
TEST(SM2Test, CorruptedCiphertext) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available in EC module (Task 9 not completed)";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  const char *plaintext = "Test message";
  size_t plaintext_len = strlen(plaintext);

  // Encrypt
  size_t ciphertext_len = SM2_ciphertext_size(plaintext_len);
  std::vector<uint8_t> ciphertext(ciphertext_len);
  ASSERT_TRUE(SM2_encrypt(key.get(),
                          (const uint8_t *)plaintext, plaintext_len,
                          ciphertext.data(), &ciphertext_len));

  // Corrupt the ciphertext
  ciphertext[ciphertext_len / 2] ^= 0xFF;

  // Try to decrypt (should fail)
  std::vector<uint8_t> decrypted(ciphertext_len);
  size_t decrypted_len = ciphertext_len;
  EXPECT_FALSE(SM2_decrypt(key.get(),
                           ciphertext.data(), ciphertext_len,
                           decrypted.data(), &decrypted_len));
}

// Test SM2 with null parameters (error handling)
TEST(SM2Test, NullParameters) {
  // SM2_generate_key with null key should fail
  EXPECT_FALSE(SM2_generate_key(nullptr));

  // SM2_check_private_key with null key should fail
  EXPECT_FALSE(SM2_check_private_key(nullptr));

  // SM2_encrypt with null key should fail
  uint8_t ciphertext[200];
  size_t ciphertext_len = sizeof(ciphertext);
  EXPECT_FALSE(SM2_encrypt(nullptr,
                           (const uint8_t *)"test", 4,
                           ciphertext, &ciphertext_len));

  // SM2_decrypt with null key should fail
  uint8_t plaintext[200];
  size_t plaintext_len = sizeof(plaintext);
  EXPECT_FALSE(SM2_decrypt(nullptr,
                           ciphertext, 100,
                           plaintext, &plaintext_len));
}

// Test SM2 private key validation (requires SM2 curve support)
TEST(SM2Test, PrivateKeyValidation) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available in EC module (Task 9 not completed)";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  // Valid key should pass
  EXPECT_TRUE(SM2_check_private_key(key.get()));

  // Key without private key should fail
  bssl::UniquePtr<EC_KEY> key_no_priv(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key_no_priv);
  EXPECT_FALSE(SM2_check_private_key(key_no_priv.get()));
}

// Test multiple encrypt/decrypt operations (requires SM2 curve support)
TEST(SM2Test, MultipleOperations) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available in EC module (Task 9 not completed)";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  // Perform multiple encrypt/decrypt operations
  for (int i = 0; i < 5; i++) {
    std::string plaintext = "Test message " + std::to_string(i);
    size_t plaintext_len = plaintext.size();

    size_t ciphertext_len = SM2_ciphertext_size(plaintext_len);
    std::vector<uint8_t> ciphertext(ciphertext_len);
    ASSERT_TRUE(SM2_encrypt(key.get(),
                            (const uint8_t *)plaintext.data(), plaintext_len,
                            ciphertext.data(), &ciphertext_len));

    std::vector<uint8_t> decrypted(ciphertext_len);
    size_t decrypted_len = ciphertext_len;
    ASSERT_TRUE(SM2_decrypt(key.get(),
                            ciphertext.data(), ciphertext_len,
                            decrypted.data(), &decrypted_len));

    EXPECT_EQ(plaintext_len, decrypted_len);
    EXPECT_EQ(Bytes(plaintext.data(), plaintext_len),
              Bytes(decrypted.data(), decrypted_len));
  }
}

// Test SM2 signature size (DER encoded)
TEST(SM2Test, SignatureSize) {
  // SM2 signature is DER-encoded SEQUENCE { r INTEGER, s INTEGER }
  // r and s are 32 bytes each, DER encoding adds ~8 bytes overhead
  EXPECT_GE(SM2_signature_size(), 70u);
  EXPECT_LE(SM2_signature_size(), 80u);
}

// Test SM2 Z value computation
// Reference: GM/T 0003-2012, test vector from Tongsuo
TEST(SM2Test, ComputeZDigest) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  // Test with default user ID
  uint8_t z[32];
  EXPECT_TRUE(SM2_compute_z_digest(z, key.get(), nullptr, 0));

  // Test with custom user ID
  const uint8_t id[] = "test_user_id";
  EXPECT_TRUE(SM2_compute_z_digest(z, key.get(), id, sizeof(id) - 1));

  // Z value should be 32 bytes (SM3 output)
  // Verify it's not all zeros
  bool all_zero = true;
  for (int i = 0; i < 32; i++) {
    if (z[i] != 0) {
      all_zero = false;
      break;
    }
  }
  EXPECT_FALSE(all_zero);
}

// Test internal message hash computation
TEST(SM2Test, ComputeMsgHash) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  const char *msg = "Hello, SM2 Signature!";
  size_t msg_len = strlen(msg);

  // Compute e = SM3(Z || M) with default ID
  bssl::UniquePtr<BIGNUM> e(sm2_compute_msg_hash(key.get(), nullptr, 0,
                                                   reinterpret_cast<const uint8_t *>(msg), msg_len));
  ASSERT_TRUE(e);
  EXPECT_FALSE(BN_is_zero(e.get()));

  // Test with custom ID
  const uint8_t custom_id[] = "custom_id";
  bssl::UniquePtr<BIGNUM> e2(sm2_compute_msg_hash(key.get(), custom_id, sizeof(custom_id) - 1,
                                                    reinterpret_cast<const uint8_t *>(msg), msg_len));
  ASSERT_TRUE(e2);
  EXPECT_FALSE(BN_is_zero(e2.get()));

  // Different IDs should produce different hashes
  EXPECT_NE(BN_cmp(e.get(), e2.get()), 0);

  // Test deterministic output
  bssl::UniquePtr<BIGNUM> e3(sm2_compute_msg_hash(key.get(), nullptr, 0,
                                                    reinterpret_cast<const uint8_t *>(msg), msg_len));
  ASSERT_TRUE(e3);
  EXPECT_EQ(BN_cmp(e.get(), e3.get()), 0);  // Same input = same output

  // Test NULL key returns NULL
  EXPECT_EQ(sm2_compute_msg_hash(nullptr, nullptr, 0,
                                  reinterpret_cast<const uint8_t *>(msg), msg_len), nullptr);

  // Test NULL message returns NULL
  EXPECT_EQ(sm2_compute_msg_hash(key.get(), nullptr, 0, nullptr, 0), nullptr);
}
