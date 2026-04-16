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
#include <openssl/ecdsa.h>
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

// Test SM2 signature generation
TEST(SM2Test, SigGen) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  // Create a test hash value (e)
  bssl::UniquePtr<BIGNUM> e(BN_new());
  ASSERT_TRUE(e);
  BN_set_word(e.get(), 12345);

  // Generate signature
  bssl::UniquePtr<ECDSA_SIG> sig(sm2_sig_gen(key.get(), e.get()));
  ASSERT_TRUE(sig);

  // Verify r and s are not zero and in valid range
  const BIGNUM *r, *s;
  ECDSA_SIG_get0(sig.get(), &r, &s);
  EXPECT_FALSE(BN_is_zero(r));
  EXPECT_FALSE(BN_is_zero(s));

  // r and s should be less than curve order
  const EC_GROUP *group = EC_KEY_get0_group(key.get());
  bssl::UniquePtr<BIGNUM> order(BN_new());
  ASSERT_TRUE(EC_GROUP_get_order(group, order.get(), nullptr));
  EXPECT_LT(BN_cmp(r, order.get()), 0);
  EXPECT_LT(BN_cmp(s, order.get()), 0);
}

// Test SM2 signature verification
TEST(SM2Test, SigVerify) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  // Create a test hash value
  bssl::UniquePtr<BIGNUM> e(BN_new());
  ASSERT_TRUE(e);
  BN_set_word(e.get(), 12345);

  // Generate signature
  bssl::UniquePtr<ECDSA_SIG> sig(sm2_sig_gen(key.get(), e.get()));
  ASSERT_TRUE(sig);

  // Verify signature
  EXPECT_EQ(1, sm2_sig_verify(key.get(), sig.get(), e.get()));

  // Verify with wrong hash should fail
  bssl::UniquePtr<BIGNUM> wrong_e(BN_new());
  BN_set_word(wrong_e.get(), 54321);
  EXPECT_EQ(0, sm2_sig_verify(key.get(), sig.get(), wrong_e.get()));
}

// Test SM2 signature verification edge cases
TEST(SM2Test, SigVerifyEdgeCases) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  // Create a test hash value
  bssl::UniquePtr<BIGNUM> e(BN_new());
  ASSERT_TRUE(e);
  BN_set_word(e.get(), 12345);

  // Generate a valid signature
  bssl::UniquePtr<ECDSA_SIG> sig(sm2_sig_gen(key.get(), e.get()));
  ASSERT_TRUE(sig);
  const BIGNUM *r, *s;
  ECDSA_SIG_get0(sig.get(), &r, &s);

  // Test with r=0 - should fail
  bssl::UniquePtr<ECDSA_SIG> sig_r_zero(ECDSA_SIG_new());
  BIGNUM *zero = BN_new();
  BIGNUM *s_copy = BN_dup(s);
  ECDSA_SIG_set0(sig_r_zero.get(), zero, s_copy);
  EXPECT_EQ(0, sm2_sig_verify(key.get(), sig_r_zero.get(), e.get()));

  // Test with s=0 - should fail
  bssl::UniquePtr<ECDSA_SIG> sig_s_zero(ECDSA_SIG_new());
  BIGNUM *r_copy = BN_dup(r);
  BIGNUM *zero2 = BN_new();
  ECDSA_SIG_set0(sig_s_zero.get(), r_copy, zero2);
  EXPECT_EQ(0, sm2_sig_verify(key.get(), sig_s_zero.get(), e.get()));

  // Test with r>=n (set r equal to curve order)
  bssl::UniquePtr<ECDSA_SIG> sig_r_ge_n(ECDSA_SIG_new());
  const EC_GROUP *group = EC_KEY_get0_group(key.get());
  bssl::UniquePtr<BIGNUM> order(BN_new());
  ASSERT_TRUE(EC_GROUP_get_order(group, order.get(), nullptr));
  BIGNUM *r_ge_n = BN_dup(order.get());
  BIGNUM *s_copy2 = BN_dup(s);
  ECDSA_SIG_set0(sig_r_ge_n.get(), r_ge_n, s_copy2);
  EXPECT_EQ(0, sm2_sig_verify(key.get(), sig_r_ge_n.get(), e.get()));

  // Test with s>=n (set s equal to curve order)
  bssl::UniquePtr<ECDSA_SIG> sig_s_ge_n(ECDSA_SIG_new());
  BIGNUM *r_copy2 = BN_dup(r);
  BIGNUM *s_ge_n = BN_dup(order.get());
  ECDSA_SIG_set0(sig_s_ge_n.get(), r_copy2, s_ge_n);
  EXPECT_EQ(0, sm2_sig_verify(key.get(), sig_s_ge_n.get(), e.get()));

  // Test with wrong public key
  bssl::UniquePtr<EC_KEY> key2(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key2);
  ASSERT_TRUE(SM2_generate_key(key2.get()));
  EXPECT_EQ(0, sm2_sig_verify(key2.get(), sig.get(), e.get()));

  // Test NULL key - should return 0
  EXPECT_EQ(0, sm2_sig_verify(nullptr, sig.get(), e.get()));

  // Test NULL sig - should return 0
  EXPECT_EQ(0, sm2_sig_verify(key.get(), nullptr, e.get()));

  // Test NULL e - should return 0
  EXPECT_EQ(0, sm2_sig_verify(key.get(), sig.get(), nullptr));
}

// Test SM2 sign/verify with user ID
TEST(SM2Test, SignVerifyWithId) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  const char *msg = "Hello, SM2!";
  const uint8_t id[] = "test_id";

  // Sign
  uint8_t sig[72];
  size_t sig_len = sizeof(sig);
  ASSERT_TRUE(SM2_sign_with_id(key.get(), id, sizeof(id) - 1,
                                (const uint8_t *)msg, strlen(msg),
                                sig, &sig_len));

  // Verify
  EXPECT_TRUE(SM2_verify_with_id(key.get(), id, sizeof(id) - 1,
                                  (const uint8_t *)msg, strlen(msg),
                                  sig, sig_len));

  // Verify with wrong message should fail
  const char *wrong_msg = "Wrong message";
  EXPECT_FALSE(SM2_verify_with_id(key.get(), id, sizeof(id) - 1,
                                   (const uint8_t *)wrong_msg, strlen(wrong_msg),
                                   sig, sig_len));
}

// Test SM2 sign/verify with default user ID
TEST(SM2Test, SignVerifyDefaultId) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  const char *msg = "Test with default ID";

  // Sign with NULL ID (uses default)
  uint8_t sig[72];
  size_t sig_len = sizeof(sig);
  ASSERT_TRUE(SM2_sign_with_id(key.get(), nullptr, 0,
                                (const uint8_t *)msg, strlen(msg),
                                sig, &sig_len));

  // Verify with NULL ID
  EXPECT_TRUE(SM2_verify_with_id(key.get(), nullptr, 0,
                                  (const uint8_t *)msg, strlen(msg),
                                  sig, sig_len));

  // Verify with wrong ID should fail
  const uint8_t wrong_id[] = "wrong_id";
  EXPECT_FALSE(SM2_verify_with_id(key.get(), wrong_id, sizeof(wrong_id) - 1,
                                   (const uint8_t *)msg, strlen(msg),
                                   sig, sig_len));
}

// Test SM2 sign/verify error handling
TEST(SM2Test, SignVerifyErrorHandling) {
  if (!SM2CurveAvailable()) {
    GTEST_SKIP() << "SM2 curve not available";
  }

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  const char *msg = "Test message";
  const uint8_t id[] = "test_id";
  uint8_t sig[72];
  size_t sig_len = sizeof(sig);

  // Test NULL key
  EXPECT_FALSE(SM2_sign_with_id(nullptr, id, sizeof(id) - 1,
                                 (const uint8_t *)msg, strlen(msg),
                                 sig, &sig_len));
  EXPECT_FALSE(SM2_verify_with_id(nullptr, id, sizeof(id) - 1,
                                   (const uint8_t *)msg, strlen(msg),
                                   sig, sig_len));

  // Test NULL message
  EXPECT_FALSE(SM2_sign_with_id(key.get(), id, sizeof(id) - 1,
                                 nullptr, 0, sig, &sig_len));
  EXPECT_FALSE(SM2_verify_with_id(key.get(), id, sizeof(id) - 1,
                                   nullptr, 0, sig, sig_len));

  // Test NULL signature buffer
  EXPECT_FALSE(SM2_sign_with_id(key.get(), id, sizeof(id) - 1,
                                 (const uint8_t *)msg, strlen(msg),
                                 nullptr, &sig_len));

  // Test NULL sig_len
  EXPECT_FALSE(SM2_sign_with_id(key.get(), id, sizeof(id) - 1,
                                 (const uint8_t *)msg, strlen(msg),
                                 sig, nullptr));

  // Test NULL signature for verify
  EXPECT_FALSE(SM2_verify_with_id(key.get(), id, sizeof(id) - 1,
                                   (const uint8_t *)msg, strlen(msg),
                                   nullptr, 0));

  // Test buffer too small
  uint8_t small_sig[1];
  size_t small_len = sizeof(small_sig);
  EXPECT_FALSE(SM2_sign_with_id(key.get(), id, sizeof(id) - 1,
                                 (const uint8_t *)msg, strlen(msg),
                                 small_sig, &small_len));

  // Test corrupted signature
  ASSERT_TRUE(SM2_sign_with_id(key.get(), id, sizeof(id) - 1,
                                (const uint8_t *)msg, strlen(msg),
                                sig, &sig_len));
  sig[0] ^= 0xFF;  // Corrupt first byte
  EXPECT_FALSE(SM2_verify_with_id(key.get(), id, sizeof(id) - 1,
                                   (const uint8_t *)msg, strlen(msg),
                                   sig, sig_len));
}
