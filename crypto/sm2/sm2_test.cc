/* Copyright 2025 mogoweb<mogoweb@gmail.com>.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

/*
 * tests for the SM2 module.
 */
#include <gtest/gtest.h>

#include <openssl/digest.h>
#include <openssl/nid.h>
#include <openssl/sm2.h>
#include <openssl/sm3.h>


TEST(SM2Test, encrypt) {
  uint8_t msg[] = {
    0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x69, 
    0x6F, 0x6E, 0x20, 0x73, 0x74, 0x61, 0x6E, 0x64,
    0x61, 0x72, 0x64,
  };  // "encryption standard"

  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(EC_KEY_generate_key(key.get()));
  uint8_t ciphertext_buf[1024];
  size_t ciphertext_len = 0;

  ASSERT_TRUE(ossl_sm2_encrypt(key.get(), EVP_sm3(), msg, sizeof(msg), ciphertext_buf, &ciphertext_len));
  ASSERT_TRUE(ciphertext_len > 0);

  uint8_t plaintext_buf[512];
  size_t plaintext_len = sizeof(plaintext_buf);
  ASSERT_TRUE(ossl_sm2_decrypt(key.get(), EVP_sm3(), ciphertext_buf, ciphertext_len, plaintext_buf, &plaintext_len));
  ASSERT_TRUE(plaintext_len > 0);
  ASSERT_TRUE(memcmp(msg, plaintext_buf, plaintext_len) == 0);
}
