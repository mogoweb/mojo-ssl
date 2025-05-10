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
 * tests for the SM4 module.
 */
#include <gtest/gtest.h>

# include <openssl/sm4.h>


TEST(SM4Test, ecb) {

  static const uint8_t k[SM4_BLOCK_SIZE] = {
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
  };

  static const uint8_t input[SM4_BLOCK_SIZE] = {
      0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
  };

  /*
    * This test vector comes from Example 1 of GB/T 32907-2016,
    * and described in Internet Draft draft-ribose-cfrg-sm4-02.
    */
  static const uint8_t expected[SM4_BLOCK_SIZE] = {
      0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e,
      0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46
  };

  /*
    * This test vector comes from Example 2 from GB/T 32907-2016,
    * and described in Internet Draft draft-ribose-cfrg-sm4-02.
    * After 1,000,000 iterations.
    */
  static const uint8_t expected_iter[SM4_BLOCK_SIZE] = {
      0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f,
      0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66
  };

  int i;
  SM4_KEY key;
  uint8_t block[SM4_BLOCK_SIZE];

  ossl_sm4_set_key(k, &key);
  memcpy(block, input, SM4_BLOCK_SIZE);

  ossl_sm4_encrypt(block, block, &key);
  EXPECT_TRUE(memcmp(block, expected, SM4_BLOCK_SIZE) == 0);

  for (i = 0; i != 999999; ++i)
    ossl_sm4_encrypt(block, block, &key);

  EXPECT_TRUE(memcmp(block, expected_iter, SM4_BLOCK_SIZE) == 0);

  for (i = 0; i != 1000000; ++i)
    ossl_sm4_decrypt(block, block, &key);

  EXPECT_TRUE(memcmp(block, input, SM4_BLOCK_SIZE) == 0);
}
