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

#include <openssl/cipher.h>

#include <string.h>

#include <openssl/nid.h>
#include <openssl/sm4.h>

#include "../fipsmodule/cipher/internal.h"
#include "../internal.h"


using namespace bssl;

static int sm4_init_key(EVP_CIPHER_CTX *ctx, const uint8_t *key,
                        const uint8_t *iv, int enc) {
  SM4_KEY *sm4_key = reinterpret_cast<SM4_KEY *>(ctx->cipher_data);
  if (!SM4_set_key(key, sm4_key)) {
    return 0;
  }
  ctx->encrypt = enc;
  return 1;
}

// SM4 ECB mode wrapper
static int sm4_ecb_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                          const uint8_t *in, size_t len) {
  SM4_KEY *sm4_key = reinterpret_cast<SM4_KEY *>(ctx->cipher_data);

  while (len >= 16) {
    if (ctx->encrypt) {
      SM4_encrypt(in, out, sm4_key);
    } else {
      SM4_decrypt(in, out, sm4_key);
    }
    len -= 16;
    in += 16;
    out += 16;
  }
  return 1;
}

static const EVP_CIPHER sm4_ecb = {
    /*nid=*/NID_undef,
    /*block_size=*/16,
    /*key_len=*/16,
    /*iv_len=*/0,
    /*ctx_size=*/sizeof(SM4_KEY),
    /*flags=*/EVP_CIPH_ECB_MODE,
    /*init=*/sm4_init_key,
    /*cipher_update=*/sm4_ecb_cipher,
    /*cipher_final=*/nullptr,
    /*update_aad=*/nullptr,
    /*cleanup=*/nullptr,
    /*ctrl=*/nullptr,
};

const EVP_CIPHER *EVP_sm4_ecb(void) { return &sm4_ecb; }

// SM4 CBC mode wrapper
static int sm4_cbc_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                          const uint8_t *in, size_t len) {
  SM4_KEY *sm4_key = reinterpret_cast<SM4_KEY *>(ctx->cipher_data);
  uint8_t *iv = ctx->iv;

  if (ctx->encrypt) {
    // CBC encryption
    while (len >= 16) {
      // XOR plaintext with IV
      for (size_t i = 0; i < 16; i++) {
        out[i] = in[i] ^ iv[i];
      }
      // Encrypt block
      SM4_encrypt(out, out, sm4_key);
      // IV becomes the ciphertext
      iv = out;
      len -= 16;
      in += 16;
      out += 16;
    }
    // Update IV for next call
    if (iv != ctx->iv) {
      OPENSSL_memcpy(ctx->iv, iv, 16);
    }
  } else {
    // CBC decryption
    uint8_t tmp[16];
    while (len >= 16) {
      // Save ciphertext block
      OPENSSL_memcpy(tmp, in, 16);
      // Decrypt block
      SM4_decrypt(in, out, sm4_key);
      // XOR with IV
      for (size_t i = 0; i < 16; i++) {
        out[i] ^= iv[i];
      }
      // IV becomes the saved ciphertext
      OPENSSL_memcpy(iv, tmp, 16);
      len -= 16;
      in += 16;
      out += 16;
    }
  }
  return 1;
}

static const EVP_CIPHER sm4_cbc = {
    /*nid=*/NID_undef,
    /*block_size=*/16,
    /*key_len=*/16,
    /*iv_len=*/16,
    /*ctx_size=*/sizeof(SM4_KEY),
    /*flags=*/EVP_CIPH_CBC_MODE,
    /*init=*/sm4_init_key,
    /*cipher_update=*/sm4_cbc_cipher,
    /*cipher_final=*/nullptr,
    /*update_aad=*/nullptr,
    /*cleanup=*/nullptr,
    /*ctrl=*/nullptr,
};

const EVP_CIPHER *EVP_sm4_cbc(void) { return &sm4_cbc; }

// SM4 CTR mode wrapper (stream cipher)
static int sm4_ctr_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                          const uint8_t *in, size_t len) {
  SM4_KEY *sm4_key = reinterpret_cast<SM4_KEY *>(ctx->cipher_data);
  uint8_t *ivec = ctx->iv;
  uint8_t *ecount_buf = ctx->buf;
  unsigned int *num = &ctx->num;

  // CTR mode: increment counter and XOR with keystream
  while (len > 0) {
    if (*num == 0) {
      // Generate next keystream block
      SM4_encrypt(ivec, ecount_buf, sm4_key);

      // Increment counter (last 4 bytes in big-endian)
      uint32_t counter = CRYPTO_load_u32_be(ivec + 12);
      counter++;
      CRYPTO_store_u32_be(ivec + 12, counter);
    }

    *out++ = *in++ ^ ecount_buf[*num];
    *num = (*num + 1) % 16;
    len--;
  }
  return 1;
}

static const EVP_CIPHER sm4_ctr = {
    /*nid=*/NID_undef,
    /*block_size=*/1,  // Stream cipher
    /*key_len=*/16,
    /*iv_len=*/16,
    /*ctx_size=*/sizeof(SM4_KEY),
    /*flags=*/EVP_CIPH_CTR_MODE,
    /*init=*/sm4_init_key,
    /*cipher_update=*/sm4_ctr_cipher,
    /*cipher_final=*/nullptr,
    /*update_aad=*/nullptr,
    /*cleanup=*/nullptr,
    /*ctrl=*/nullptr,
};

const EVP_CIPHER *EVP_sm4_ctr(void) { return &sm4_ctr; }

// SM4 OFB mode wrapper (stream cipher)
static int sm4_ofb_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                          const uint8_t *in, size_t len) {
  SM4_KEY *sm4_key = reinterpret_cast<SM4_KEY *>(ctx->cipher_data);
  uint8_t *iv = ctx->iv;
  unsigned int *num = &ctx->num;

  while (len > 0) {
    if (*num == 0) {
      // Encrypt IV to get next keystream
      SM4_encrypt(iv, iv, sm4_key);
    }

    *out++ = *in++ ^ iv[*num];
    *num = (*num + 1) % 16;
    len--;
  }
  return 1;
}

static const EVP_CIPHER sm4_ofb = {
    /*nid=*/NID_undef,
    /*block_size=*/1,  // Stream cipher
    /*key_len=*/16,
    /*iv_len=*/16,
    /*ctx_size=*/sizeof(SM4_KEY),
    /*flags=*/EVP_CIPH_OFB_MODE,
    /*init=*/sm4_init_key,
    /*cipher_update=*/sm4_ofb_cipher,
    /*cipher_final=*/nullptr,
    /*update_aad=*/nullptr,
    /*cleanup=*/nullptr,
    /*ctrl=*/nullptr,
};

const EVP_CIPHER *EVP_sm4_ofb(void) { return &sm4_ofb; }

// SM4 CFB mode wrapper (stream cipher)
static int sm4_cfb_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out,
                          const uint8_t *in, size_t len) {
  SM4_KEY *sm4_key = reinterpret_cast<SM4_KEY *>(ctx->cipher_data);
  uint8_t *iv = ctx->iv;
  unsigned int *num = &ctx->num;

  while (len > 0) {
    if (*num == 0) {
      if (ctx->encrypt) {
        // Encrypt IV
        SM4_encrypt(iv, iv, sm4_key);
      } else {
        // For decryption, we need to save the input first
        // The IV is updated with the ciphertext before decryption
        uint8_t tmp[16];
        OPENSSL_memcpy(tmp, iv, 16);
        SM4_encrypt(tmp, iv, sm4_key);
      }
    }

    if (ctx->encrypt) {
      // Ciphertext = Plaintext XOR keystream
      uint8_t c = *in++ ^ iv[*num];
      // Save ciphertext for next IV
      iv[*num] = c;
      *out++ = c;
    } else {
      // Save ciphertext for next IV
      uint8_t c = *in++;
      // Plaintext = Ciphertext XOR keystream
      *out++ = c ^ iv[*num];
      // Update IV with ciphertext
      iv[*num] = c;
    }

    *num = (*num + 1) % 16;
    len--;
  }
  return 1;
}

static const EVP_CIPHER sm4_cfb = {
    /*nid=*/NID_undef,
    /*block_size=*/1,  // Stream cipher
    /*key_len=*/16,
    /*iv_len=*/16,
    /*ctx_size=*/sizeof(SM4_KEY),
    /*flags=*/EVP_CIPH_CFB_MODE,
    /*init=*/sm4_init_key,
    /*cipher_update=*/sm4_cfb_cipher,
    /*cipher_final=*/nullptr,
    /*update_aad=*/nullptr,
    /*cleanup=*/nullptr,
    /*ctrl=*/nullptr,
};

const EVP_CIPHER *EVP_sm4_cfb(void) { return &sm4_cfb; }
