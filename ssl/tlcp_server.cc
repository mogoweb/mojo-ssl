// Copyright 2026 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0

#include <openssl/ssl.h>
#include <openssl/tlcp.h>
#include <openssl/evp.h>

#include "../crypto/internal.h"
#include "internal.h"

BSSL_NAMESPACE_BEGIN

// kTLCPPreMasterLen is the length of the pre-master secret for TLCP.
static constexpr size_t kTLCPPreMasterLen = 48;

// tlcp_decrypt_pre_master_secret decrypts the ClientKeyExchange content
// using the server's SM2 encryption private key.
bool tlcp_decrypt_pre_master_secret(SSL_HANDSHAKE *hs,
                                    const EVP_PKEY *server_enc_pkey,
                                    const uint8_t *in, size_t in_len,
                                    uint8_t *out, size_t *out_len) {
  if (hs == nullptr || server_enc_pkey == nullptr ||
      in == nullptr || out == nullptr || out_len == nullptr) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_PASSED_NULL_PARAMETER);
    return false;
  }

  // Decrypt with SM2
  bssl::UniquePtr<EVP_PKEY_CTX> ctx(
      EVP_PKEY_CTX_new(const_cast<EVP_PKEY*>(server_enc_pkey), nullptr));
  if (!ctx) {
    OPENSSL_PUT_ERROR(SSL, TLCP_R_SM2_DECRYPTION_FAILED);
    return false;
  }

  if (EVP_PKEY_decrypt_init(ctx.get()) <= 0) {
    OPENSSL_PUT_ERROR(SSL, TLCP_R_SM2_DECRYPTION_FAILED);
    return false;
  }

  // Decrypt
  size_t plaintext_len = kTLCPPreMasterLen;
  if (EVP_PKEY_decrypt(ctx.get(), out, &plaintext_len, in, in_len) <= 0) {
    OPENSSL_PUT_ERROR(SSL, TLCP_R_SM2_DECRYPTION_FAILED);
    return false;
  }

  // Verify length
  if (plaintext_len != kTLCPPreMasterLen) {
    OPENSSL_PUT_ERROR(SSL, TLCP_R_INVALID_PRE_MASTER_SECRET);
    return false;
  }

  // Verify version bytes
  uint16_t version = (static_cast<uint16_t>(out[0]) << 8) | out[1];
  if (version != TLCP_VERSION) {
    OPENSSL_PUT_ERROR(SSL, TLCP_R_INVALID_PRE_MASTER_SECRET);
    return false;
  }

  // Store pre-master secret in handshake
  if (!hs->pre_master_secret.Init(plaintext_len)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return false;
  }
  OPENSSL_memcpy(hs->pre_master_secret.data(), out, plaintext_len);

  *out_len = plaintext_len;
  return true;
}

BSSL_NAMESPACE_END
