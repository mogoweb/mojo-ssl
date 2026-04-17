// Copyright 2026 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0

#include <openssl/ssl.h>
#include <openssl/tlcp.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include "../crypto/internal.h"
#include "internal.h"

BSSL_NAMESPACE_BEGIN

// kTLCPPreMasterLen is the length of the pre-master secret for TLCP.
static constexpr size_t kTLCPPreMasterLen = 48;

// tlcp_generate_pre_master_secret generates a 48-byte pre-master secret
// for TLCP. The first two bytes are the TLCP version, and the remaining
// 46 bytes are random.
static bool tlcp_generate_pre_master_secret(uint8_t *out, size_t *out_len) {
  if (out == nullptr || out_len == nullptr) {
    return false;
  }

  // First 2 bytes: version
  out[0] = (TLCP_VERSION >> 8) & 0xff;
  out[1] = TLCP_VERSION & 0xff;

  // Remaining 46 bytes: random
  if (!RAND_bytes(out + 2, kTLCPPreMasterLen - 2)) {
    return false;
  }

  *out_len = kTLCPPreMasterLen;
  return true;
}

// tlcp_encrypt_pre_master_secret encrypts the pre-master secret using
// the server's SM2 encryption certificate public key.
bool tlcp_encrypt_pre_master_secret(SSL_HANDSHAKE *hs,
                                    const EVP_PKEY *server_enc_pkey,
                                    uint8_t *out, size_t *out_len) {
  if (hs == nullptr || server_enc_pkey == nullptr ||
      out == nullptr || out_len == nullptr) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_PASSED_NULL_PARAMETER);
    return false;
  }

  // Generate pre-master secret
  uint8_t pre_master[kTLCPPreMasterLen];
  size_t pre_master_len;
  if (!tlcp_generate_pre_master_secret(pre_master, &pre_master_len)) {
    OPENSSL_PUT_ERROR(SSL, TLCP_R_HANDSHAKE_FAILURE);
    return false;
  }

  // Store pre-master secret in handshake for later use
  if (!hs->pre_master_secret.Init(pre_master_len)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_MALLOC_FAILURE);
    return false;
  }
  OPENSSL_memcpy(hs->pre_master_secret.data(), pre_master, pre_master_len);

  // Encrypt with SM2
  bssl::UniquePtr<EVP_PKEY_CTX> ctx(
      EVP_PKEY_CTX_new(const_cast<EVP_PKEY*>(server_enc_pkey), nullptr));
  if (!ctx) {
    OPENSSL_PUT_ERROR(SSL, TLCP_R_SM2_ENCRYPTION_FAILED);
    return false;
  }

  if (EVP_PKEY_encrypt_init(ctx.get()) <= 0) {
    OPENSSL_PUT_ERROR(SSL, TLCP_R_SM2_ENCRYPTION_FAILED);
    return false;
  }

  // Determine output length
  size_t ciphertext_len;
  if (EVP_PKEY_encrypt(ctx.get(), nullptr, &ciphertext_len,
                       pre_master, pre_master_len) <= 0) {
    OPENSSL_PUT_ERROR(SSL, TLCP_R_SM2_ENCRYPTION_FAILED);
    return false;
  }

  // Encrypt
  if (EVP_PKEY_encrypt(ctx.get(), out, &ciphertext_len,
                       pre_master, pre_master_len) <= 0) {
    OPENSSL_PUT_ERROR(SSL, TLCP_R_SM2_ENCRYPTION_FAILED);
    return false;
  }

  *out_len = ciphertext_len;
  return true;
}

BSSL_NAMESPACE_END
