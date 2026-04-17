// Copyright 2026 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0

#include <openssl/ssl.h>
#include <openssl/tlcp.h>

#include <assert.h>

#include "../crypto/internal.h"
#include "internal.h"

BSSL_NAMESPACE_BEGIN

// TLCP uses the same record layer as TLS 1.2, but with SM4-CBC/SM3.
// We reuse the TLS protocol method functions.

static void tlcp_on_handshake_complete(SSL *ssl) {
  assert(!ssl->s3->has_message);
  assert(!ssl->s3->hs_buf || ssl->s3->hs_buf->length == 0);
  if (ssl->s3->hs_buf && ssl->s3->hs_buf->length == 0) {
    ssl->s3->hs_buf.reset();
  }
}

static bool tlcp_set_read_state(SSL *ssl, ssl_encryption_level_t level,
                                UniquePtr<SSLAEADContext> aead_ctx,
                                Span<const uint8_t> traffic_secret) {
  if (tls_has_unprocessed_handshake_data(ssl)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_EXCESS_HANDSHAKE_DATA);
    ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
    return false;
  }

  ssl->s3->read_sequence = 0;
  ssl->s3->aead_read_ctx = std::move(aead_ctx);
  return true;
}

static bool tlcp_set_write_state(SSL *ssl, ssl_encryption_level_t level,
                                 UniquePtr<SSLAEADContext> aead_ctx,
                                 Span<const uint8_t> traffic_secret) {
  if (!tls_flush_pending_hs_data(ssl)) {
    return false;
  }

  ssl->s3->write_sequence = 0;
  ssl->s3->aead_write_ctx = std::move(aead_ctx);
  return true;
}

static void tlcp_finish_flight(SSL *ssl) {}

static void tlcp_schedule_ack(SSL *ssl) {}

static const SSL_PROTOCOL_METHOD kTLCPProtocolMethod = {
    false /* is_dtls */,
    tls_new,
    tls_free,
    tls_get_message,
    tls_next_message,
    tls_has_unprocessed_handshake_data,
    tls_open_handshake,
    tls_open_change_cipher_spec,
    tls_open_app_data,
    tls_write_app_data,
    tls_dispatch_alert,
    tls_init_message,
    tls_finish_message,
    tls_add_message,
    tls_add_change_cipher_spec,
    tlcp_finish_flight,
    tlcp_schedule_ack,
    tls_flush,
    tlcp_on_handshake_complete,
    tlcp_set_read_state,
    tlcp_set_write_state,
};

BSSL_NAMESPACE_END

using namespace bssl;

const SSL_METHOD *TLCP_method() {
  static const SSL_METHOD kMethod = {
      0,
      &kTLCPProtocolMethod,
      &ssl_crypto_x509_method,
  };
  return &kMethod;
}

const SSL_METHOD *TLCP_server_method() { return TLCP_method(); }

const SSL_METHOD *TLCP_client_method() { return TLCP_method(); }

int SSL_is_tlcp(const SSL *ssl) {
  if (ssl == nullptr || ssl->s3 == nullptr) {
    return 0;
  }
  return ssl->s3->version == TLCP_VERSION;
}
