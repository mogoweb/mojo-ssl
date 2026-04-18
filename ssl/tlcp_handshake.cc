// Copyright 2026 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0

#include <openssl/ssl.h>
#include <openssl/tlcp.h>

#include "../crypto/internal.h"
#include "internal.h"

BSSL_NAMESPACE_BEGIN

// TLCP handshake states.
// These follow the TLS 1.2 state machine pattern but simplified for TLCP.
enum class tlcp_state_t {
  kOK = 0,                      // Handshake complete
  kSW_CLNT_HELLO,               // Send ClientHello
  kSR_SRVR_HELLO,               // Receive ServerHello
  kSR_CERT,                     // Receive Certificate (dual certs)
  kSR_SRVR_DONE,                // Receive ServerHelloDone
  kSW_KEY_EXCH,                 // Send ClientKeyExchange
  kSW_CHANGE,                   // Send ChangeCipherSpec
  kSW_FINISHED,                 // Send Finished
  kSR_CHANGE,                   // Receive ChangeCipherSpec
  kSR_FINISHED,                 // Receive Finished
};

// tlcp_handshake performs TLCP handshake.
bool tlcp_handshake(SSL_HANDSHAKE *hs) {
  if (hs == nullptr || hs->ssl == nullptr) {
    return false;
  }

  // The actual state machine implementation will be added
  // in subsequent tasks. For now, this is a skeleton.

  return true;
}

BSSL_NAMESPACE_END
