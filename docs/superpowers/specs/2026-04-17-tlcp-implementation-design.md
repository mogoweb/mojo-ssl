# TLCP Protocol Implementation Design

**Date:** 2026-04-17
**Status:** Draft
**Scope:** Minimal viable TLCP with ECC_SM2_SM4_CBC_SM3 cipher suite

## Overview

This document describes the design for implementing TLCP (Transport Layer Cryptography Protocol, GB/T 38636-2020) on BoringSSL. TLCP is a Chinese national standard for secure communications that uses SM2, SM3, and SM4 cryptographic algorithms.

### Scope

- **Protocol:** Minimal viable TLCP (core handshake, one cipher suite)
- **Cipher Suite:** ECC_SM2_SM4_CBC_SM3 (static SM2 key exchange)
- **Authentication:** Server-only (client authentication can be added later)
- **Certificates:** Dual certificate mechanism (sign + encrypt)
- **Approach:** Clean BoringSSL-style implementation, referencing Tongsuo for protocol details
- **Testing:** Unit tests + interoperability tests with Tongsuo

## Architecture

### Component Structure

```
Application Layer (SSL_CTX/SSL)
    |
ssl/tlcp_method.cc --> TLCP_METHOD (version 0x0101)
    |
ssl/tlcp_handshake.cc [Core handshake coordinator]
    |                     |
    +-- ssl/tlcp_client.cc [Client handshake]
    |       |
    +-- ssl/tlcp_server.cc [Server handshake]
            |
ssl/tlcp_lib.cc [Shared utilities]
    |
EVP API --> SM2/SM3/SM4 (already implemented)
```

### Key Design Decisions

1. **Version Number:** TLCP uses wire version `0x0101` (same as TLS 1.1)
2. **Separate Files:** New `ssl/tlcp_*` files, not mixed with TLS code
3. **Record Layer:** Reuse BoringSSL's TLS 1.2 record layer with SM4-CBC
4. **State Machine:** Adapted from TLS 1.2 but simplified for TLCP
5. **Dual Certificates:** Sign cert for authentication, enc cert for key exchange

## Core Components

### 1. Protocol Method and Version

```c
// ssl/tlcp_method.cc
#define TLCP_VERSION 0x0101

extern const SSL_PROTOCOL_METHOD kTLCPProtocolMethod;
extern const SSL3_ENC_METHOD kTLCPEncMethod;
```

**Version handling:**
- Wire version: `0x0101` (distinguishes from TLS 1.2 `0x0303`)
- `SSL_is_tlcp(ssl)` helper to detect TLCP connections
- Cipher suites use TLCP-specific constants

### 2. Cipher Suite Definition

```c
// include/openssl/tlcp.h
#define TLCP_ECC_SM2_SM4_CBC_SM3 0x0001

// ssl/tlcp_ciphers.cc
static const SSL_CIPHER kTLCPCiphers[] = {
    {
        .id = TLCP_ECC_SM2_SM4_CBC_SM3,
        .name = "ECC-SM2-SM4-CBC-SM3",
        .algorithm_mkey = SSL_kSM2,
        .algorithm_auth = SSL_aSM2,
        .algorithm_enc = SSL_SM4CBC,
        .algorithm_mac = SSL_SM3,
        .min_tls = TLCP_VERSION,
        .max_tls = TLCP_VERSION,
    },
};
```

### 3. Dual Certificate Handling

```c
// ssl/internal.h additions
struct CERT {
    // Existing TLS fields...

    // TLCP dual certificate support
    CERT_PKEY *tlcp_sign;    // Signing certificate
    CERT_PKEY *tlcp_enc;     // Encryption certificate
};

// New API functions
int SSL_CTX_use_tlcp_sign_certificate(SSL_CTX *ctx, X509 *x, EVP_PKEY *pkey);
int SSL_CTX_use_tlcp_enc_certificate(SSL_CTX *ctx, X509 *x, EVP_PKEY *pkey);
int SSL_use_tlcp_sign_certificate(SSL *ssl, X509 *x, EVP_PKEY *pkey);
int SSL_use_tlcp_enc_certificate(SSL *ssl, X509 *x, EVP_PKEY *pkey);
```

**Certificate chain transmission:**
1. Server sends: sign_cert || enc_cert || intermediate_CA_chain
2. Client validates both certificates
3. Sign cert used for: CertificateVerify signature (future)
4. Enc cert used for: ClientKeyExchange encryption

## Handshake Flow

### ECC_SM2_SM4_CBC_SM3 Handshake Sequence

```
Client                                          Server
  |                                                |
  | -------- ClientHello (version=0x0101) -------> |
  |                                                |
  | <------- ServerHello (cipher_suite) ---------- |
  |                                                |
  | <---- Certificate (sign + enc + chain) ------- |
  |                                                |
  | <----------- ServerHelloDone ----------------- |
  |                                                |
  | -------- ClientKeyExchange (encrypted_premaster) --> |
  |                                                |
  | ----------- ChangeCipherSpec ----------------> |
  |                                                |
  | -------------- Finished ---------------------> |
  |                                                |
  | <----------- ChangeCipherSpec ----------------- |
  |                                                |
  | <--------------- Finished -------------------- |
  |                                                |
  | <======== Encrypted Application Data ========> |
```

**Key differences from TLS 1.2:**
- No ServerKeyExchange for static ECC mode (public key in enc certificate)
- No CertificateRequest (server-only auth for MVP)
- Dual certificates in Certificate message
- SM2 encryption for pre-master secret

### State Machine States

```c
enum tlcp_state_t {
    TLS_ST_OK,                    // Handshake complete
    TLS_ST_SW_CLNT_HELLO,         // Send ClientHello
    TLS_ST_SR_SRVR_HELLO,         // Receive ServerHello
    TLS_ST_SR_CERT,               // Receive Certificate (dual certs)
    TLS_ST_SR_SRVR_DONE,          // Receive ServerHelloDone
    TLS_ST_SW_KEY_EXCH,           // Send ClientKeyExchange
    TLS_ST_SW_CHANGE,             // Send ChangeCipherSpec
    TLS_ST_SW_FINISHED,           // Send Finished
    TLS_ST_SR_CHANGE,             // Receive ChangeCipherSpec
    TLS_ST_SR_FINISHED,           // Receive Finished
};
```

## Key Exchange

### Pre-Master Secret Generation (Client Side)

```c
// ssl/tlcp_client.cc
int tlcp_generate_pre_master_secret(SSL_HANDSHAKE *hs, uint8_t *out, size_t *out_len) {
    // 1. Generate random 48-byte pre-master secret
    //    pre_master[0..1] = TLCP_VERSION (0x0101)
    //    pre_master[2..47] = random 46 bytes
    // 2. Get server's encryption certificate public key (peer_chain[1])
    // 3. Encrypt with SM2: EVP_PKEY_encrypt() using SM2 key
    // 4. Return ASN.1 DER encoded ciphertext
}
```

### Pre-Master Secret Decryption (Server Side)

```c
// ssl/tlcp_server.cc
int tlcp_decrypt_pre_master_secret(SSL_HANDSHAKE *hs,
                                    const uint8_t *in, size_t in_len,
                                    uint8_t *out) {
    // 1. Parse ASN.1 DER ciphertext
    // 2. Decrypt with server's enc certificate private key
    // 3. Verify first 2 bytes == TLCP_VERSION
    // 4. Return 48-byte pre-master secret
}
```

### Master Secret Derivation

```c
// ssl/tlcp_lib.cc
// Uses TLS 1.2 PRF with SM3 as the hash function
// master_secret = PRF(pre_master_secret, "master secret",
//                     ClientRandom || ServerRandom)[0..47]
```

### Key Block Derivation

```c
// For SM4-CBC with SM3:
// key_block = PRF(master_secret, "key expansion",
//                 ServerRandom || ClientRandom)
//
// Key material layout:
//   client_write_MAC_key[32]  (SM3 digest size)
//   server_write_MAC_key[32]
//   client_write_key[16]      (SM4 key size)
//   server_write_key[16]
//   client_write_IV[16]
//   server_write_IV[16]
```

## Record Layer

### SM4-CBC with SM3 HMAC

```c
// ssl/tlcp_record.cc
// Reuses TLS 1.2 CBC pattern with SM4 and SM3

// MAC computation:
// MAC = HMAC-SM3(mac_key, seq_num || TLCP_version || content_type || length || data)

static const SSL3_ENC_METHOD kTLCPEncMethod = {
    .prf = tls1_prf,
    .mac = tls1_mac,
    .setup_key_block = tlcp_setup_key_block,
    .generate_master_secret = tls1_generate_master_secret,
    .final_finish_mac = tls1_final_finish_mac,
    .client_finished_label = "client finished",
    .server_finished_label = "server finished",
    .client_finished_label_len = 15,
    .server_finished_label_len = 15,
};
```

## Error Handling

### Error Codes

```c
// include/openssl/tlcp.h
#define TLCP_R_INVALID_DUAL_CERTIFICATE        100
#define TLCP_R_MISSING_ENCRYPTION_CERTIFICATE   101
#define TLCP_R_MISSING_SIGNING_CERTIFICATE      102
#define TLCP_R_INVALID_CERTIFICATE_USAGE        103
#define TLCP_R_SM2_ENCRYPTION_FAILED            104
#define TLCP_R_SM2_DECRYPTION_FAILED            105
#define TLCP_R_INVALID_PRE_MASTER_SECRET        106
#define TLCP_R_UNSUPPORTED_CIPHER_SUITE         107
#define TLCP_R_HANDSHAKE_FAILURE                108
```

### Certificate Validation

```c
// ssl/tlcp_lib.cc
int tlcp_validate_dual_certificates(SSL_HANDSHAKE *hs) {
    // 1. Verify sign certificate has digitalSignature key usage
    // 2. Verify enc certificate has keyEncipherment key usage
    // 3. Both certificates must be SM2 (EVP_PKEY_SM2)
    // 4. Check certificate validity period
    // 5. Verify certificate chain
}
```

## Testing Strategy

### Unit Tests

```c
// crypto/tlcp/tlcp_test.cc
TEST_F(TLCPTest, MethodCreation);
TEST_F(TLCPTest, VersionNumber);
TEST_F(TLCPTest, CipherSuiteRegistration);
TEST_F(TLCPTest, DualCertificateLoad);
TEST_F(TLCPTest, PreMasterSecretGeneration);
TEST_F(TLCPTest, MasterSecretDerivation);
TEST_F(TLCPTest, KeyBlockDerivation);
```

### Integration Tests

```c
// ssl/test/tlcp_test.cc
TEST_F(TLCPIntegrationTest, BasicHandshake);
TEST_F(TLCPIntegrationTest, DataTransfer);
```

### Interoperability Tests

```python
# ssl/test/tlcp_interop_test.py
class TLCPInteropTest:
    def test_handshake_with_tongsuo_server(self);
    def test_handshake_with_tongsuo_client(self);
```

## File Organization

```
ssl/
  |-- tlcp_method.cc          # Protocol method and version
  |-- tlcp_ciphers.cc         # Cipher suite definitions
  |-- tlcp_handshake.cc       # State machine coordinator
  |-- tlcp_client.cc          # Client handshake logic
  |-- tlcp_server.cc          # Server handshake logic
  |-- tlcp_lib.cc             # Shared utilities
  |-- tlcp_record.cc          # Record layer integration
  '-- internal.h              # Add TLCP fields to SSL/CERT structs

include/openssl/
  '-- tlcp.h                  # Public API declarations

crypto/
  '-- tlcp/
      '-- tlcp_test.cc        # Unit tests

ssl/test/
  |-- tlcp_test.cc            # Integration tests
  '-- tlcp_interop_test.py    # Interoperability tests
```

## Implementation Dependencies

### Already Implemented in BoringSSL

- SM2 (crypto/sm2/) - key generation, sign/verify, encrypt/decrypt
- SM3 (crypto/sm3/) - hash function
- SM4 (crypto/sm4/) - block cipher
- EVP API for SM2/SM3/SM4
- TLS 1.2 record layer (reused)
- TLS 1.2 PRF (adapted for SM3)

### To Be Implemented

- TLCP protocol method
- Cipher suite registration
- Dual certificate handling
- Handshake state machine
- Key exchange (SM2 encryption of pre-master)
- Certificate validation for dual certs

## Reference Documentation

- `docs/tongsuo/tlcp.md` - TLCP protocol flow analysis
- `docs/tongsuo/sm2_crypt.md` - SM2 encryption/decryption
- `docs/tongsuo/sm3.md` - SM3 hash implementation
- `docs/tongsuo/sm4.md` - SM4 cipher implementation
- Tongsuo source: `../Tongsuo/ssl/statem_ntls/`
