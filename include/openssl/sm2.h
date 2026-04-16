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

#ifndef OPENSSL_HEADER_SM2_H
#define OPENSSL_HEADER_SM2_H

#include <openssl/base.h>  // IWYU pragma: export
#include <openssl/ec_key.h>

#if defined(__cplusplus)
extern "C" {
#endif


// SM2 is an elliptic curve asymmetric encryption algorithm defined in
// GM/T 0003-2012 (China). This implementation supports key generation,
// encryption, and decryption using the SM2 curve.


// SM2_ciphertext_size returns the maximum size of an SM2 ciphertext for a
// plaintext of length |plaintext_len|.
OPENSSL_EXPORT size_t SM2_ciphertext_size(size_t plaintext_len);

// SM2_plaintext_size returns the maximum plaintext size for a ciphertext
// of length |ciphertext_len|.
OPENSSL_EXPORT size_t SM2_plaintext_size(size_t ciphertext_len);

// SM2_generate_key generates an SM2 key pair and stores it in |key|.
// |key| must have the SM2 curve group set (via EC_KEY_new_by_curve_name
// with NID_sm2). It returns 1 on success and 0 on error.
OPENSSL_EXPORT int SM2_generate_key(EC_KEY *key);

// SM2_check_private_key validates that |key| contains a valid SM2 private key.
// The private key must be in range [1, n-1) where n is the curve order.
// It returns 1 if valid, 0 otherwise.
OPENSSL_EXPORT int SM2_check_private_key(const EC_KEY *key);

// SM2_encrypt encrypts |plaintext_len| bytes from |plaintext| using the
// public key in |key|. The ciphertext is written to |ciphertext| and its
// length is stored in |*ciphertext_len|. The |ciphertext| buffer must have
// at least |SM2_ciphertext_size(plaintext_len)| bytes. The ciphertext is
// ASN.1 DER encoded. It returns 1 on success and 0 on error.
OPENSSL_EXPORT int SM2_encrypt(const EC_KEY *key,
                                const uint8_t *plaintext, size_t plaintext_len,
                                uint8_t *ciphertext, size_t *ciphertext_len);

// SM2_decrypt decrypts |ciphertext_len| bytes from |ciphertext| using the
// private key in |key|. The plaintext is written to |plaintext| and its
// length is stored in |*plaintext_len|. The |plaintext| buffer must have
// at least |SM2_plaintext_size(ciphertext_len)| bytes.
// It returns 1 on success and 0 on error.
OPENSSL_EXPORT int SM2_decrypt(const EC_KEY *key,
                                const uint8_t *ciphertext, size_t ciphertext_len,
                                uint8_t *plaintext, size_t *plaintext_len);

// SM2_signature_size returns the maximum size of an SM2 signature.
// SM2 signatures are DER-encoded and contain two 32-byte integers (r and s).
OPENSSL_EXPORT size_t SM2_signature_size(void);

// SM2_compute_z_digest computes the Z value for SM2 signing.
// Z = SM3(ENTL || ID || a || b || xG || yG || xA || yA) per GM/T 0003-2012.
// ENTL is the 16-bit big-endian bit length of the user ID.
// If |id| is NULL, uses the default user ID "1234567812345678".
// |out| must have space for 32 bytes (SM3 digest size).
// Returns 1 on success, 0 on error.
OPENSSL_EXPORT int SM2_compute_z_digest(uint8_t *out, const EC_KEY *key,
                                        const uint8_t *id, size_t id_len);


// Error codes for SM2 operations.
#define SM2_R_INVALID_PRIVATE_KEY 100
#define SM2_R_INVALID_PUBLIC_KEY 101
#define SM2_R_INVALID_CIPHERTEXT 102
#define SM2_R_ASN1_ERROR 103
#define SM2_R_DIGEST_MISMATCH 104
#define SM2_R_BUFFER_TOO_SMALL 105
#define SM2_R_ID_TOO_LARGE 106
#define SM2_R_TOO_MANY_ITERATIONS 107
#define SM2_R_INVALID_SIGNATURE 108


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_SM2_H
