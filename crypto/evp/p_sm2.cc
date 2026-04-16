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

#include <openssl/evp.h>

#include <string.h>

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/digest.h>
#include <openssl/ec.h>
#include <openssl/ec_key.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/span.h>

#include "../ec/internal.h"
#include "../fipsmodule/ec/internal.h"
#include "../internal.h"
#include "internal.h"


using namespace bssl;

namespace {

struct EVP_PKEY_ALG_SM2 : public EVP_PKEY_ALG {
  // ec_group returns the |EC_GROUP| for this algorithm.
  const EC_GROUP *(*ec_group)();
};

extern const EVP_PKEY_ASN1_METHOD sm2_asn1_meth;

// sm2_pub_encode encodes an SM2 public key as a SubjectPublicKeyInfo.
// SM2 uses the same SEC1 encoding as EC keys.
static int sm2_pub_encode(CBB *out, const EvpPkey *key) {
  const EC_KEY *ec_key = reinterpret_cast<const EC_KEY *>(key->pkey);
  const EC_GROUP *group = EC_KEY_get0_group(ec_key);
  const EC_POINT *public_key = EC_KEY_get0_public_key(ec_key);

  // See RFC 5480, section 2 (same encoding as EC keys).
  CBB spki, algorithm, key_bitstring;
  if (!CBB_add_asn1(out, &spki, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1(&spki, &algorithm, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1_element(&algorithm, CBS_ASN1_OBJECT, sm2_asn1_meth.oid,
                            sm2_asn1_meth.oid_len) ||
      !EC_KEY_marshal_curve_name(&algorithm, group) ||
      !CBB_add_asn1(&spki, &key_bitstring, CBS_ASN1_BITSTRING) ||
      !CBB_add_u8(&key_bitstring, 0 /* padding */) ||
      !EC_POINT_point2cbb(&key_bitstring, group, public_key,
                          POINT_CONVERSION_UNCOMPRESSED, nullptr) ||
      !CBB_flush(out)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);
    return 0;
  }

  return 1;
}

// sm2_pub_decode decodes a SubjectPublicKeyInfo as an SM2 public key.
static bssl::evp_decode_result_t sm2_pub_decode(const EVP_PKEY_ALG *alg,
                                                 EvpPkey *out, CBS *params,
                                                 CBS *key) {
  // See RFC 5480, section 2 (same encoding as EC keys).

  // Check that |params| matches the SM2 curve.
  const EC_GROUP *group = static_cast<const EVP_PKEY_ALG_SM2 *>(alg)->ec_group();
  if (ec_key_parse_curve_name(params, Span(&group, 1)) == nullptr) {
    if (ERR_equals(ERR_peek_last_error(), ERR_LIB_EC, EC_R_UNKNOWN_GROUP)) {
      ERR_clear_error();
      return evp_decode_unsupported;
    }
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return evp_decode_error;
  }
  if (CBS_len(params) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return evp_decode_error;
  }

  UniquePtr<EC_KEY> eckey(EC_KEY_new());
  if (eckey == nullptr ||  //
      !EC_KEY_set_group(eckey.get(), group) ||
      !EC_KEY_oct2key(eckey.get(), CBS_data(key), CBS_len(key), nullptr)) {
    return evp_decode_error;
  }

  EVP_PKEY_assign_EC_KEY(out, eckey.release());
  return evp_decode_ok;
}

// sm2_pub_equal compares two SM2 public keys.
static bool sm2_pub_equal(const EvpPkey *a, const EvpPkey *b) {
  const EC_KEY *a_ec = reinterpret_cast<const EC_KEY *>(a->pkey);
  const EC_KEY *b_ec = reinterpret_cast<const EC_KEY *>(b->pkey);
  const EC_GROUP *group = EC_KEY_get0_group(b_ec);
  const EC_POINT *pa = EC_KEY_get0_public_key(a_ec),
                 *pb = EC_KEY_get0_public_key(b_ec);
  return EC_POINT_cmp(group, pa, pb, nullptr) == 0;
}

// sm2_pub_present checks if the public key exists.
static bool sm2_pub_present(const EvpPkey *pkey) {
  const EC_KEY *ec_key = reinterpret_cast<const EC_KEY *>(pkey->pkey);
  return EC_KEY_get0_public_key(ec_key) != nullptr;
}

// sm2_priv_decode decodes a PrivateKeyInfo as an SM2 private key.
static bssl::evp_decode_result_t sm2_priv_decode(const EVP_PKEY_ALG *alg,
                                                  EvpPkey *out, CBS *params,
                                                  CBS *key) {
  // See RFC 5915 (same encoding as EC keys).
  const EC_GROUP *group = static_cast<const EVP_PKEY_ALG_SM2 *>(alg)->ec_group();
  if (ec_key_parse_parameters(params, Span(&group, 1)) == nullptr) {
    if (ERR_equals(ERR_peek_last_error(), ERR_LIB_EC, EC_R_UNKNOWN_GROUP)) {
      ERR_clear_error();
      return evp_decode_unsupported;
    }
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return evp_decode_error;
  }
  if (CBS_len(params) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return evp_decode_error;
  }

  UniquePtr<EC_KEY> ec_key(ec_key_parse_private_key(key, group, {}));
  if (ec_key == nullptr || CBS_len(key) != 0) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_DECODE_ERROR);
    return evp_decode_error;
  }

  EVP_PKEY_assign_EC_KEY(out, ec_key.release());
  return evp_decode_ok;
}

// sm2_priv_encode encodes an SM2 private key as a PrivateKeyInfo.
static int sm2_priv_encode(CBB *out, const EvpPkey *key) {
  const EC_KEY *ec_key = reinterpret_cast<const EC_KEY *>(key->pkey);

  // Omit the redundant copy of the curve name, following EC key convention.
  unsigned enc_flags = EC_KEY_get_enc_flags(ec_key) | EC_PKEY_NO_PARAMETERS;

  // See RFC 5915 (same encoding as EC keys).
  CBB pkcs8, algorithm, private_key;
  if (!CBB_add_asn1(out, &pkcs8, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1_uint64(&pkcs8, 0 /* version */) ||
      !CBB_add_asn1(&pkcs8, &algorithm, CBS_ASN1_SEQUENCE) ||
      !CBB_add_asn1_element(&algorithm, CBS_ASN1_OBJECT, sm2_asn1_meth.oid,
                            sm2_asn1_meth.oid_len) ||
      !EC_KEY_marshal_curve_name(&algorithm, EC_KEY_get0_group(ec_key)) ||
      !CBB_add_asn1(&pkcs8, &private_key, CBS_ASN1_OCTETSTRING) ||
      !EC_KEY_marshal_private_key(&private_key, ec_key, enc_flags) ||
      !CBB_flush(out)) {
    OPENSSL_PUT_ERROR(EVP, EVP_R_ENCODE_ERROR);
    return 0;
  }

  return 1;
}

// sm2_priv_present checks if the private key exists.
static bool sm2_priv_present(const EvpPkey *pkey) {
  const EC_KEY *ec_key = reinterpret_cast<const EC_KEY *>(pkey->pkey);
  return EC_KEY_get0_private_key(ec_key) != nullptr;
}

// sm2_size returns the maximum SM2 signature size.
// SM2 signatures are up to 72 bytes (two 32-byte integers with DER encoding).
static int sm2_size(const EvpPkey *pkey) {
  // SM2 uses 256-bit scalars, so signatures are similar in size to P-256.
  // Maximum DER-encoded signature is approximately 72 bytes.
  return 72;
}

// sm2_bits returns the number of bits in the SM2 key.
static int sm2_bits(const EvpPkey *pkey) {
  const EC_KEY *ec_key = reinterpret_cast<const EC_KEY *>(pkey->pkey);
  const EC_GROUP *group = EC_KEY_get0_group(ec_key);
  if (group == nullptr) {
    ERR_clear_error();
    return 0;
  }
  return EC_GROUP_order_bits(group);
}

// sm2_free frees the EC_KEY associated with an SM2 EVP_PKEY.
static void sm2_free(EvpPkey *pkey) {
  EC_KEY_free(reinterpret_cast<EC_KEY *>(pkey->pkey));
  pkey->pkey = nullptr;
}

// sm2_asn1_meth is the ASN.1 method for SM2 keys.
const EVP_PKEY_ASN1_METHOD sm2_asn1_meth = {
    EVP_PKEY_SM2,
    // OID for SM2: 1.2.156.10197.1.301
    // DER encoded: 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d
    {0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d},
    8,

    &sm2_pkey_meth,

    sm2_pub_decode,
    sm2_pub_encode,
    sm2_pub_equal,
    sm2_pub_present,

    sm2_priv_decode,
    sm2_priv_encode,
    sm2_priv_present,

    /*set_priv_raw=*/nullptr,
    /*set_priv_seed=*/nullptr,
    /*set_pub_raw=*/nullptr,
    /*get_priv_raw=*/nullptr,
    /*get_priv_seed=*/nullptr,
    /*get_pub_raw=*/nullptr,
    /*set1_tls_encodedpoint=*/nullptr,
    /*get1_tls_encodedpoint=*/nullptr,

    /*pkey_opaque=*/nullptr,

    sm2_size,
    sm2_bits,

    /*param_missing=*/nullptr,
    /*param_copy=*/nullptr,
    /*param_equal=*/nullptr,

    sm2_free,
};

}  // namespace

// EVP_pkey_sm2 returns the EVP_PKEY_ALG for SM2 keys.
const EVP_PKEY_ALG *EVP_pkey_sm2() {
  static const EVP_PKEY_ALG_SM2 kAlg = {{&sm2_asn1_meth}, &EC_group_sm2};
  return &kAlg;
}
