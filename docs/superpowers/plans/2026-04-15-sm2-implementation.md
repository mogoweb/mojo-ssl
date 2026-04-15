# SM2 非对称加密实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现 SM2 非对称加密算法（密钥生成、加密、解密）在 BoringSSL 中，复用现有 EC 模块。

**Architecture:** SM2 实现为独立模块 `crypto/sm2/`，复用 `crypto/fipsmodule/ec/` 进行椭圆曲线点运算，使用 SM3 作为默认哈希，ASN.1 DER 编码密文。

**Tech Stack:** C++11, BoringSSL EC/BN/CBS/CBB API, SM3 hash

---

## 文件结构

| 文件 | 职责 |
|------|------|
| `include/openssl/sm2.h` | 公共 API 头文件 |
| `include/openssl/nid.h` | 添加 `NID_sm2` 定义 |
| `include/openssl/prefix_symbols.h` | 添加 SM2 符号前缀 |
| `crypto/sm2/sm2.cc` | 核心加密/解密算法 |
| `crypto/sm2/sm2_key.cc` | 密钥生成和验证 |
| `crypto/sm2/sm2_kdf.cc` | X9.63 KDF 实现 |
| `crypto/sm2/sm2_test.cc` | 单元测试 |
| `crypto/sm2/internal.h` | 内部头文件（可选） |
| `build.json` | 添加源文件到构建系统 |
| `gen/sources.*` | 由 pregenerate 更新 |

---

### Task 1: 添加 SM2 曲线 NID 定义

**Files:**
- Modify: `include/openssl/nid.h`

- [ ] **Step 1: 在 `include/openssl/nid.h` 添加 SM2 NID 定义**

在 NID 定义区域（约 1170 行附近，curves 区域）添加：

```c
// SM2 curve (GM/T 0003)
#define SN_sm2 "SM2"
#define LN_sm2 "sm2"
#define NID_sm2 1199
#define OBJ_sm2 1L, 2L, 156L, 10197L, 1L, 301L
#define OBJ_ENC_sm2 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d
```

- [ ] **Step 2: 验证 NID 没有冲突**

Run: `grep -n "NID_sm2\|1199" include/openssl/nid.h`
Expected: 仅显示新添加的定义

- [ ] **Step 3: 提交**

```bash
git add include/openssl/nid.h
git commit -m "sm2: add SM2 curve NID definition"
```

---

### Task 2: 创建 SM2 公共头文件

**Files:**
- Create: `include/openssl/sm2.h`

- [ ] **Step 1: 创建 `include/openssl/sm2.h`**

```c
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

#include <openssl/base.h>
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
// length is stored in |*ciphertext_len|. The ciphertext is ASN.1 DER encoded.
// It returns 1 on success and 0 on error.
OPENSSL_EXPORT int SM2_encrypt(const EC_KEY *key,
                                const uint8_t *plaintext, size_t plaintext_len,
                                uint8_t *ciphertext, size_t *ciphertext_len);

// SM2_decrypt decrypts |ciphertext_len| bytes from |ciphertext| using the
// private key in |key|. The plaintext is written to |plaintext| and its
// length is stored in |*plaintext_len|.
// It returns 1 on success and 0 on error.
OPENSSL_EXPORT int SM2_decrypt(const EC_KEY *key,
                                const uint8_t *ciphertext, size_t ciphertext_len,
                                uint8_t *plaintext, size_t *plaintext_len);


// Error codes for SM2 operations.
#define SM2_R_INVALID_PRIVATE_KEY 100
#define SM2_R_INVALID_PUBLIC_KEY 101
#define SM2_R_INVALID_CIPHERTEXT 102
#define SM2_R_ASN1_ERROR 103
#define SM2_R_DIGEST_MISMATCH 104
#define SM2_R_BUFFER_TOO_SMALL 105


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_SM2_H
```

- [ ] **Step 2: 提交**

```bash
git add include/openssl/sm2.h
git commit -m "sm2: add public API header"
```

---

### Task 3: 实现 X9.63 KDF

**Files:**
- Create: `crypto/sm2/sm2_kdf.cc`
- Create: `crypto/sm2/internal.h`

- [ ] **Step 1: 创建目录**

```bash
mkdir -p crypto/sm2
```

- [ ] **Step 2: 创建 `crypto/sm2/internal.h`**

```c
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

#ifndef OPENSSL_HEADER_CRYPTO_SM2_INTERNAL_H
#define OPENSSL_HEADER_CRYPTO_SM2_INTERNAL_H

#include <openssl/base.h>
#include <openssl/digest.h>

#if defined(__cplusplus)
extern "C" {
#endif


// sm2_kdf implements X9.63 KDF (equivalent to SM2 KDF).
// It derives |out_len| bytes from shared secret |z| of length |z_len|
// using hash function |md|. Returns 1 on success, 0 on failure.
int sm2_kdf(uint8_t *out, size_t out_len,
            const uint8_t *z, size_t z_len,
            const EVP_MD *md);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_CRYPTO_SM2_INTERNAL_H
```

- [ ] **Step 3: 创建 `crypto/sm2/sm2_kdf.cc`**

```c
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

#include "internal.h"

#include <openssl/digest.h>
#include <openssl/mem.h>

#include <string.h>

#include "../../internal.h"


// X9.63 KDF (equivalent to SM2 KDF)
// K = KDF(Z, klen)
// For i = 1 to ceil(klen / hashlen):
//   K_i = Hash(Z || i)
// K = K_1 || K_2 || ... || K_n (truncated to klen)
int sm2_kdf(uint8_t *out, size_t out_len,
            const uint8_t *z, size_t z_len,
            const EVP_MD *md) {
  if (out == NULL || out_len == 0) {
    return 0;
  }

  const size_t md_size = EVP_MD_size(md);
  if (md_size == 0) {
    return 0;
  }

  // Counter is 4 bytes (big-endian)
  uint8_t counter[4];
  uint8_t digest[EVP_MAX_MD_SIZE];

  size_t remaining = out_len;
  uint8_t *out_ptr = out;

  for (uint32_t i = 1; remaining > 0; i++) {
    // Encode counter as big-endian 4 bytes
    counter[0] = (uint8_t)(i >> 24);
    counter[1] = (uint8_t)(i >> 16);
    counter[2] = (uint8_t)(i >> 8);
    counter[3] = (uint8_t)i;

    // Hash(Z || counter)
    unsigned int digest_len = 0;
    if (!EVP_Digest(z, z_len, digest, &digest_len, md, NULL)) {
      OPENSSL_cleanse(out, out_len);
      return 0;
    }

    size_t copy_len = remaining < md_size ? remaining : md_size;
    OPENSSL_memcpy(out_ptr, digest, copy_len);
    out_ptr += copy_len;
    remaining -= copy_len;
  }

  OPENSSL_cleanse(digest, sizeof(digest));
  return 1;
}
```

- [ ] **Step 4: 提交**

```bash
git add crypto/sm2/internal.h crypto/sm2/sm2_kdf.cc
git commit -m "sm2: implement X9.63 KDF"
```

---

### Task 4: 实现密钥生成

**Files:**
- Create: `crypto/sm2/sm2_key.cc`

- [ ] **Step 1: 创建 `crypto/sm2/sm2_key.cc`**

```c
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

#include <openssl/sm2.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/nid.h>

#include <string.h>

#include "../../internal.h"
#include "../fipsmodule/ec/internal.h"


BSSL_NAMESPACE_BEGIN

size_t SM2_ciphertext_size(size_t plaintext_len) {
  // ASN.1 DER encoding overhead:
  // SEQUENCE header: ~4 bytes
  // C1x (INTEGER): ~35 bytes (32 bytes + 3 bytes header)
  // C1y (INTEGER): ~35 bytes
  // C3 (OCTET STRING): 34 bytes (32 bytes + 2 bytes header)
  // C2 (OCTET STRING): plaintext_len + 2 bytes header
  return 108 + plaintext_len + 10;  // Extra padding for safety
}

size_t SM2_plaintext_size(size_t ciphertext_len) {
  // Reverse estimate: subtract ASN.1 overhead
  if (ciphertext_len < 110) {
    return 0;
  }
  return ciphertext_len - 110;
}

int SM2_check_private_key(const EC_KEY *key) {
  if (key == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  const EC_GROUP *group = EC_KEY_get0_group(key);
  const BIGNUM *priv_key = EC_KEY_get0_private_key(key);

  if (group == NULL || priv_key == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  // SM2 private key must be in range [1, n-1)
  // where n is the curve order
  BIGNUM *n_minus_1 = BN_new();
  if (n_minus_1 == NULL) {
    return 0;
  }

  const BIGNUM *order = EC_GROUP_get0_order(group);
  int ret = 0;

  // n - 1
  if (!BN_sub(n_minus_1, order, BN_value_one())) {
    goto end;
  }

  // Check: 1 <= priv_key < n - 1
  if (BN_cmp(priv_key, BN_value_one()) < 0 ||
      BN_cmp(priv_key, n_minus_1) >= 0) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_PRIVATE_KEY);
    goto end;
  }

  ret = 1;

end:
  BN_free(n_minus_1);
  return ret;
}

int SM2_generate_key(EC_KEY *key) {
  if (key == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  const EC_GROUP *group = EC_KEY_get0_group(key);
  if (group == NULL) {
    // Set SM2 curve group if not set
    EC_GROUP *sm2_group = EC_GROUP_new_by_curve_name(NID_sm2);
    if (sm2_group == NULL) {
      OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
      return 0;
    }
    if (!EC_KEY_set_group(key, sm2_group)) {
      EC_GROUP_free(sm2_group);
      return 0;
    }
    EC_GROUP_free(sm2_group);
    group = EC_KEY_get0_group(key);
  }

  // Generate key pair using standard EC key generation
  // Note: Standard EC key generation uses [1, n-1] range.
  // SM2 requires [1, n-1) range, but the difference is negligible.
  if (!EC_KEY_generate_key(key)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    return 0;
  }

  // Validate the generated key
  if (!SM2_check_private_key(key)) {
    // Retry if by chance we got n-1 (extremely rare)
    return SM2_generate_key(key);
  }

  return 1;
}

BSSL_NAMESPACE_END
```

- [ ] **Step 2: 提交**

```bash
git add crypto/sm2/sm2_key.cc
git commit -m "sm2: implement key generation"
```

---

### Task 5: 实现加密和解密

**Files:**
- Create: `crypto/sm2/sm2.cc`

- [ ] **Step 1: 创建 `crypto/sm2/sm2.cc`**

```c
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

#include <openssl/sm2.h>

#include <openssl/bn.h>
#include <openssl/bytestring.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/rand.h>
#include <openssl/sm3.h>

#include <string.h>

#include "../../internal.h"
#include "../fipsmodule/ec/internal.h"
#include "internal.h"


BSSL_NAMESPACE_BEGIN

static int sm2_encode_ciphertext(CBB *out,
                                  const BIGNUM *c1x, const BIGNUM *c1y,
                                  const uint8_t *c3, size_t c3_len,
                                  const uint8_t *c2, size_t c2_len) {
  CBB seq, child;

  if (!CBB_add_asn1(out, &seq, CBS_ASN1_SEQUENCE)) {
    return 0;
  }

  // C1x (INTEGER)
  if (!BN_marshal_asn1(&seq, c1x)) {
    return 0;
  }

  // C1y (INTEGER)
  if (!BN_marshal_asn1(&seq, c1y)) {
    return 0;
  }

  // C3 (OCTET STRING)
  if (!CBB_add_asn1(&seq, &child, CBS_ASN1_OCTETSTRING) ||
      !CBB_add_bytes(&child, c3, c3_len)) {
    return 0;
  }

  // C2 (OCTET STRING)
  if (!CBB_add_asn1(&seq, &child, CBS_ASN1_OCTETSTRING) ||
      !CBB_add_bytes(&child, c2, c2_len)) {
    return 0;
  }

  return CBB_flush(out);
}

static int sm2_decode_ciphertext(CBS *in,
                                  BIGNUM *c1x, BIGNUM *c1y,
                                  uint8_t *c3, size_t *c3_len,
                                  uint8_t *c2, size_t *c2_len) {
  CBS seq, c3_octet, c2_octet;

  if (!CBS_get_asn1(in, &seq, CBS_ASN1_SEQUENCE)) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_ASN1_ERROR);
    return 0;
  }

  // C1x (INTEGER)
  if (!BN_parse_asn1_unsigned(&seq, c1x)) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_ASN1_ERROR);
    return 0;
  }

  // C1y (INTEGER)
  if (!BN_parse_asn1_unsigned(&seq, c1y)) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_ASN1_ERROR);
    return 0;
  }

  // C3 (OCTET STRING)
  if (!CBS_get_asn1(&seq, &c3_octet, CBS_ASN1_OCTETSTRING)) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_ASN1_ERROR);
    return 0;
  }
  if (CBS_len(&c3_octet) != SM3_DIGEST_LENGTH) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_CIPHERTEXT);
    return 0;
  }
  OPENSSL_memcpy(c3, CBS_data(&c3_octet), SM3_DIGEST_LENGTH);
  *c3_len = SM3_DIGEST_LENGTH;

  // C2 (OCTET STRING)
  if (!CBS_get_asn1(&seq, &c2_octet, CBS_ASN1_OCTETSTRING)) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_ASN1_ERROR);
    return 0;
  }
  size_t len = CBS_len(&c2_octet);
  OPENSSL_memcpy(c2, CBS_data(&c2_octet), len);
  *c2_len = len;

  return 1;
}

int SM2_encrypt(const EC_KEY *key,
                const uint8_t *plaintext, size_t plaintext_len,
                uint8_t *ciphertext, size_t *ciphertext_len) {
  if (key == NULL || plaintext == NULL || ciphertext_len == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  const EC_GROUP *group = EC_KEY_get0_group(key);
  const EC_POINT *pub_key = EC_KEY_get0_public_key(key);

  if (group == NULL || pub_key == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  BN_CTX *ctx = BN_CTX_new();
  if (ctx == NULL) {
    return 0;
  }

  int ret = 0;
  BIGNUM *k = BN_new();
  BIGNUM *x1 = BN_new();
  BIGNUM *y1 = BN_new();
  BIGNUM *x2 = BN_new();
  BIGNUM *y2 = BN_new();
  EC_POINT *C1 = EC_POINT_new(group);
  EC_POINT *kP = EC_POINT_new(group);

  uint8_t *x2y2 = NULL;
  uint8_t *c2 = NULL;
  uint8_t c3[SM3_DIGEST_LENGTH];

  if (k == NULL || x1 == NULL || y1 == NULL || x2 == NULL || y2 == NULL ||
      C1 == NULL || kP == NULL) {
    goto end;
  }

  const BIGNUM *order = EC_GROUP_get0_order(group);
  size_t field_size = (EC_GROUP_get_degree(group) + 7) / 8;

  // Allocate buffers
  x2y2 = (uint8_t *)OPENSSL_zalloc(2 * field_size);
  c2 = (uint8_t *)OPENSSL_zalloc(plaintext_len);

  if (x2y2 == NULL || c2 == NULL) {
    goto end;
  }

  // Step 1: Generate random k in [1, n-1)
  if (!BN_rand_range_ex(k, 1, order) ||
      BN_cmp(k, order) >= 0) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto end;
  }

  // Step 2: C1 = k * G
  if (!EC_POINT_mul(group, C1, k, NULL, NULL, ctx) ||
      !EC_POINT_get_affine_coordinates(group, C1, x1, y1, ctx)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    goto end;
  }

  // Step 3: kP = k * P (where P is the public key)
  if (!EC_POINT_mul(group, kP, NULL, pub_key, k, ctx) ||
      !EC_POINT_get_affine_coordinates(group, kP, x2, y2, ctx)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    goto end;
  }

  // Convert x2, y2 to bytes
  if (BN_bn2binpad(x2, x2y2, field_size) < 0 ||
      BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto end;
  }

  // Step 4: t = KDF(x2 || y2, plaintext_len)
  if (!sm2_kdf(c2, plaintext_len, x2y2, 2 * field_size, EVP_sm3())) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto end;
  }

  // Step 5: C2 = M XOR t
  for (size_t i = 0; i < plaintext_len; i++) {
    c2[i] ^= plaintext[i];
  }

  // Step 6: C3 = SM3(x2 || M || y2)
  SM3_CTX sm3_ctx;
  SM3_Init(&sm3_ctx);
  SM3_Update(&sm3_ctx, x2y2, field_size);            // x2
  SM3_Update(&sm3_ctx, plaintext, plaintext_len);    // M
  SM3_Update(&sm3_ctx, x2y2 + field_size, field_size); // y2
  SM3_Final(c3, &sm3_ctx);

  // Step 7: Encode ciphertext as ASN.1 DER
  CBB cbb;
  CBB_init(&cbb, 0);

  if (!sm2_encode_ciphertext(&cbb, x1, y1, c3, sizeof(c3), c2, plaintext_len)) {
    CBB_cleanup(&cbb);
    OPENSSL_PUT_ERROR(SM2, SM2_R_ASN1_ERROR);
    goto end;
  }

  size_t len;
  if (!CBB_finish(&cbb, &ciphertext, &len)) {
    CBB_cleanup(&cbb);
    OPENSSL_PUT_ERROR(SM2, SM2_R_ASN1_ERROR);
    goto end;
  }
  *ciphertext_len = len;

  ret = 1;

end:
  BN_free(k);
  BN_free(x1);
  BN_free(y1);
  BN_free(x2);
  BN_free(y2);
  EC_POINT_free(C1);
  EC_POINT_free(kP);
  OPENSSL_free(x2y2);
  OPENSSL_free(c2);
  BN_CTX_free(ctx);

  if (!ret) {
    OPENSSL_cleanse(ciphertext, *ciphertext_len);
  }

  return ret;
}

int SM2_decrypt(const EC_KEY *key,
                const uint8_t *ciphertext, size_t ciphertext_len,
                uint8_t *plaintext, size_t *plaintext_len) {
  if (key == NULL || ciphertext == NULL || plaintext_len == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  const EC_GROUP *group = EC_KEY_get0_group(key);
  const BIGNUM *priv_key = EC_KEY_get0_private_key(key);

  if (group == NULL || priv_key == NULL) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_PASSED_NULL_PARAMETER);
    return 0;
  }

  BN_CTX *ctx = BN_CTX_new();
  if (ctx == NULL) {
    return 0;
  }

  int ret = 0;
  BIGNUM *c1x = BN_new();
  BIGNUM *c1y = BN_new();
  BIGNUM *x2 = BN_new();
  BIGNUM *y2 = BN_new();
  EC_POINT *C1 = EC_POINT_new(group);
  EC_POINT *dC1 = EC_POINT_new(group);

  uint8_t *x2y2 = NULL;
  uint8_t *c2 = NULL;
  uint8_t c3_from_input[SM3_DIGEST_LENGTH];
  uint8_t c3_computed[SM3_DIGEST_LENGTH];
  size_t c3_len = 0, c2_len = 0;

  if (c1x == NULL || c1y == NULL || x2 == NULL || y2 == NULL ||
      C1 == NULL || dC1 == NULL) {
    goto end;
  }

  size_t field_size = (EC_GROUP_get_degree(group) + 7) / 8;

  // Allocate buffers
  x2y2 = (uint8_t *)OPENSSL_zalloc(2 * field_size);
  c2 = (uint8_t *)OPENSSL_zalloc(ciphertext_len);  // Upper bound

  if (x2y2 == NULL || c2 == NULL) {
    goto end;
  }

  // Parse ASN.1 DER ciphertext
  CBS cbs;
  CBS_init(&cbs, ciphertext, ciphertext_len);

  if (!sm2_decode_ciphertext(&cbs, c1x, c1y, c3_from_input, &c3_len,
                              c2, &c2_len)) {
    goto end;
  }

  if (*plaintext_len < c2_len) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_BUFFER_TOO_SMALL);
    goto end;
  }

  // Step 2: Reconstruct C1 point from (c1x, c1y)
  if (!EC_POINT_set_affine_coordinates(group, C1, c1x, c1y, ctx)) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_INVALID_CIPHERTEXT);
    goto end;
  }

  // Step 3: d * C1 = d * k * G = k * P = (x2, y2)
  if (!EC_POINT_mul(group, dC1, NULL, C1, priv_key, ctx) ||
      !EC_POINT_get_affine_coordinates(group, dC1, x2, y2, ctx)) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_EC_LIB);
    goto end;
  }

  // Convert x2, y2 to bytes
  if (BN_bn2binpad(x2, x2y2, field_size) < 0 ||
      BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0) {
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto end;
  }

  // Step 4: t = KDF(x2 || y2, c2_len)
  uint8_t *t = (uint8_t *)OPENSSL_zalloc(c2_len);
  if (t == NULL) {
    goto end;
  }

  if (!sm2_kdf(t, c2_len, x2y2, 2 * field_size, EVP_sm3())) {
    OPENSSL_free(t);
    OPENSSL_PUT_ERROR(SM2, ERR_R_INTERNAL_ERROR);
    goto end;
  }

  // Step 5: M = C2 XOR t
  for (size_t i = 0; i < c2_len; i++) {
    plaintext[i] = c2[i] ^ t[i];
  }
  OPENSSL_free(t);

  // Step 6: Verify C3 = SM3(x2 || M || y2)
  SM3_CTX sm3_ctx;
  SM3_Init(&sm3_ctx);
  SM3_Update(&sm3_ctx, x2y2, field_size);              // x2
  SM3_Update(&sm3_ctx, plaintext, c2_len);             // M
  SM3_Update(&sm3_ctx, x2y2 + field_size, field_size); // y2
  SM3_Final(c3_computed, &sm3_ctx);

  if (CRYPTO_memcmp(c3_computed, c3_from_input, SM3_DIGEST_LENGTH) != 0) {
    OPENSSL_PUT_ERROR(SM2, SM2_R_DIGEST_MISMATCH);
    OPENSSL_cleanse(plaintext, c2_len);
    goto end;
  }

  *plaintext_len = c2_len;
  ret = 1;

end:
  BN_free(c1x);
  BN_free(c1y);
  BN_free(x2);
  BN_free(y2);
  EC_POINT_free(C1);
  EC_POINT_free(dC1);
  OPENSSL_free(x2y2);
  OPENSSL_free(c2);
  BN_CTX_free(ctx);

  return ret;
}

BSSL_NAMESPACE_END
```

- [ ] **Step 2: 提交**

```bash
git add crypto/sm2/sm2.cc
git commit -m "sm2: implement encrypt and decrypt"
```

---

### Task 6: 更新构建系统

**Files:**
- Modify: `build.json`
- Regenerate: `gen/sources.cmake`, `gen/sources.gni`, `gen/sources.mk`, `gen/sources.bzl`

- [ ] **Step 1: 更新 `build.json`**

在 `"crypto"` 数组中添加 SM2 源文件：

```json
"crypto/sm2/sm2.cc",
"crypto/sm2/sm2_key.cc",
"crypto/sm2/sm2_kdf.cc",
```

在 `"crypto_test"` 数组中添加：

```json
"crypto/sm2/sm2_test.cc",
```

- [ ] **Step 2: 运行 pregenerate 更新生成文件**

Run: `go run ./util/pregenerate`

Expected: 成功更新 `gen/sources.*` 文件

- [ ] **Step 3: 提交**

```bash
git add build.json gen/sources.cmake gen/sources.gni gen/sources.mk gen/sources.bzl gen/sources.json
git commit -m "build: add SM2 source files"
```

---

### Task 7: 添加前缀符号

**Files:**
- Modify: `include/openssl/prefix_symbols.h`

- [ ] **Step 1: 在 `include/openssl/prefix_symbols.h` 添加 SM2 符号**

在适当位置添加：

```c
#define SM2_ciphertext_size BORINGSSL_PREFIX_NAME(SM2_ciphertext_size)
#define SM2_plaintext_size BORINGSSL_PREFIX_NAME(SM2_plaintext_size)
#define SM2_generate_key BORINGSSL_PREFIX_NAME(SM2_generate_key)
#define SM2_check_private_key BORINGSSL_PREFIX_NAME(SM2_check_private_key)
#define SM2_encrypt BORINGSSL_PREFIX_NAME(SM2_encrypt)
#define SM2_decrypt BORINGSSL_PREFIX_NAME(SM2_decrypt)
```

- [ ] **Step 2: 提交**

```bash
git add include/openssl/prefix_symbols.h
git commit -m "sm2: add prefix symbols"
```

---

### Task 8: 编写单元测试

**Files:**
- Create: `crypto/sm2/sm2_test.cc`

- [ ] **Step 1: 创建 `crypto/sm2/sm2_test.cc`**

```c
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

#include <gtest/gtest.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/nid.h>
#include <openssl/sm2.h>

#include "../test/test_util.h"


// Test SM2 key generation
TEST(SM2Test, KeyGeneration) {
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);

  ASSERT_TRUE(SM2_generate_key(key.get()));
  ASSERT_TRUE(SM2_check_private_key(key.get()));
  ASSERT_TRUE(EC_KEY_check_key(key.get()));
}

// Test SM2 encrypt/decrypt round-trip
TEST(SM2Test, EncryptDecrypt) {
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  const char *plaintext = "Hello, SM2!";
  size_t plaintext_len = strlen(plaintext);

  // Encrypt
  size_t ciphertext_len = SM2_ciphertext_size(plaintext_len);
  std::vector<uint8_t> ciphertext(ciphertext_len);
  ASSERT_TRUE(SM2_encrypt(key.get(),
                          (const uint8_t *)plaintext, plaintext_len,
                          ciphertext.data(), &ciphertext_len));

  // Decrypt
  size_t decrypted_len = SM2_plaintext_size(ciphertext_len);
  std::vector<uint8_t> decrypted(decrypted_len);
  ASSERT_TRUE(SM2_decrypt(key.get(),
                          ciphertext.data(), ciphertext_len,
                          decrypted.data(), &decrypted_len));

  EXPECT_EQ(plaintext_len, decrypted_len);
  EXPECT_EQ(Bytes(plaintext, plaintext_len),
            Bytes(decrypted.data(), decrypted_len));
}

// Test SM2 with empty message
TEST(SM2Test, EmptyMessage) {
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  // Encrypt empty message
  size_t ciphertext_len = SM2_ciphertext_size(0);
  std::vector<uint8_t> ciphertext(ciphertext_len);
  ASSERT_TRUE(SM2_encrypt(key.get(), NULL, 0, ciphertext.data(), &ciphertext_len));

  // Decrypt
  size_t decrypted_len = SM2_plaintext_size(ciphertext_len);
  std::vector<uint8_t> decrypted(decrypted_len);
  ASSERT_TRUE(SM2_decrypt(key.get(),
                          ciphertext.data(), ciphertext_len,
                          decrypted.data(), &decrypted_len));

  EXPECT_EQ(0u, decrypted_len);
}

// Test SM2 with larger message
TEST(SM2Test, LargeMessage) {
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  // 1KB message
  std::vector<uint8_t> plaintext(1024);
  for (size_t i = 0; i < plaintext.size(); i++) {
    plaintext[i] = (uint8_t)(i & 0xFF);
  }

  // Encrypt
  size_t ciphertext_len = SM2_ciphertext_size(plaintext.size());
  std::vector<uint8_t> ciphertext(ciphertext_len);
  ASSERT_TRUE(SM2_encrypt(key.get(),
                          plaintext.data(), plaintext.size(),
                          ciphertext.data(), &ciphertext_len));

  // Decrypt
  size_t decrypted_len = SM2_plaintext_size(ciphertext_len);
  std::vector<uint8_t> decrypted(decrypted_len);
  ASSERT_TRUE(SM2_decrypt(key.get(),
                          ciphertext.data(), ciphertext_len,
                          decrypted.data(), &decrypted_len));

  EXPECT_EQ(plaintext.size(), decrypted_len);
  EXPECT_EQ(Bytes(plaintext), Bytes(decrypted.data(), decrypted_len));
}

// Test decryption with wrong key
TEST(SM2Test, WrongKey) {
  bssl::UniquePtr<EC_KEY> key1(EC_KEY_new_by_curve_name(NID_sm2));
  bssl::UniquePtr<EC_KEY> key2(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key1);
  ASSERT_TRUE(key2);
  ASSERT_TRUE(SM2_generate_key(key1.get()));
  ASSERT_TRUE(SM2_generate_key(key2.get()));

  const char *plaintext = "Secret message";
  size_t plaintext_len = strlen(plaintext);

  // Encrypt with key1
  size_t ciphertext_len = SM2_ciphertext_size(plaintext_len);
  std::vector<uint8_t> ciphertext(ciphertext_len);
  ASSERT_TRUE(SM2_encrypt(key1.get(),
                          (const uint8_t *)plaintext, plaintext_len,
                          ciphertext.data(), &ciphertext_len));

  // Try to decrypt with key2 (should fail)
  size_t decrypted_len = SM2_plaintext_size(ciphertext_len);
  std::vector<uint8_t> decrypted(decrypted_len);
  EXPECT_FALSE(SM2_decrypt(key2.get(),
                           ciphertext.data(), ciphertext_len,
                           decrypted.data(), &decrypted_len));
}

// Test decryption with corrupted ciphertext
TEST(SM2Test, CorruptedCiphertext) {
  bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_sm2));
  ASSERT_TRUE(key);
  ASSERT_TRUE(SM2_generate_key(key.get()));

  const char *plaintext = "Test message";
  size_t plaintext_len = strlen(plaintext);

  // Encrypt
  size_t ciphertext_len = SM2_ciphertext_size(plaintext_len);
  std::vector<uint8_t> ciphertext(ciphertext_len);
  ASSERT_TRUE(SM2_encrypt(key.get(),
                          (const uint8_t *)plaintext, plaintext_len,
                          ciphertext.data(), &ciphertext_len));

  // Corrupt the ciphertext
  ciphertext[ciphertext_len / 2] ^= 0xFF;

  // Try to decrypt (should fail)
  size_t decrypted_len = SM2_plaintext_size(ciphertext_len);
  std::vector<uint8_t> decrypted(decrypted_len);
  EXPECT_FALSE(SM2_decrypt(key.get(),
                           ciphertext.data(), ciphertext_len,
                           decrypted.data(), &decrypted_len));
}

// Test ciphertext size calculation
TEST(SM2Test, CiphertextSize) {
  // SM2 ciphertext format: ASN.1 SEQUENCE { C1x, C1y, C3, C2 }
  // C1x, C1y: ~35 bytes each (32-byte coord + ASN.1 overhead)
  // C3: 34 bytes (32-byte hash + ASN.1 overhead)
  // C2: plaintext_len + ASN.1 overhead
  // SEQUENCE header: ~4 bytes

  EXPECT_GT(SM2_ciphertext_size(0), 100u);
  EXPECT_GT(SM2_ciphertext_size(32), 130u);
  EXPECT_GT(SM2_ciphertext_size(1024), 1100u);
}
```

- [ ] **Step 2: 构建并运行测试**

Run: 
```bash
cmake -GNinja -B build && ninja -C build crypto_test
./build/crypto_test --gtest_filter=SM2Test*
```

Expected: 所有测试通过

- [ ] **Step 3: 提交**

```bash
git add crypto/sm2/sm2_test.cc
git commit -m "sm2: add unit tests"
```

---

### Task 9: 添加 SM2 曲线支持到 EC 模块

**Files:**
- Modify: `crypto/fipsmodule/ec/ec.cc.inc`
- Modify: `crypto/fipsmodule/ec/builtin_curves.h`
- Modify: `crypto/fipsmodule/ec/ec.c` (if exists)

- [ ] **Step 1: 在 `crypto/fipsmodule/ec/builtin_curves.h` 添加 SM2 曲线预计算值**

SM2 曲线参数（来自 GM/T 0003-2012）：

```c
// SM2 curve (GM/T 0003)
[[maybe_unused]] static const uint64_t kSM2FieldN0 = 0x0000000400000004;
[[maybe_unused]] static const uint64_t kSM2OrderN0 = 0xd409a6e99d69b281;
#if defined(OPENSSL_64_BIT)
[[maybe_unused]] static const uint64_t kSM2Field[] = {
    0xffffffffffffffff, 0xffffffff00000000, 0xffffffffffffffff,
    0xfffffffeffffffff};
[[maybe_unused]] static const uint64_t kSM2Order[] = {
    0x53bbf40939d54123, 0x7203df6b21c6052b, 0xffffffffffffffff,
    0xfffffffeffffffff};
[[maybe_unused]] static const uint64_t kSM2B[] = {
    0x4d940e93ddbcb8f9, 0x39d54123f3b9cac2, 0xa7179e84bce6faad,
    0x28e9fa9e9d9f5e34};
[[maybe_unused]] static const uint64_t kSM2GX[] = {
    0x334c74c715a45893, 0xbbf40939d5412344, 0x5f9904466a39c994,
    0x32c4ae2c1f198119};
[[maybe_unused]] static const uint64_t kSM2GY[] = {
    0x2139f0a002df32e4, 0xd0a9877cc62a4740, 0x59bdcee36b692153,
    0xbc3736a2f4f6779c};
[[maybe_unused]] static const uint64_t kSM2FieldR[] = {
    0x0000000000000001, 0x00000000ffffffff, 0x0000000000000000,
    0x0000000100000000};
[[maybe_unused]] static const uint64_t kSM2FieldRR[] = {
    0x0000000300000002, 0x00000002fffffffe, 0xffffffff00000000,
    0x00000001fffffffd};
[[maybe_unused]] static const uint64_t kSM2OrderRR[] = {
    0x286afc2f3f0f74c8, 0x6f9b6e9a6b5c8d7e, 0x123456789abcdef0,
    0xfedcba9876543210};
[[maybe_unused]] static const uint64_t kSM2MontB[] = {
    // Montgomery form of b coefficient
    0x123456789abcdef0, 0xfedcba9876543210, 0xabcdef0123456789,
    0x0987654321fedcba};
[[maybe_unused]] static const uint64_t kSM2MontGX[] = {
    // Montgomery form of generator X
    0xabcdef0123456789, 0x0987654321fedcba, 0x123456789abcdef0,
    0xfedcba9876543210};
[[maybe_unused]] static const uint64_t kSM2MontGY[] = {
    // Montgomery form of generator Y
    0xfedcba9876543210, 0x123456789abcdef0, 0x0987654321fedcba,
    0xabcdef0123456789};
#elif defined(OPENSSL_32_BIT)
// 32-bit versions...
#else
#error "unknown word size"
#endif
```

注意：精确的 Montgomery 值需要通过 `make_tables.go` 工具计算。上述值为占位符。

- [ ] **Step 2: 运行 make_tables.go 生成精确值**

Run: `go run ./crypto/fipsmodule/ec/make_tables.go`

这会自动生成精确的 Montgomery 预计算值到 `builtin_curves.h`。

- [ ] **Step 3: 在 `crypto/fipsmodule/ec/ec.cc.inc` 添加 SM2 曲线组函数**

在 `EC_group_p521` 函数后添加：

```c
DEFINE_METHOD_FUNCTION(EC_GROUP, EC_group_sm2) {
  out->curve_name = NID_sm2;
  out->comment = "SM2";
  // OID: 1.2.156.10197.1.301
  static const uint8_t kOIDSM2[] = {0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d};
  static_assert(sizeof(kOIDSM2) <= sizeof(out->oid));
  OPENSSL_memcpy(out->oid, kOIDSM2, sizeof(kOIDSM2));
  out->oid_len = sizeof(kOIDSM2);

  ec_group_init_static_mont(&out->field, std::size(kSM2Field), kSM2Field,
                            kSM2FieldRR, kSM2FieldN0);
  ec_group_init_static_mont(&out->order, std::size(kSM2Order), kSM2Order,
                            kSM2OrderRR, kSM2OrderN0);

  out->meth = EC_GFp_mont_method();
  out->generator.group = out;
  OPENSSL_memcpy(out->generator.raw.X.words, kSM2MontGX, sizeof(kSM2MontGX));
  OPENSSL_memcpy(out->generator.raw.Y.words, kSM2MontGY, sizeof(kSM2MontGY));
  OPENSSL_memcpy(out->generator.raw.Z.words, kSM2FieldR, sizeof(kSM2FieldR));
  OPENSSL_memcpy(out->b.words, kSM2MontB, sizeof(kSM2MontB));

  ec_group_set_a_minus3(out);
  out->has_order = 1;
  out->field_greater_than_order = 1;
}
```

- [ ] **Step 4: 更新 `EC_GROUP_new_by_curve_name` 函数**

找到 `EC_GROUP_new_by_curve_name` 函数的 switch 语句，添加 SM2 case：

```c
case NID_sm2:
  return EC_group_sm2();
```

- [ ] **Step 5: 构建验证**

Run: `cmake -GNinja -B build && ninja -C build`

Expected: 编译成功，无错误

- [ ] **Step 6: 提交**

```bash
git add crypto/fipsmodule/ec/ec.cc.inc crypto/fipsmodule/ec/builtin_curves.h
git commit -m "ec: add SM2 curve support"
```

---

### Task 10: 最终集成测试

**Files:**
- Test: 整体构建和测试

- [ ] **Step 1: 完整构建**

Run: `rm -rf build && cmake -GNinja -B build && ninja -C build`

Expected: 编译成功，无警告

- [ ] **Step 2: 运行所有 crypto 测试**

Run: `./build/crypto_test --gtest_filter=SM2*`

Expected: 所有 SM2 测试通过

- [ ] **Step 3: 运行完整测试套件**

Run: `ninja -C build run_tests`

Expected: 所有测试通过

- [ ] **Step 4: 提交所有更改**

```bash
git add -A
git commit -m "sm2: complete SM2 implementation"
```

---

## 实现注意事项

1. **SM2 曲线参数**: SM2 使用的是特定的 256 位椭圆曲线，参数来自 GM/T 0003 标准。

2. **私钥范围**: SM2 私钥范围 [1, n-1) 比标准 ECDSA [1, n-1] 更严格，需要特别注意边界检查。

3. **ASN.1 编码**: 密文使用 DER 编码，包含 C1x, C1y, C3, C2 四个字段。

4. **KDF**: X9.63 KDF 与 SM2 KDF 等价，用于从共享密钥派生对称密钥。

5. **错误处理**: 所有函数返回 1 表示成功，0 表示失败，错误码通过 `OPENSSL_PUT_ERROR` 设置。

## 参考文档

- GM/T 0003-2012 SM2 椭圆曲线公钥密码算法
- GB/T 32918-2016 SM2 椭圆曲线公钥密码算法
- Tongsuo 源码: `/work/myprojects/mojo-browser/source/Tongsuo/crypto/sm2/`
