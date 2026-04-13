# SM3 算法实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 BoringSSL 中实现 SM3 国密哈希算法（GM/T 0004-2012），提供底层 API 和 EVP 接口。

**Architecture:** 参考 BLAKE2B256 模式，在 `crypto/sm3/` 目录实现核心算法，在 `crypto/digest/digest_extra.cc` 添加 EVP 集成。使用 TDD 流程，先写测试再实现。

**Tech Stack:** C++17, BoringSSL 内部 API（CRYPTO_rotl_u32, CRYPTO_load_u32_be 等）, GTest

---

## 文件结构

```
新建文件:
- crypto/sm3/sm3.cc           # 核心实现
- crypto/sm3/sm3_test.cc      # 单元测试
- crypto/sm3/sm3_tests.txt    # 测试向量
- include/openssl/sm3.h       # 公开 API 头文件

修改文件:
- crypto/digest/digest_extra.cc  # 添加 EVP_sm3()
- include/openssl/digest.h       # 添加 EVP_sm3() 声明
- build.json                     # 添加源文件
```

---

## Task 1: 创建测试向量文件

**Files:**
- Create: `crypto/sm3/sm3_tests.txt`

- [ ] **Step 1: 创建测试向量文件**

创建 `crypto/sm3/sm3_tests.txt`，包含 GM/T 0004-2012 标准测试向量：

```
# SM3 test vectors from GM/T 0004-2012
# Example 1 (A.1): "abc"
IN = 616263
HASH = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0

# Example 2 (A.2): "abcd" repeated 16 times (64 bytes)
IN = 61626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364
HASH = debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732
```

- [ ] **Step 2: 创建 sm3 目录**

```bash
mkdir -p crypto/sm3
```

---

## Task 2: 创建公开 API 头文件

**Files:**
- Create: `include/openssl/sm3.h`

- [ ] **Step 1: 创建 sm3.h 头文件**

创建 `include/openssl/sm3.h`：

```c
// Copyright 2024 The BoringSSL Authors
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

#ifndef OPENSSL_HEADER_SM3_H
#define OPENSSL_HEADER_SM3_H

#include <openssl/base.h>  // IWYU pragma: export

#if defined(__cplusplus)
extern "C" {
#endif


// SM3 is a cryptographic hash function defined in GM/T 0004-2012.
// It produces a 256-bit (32-byte) digest.


// SM3_DIGEST_LENGTH is the length of an SM3 digest.
#define SM3_DIGEST_LENGTH 32

// SM3_CBLOCK is the block size of SM3.
#define SM3_CBLOCK 64


// SM3_CTX is the state for an SM3 digest operation.
struct sm3_state_st {
  uint32_t h[8];              // 8 state words (A-H)
  uint32_t Nl, Nh;            // message bit count
  uint8_t data[SM3_CBLOCK];   // data buffer
  unsigned num;               // bytes in buffer
} /* SM3_CTX */;


// SM3_Init initialises |ctx| for a fresh SM3 hash. It returns one.
OPENSSL_EXPORT int SM3_Init(SM3_CTX *ctx);

// SM3_Update adds |len| bytes from |data| to |ctx|. It returns one.
OPENSSL_EXPORT int SM3_Update(SM3_CTX *ctx, const void *data, size_t len);

// SM3_Final completes the hash and writes |SM3_DIGEST_LENGTH| bytes to |out|.
// It returns one.
OPENSSL_EXPORT int SM3_Final(uint8_t out[SM3_DIGEST_LENGTH], SM3_CTX *ctx);

// SM3 computes the SM3 hash of |len| bytes from |data| and writes the result
// to |out|.
OPENSSL_EXPORT void SM3(const uint8_t *data, size_t len,
                         uint8_t out[SM3_DIGEST_LENGTH]);


#if defined(__cplusplus)
}  // extern C
#endif

#endif  // OPENSSL_HEADER_SM3_H
```

- [ ] **Step 2: 提交头文件**

```bash
git add include/openssl/sm3.h
git commit -m "sm3: add public API header"
```

---

## Task 3: 创建单元测试（TDD - 先写失败测试）

**Files:**
- Create: `crypto/sm3/sm3_test.cc`

- [ ] **Step 1: 创建测试文件**

创建 `crypto/sm3/sm3_test.cc`：

```cpp
// Copyright 2024 The BoringSSL Authors
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

#include <openssl/sm3.h>

#include <gtest/gtest.h>

#include "../test/file_test.h"
#include "../test/test_util.h"


BSSL_NAMESPACE_BEGIN
namespace {

// Test vector from GM/T 0004-2012 Example 1 (A.1)
TEST(SM3Test, ABC) {
  const uint8_t kInput[] = {0x61, 0x62, 0x63};  // "abc"
  const uint8_t kExpected[SM3_DIGEST_LENGTH] = {
      0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
      0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
      0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
      0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
  };

  uint8_t digest[SM3_DIGEST_LENGTH];
  SM3(kInput, sizeof(kInput), digest);
  EXPECT_EQ(Bytes(kExpected), Bytes(digest));
}

// Test vector from GM/T 0004-2012 Example 2 (A.2)
TEST(SM3Test, ABCD16) {
  // "abcd" repeated 16 times (64 bytes)
  const uint8_t kInput[] = {
      0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
      0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
      0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
      0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
      0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
      0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
      0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
      0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64
  };
  const uint8_t kExpected[SM3_DIGEST_LENGTH] = {
      0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1,
      0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d,
      0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65,
      0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32
  };

  uint8_t digest[SM3_DIGEST_LENGTH];
  SM3(kInput, sizeof(kInput), digest);
  EXPECT_EQ(Bytes(kExpected), Bytes(digest));
}

// Test streaming API (Init/Update/Final)
TEST(SM3Test, Streaming) {
  const uint8_t kInput[] = {0x61, 0x62, 0x63};  // "abc"
  const uint8_t kExpected[SM3_DIGEST_LENGTH] = {
      0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
      0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
      0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
      0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
  };

  SM3_CTX ctx;
  uint8_t digest[SM3_DIGEST_LENGTH];

  ASSERT_TRUE(SM3_Init(&ctx));
  ASSERT_TRUE(SM3_Update(&ctx, kInput, sizeof(kInput)));
  ASSERT_TRUE(SM3_Final(digest, &ctx));
  EXPECT_EQ(Bytes(kExpected), Bytes(digest));
}

// Test byte-by-byte streaming
TEST(SM3Test, StreamingByteByByte) {
  const uint8_t kInput[] = {0x61, 0x62, 0x63};  // "abc"
  const uint8_t kExpected[SM3_DIGEST_LENGTH] = {
      0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9,
      0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
      0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2,
      0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
  };

  SM3_CTX ctx;
  uint8_t digest[SM3_DIGEST_LENGTH];

  ASSERT_TRUE(SM3_Init(&ctx));
  for (size_t i = 0; i < sizeof(kInput); i++) {
    ASSERT_TRUE(SM3_Update(&ctx, &kInput[i], 1));
  }
  ASSERT_TRUE(SM3_Final(digest, &ctx));
  EXPECT_EQ(Bytes(kExpected), Bytes(digest));
}

// Test file-based test vectors
TEST(SM3Test, TestVectors) {
  FileTestGTest("crypto/sm3/sm3_tests.txt", [](FileTest *t) {
    std::vector<uint8_t> msg, expected;
    ASSERT_TRUE(t->GetBytes(&msg, "IN"));
    ASSERT_TRUE(t->GetBytes(&expected, "HASH"));

    uint8_t digest[SM3_DIGEST_LENGTH];
    SM3(msg.data(), msg.size(), digest);
    EXPECT_EQ(Bytes(digest), Bytes(expected)) << "Input length: " << msg.size();

    // Also test streaming API
    OPENSSL_memset(digest, 0, sizeof(digest));
    SM3_CTX ctx;
    SM3_Init(&ctx);
    for (uint8_t b : msg) {
      SM3_Update(&ctx, &b, 1);
    }
    SM3_Final(digest, &ctx);
    EXPECT_EQ(Bytes(digest), Bytes(expected)) << "Streaming, input length: " << msg.size();
  });
}

}  // namespace
BSSL_NAMESPACE_END
```

- [ ] **Step 2: 提交测试文件**

```bash
git add crypto/sm3/sm3_test.cc crypto/sm3/sm3_tests.txt
git commit -m "sm3: add unit tests (TDD - failing)"
```

---

## Task 4: 实现核心算法

**Files:**
- Create: `crypto/sm3/sm3.cc`

- [ ] **Step 1: 创建核心实现文件**

创建 `crypto/sm3/sm3.cc`：

```cpp
// Copyright 2024 The BoringSSL Authors
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

#include <openssl/sm3.h>

#include <string.h>

#include "../internal.h"


using namespace bssl;

// SM3 initial values (GM/T 0004-2012)
static const uint32_t kIV[8] = {
    0x7380166fUL, 0x4914b2b9UL, 0x172442d7UL, 0xda8a0600UL,
    0xa96f30bcUL, 0x163138aaUL, 0xe38dee4dUL, 0xb0fb0e4eUL,
};

// Permutation functions
static inline uint32_t P0(uint32_t x) {
  return x ^ CRYPTO_rotl_u32(x, 9) ^ CRYPTO_rotl_u32(x, 17);
}

static inline uint32_t P1(uint32_t x) {
  return x ^ CRYPTO_rotl_u32(x, 15) ^ CRYPTO_rotl_u32(x, 23);
}

// Boolean functions for first 16 rounds
static inline uint32_t FF0(uint32_t x, uint32_t y, uint32_t z) {
  return x ^ y ^ z;
}

static inline uint32_t GG0(uint32_t x, uint32_t y, uint32_t z) {
  return x ^ y ^ z;
}

// Boolean functions for remaining 48 rounds
static inline uint32_t FF1(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) | ((x | y) & z);
}

static inline uint32_t GG1(uint32_t x, uint32_t y, uint32_t z) {
  return z ^ (x & (y ^ z));
}

// Load 32-bit big-endian word
static inline uint32_t load_u32_be(const uint8_t *p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) |
         static_cast<uint32_t>(p[3]);
}

// Store 32-bit big-endian word
static inline void store_u32_be(uint8_t *p, uint32_t x) {
  p[0] = static_cast<uint8_t>(x >> 24);
  p[1] = static_cast<uint8_t>(x >> 16);
  p[2] = static_cast<uint8_t>(x >> 8);
  p[3] = static_cast<uint8_t>(x);
}

// SM3 compression function
// Processes one 64-byte block
static void sm3_compress(uint32_t state[8], const uint8_t block[64]) {
  uint32_t W[68];
  uint32_t Wp[64];

  // Message expansion: load 16 words from input (big-endian)
  for (int i = 0; i < 16; i++) {
    W[i] = load_u32_be(block + 4 * i);
  }

  // Expand to 68 words
  for (int i = 16; i < 68; i++) {
    W[i] = P1(W[i-16] ^ W[i-9] ^ CRYPTO_rotl_u32(W[i-3], 15)) ^
           CRYPTO_rotl_u32(W[i-13], 7) ^ W[i-6];
  }

  // Compute W' = W[i] ^ W[i+4]
  for (int i = 0; i < 64; i++) {
    Wp[i] = W[i] ^ W[i+4];
  }

  // Initialize working variables
  uint32_t A = state[0], B = state[1], C = state[2], D = state[3];
  uint32_t E = state[4], F = state[5], G = state[6], H = state[7];

  // Constants: Tj = 0x79CC4519 for j in [0,15], 0x9D8A7A87 for j in [16,63]
  const uint32_t Tj0 = 0x79CC4519;
  const uint32_t Tj1 = 0x9D8A7A87;

  // 64 rounds
  for (int j = 0; j < 64; j++) {
    uint32_t Tj = (j < 16) ? Tj0 : Tj1;
    uint32_t SS1, SS2, TT1, TT2;

    SS1 = CRYPTO_rotl_u32(CRYPTO_rotl_u32(A, 12) + E + CRYPTO_rotl_u32(Tj, j), 7);
    SS2 = SS1 ^ CRYPTO_rotl_u32(A, 12);

    if (j < 16) {
      TT1 = FF0(A, B, C) + D + SS2 + Wp[j];
      TT2 = GG0(E, F, G) + H + SS1 + W[j];
    } else {
      TT1 = FF1(A, B, C) + D + SS2 + Wp[j];
      TT2 = GG1(E, F, G) + H + SS1 + W[j];
    }

    D = C;
    C = CRYPTO_rotl_u32(B, 9);
    B = A;
    A = TT1;
    H = G;
    G = CRYPTO_rotl_u32(F, 19);
    F = E;
    E = P0(TT2);
  }

  // Update state
  state[0] ^= A;
  state[1] ^= B;
  state[2] ^= C;
  state[3] ^= D;
  state[4] ^= E;
  state[5] ^= F;
  state[6] ^= G;
  state[7] ^= H;
}

int SM3_Init(SM3_CTX *ctx) {
  OPENSSL_memset(ctx, 0, sizeof(*ctx));
  for (int i = 0; i < 8; i++) {
    ctx->h[i] = kIV[i];
  }
  return 1;
}

int SM3_Update(SM3_CTX *ctx, const void *data, size_t len) {
  if (len == 0) {
    return 1;
  }

  const uint8_t *in = static_cast<const uint8_t *>(data);
  size_t todo;

  // Handle any buffered data
  if (ctx->num != 0) {
    todo = SM3_CBLOCK - ctx->num;
    if (todo > len) {
      todo = len;
    }
    OPENSSL_memcpy(&ctx->data[ctx->num], in, todo);
    ctx->num += todo;
    in += todo;
    len -= todo;

    if (ctx->num == SM3_CBLOCK) {
      sm3_compress(ctx->h, ctx->data);
      ctx->num = 0;

      // Update bit count
      uint64_t bits = SM3_CBLOCK * 8;
      ctx->Nh += (bits >> 32) + ((ctx->Nl + (bits & 0xffffffff)) < ctx->Nl);
      ctx->Nl += bits & 0xffffffff;
    }
  }

  // Process complete blocks
  while (len >= SM3_CBLOCK) {
    sm3_compress(ctx->h, in);
    in += SM3_CBLOCK;
    len -= SM3_CBLOCK;

    // Update bit count
    uint64_t bits = SM3_CBLOCK * 8;
    ctx->Nh += (bits >> 32) + ((ctx->Nl + (bits & 0xffffffff)) < ctx->Nl);
    ctx->Nl += bits & 0xffffffff;
  }

  // Buffer remaining data
  if (len > 0) {
    OPENSSL_memcpy(ctx->data, in, len);
    ctx->num = len;
  }

  return 1;
}

int SM3_Final(uint8_t out[SM3_DIGEST_LENGTH], SM3_CTX *ctx) {
  // Save the number of bits
  uint32_t low = ctx->Nl;
  uint32_t high = ctx->Nh;

  // Add padding bit count for buffered data
  uint64_t bits = ctx->num * 8;
  high += (bits >> 32) + ((low + (bits & 0xffffffff)) < low);
  low += bits & 0xffffffff;

  // Pad to 56 mod 64 bytes
  size_t pad = (ctx->num < 56) ? (56 - ctx->num) : (120 - ctx->num);

  // Padding: 0x80 followed by zeros
  uint8_t padding[128] = {0x80};

  SM3_Update(ctx, padding, pad);

  // Append length in bits (big-endian 64-bit)
  uint8_t length[8];
  store_u32_be(length, high);
  store_u32_be(length + 4, low);
  SM3_Update(ctx, length, 8);

  // Output digest (big-endian)
  for (int i = 0; i < 8; i++) {
    store_u32_be(out + 4 * i, ctx->h[i]);
  }

  return 1;
}

void SM3(const uint8_t *data, size_t len, uint8_t out[SM3_DIGEST_LENGTH]) {
  SM3_CTX ctx;
  SM3_Init(&ctx);
  SM3_Update(&ctx, data, len);
  SM3_Final(out, &ctx);
}
```

- [ ] **Step 2: 提交核心实现**

```bash
git add crypto/sm3/sm3.cc
git commit -m "sm3: implement core algorithm (GM/T 0004-2012)"
```

---

## Task 5: 更新构建系统

**Files:**
- Modify: `build.json`

- [ ] **Step 1: 添加源文件到 build.json**

在 `build.json` 的 `crypto.srcs` 数组中添加：
```json
"crypto/sm3/sm3.cc",
```

在 `crypto.internal_hdrs` 数组中添加：
```json
"include/openssl/sm3.h",
```

在 `crypto_test.srcs` 数组中添加：
```json
"crypto/sm3/sm3_test.cc",
```

在 `crypto_test.data` 数组中添加：
```json
"crypto/sm3/sm3_tests.txt",
```

- [ ] **Step 2: 运行预生成工具**

```bash
go run ./util/pregenerate
```

Expected: 成功生成构建文件

- [ ] **Step 3: 提交构建系统更新**

```bash
git add build.json gen/
git commit -m "sm3: add to build system"
```

---

## Task 6: 编译并运行测试

**Files:**
- None (verification)

- [ ] **Step 1: 配置 CMake**

```bash
cmake -GNinja -B build
```

Expected: 成功配置

- [ ] **Step 2: 编译**

```bash
ninja -C build crypto_test
```

Expected: 编译成功，无错误

- [ ] **Step 3: 运行 SM3 测试**

```bash
./build/crypto_test --gtest_filter=SM3*
```

Expected: 所有测试通过

- [ ] **Step 4: 提交测试通过确认**

```bash
git status
```

---

## Task 7: 添加 EVP 接口

**Files:**
- Modify: `include/openssl/digest.h`
- Modify: `crypto/digest/digest_extra.cc`

- [ ] **Step 1: 在 digest.h 添加声明**

在 `include/openssl/digest.h` 的 hash 算法声明部分（约第 45 行，`EVP_blake2b256` 附近）添加：

```c
OPENSSL_EXPORT const EVP_MD *EVP_sm3(void);
```

- [ ] **Step 2: 在 digest_extra.cc 添加实现**

在 `crypto/digest/digest_extra.cc` 中：

1. 在文件顶部的 include 部分添加：
```cpp
#include <openssl/sm3.h>
```

2. 在文件末尾（`EVP_md5_sha1` 之后）添加：

```cpp
static void sm3_init(EVP_MD_CTX *ctx) {
  SM3_Init(reinterpret_cast<SM3_CTX *>(ctx->md_data));
}

static void sm3_update(EVP_MD_CTX *ctx, const void *data, size_t len) {
  SM3_Update(reinterpret_cast<SM3_CTX *>(ctx->md_data), data, len);
}

static void sm3_final(EVP_MD_CTX *ctx, uint8_t *md) {
  SM3_Final(md, reinterpret_cast<SM3_CTX *>(ctx->md_data));
}

static const EVP_MD evp_md_sm3 = {
    NID_undef,       // SM3 has no official NID in BoringSSL
    SM3_DIGEST_LENGTH,
    0,
    sm3_init,
    sm3_update,
    sm3_final,
    SM3_CBLOCK,
    sizeof(SM3_CTX),
};

const EVP_MD *EVP_sm3() { return &evp_md_sm3; }

static_assert(sizeof(SM3_CTX) <= EVP_MAX_MD_DATA_SIZE);
```

- [ ] **Step 3: 提交 EVP 集成**

```bash
git add include/openssl/digest.h crypto/digest/digest_extra.cc
git commit -m "sm3: add EVP interface"
```

---

## Task 8: 验证 EVP 接口

**Files:**
- None (verification)

- [ ] **Step 1: 重新编译**

```bash
ninja -C build
```

Expected: 编译成功

- [ ] **Step 2: 运行完整测试套件**

```bash
./build/crypto_test --gtest_filter=SM3*
ninja -C build run_tests
```

Expected: 所有测试通过

- [ ] **Step 3: 最终提交**

```bash
git status
git log --oneline -10
```

---

## 验证清单

- [ ] SM3("abc") 产生正确输出（GM/T 0004-2012 示例 1）
- [ ] SM3("abcd"×16) 产生正确输出（GM/T 0004-2012 示例 2）
- [ ] 流式 API（Init/Update/Final）工作正常
- [ ] 逐字节流式处理工作正常
- [ ] EVP_sm3() 可通过 EVP API 使用
- [ ] 编译无警告
- [ ] 所有现有测试继续通过
