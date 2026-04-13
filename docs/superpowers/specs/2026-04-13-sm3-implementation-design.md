# SM3 算法实现设计

## 概述

在 BoringSSL 上实现 SM3 国密哈希算法（GM/T 0004-2012），参考 Tongsuo 项目的实现，采用测试驱动开发流程。

## 需求

- ✅ 提供 EVP 接口（`EVP_sm3()`）
- ✅ 仅 C++ 实现，不依赖汇编优化
- ✅ 非 FIPS 模块
- ✅ 遵循 BoringSSL 代码风格（参考 BLAKE2B256）

## 文件结构

```
crypto/sm3/
├── sm3.cc              # 核心实现
└── sm3_test.cc         # GTest 单元测试

include/openssl/
└── sm3.h               # 公开 API 头文件

crypto/sm3/sm3_tests.txt    # 测试向量（GM/T 0004-2012）
```

## 公开 API

```c
#define SM3_DIGEST_LENGTH 32   // 256 位输出
#define SM3_CBLOCK 64          // 512 位分组

typedef struct sm3_state_st {
  uint32_t h[8];              // 8 个状态字 (A-H)
  uint32_t Nl, Nh;            // 消息长度计数器
  uint8_t data[SM3_CBLOCK];   // 缓冲区
  unsigned num;               // 缓冲区已用字节数
} SM3_CTX;

// 初始化/更新/完成
OPENSSL_EXPORT int SM3_Init(SM3_CTX *ctx);
OPENSSL_EXPORT int SM3_Update(SM3_CTX *ctx, const void *data, size_t len);
OPENSSL_EXPORT int SM3_Final(uint8_t out[SM3_DIGEST_LENGTH], SM3_CTX *ctx);

// 一次性计算
OPENSSL_EXPORT void SM3(const uint8_t *data, size_t len, 
                         uint8_t out[SM3_DIGEST_LENGTH]);

// 底层变换
OPENSSL_EXPORT void SM3_Transform(SM3_CTX *ctx, 
                                   const uint8_t block[SM3_CBLOCK]);
```

## 核心算法

### 初始向量（GM/T 0004-2012）

```
A = 0x7380166f    B = 0x4914b2b9    C = 0x172442d7    D = 0xda8a0600
E = 0xa96f30bc    F = 0x163138aa    G = 0xe38dee4d    H = 0xb0fb0e4e
```

### 置换函数

```
P0(X) = X ⊕ ROTL(X, 9) ⊕ ROTL(X, 17)
P1(X) = X ⊕ ROTL(X, 15) ⊕ ROTL(X, 23)
```

### 布尔函数

- 前 16 轮：`FF0(X,Y,Z) = X ⊕ Y ⊕ Z`，`GG0(X,Y,Z) = X ⊕ Y ⊕ Z`
- 后 48 轮：`FF1(X,Y,Z) = (X ∧ Y) ∨ ((X ∨ Y) ∧ Z)`，`GG1(X,Y,Z) = Z ⊕ (X ∧ (Y ⊕ Z))`

### 消息扩展

```
W[j] = 输入字 (j = 0..15)
W[j] = P1(W[j-16] ⊕ W[j-9] ⊕ ROTL(W[j-3], 15)) ⊕ ROTL(W[j-13], 7) ⊕ W[j-6] (j = 16..67)
W'[j] = W[j] ⊕ W[j+4] (j = 0..63)
```

### 压缩函数

64 轮迭代，每轮：
1. `SS1 = ROTL(ROTL(A, 12) + E + Tj, 7)`
2. `SS2 = SS1 ⊕ ROTL(A, 12)`
3. `TT1 = FF(A, B, C) + D + SS2 + W'[j]`
4. `TT2 = GG(E, F, G) + H + SS1 + W[j]`
5. 更新状态：`D = A`, `A = TT1`, `H = E`, `E = P0(TT2)`, `B = ROTL(B, 9)`, `F = ROTL(F, 19)`

常量 Tj：前 16 轮用 `0x79CC4519`，后 48 轮用 `0x9D8A7A87`

## EVP 集成

### 修改文件

1. `include/openssl/digest.h` - 添加声明：
   ```c
   OPENSSL_EXPORT const EVP_MD *EVP_sm3(void);
   ```

2. `crypto/digest_extra/digest_extra.cc` - 实现 `EVP_sm3()`

3. `include/openssl/obj_mac.h` - 添加 NID：
   ```c
   #define NID_sm3 1147
   #define NID_sm3WithRSAEncryption 1148
   ```

4. `crypto/obj/obj_dat.h` - 添加 OID 数据（SM3 OID: 1.2.156.10197.1.401）

## 测试

### 测试向量（GM/T 0004-2012 附录）

**示例 1：**
- 输入：`"abc"` (0x61 0x62 0x63)
- 输出：`66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0`

**示例 2：**
- 输入：`"abcd"` 重复 16 次（64 字节）
- 输出：`debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732`

### 测试文件格式

参考 `crypto/blake2/blake2b256_tests.txt`：
```
IN = 616263
HASH = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```

## 构建系统集成

### build.json 修改

```json
"crypto": {
  "srcs": [
    // ... existing files ...
    "crypto/sm3/sm3.cc"
  ],
  "internal_hdrs": [
    // ... existing files ...
    "include/openssl/sm3.h"
  ]
},
"crypto_test": {
  "srcs": [
    // ... existing files ...
    "crypto/sm3/sm3_test.cc"
  ],
  "data": [
    // ... existing files ...
    "crypto/sm3/sm3_tests.txt"
  ]
}
```

### 运行预生成

```bash
go run ./util/pregenerate
```

## 实现步骤（TDD 流程）

1. **先写测试** - 创建 `sm3_test.cc` 和 `sm3_tests.txt`，使用 GM/T 0004-2012 测试向量
2. **实现 API** - 创建 `sm3.h` 头文件定义接口
3. **实现核心** - 创建 `sm3.cc` 实现算法
4. **集成 EVP** - 添加 `EVP_sm3()` 支持
5. **集成构建** - 修改 `build.json` 并运行 `go run ./util/pregenerate`
6. **验证** - 编译并运行测试 `./build/crypto_test --gtest_filter=SM3*`

## 参考

- GM/T 0004-2012 SM3 密码杂凑算法
- Tongsuo 实现：`../Tongsuo/crypto/sm3/`
- BoringSSL BLAKE2B256：`crypto/blake2/blake2.cc`
