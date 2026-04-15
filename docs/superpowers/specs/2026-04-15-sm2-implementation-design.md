# SM2 非对称加密算法实现设计

## 概述

本文档描述在 BoringSSL 中实现 SM2 非对称加密算法的设计方案。SM2 是中国国家密码管理局发布的椭圆曲线公钥密码算法（GM/T 0003），用于密钥生成、加密和解密。

**实现范围**: 仅加密/解密功能（不包括签名）

## 架构设计

### 方案选择：复用 EC 模块

SM2 本质上是特定椭圆曲线上的加密方案。本设计复用 BoringSSL 现有的 `crypto/fipsmodule/ec/` 模块进行所有椭圆曲线点运算，避免重复实现。

### 目录结构

```
include/openssl/sm2.h         - 公共 API 头文件
crypto/sm2/
├── sm2.cc                    - 核心 SM2 加密/解密算法
├── sm2_key.cc                - SM2 密钥生成/验证
├── sm2_kdf.cc                - X9.63 KDF 实现
└── sm2_test.cc               - 单元测试
```

## SM2 曲线参数

SM2 使用 256 位素数域椭圆曲线：

```
曲线方程: y² = x³ + ax + b

p = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC  
b = 28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
```

**实现**: 在 `include/openssl/nid.h` 添加 `NID_sm2`，在 `crypto/fipsmodule/ec/ec.c` 注册曲线。

## 密钥生成

### 私钥范围差异

SM2 私钥范围为 **[1, n-1)**，比标准 ECDSA 的 [1, n-1] 更严格（上界不含 n-1）。

### 实现方案

添加 `EC_FLAG_SM2_RANGE` 标志到 `EC_KEY` 结构，在 `EC_KEY_generate_key` 中检测此标志并调整随机数生成范围：

```c
int SM2_generate_key(EC_KEY *key) {
    // 1. 设置 SM2 曲线组
    // 2. 设置 EC_FLAG_SM2_RANGE 标志
    // 3. 调用 EC_KEY_generate_key
    // 4. 验证私钥范围 [1, n-1)
}
```

### 私钥验证

```c
int SM2_check_private_key(const EC_KEY *key) {
    // 验证: 1 <= d < n-1
}
```

## 加密算法

### 算法流程

输入: 明文 M，公钥 P  
输出: 密文 (C1, C3, C2)

```
1. 生成随机数 k ∈ [1, n-1)
2. C1 = k·G = (x1, y1)        // 基点乘法
3. kP = k·P = (x2, y2)        // 公钥点乘法
4. t = KDF(x2 || y2, len(M))  // X9.63 KDF
5. C2 = M XOR t               // 消息掩码
6. C3 = SM3(x2 || M || y2)    // 哈希值
7. 输出 ASN.1 DER(C1x, C1y, C3, C2)
```

### 实现函数

```c
int SM2_encrypt(const EC_KEY *pub_key,
                const uint8_t *plaintext, size_t plaintext_len,
                uint8_t *ciphertext, size_t *ciphertext_len);
```

## 解密算法

### 算法流程

输入: 密文 (C1, C3, C2)，私钥 d  
输出: 明文 M

```
1. 解析 ASN.1 DER 获取 C1x, C1y, C3, C2
2. C1 = (C1x, C1y)            // 重建点
3. dC1 = d·C1 = (x2, y2)      // 私钥点乘法
4. t = KDF(x2 || y2, len(C2))
5. M = C2 XOR t               // 恢复明文
6. 验证: SM3(x2 || M || y2) == C3
7. 验证通过返回 M，否则返回错误
```

### 实现函数

```c
int SM2_decrypt(const EC_KEY *priv_key,
                const uint8_t *ciphertext, size_t ciphertext_len,
                uint8_t *plaintext, size_t *plaintext_len);
```

## ASN.1 密文格式

SM2 密文使用 ASN.1 DER 编码：

```asn1
SM2Ciphertext ::= SEQUENCE {
    C1x INTEGER,          -- 随机点 x 坐标 (32 字节)
    C1y INTEGER,          -- 随机点 y 坐标 (32 字节)
    C3  OCTET STRING,     -- SM3 哈希值 (32 字节)
    C2  OCTET STRING      -- 加密消息 (变长)
}
```

### 编码实现

使用 BoringSSL 的 `CBB` (Const Byte Builder) 构建 DER 序列：

```c
static int sm2_encode_ciphertext(CBB *out,
                                 const BIGNUM *c1x, const BIGNUM *c1y,
                                 const uint8_t *c3, size_t c3_len,
                                 const uint8_t *c2, size_t c2_len);
```

### 解码实现

使用 BoringSSL 的 `CBS` (Const Byte String) 解析 DER 序列：

```c
static int sm2_decode_ciphertext(CBS *in,
                                 BIGNUM *c1x, BIGNUM *c1y,
                                 uint8_t *c3, size_t *c3_len,
                                 uint8_t *c2, size_t *c2_len);
```

## X9.63 KDF

X9.63 KDF 与 SM2 KDF 等价，用于从共享密钥派生对称密钥：

```
输入: Z (共享密钥), key_len (输出长度)
输出: K (派生密钥)

for i = 1 to ceil(key_len / hash_len):
    K_i = Hash(Z || i)
K = K_1 || K_2 || ... || K_n
截断到 key_len 字节
```

### 实现函数

```c
int SM2_KDF(uint8_t *out, size_t out_len,
            const uint8_t *z, size_t z_len,
            const EVP_MD *md);
```

默认使用 SM3 作为哈希函数。

## API 设计

### 底层 API (include/openssl/sm2.h)

```c
// 密钥生成
int SM2_generate_key(EC_KEY *key);

// 私钥验证
int SM2_check_private_key(const EC_KEY *key);

// 加密
int SM2_encrypt(const EC_KEY *pub_key,
                const uint8_t *plaintext, size_t plaintext_len,
                uint8_t *ciphertext, size_t *ciphertext_len);

// 解密
int SM2_decrypt(const EC_KEY *priv_key,
                const uint8_t *ciphertext, size_t ciphertext_len,
                uint8_t *plaintext, size_t *plaintext_len);

// 密文大小计算
size_t SM2_ciphertext_size(size_t plaintext_len);
size_t SM2_max_plaintext_size(size_t ciphertext_len);

// 曲线操作
EC_KEY *EC_KEY_new_by_curve_name_SM2(void);
#define NID_sm2 1199  // Allocated in include/openssl/nid.h
```

### EVP 层 API

```c
// 创建 SM2 密钥
EVP_PKEY *EVP_PKEY_new_SM2_key(void);

// 设置/获取 SM2 密钥
int EVP_PKEY_set1_EC_KEY_SM2(EVP_PKEY *pkey, EC_KEY *key);
```

## 依赖关系

| 组件 | 来源 | 状态 |
|------|------|------|
| SM3 哈希 | `crypto/sm3/` | ✅ 已实现 |
| EC 点运算 | `crypto/fipsmodule/ec/` | ✅ 可用 |
| BIGNUM | `crypto/fipsmodule/bn/` | ✅ 可用 |
| ASN.1 DER | `crypto/asn1/` (CBS/CBB) | ✅ 可用 |
| 随机数生成 | `crypto/rand/` | ✅ 可用 |
| X9.63 KDF | `crypto/sm2/sm2_kdf.cc` | ⚠️ 需新增 |

## 测试策略

### 测试向量来源

1. **GM/T 0003 标准测试向量** - 官方标准提供的测试数据
2. **Tongsuo 测试向量** - 兼容性验证
3. **随机测试** - 与 Tongsuo 交叉验证

### 测试用例

```c
// 密钥生成测试
TEST(SM2Test, KeyGeneration);

// 加解密往返测试
TEST(SM2Test, EncryptDecrypt);

// GM/T 0003 标准向量测试
TEST(SM2Test, GMT0003Vectors);

// 边界情况测试
TEST(SM2Test, EmptyMessage);
TEST(SM2Test, LargeMessage);
TEST(SM2Test, InvalidCiphertext);

// 互操作性测试
TEST(SM2Test, TongsuoCompatibility);
```

## 错误处理

定义 SM2 专用错误码：

```c
#define SM2_R_INVALID_PRIVATE_KEY 100
#define SM2_R_INVALID_PUBLIC_KEY 101
#define SM2_R_INVALID_CIPHERTEXT 102
#define SM2_R_ASN1_ERROR 103
#define SM2_R_DIGEST_MISMATCH 104
#define SM2_R_BUFFER_TOO_SMALL 105
```

## 构建系统集成

更新 `build.json` 添加新源文件：

```json
{
  "crypto": [
    "crypto/sm2/sm2.cc",
    "crypto/sm2/sm2_key.cc",
    "crypto/sm2/sm2_kdf.cc"
  ],
  "crypto_test": [
    "crypto/sm2/sm2_test.cc"
  ]
}
```

运行 `go run ./util/pregenerate` 更新 `gen/sources.*` 文件。

## 实现顺序

1. 添加 SM2 曲线定义和 NID
2. 实现 X9.63 KDF
3. 实现 ASN.1 密文编解码
4. 实现密钥生成
5. 实现加密算法
6. 实现解密算法
7. 添加单元测试
8. 与 Tongsuo 互操作测试

## 参考文档

- GM/T 0003-2012 SM2 椭圆曲线公钥密码算法
- GB/T 32918-2016 SM2 椭圆曲线公钥密码算法
- Tongsuo 源码: `crypto/sm2/sm2_crypt.c`
