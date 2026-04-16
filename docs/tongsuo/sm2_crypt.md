# SM2非对称加密算法的密钥生成，加密和解密的实现流程

## Key Generation Flow

1. **Top-level API**: `TSAPI_SM2Keygen()` in `crypto/tsapi/tsapi_lib.c` calls `EVP_PKEY_Q_keygen(NULL, NULL, "SM2")`
2. **Provider layer**: `sm2_gen()` in `providers/implementations/keymgmt/ec_kmgmt.c` - initializes with "sm2" group, calls `EC_KEY_generate_key(ec)`
3. **Core generation**: `ec_generate_key()` in `crypto/ec/ec_key.c`:
   - SM2 private key range is [1, n-1) (note: different from standard EC which is [1, n-1])
   - Generates random private key `d` using `BN_priv_rand_range_ex`
   - Computes public key `Q = d * G` using `EC_POINT_mul`
4. **Validation**: `ossl_sm2_key_private_check()` in `crypto/sm2/sm2_key.c` validates private key is in [1, n-1)

## Encryption Flow

1. **Top-level API**: `TSAPI_SM2Encrypt()` → `do_SM2Crypt(1, ...)` in `crypto/tsapi/tsapi_lib.c`
2. **EVP layer**: `EVP_PKEY_encrypt_init()` + `EVP_PKEY_encrypt()`
3. **Provider layer**: `sm2_asym_encrypt()` in `providers/implementations/asymciphers/sm2_enc.c` → calls `ossl_sm2_encrypt()`
4. **Core encryption**: `ossl_sm2_encrypt()` in `crypto/sm2/sm2_crypt.c`:
   - Generate random `k` in [1, n-1)
   - Compute `C1 = k*G` (x1, y1)
   - Compute `kP = k*P` (x2, y2) where P is the public key
   - Derive key mask via KDF: `t = KDF(x2||y2, msg_len)` using X9.63 KDF (which matches SM2 KDF)
   - Compute `C2 = msg XOR t`
   - Compute `C3 = Hash(x2 || msg || y2)` using SM3
   - Encode as ASN.1 DER: `C1x || C1y || C3 || C2`

## Decryption Flow

1. **Top-level API**: `TSAPI_SM2Decrypt()` → `do_SM2Crypt(0, ...)` in `crypto/tsapi/tsapi_lib.c`
2. **EVP layer**: `EVP_PKEY_decrypt_init()` + `EVP_PKEY_decrypt()`
3. **Provider layer**: `sm2_asym_decrypt()` in `providers/implementations/asymciphers/sm2_enc.c` → calls `ossl_sm2_decrypt()`
4. **Core decryption**: `ossl_sm2_decrypt()` in `crypto/sm2/sm2_crypt.c`:
   - Parse ASN.1 DER ciphertext to get C1x, C1y, C3, C2
   - Reconstruct point C1 from (C1x, C1y)
   - Compute `dC1 = d * C1` (x2, y2) where d is the private key
   - Derive key mask via KDF: `t = KDF(x2||y2, msg_len)`
   - Recover plaintext: `msg = C2 XOR t`
   - Verify: compute `Hash(x2 || msg || y2)` and compare with C3
   - Return plaintext if hash matches

The ciphertext format is ASN.1 DER encoded as `SEQUENCE { C1x INTEGER, C1y INTEGER, C3 OCTET STRING, C2 OCTET STRING }`.

The default digest is SM3 (set in `sm2_get_md()` in `providers/implementations/asymciphers/sm2_enc.c`).

Now let me write a comprehensive analysis.


以下是 Tongsuo 中 SM2 非对称加密算法的完整实现流程分析。

---

## 整体架构层次

```
应用层 (TSAPI_SM2Keygen / TSAPI_SM2Encrypt / TSAPI_SM2Decrypt)
    ↓
EVP 层 (EVP_PKEY_Q_keygen / EVP_PKEY_encrypt / EVP_PKEY_decrypt)
    ↓
Provider 层 (sm2_gen / sm2_asym_encrypt / sm2_asym_decrypt)
    ↓
核心算法层 (ec_generate_key / ossl_sm2_encrypt / ossl_sm2_decrypt)
```

---

## 一、密钥生成

### 入口

最高层 API `TSAPI_SM2Keygen()` 直接调用 EVP 接口：

```c
// crypto/tsapi/tsapi_lib.c:818
EVP_PKEY *TSAPI_SM2Keygen(void) {
    return EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
}
``` Tongsuo:818-821 

### Provider 层：`sm2_gen()`

Provider 层的 `sm2_gen()` 负责初始化 SM2 曲线组（默认 group 名为 `"sm2"`），然后调用 `EC_KEY_generate_key(ec)`： Tongsuo:1280-1323 

`sm2_gen_init()` 确保 group 默认设置为 `"sm2"`： Tongsuo:999-1013 

### 核心层：`ec_generate_key()`

实际密钥生成在 `crypto/ec/ec_key.c` 的 `ec_generate_key()` 中完成。SM2 私钥范围是 **[1, n-1)**（比标准 ECDSA 的 [1, n-1] 更严格，上界不含 n-1）： Tongsuo:251-315 

关键步骤：
1. 检测 `EC_FLAG_SM2_RANGE` 标志，将随机范围上界设为 `n-1`（而非 `n`）
2. 用 `BN_priv_rand_range_ex` 生成随机私钥 `d`，循环直到非零
3. 计算公钥 `Q = d * G`（椭圆曲线点乘）

### 私钥合法性校验：`ossl_sm2_key_private_check()` Tongsuo:22-51 

验证私钥满足 `1 ≤ d < n-1`。

---

## 二、加密

### 调用链

```
TSAPI_SM2Encrypt()
  → do_SM2Crypt(enc=1, ...)
    → EVP_PKEY_encrypt_init() + EVP_PKEY_encrypt()
      → sm2_asym_encrypt()  [Provider 层]
        → ossl_sm2_encrypt()  [核心算法层]
```

### Provider 层：`sm2_asym_encrypt()`

默认摘要算法为 **SM3**（由 `sm2_get_md()` 决定）： Tongsuo:71-99 

### 核心层：`ossl_sm2_encrypt()` Tongsuo:95-255 

加密步骤（对应 GM/T 0003 标准）：

| 步骤 | 代码操作 | 说明 |
|------|----------|------|
| 1 | `BN_priv_rand_range_ex(k, order, ...)` | 生成随机数 `k ∈ [1, n-1)` |
| 2 | `EC_POINT_mul(group, kG, k, NULL, NULL, ctx)` | 计算 `C1 = k·G`，得到 `(x1, y1)` |
| 3 | `EC_POINT_mul(group, kP, NULL, P, k, ctx)` | 计算 `kP = k·P`（P 为公钥），得到 `(x2, y2)` |
| 4 | `ossl_ecdh_kdf_X9_63(msg_mask, ...)` | 用 KDF 从 `x2‖y2` 派生掩码 `t`（X9.63 KDF 与 SM2 KDF 等价） |
| 5 | `msg_mask[i] ^= msg[i]` | 计算密文 `C2 = M ⊕ t` |
| 6 | `EVP_DigestUpdate(hash, x2‖msg‖y2)` | 计算 `C3 = Hash(x2 ‖ M ‖ y2)`（默认 SM3） |
| 7 | `i2d_SM2_Ciphertext(...)` | 将 `(C1x, C1y, C3, C2)` 编码为 ASN.1 DER |

### 密文结构

```c
// crypto/sm2/sm2_crypt.c:31-43
struct SM2_Ciphertext_st {
    BIGNUM *C1x;           // 随机点 x 坐标
    BIGNUM *C1y;           // 随机点 y 坐标
    ASN1_OCTET_STRING *C3; // 哈希值（SM3，32字节）
    ASN1_OCTET_STRING *C2; // 加密后的消息
};
``` Tongsuo:31-43 

---

## 三、解密

### 调用链

```
TSAPI_SM2Decrypt()
  → do_SM2Crypt(enc=0, ...)
    → EVP_PKEY_decrypt_init() + EVP_PKEY_decrypt()
      → sm2_asym_decrypt()  [Provider 层]
        → ossl_sm2_decrypt()  [核心算法层]
``` Tongsuo:891-951 

### 核心层：`ossl_sm2_decrypt()` Tongsuo:257-393 

解密步骤：

| 步骤 | 代码操作 | 说明 |
|------|----------|------|
| 1 | `d2i_SM2_Ciphertext(...)` | 解析 ASN.1 DER，提取 `C1x, C1y, C3, C2` |
| 2 | `EC_POINT_set_affine_coordinates(group, C1, C1x, C1y, ...)` | 从坐标重建椭圆曲线点 `C1` |
| 3 | `EC_POINT_mul(group, C1, NULL, C1, private_key, ctx)` | 计算 `d·C1 = d·k·G = k·(d·G) = k·P`，得到 `(x2, y2)` |
| 4 | `ossl_ecdh_kdf_X9_63(msg_mask, ...)` | 用 KDF 从 `x2‖y2` 派生掩码 `t` |
| 5 | `ptext_buf[i] = C2[i] ^ msg_mask[i]` | 恢复明文 `M = C2 ⊕ t` |
| 6 | `EVP_DigestUpdate(hash, x2‖M‖y2)` | 重新计算 `Hash(x2 ‖ M ‖ y2)` |
| 7 | `CRYPTO_memcmp(computed_C3, C3, hash_size)` | 与 C3 比较，验证完整性，不匹配则返回错误 | Tongsuo:337-375 

---

## 完整流程图

```mermaid
flowchart TD
    subgraph "密钥生成"
        A["TSAPI_SM2Keygen()"] --> B["EVP_PKEY_Q_keygen('SM2')"]
        B --> C["sm2_gen() - 设置 sm2 曲线组"]
        C --> D["EC_KEY_generate_key()"]
        D --> E["ec_generate_key()\n随机 d ∈ [1, n-1)"]
        E --> F["Q = d·G\n(公钥 = 私钥 × 基点)"]
    end

    subgraph "加密"
        G["TSAPI_SM2Encrypt(pubkey, M)"] --> H["EVP_PKEY_encrypt()"]
        H --> I["sm2_asym_encrypt()\n默认摘要: SM3"]
        I --> J["ossl_sm2_encrypt()"]
        J --> K["随机 k, C1 = k·G"]
        K --> L["kP = k·P (x2,y2)"]
        L --> M["t = KDF(x2‖y2)\nC2 = M ⊕ t"]
        M --> N["C3 = SM3(x2‖M‖y2)"]
        N --> O["ASN.1 DER 编码\n(C1x,C1y,C3,C2)"]
    end

    subgraph "解密"
        P["TSAPI_SM2Decrypt(privkey, CT)"] --> Q["EVP_PKEY_decrypt()"]
        Q --> R["sm2_asym_decrypt()"]
        R --> S["ossl_sm2_decrypt()"]
        S --> T["解析 ASN.1: C1,C2,C3"]
        T --> U["d·C1 = (x2,y2)"]
        U --> V["t = KDF(x2‖y2)\nM = C2 ⊕ t"]
        V --> W["验证 SM3(x2‖M‖y2) == C3"]
        W --> X["返回明文 M"]
    end
```

---

## 关键文件汇总

| 文件 | 职责 |
|------|------|
| `crypto/sm2/sm2_key.c` | 私钥合法性校验（范围 [1, n-1)） |
| `crypto/sm2/sm2_crypt.c` | 核心加解密算法 `ossl_sm2_encrypt` / `ossl_sm2_decrypt` |
| `providers/implementations/asymciphers/sm2_enc.c` | Provider 层适配，默认绑定 SM3 摘要 |
| `providers/implementations/keymgmt/ec_kmgmt.c` | SM2 密钥管理，`sm2_gen()` 生成密钥对 |
| `crypto/ec/ec_key.c` | 底层 EC 密钥生成，SM2 特殊范围处理 |
| `crypto/tsapi/tsapi_lib.c` | 高层 TSAPI 接口封装 |
### Citations
**File:** crypto/tsapi/tsapi_lib.c (L818-821)
```c
EVP_PKEY *TSAPI_SM2Keygen(void)
{
    return EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
}
```
**File:** crypto/tsapi/tsapi_lib.c (L891-951)
```c
static unsigned char *do_SM2Crypt(int enc, EVP_PKEY *key,
                                  const unsigned char *in, size_t inlen,
                                  size_t *outlen)
{
    EVP_PKEY_CTX *ctx = NULL;
    size_t len = 0;
    unsigned char *out = NULL;

    if (key == NULL || in == NULL || outlen == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (enc) {
        ctx = EVP_PKEY_CTX_new_from_pkey_provided(NULL, key, NULL);
    } else {
        ctx = EVP_PKEY_CTX_new(key, NULL);
    }

    if (ctx == NULL)
        return NULL;

    if (enc) {
        if (EVP_PKEY_encrypt_init(ctx) <= 0
            || EVP_PKEY_encrypt(ctx, NULL, &len, in, inlen) <= 0) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
            goto end;
        }
    } else {
        if (EVP_PKEY_decrypt_init(ctx) <= 0
            || EVP_PKEY_decrypt(ctx, NULL, &len, in, inlen) <= 0) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
            goto end;
        }
    }

    out = OPENSSL_malloc(len);
    if (out == NULL)
        goto end;

    if (enc) {
        if (EVP_PKEY_encrypt(ctx, out, &len, in, inlen) <= 0) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
            OPENSSL_free(out);
            out = NULL;
            len = 0;
        }
    } else {
        if (EVP_PKEY_decrypt(ctx, out, &len, in, inlen) <= 0) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_EVP_LIB);
            OPENSSL_free(out);
            out = NULL;
            len = 0;
        }
    }

    *outlen = len;
end:
    EVP_PKEY_CTX_free(ctx);
    return out;
}
```
**File:** providers/implementations/keymgmt/ec_kmgmt.c (L999-1013)
```c
static void *sm2_gen_init(void *provctx, int selection,
                         const OSSL_PARAM params[])
{
    struct ec_gen_ctx *gctx = ec_gen_init(provctx, selection, params);

    if (gctx != NULL) {
        if (gctx->group_name != NULL)
            return gctx;
        if ((gctx->group_name = OPENSSL_strdup("sm2")) != NULL)
            return gctx;
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        ec_gen_cleanup(gctx);
    }
    return NULL;
}
```
**File:** providers/implementations/keymgmt/ec_kmgmt.c (L1280-1323)
```c
static void *sm2_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct ec_gen_ctx *gctx = genctx;
    EC_KEY *ec = NULL;
    int ret = 1;

    if (gctx == NULL
        || (ec = EC_KEY_new_ex(gctx->libctx, NULL)) == NULL)
        return NULL;

    if (gctx->gen_group == NULL) {
        if (!ec_gen_set_group_from_params(gctx))
            goto err;
    } else {
        if (gctx->encoding) {
            int flags = ossl_ec_encoding_name2id(gctx->encoding);

            if (flags < 0)
                goto err;
            EC_GROUP_set_asn1_flag(gctx->gen_group, flags);
        }
        if (gctx->pt_format != NULL) {
            int format = ossl_ec_pt_format_name2id(gctx->pt_format);

            if (format < 0)
                goto err;
            EC_GROUP_set_point_conversion_form(gctx->gen_group, format);
        }
    }

    /* We must always assign a group, no matter what */
    ret = ec_gen_assign_group(ec, gctx->gen_group);

    /* Whether you want it or not, you get a keypair, not just one half */
    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ret = ret && EC_KEY_generate_key(ec);

    if (ret)
        return ec;
err:
    /* Something went wrong, throw the key away */
    EC_KEY_free(ec);
    return NULL;
}
```
**File:** crypto/ec/ec_key.c (L251-315)
```c
static int ec_generate_key(EC_KEY *eckey, int pairwise_test)
{
    int ok = 0;
    BIGNUM *priv_key = NULL;
    const BIGNUM *tmp = NULL;
    BIGNUM *order = NULL;
    EC_POINT *pub_key = NULL;
    const EC_GROUP *group = eckey->group;
    BN_CTX *ctx = BN_CTX_secure_new_ex(eckey->libctx);
    int sm2 = EC_KEY_get_flags(eckey) & EC_FLAG_SM2_RANGE ? 1 : 0;

    if (ctx == NULL)
        goto err;

    if (eckey->priv_key == NULL) {
        priv_key = BN_secure_new();
        if (priv_key == NULL)
            goto err;
    } else
        priv_key = eckey->priv_key;

    /*
     * Steps (1-2): Check domain parameters and security strength.
     * These steps must be done by the user. This would need to be
     * stated in the security policy.
     */

    tmp = EC_GROUP_get0_order(group);
    if (tmp == NULL)
        goto err;

    /*
     * Steps (3-7): priv_key = DRBG_RAND(order_n_bits) (range [1, n-1]).
     * Although this is slightly different from the standard, it is effectively
     * equivalent as it gives an unbiased result ranging from 1..n-1. It is also
     * faster as the standard needs to retry more often. Also doing
     * 1 + rand[0..n-2] would effect the way that tests feed dummy entropy into
     * rand so the simpler backward compatible method has been used here.
     */

    /* range of SM2 private key is [1, n-1) */
    if (sm2) {
        order = BN_new();
        if (order == NULL || !BN_sub(order, tmp, BN_value_one()))
            goto err;
    } else {
        order = BN_dup(tmp);
        if (order == NULL)
            goto err;
    }

    do
        if (!BN_priv_rand_range_ex(priv_key, order, 0, ctx))
            goto err;
    while (BN_is_zero(priv_key)) ;

    if (eckey->pub_key == NULL) {
        pub_key = EC_POINT_new(group);
        if (pub_key == NULL)
            goto err;
    } else
        pub_key = eckey->pub_key;

    /* Step (8) : pub_key = priv_key * G (where G is a point on the curve) */
    if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
```
**File:** crypto/sm2/sm2_key.c (L22-51)
```c
int ossl_sm2_key_private_check(const EC_KEY *eckey)
{
    int ret = 0;
    BIGNUM *max = NULL;
    const EC_GROUP *group = NULL;
    const BIGNUM *priv_key = NULL, *order = NULL;

    if (eckey == NULL
            || (group = EC_KEY_get0_group(eckey)) == NULL
            || (priv_key = EC_KEY_get0_private_key(eckey)) == NULL
            || (order = EC_GROUP_get0_order(group)) == NULL ) {
        ERR_raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /* range of SM2 private key is [1, n-1) */
    max = BN_dup(order);
    if (max == NULL || !BN_sub_word(max, 1))
        goto end;
    if (BN_cmp(priv_key, BN_value_one()) < 0
        || BN_cmp(priv_key, max) >= 0) {
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_PRIVATE_KEY);
        goto end;
    }
    ret = 1;

 end:
    BN_free(max);
    return ret;
}
```
**File:** providers/implementations/asymciphers/sm2_enc.c (L71-99)
```c
static const EVP_MD *sm2_get_md(PROV_SM2_CTX *psm2ctx)
{
    const EVP_MD *md = ossl_prov_digest_md(&psm2ctx->md);

    if (md == NULL)
        md = ossl_prov_digest_fetch(&psm2ctx->md, psm2ctx->libctx, "SM3", NULL);

    return md;
}

static int sm2_asym_encrypt(void *vpsm2ctx, unsigned char *out, size_t *outlen,
                            size_t outsize, const unsigned char *in,
                            size_t inlen)
{
    PROV_SM2_CTX *psm2ctx = (PROV_SM2_CTX *)vpsm2ctx;
    const EVP_MD *md = sm2_get_md(psm2ctx);

    if (md == NULL)
        return 0;

    if (out == NULL) {
        if (!ossl_sm2_ciphertext_size(psm2ctx->key, md, inlen, outlen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
            return 0;
        }
        return 1;
    }

    return ossl_sm2_encrypt(psm2ctx->key, md, in, inlen, out, outlen);
```
**File:** crypto/sm2/sm2_crypt.c (L31-43)
```c
struct SM2_Ciphertext_st {
    BIGNUM *C1x;
    BIGNUM *C1y;
    ASN1_OCTET_STRING *C3;
    ASN1_OCTET_STRING *C2;
};

ASN1_SEQUENCE(SM2_Ciphertext) = {
    ASN1_SIMPLE(SM2_Ciphertext, C1x, BIGNUM),
    ASN1_SIMPLE(SM2_Ciphertext, C1y, BIGNUM),
    ASN1_SIMPLE(SM2_Ciphertext, C3, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SM2_Ciphertext, C2, ASN1_OCTET_STRING),
} static_ASN1_SEQUENCE_END(SM2_Ciphertext)
```
**File:** crypto/sm2/sm2_crypt.c (L95-255)
```c
int ossl_sm2_encrypt(const EC_KEY *key,
                     const EVP_MD *digest,
                     const uint8_t *msg, size_t msg_len,
                     uint8_t *ciphertext_buf, size_t *ciphertext_len)
{
    int rc = 0, ciphertext_leni;
    size_t i;
    BN_CTX *ctx = NULL;
    BIGNUM *k = NULL;
    BIGNUM *x1 = NULL;
    BIGNUM *y1 = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    struct SM2_Ciphertext_st ctext_struct;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    const EC_POINT *P = EC_KEY_get0_public_key(key);
    EC_POINT *kG = NULL;
    EC_POINT *kP = NULL;
    uint8_t *msg_mask = NULL;
    uint8_t *x2y2 = NULL;
    uint8_t *C3 = NULL;
    size_t field_size;
    const int C3_size = EVP_MD_get_size(digest);
    EVP_MD *fetched_digest = NULL;
    OSSL_LIB_CTX *libctx = ossl_ec_key_get_libctx(key);
    const char *propq = ossl_ec_key_get0_propq(key);

    /* NULL these before any "goto done" */
    ctext_struct.C2 = NULL;
    ctext_struct.C3 = NULL;

    if (hash == NULL || C3_size <= 0) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    field_size = ec_field_size(group);
    if (field_size == 0) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    kG = EC_POINT_new(group);
    kP = EC_POINT_new(group);
    ctx = BN_CTX_new_ex(libctx);
    if (kG == NULL || kP == NULL || ctx == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    k = BN_CTX_get(ctx);
    x1 = BN_CTX_get(ctx);
    x2 = BN_CTX_get(ctx);
    y1 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    x2y2 = OPENSSL_zalloc(2 * field_size);
    C3 = OPENSSL_zalloc(C3_size);

    if (x2y2 == NULL || C3 == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    memset(ciphertext_buf, 0, *ciphertext_len);

    if (!BN_priv_rand_range_ex(k, order, 0, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    if (!EC_POINT_mul(group, kG, k, NULL, NULL, ctx)
            || !EC_POINT_get_affine_coordinates(group, kG, x1, y1, ctx)
            || !EC_POINT_mul(group, kP, NULL, P, k, ctx)
            || !EC_POINT_get_affine_coordinates(group, kP, x2, y2, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto done;
    }

    if (BN_bn2binpad(x2, x2y2, field_size) < 0
            || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    msg_mask = OPENSSL_zalloc(msg_len);
    if (msg_mask == NULL) {
       ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
       goto done;
   }

    /* X9.63 with no salt happens to match the KDF used in SM2 */
    if (!ossl_ecdh_kdf_X9_63(msg_mask, msg_len, x2y2, 2 * field_size, NULL, 0,
                             digest, libctx, propq)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto done;
    }

    for (i = 0; i != msg_len; ++i)
        msg_mask[i] ^= msg[i];

    fetched_digest = EVP_MD_fetch(libctx, EVP_MD_get0_name(digest), propq);
    if (fetched_digest == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }
    if (EVP_DigestInit(hash, fetched_digest) == 0
            || EVP_DigestUpdate(hash, x2y2, field_size) == 0
            || EVP_DigestUpdate(hash, msg, msg_len) == 0
            || EVP_DigestUpdate(hash, x2y2 + field_size, field_size) == 0
            || EVP_DigestFinal(hash, C3, NULL) == 0) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto done;
    }

    ctext_struct.C1x = x1;
    ctext_struct.C1y = y1;
    ctext_struct.C3 = ASN1_OCTET_STRING_new();
    ctext_struct.C2 = ASN1_OCTET_STRING_new();

    if (ctext_struct.C3 == NULL || ctext_struct.C2 == NULL) {
       ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
       goto done;
    }
    if (!ASN1_OCTET_STRING_set(ctext_struct.C3, C3, C3_size)
            || !ASN1_OCTET_STRING_set(ctext_struct.C2, msg_mask, msg_len)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    ciphertext_leni = i2d_SM2_Ciphertext(&ctext_struct, &ciphertext_buf);
    /* Ensure cast to size_t is safe */
    if (ciphertext_leni < 0) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }
    *ciphertext_len = (size_t)ciphertext_leni;

    rc = 1;

 done:
    EVP_MD_free(fetched_digest);
    ASN1_OCTET_STRING_free(ctext_struct.C2);
    ASN1_OCTET_STRING_free(ctext_struct.C3);
    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    OPENSSL_free(C3);
    EVP_MD_CTX_free(hash);
    BN_CTX_free(ctx);
    EC_POINT_free(kG);
    EC_POINT_free(kP);
    return rc;
}
```
**File:** crypto/sm2/sm2_crypt.c (L257-393)
```c
int ossl_sm2_decrypt(const EC_KEY *key,
                     const EVP_MD *digest,
                     const uint8_t *ciphertext, size_t ciphertext_len,
                     uint8_t *ptext_buf, size_t *ptext_len)
{
    int rc = 0;
    int i;
    BN_CTX *ctx = NULL;
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *C1 = NULL;
    struct SM2_Ciphertext_st *sm2_ctext = NULL;
    BIGNUM *x2 = NULL;
    BIGNUM *y2 = NULL;
    uint8_t *x2y2 = NULL;
    uint8_t *computed_C3 = NULL;
    const size_t field_size = ec_field_size(group);
    const int hash_size = EVP_MD_get_size(digest);
    uint8_t *msg_mask = NULL;
    const uint8_t *C2 = NULL;
    const uint8_t *C3 = NULL;
    int msg_len = 0;
    EVP_MD_CTX *hash = NULL;
    OSSL_LIB_CTX *libctx = ossl_ec_key_get_libctx(key);
    const char *propq = ossl_ec_key_get0_propq(key);

    if (field_size == 0 || hash_size <= 0)
       goto done;

    memset(ptext_buf, 0xFF, *ptext_len);

    sm2_ctext = d2i_SM2_Ciphertext(NULL, &ciphertext, ciphertext_len);

    if (sm2_ctext == NULL) {
        ERR_raise(ERR_LIB_SM2, SM2_R_ASN1_ERROR);
        goto done;
    }

    if (sm2_ctext->C3->length != hash_size) {
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_ENCODING);
        goto done;
    }

    C2 = sm2_ctext->C2->data;
    C3 = sm2_ctext->C3->data;
    msg_len = sm2_ctext->C2->length;
    if (*ptext_len < (size_t)msg_len) {
        ERR_raise(ERR_LIB_SM2, SM2_R_BUFFER_TOO_SMALL);
        goto done;
    }

    ctx = BN_CTX_new_ex(libctx);
    if (ctx == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    BN_CTX_start(ctx);
    x2 = BN_CTX_get(ctx);
    y2 = BN_CTX_get(ctx);

    if (y2 == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_BN_LIB);
        goto done;
    }

    msg_mask = OPENSSL_zalloc(msg_len);
    x2y2 = OPENSSL_zalloc(2 * field_size);
    computed_C3 = OPENSSL_zalloc(hash_size);

    if (msg_mask == NULL || x2y2 == NULL || computed_C3 == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    C1 = EC_POINT_new(group);
    if (C1 == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!EC_POINT_set_affine_coordinates(group, C1, sm2_ctext->C1x,
                                         sm2_ctext->C1y, ctx)
            || !EC_POINT_mul(group, C1, NULL, C1, EC_KEY_get0_private_key(key),
                             ctx)
            || !EC_POINT_get_affine_coordinates(group, C1, x2, y2, ctx)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EC_LIB);
        goto done;
    }

    if (BN_bn2binpad(x2, x2y2, field_size) < 0
            || BN_bn2binpad(y2, x2y2 + field_size, field_size) < 0
            || !ossl_ecdh_kdf_X9_63(msg_mask, msg_len, x2y2, 2 * field_size,
                                    NULL, 0, digest, libctx, propq)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_INTERNAL_ERROR);
        goto done;
    }

    for (i = 0; i != msg_len; ++i)
        ptext_buf[i] = C2[i] ^ msg_mask[i];

    hash = EVP_MD_CTX_new();
    if (hash == NULL) {
        ERR_raise(ERR_LIB_SM2, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    if (!EVP_DigestInit(hash, digest)
            || !EVP_DigestUpdate(hash, x2y2, field_size)
            || !EVP_DigestUpdate(hash, ptext_buf, msg_len)
            || !EVP_DigestUpdate(hash, x2y2 + field_size, field_size)
            || !EVP_DigestFinal(hash, computed_C3, NULL)) {
        ERR_raise(ERR_LIB_SM2, ERR_R_EVP_LIB);
        goto done;
    }

    if (CRYPTO_memcmp(computed_C3, C3, hash_size) != 0) {
        ERR_raise(ERR_LIB_SM2, SM2_R_INVALID_DIGEST);
        goto done;
    }

    rc = 1;
    *ptext_len = msg_len;

 done:
    if (rc == 0)
        memset(ptext_buf, 0, *ptext_len);

    OPENSSL_free(msg_mask);
    OPENSSL_free(x2y2);
    OPENSSL_free(computed_C3);
    EC_POINT_free(C1);
    BN_CTX_free(ctx);
    SM2_Ciphertext_free(sm2_ctext);
    EVP_MD_CTX_free(hash);

    return rc;
}
```