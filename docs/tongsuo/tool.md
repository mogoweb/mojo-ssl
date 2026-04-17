# 命令行工具的用法

## SM2 签名和验证签名

Tongsuo 的命令行工具通过多个子命令支持 SM2 签名和验证签名。

### 支持的命令

#### 1. `openssl pkeyutl`

用于直接对数据进行 SM2 签名和验证：

```bash
# 签名
openssl pkeyutl -sign -inkey sm2.key -in data.bin -out sig.bin \
    -rawin -digest sm3 -pkeyopt distid:1234567812345678

# 验证
openssl pkeyutl -verify -pubin -inkey sm2pub.key \
    -in data.bin -sigfile sig.bin \
    -rawin -digest sm3 -pkeyopt distid:1234567812345678
```

#### 2. `openssl dgst`

用于摘要+签名/验证：

```bash
# 签名
openssl dgst -sm3 -sign sm2.key -out sig.bin data.bin

# 验证
openssl dgst -sm3 -verify sm2pub.key -signature sig.bin data.bin
```

测试文件中有对应的 SM2 + SM3 签名验证用例。 [1](#0-0) 

#### 3. `openssl req` / `openssl ca`

用于证书请求和签发，支持 `-sigopt` 和 `-vfyopt` 指定 SM2 的 distinguishing identifier（`distid`）：

```bash
# 生成 SM2 密钥
openssl ecparam -genkey -name SM2 -out sm2.key

# 生成 CSR（签名时指定 distid）
openssl req -new -key sm2.key -out sm2.csr \
    -sm3 -sigopt distid:1234567812345678

# 签发证书（验证时指定 distid）
openssl ca -in sm2.csr -md sm3 \
    -vfyopt distid:1234567812345678 ...
``` [2](#0-1) 

### SM2 ID（distid）选项

SM2 签名需要一个用户标识符（distinguishing identifier）。Tongsuo 在 CLI 中支持以下几种写法，均等价：

| 选项写法 | 说明 |
|---|---|
| `distid:<value>` | 标准写法 |
| `hexdistid:<hex>` | 十六进制写法 |
| `sm2_id:<value>` | 兼容写法（自动转换为 `distid:`） |
| `sm2_hex_id:<hex>` | 兼容写法（自动转换为 `hexdistid:`） | [3](#0-2) [4](#0-3) 

底层实现在 `crypto/sm2/sm2_sign.c` 中，核心函数为 `ossl_sm2_do_sign` 和 `ossl_sm2_do_verify`。 [5](#0-4)

#### Citations

**File:** test/recipes/20-test_cli_smtc.t (L81-95)
```text
    ok(run(app(['openssl', 'dgst', $md,
                '-sign', $smtc_key,
                '-out', $sigfile,
                $tbs_data])),
       $testtext);

    $testtext = $prefix.': '.
        'Verify something with a SMTC key';
    ok(run(app(['openssl', 'dgst', $md,
                '-verify', $smtc_pub_key,
                '-signature', $sigfile,
                $tbs_data])),
       $testtext);
}

```

**File:** test/recipes/80-test_sign_sm2.t (L63-79)
```text
ok(run(app(["openssl", "req",
    "-config", data_file("ca.cnf"),
    "-new", "-key", catfile(".", $test_name, "ca.key"),
    "-out", catfile(".", $test_name, "ca.csr"),
    "-sm3", "-nodes", "-sigopt", "distid:1234567812345678",
    "-subj", "/C=AA/ST=BB/O=CC/OU=DD/CN=root ca"])));

ok(run(app(["openssl", "ca",
    "-selfsign", "-config", data_file("ca.cnf"),
    "-in", catfile(".", $test_name, "ca.csr"),
    "-keyfile", catfile(".", $test_name, "ca.key"),
    "-extensions", "v3_ca",
    "-days", "365",
    "-notext", "-out", catfile(".", $test_name, "ca.crt"),
    "-md", "sm3",
    "-vfyopt", "distid:1234567812345678",
    "-batch"])));
```

**File:** apps/include/apps.h (L346-354)
```text
/* for SM2 compatibility usage */
#define DISTID           "distid:"
#define DISTID_LEN       (sizeof("distid:") - 1)
#define HEXDISTID        "hexdistid:"
#define HEXDISTID_LEN    (sizeof("hexdistid:") - 1)
#define SM2ID            "sm2_id:"
#define SM2ID_LEN        (sizeof("sm2_id:") - 1)
#define SM2HEXID         "sm2_hex_id:"
#define SM2HEXID_LEN     (sizeof("sm2_hex_id:") - 1)
```

**File:** apps/lib/apps.c (L3319-3348)
```c
int build_sigopt_compat_string(char **ret, const char *value)
{
    int prefix_len = 0;
    int new_prefix_len = 0;
    char *new_prefix = NULL;
    char *tmp = NULL;

    if (!strncmp(value, SM2ID, SM2ID_LEN)) {
        prefix_len = SM2ID_LEN;
        new_prefix = DISTID;
        new_prefix_len = DISTID_LEN;
    } else if (!strncmp(value, SM2HEXID, SM2HEXID_LEN)) {
        prefix_len = SM2HEXID_LEN;
        new_prefix = HEXDISTID;
        new_prefix_len = HEXDISTID_LEN;
    } else {
        /* pattern not found */
        return -1;
    }

    tmp = OPENSSL_zalloc(new_prefix_len + strlen(value) - prefix_len + 1);
    if (tmp == NULL)
        return 0;

    memcpy(tmp, new_prefix, new_prefix_len);
    memcpy(tmp + new_prefix_len, value + prefix_len,
           strlen(value) - prefix_len);
    *ret = tmp;

    return 1;
```

**File:** crypto/sm2/sm2_sign.c (L396-439)
```c
ECDSA_SIG *ossl_sm2_do_sign(const EC_KEY *key,
                            const EVP_MD *digest,
                            const uint8_t *id,
                            const size_t id_len,
                            const uint8_t *msg, size_t msg_len)
{
    BIGNUM *e = NULL;
    ECDSA_SIG *sig = NULL;

    e = sm2_compute_msg_hash(digest, key, id, id_len, msg, msg_len);
    if (e == NULL) {
        /* SM2err already called */
        goto done;
    }

    sig = sm2_sig_gen(key, e);

 done:
    BN_free(e);
    return sig;
}

int ossl_sm2_do_verify(const EC_KEY *key,
                       const EVP_MD *digest,
                       const ECDSA_SIG *sig,
                       const uint8_t *id,
                       const size_t id_len,
                       const uint8_t *msg, size_t msg_len)
{
    BIGNUM *e = NULL;
    int ret = 0;

    e = sm2_compute_msg_hash(digest, key, id, id_len, msg, msg_len);
    if (e == NULL) {
        /* SM2err already called */
        goto done;
    }

    ret = sm2_sig_verify(key, sig, e);

 done:
    BN_free(e);
    return ret;
}
```

## 从私钥导出公钥

有两种命令可以从私钥生成公钥，适用于 SM2（EC 类型）密钥：

### 方法一：`openssl ec`（EC 专用命令）

```bash
openssl ec -in sm2.key -pubout -out sm2pub.pem
```

测试代码中有对应示例： [1](#1-0) 

`-pubout` 选项告诉 `ec` 子命令只输出公钥部分。 [2](#1-1) 

### 方法二：`openssl pkey`（通用密钥命令）

```bash
openssl pkey -in sm2.key -pubout -out sm2pub.pem
```

`pkey` 是更通用的命令，同样支持 `-pubout` 选项。 [3](#1-2) 

### 完整流程示例（SM2）

```bash
# 1. 生成 SM2 私钥
openssl ecparam -genkey -name SM2 -out sm2.key

# 2. 从私钥提取公钥
openssl ec -in sm2.key -pubout -out sm2pub.pem

# 或者用 pkey 命令
openssl pkey -in sm2.key -pubout -out sm2pub.pem
```

两个命令的区别：`openssl ec` 是 EC 专用命令，`openssl pkey` 是通用命令，对 SM2 密钥两者效果相同。输出的公钥文件为 SubjectPublicKeyInfo 格式（PEM）。 [4](#1-3)

#### Citations

**File:** test/recipes/80-test_app_ec_elgamal.t (L142-143)
```text
ok(run(app(["openssl", "ec",
    "-in", $ec_key_path, "-pubout", "-out", $ec_pub_path])), "generate ec pub key");
```

**File:** apps/ec.c (L56-56)
```c
    {"pubout", OPT_PUBOUT, '-', "Output public key, not private"},
```

**File:** apps/ec.c (L250-253)
```c
        } else if (pubin || pubout) {
            selection = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
                | OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
            output_structure = "SubjectPublicKeyInfo";
```

**File:** apps/pkey.c (L55-55)
```c
    {"pubout", OPT_PUBOUT, '-', "Restrict encoded output to public components"},
```
