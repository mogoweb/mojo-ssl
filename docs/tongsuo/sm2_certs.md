# 制作 SM2 证书

## 第一步：生成 SM2 私钥

```bash
tongsuo ecparam -genkey -name SM2 -out sm2.key
``` [1](#3-0) 

## 第二步：生成证书签名请求（CSR）

```bash
tongsuo req \
    -new -key sm2.key \
    -out sm2.csr \
    -sm3 \
    -nodes \
    -sigopt distid:1234567812345678 \
    -subj "/C=CN/ST=GD/O=MyOrg/CN=myserver"
```

关键参数：
- `-sm3`：使用 SM3 作为哈希算法
- `-sigopt distid:<id>`：SM2 签名所需的用户标识符（Z 值计算用）
- `-nodes`：私钥不加密 [2](#3-1) 

## 第三步A：生成自签名根 CA 证书

```bash
tongsuo ca \
    -selfsign \
    -config ca.cnf \
    -in sm2.csr \
    -keyfile sm2.key \
    -extensions v3_ca \
    -days 365 \
    -notext \
    -out ca.crt \
    -md sm3 \
    -vfyopt distid:1234567812345678 \
    -batch
```

`-vfyopt distid:...` 用于验证 CSR 中的 SM2 签名，值必须与生成 CSR 时的 `distid` 一致。 [3](#3-2) 

## 第三步B：由 CA 签发终端证书

```bash
tongsuo ca \
    -config subca.cnf \
    -in server.csr \
    -cert ca.crt \
    -keyfile ca.key \
    -extensions sign_req \
    -days 365 \
    -notext \
    -out server.crt \
    -md sm3 \
    -vfyopt distid:1234567812345678 \
    -batch
``` [4](#3-3) 

## 注意事项

- `ca.cnf` / `subca.cnf` 是 CA 配置文件，需要提前准备（定义 CA 目录结构、数据库文件等）。
- `distid` 在生成 CSR（`-sigopt`）和签发证书（`-vfyopt`）时必须保持一致，否则签名验证会失败。
- 测试代码中展示了完整的双证书体系（签名证书 + 加密证书），这是国密 TLCP 协议的典型用法。 [5](#3-4)

### Citations

**File:** test/recipes/80-test_sign_sm2.t (L59-61)
```text
ok(run(app(["openssl", "ecparam",
    "-genkey", "-name", "SM2",
    "-out", catfile(".", $test_name, "ca.key")])));
```

**File:** test/recipes/80-test_sign_sm2.t (L63-68)
```text
ok(run(app(["openssl", "req",
    "-config", data_file("ca.cnf"),
    "-new", "-key", catfile(".", $test_name, "ca.key"),
    "-out", catfile(".", $test_name, "ca.csr"),
    "-sm3", "-nodes", "-sigopt", "distid:1234567812345678",
    "-subj", "/C=AA/ST=BB/O=CC/OU=DD/CN=root ca"])));
```

**File:** test/recipes/80-test_sign_sm2.t (L70-79)
```text
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

**File:** test/recipes/80-test_sign_sm2.t (L110-132)
```text
# server sm2 double certs
ok(run(app(["openssl", "ecparam",
    "-genkey", "-name", "SM2",
    "-out", catfile(".", $test_name, "server_sign.key")])));

ok(run(app(["openssl", "req",
    "-config", data_file("subca.cnf"),
    "-key", catfile(".", $test_name, "server_sign.key"),
    "-sm3", "-nodes", "-sigopt", "distid:1234567812345678",
    "-new", "-out", catfile(".", $test_name, "server_sign.csr"),
    "-subj", "/C=AA/ST=BB/O=CC/OU=DD/CN=server sign"])));

ok(run(app(["openssl", "ca",
    "-config", data_file("subca.cnf"),
    "-extensions", "sign_req",
    "-days", "365",
    "-in", catfile(".", $test_name, "server_sign.csr"),
    "-notext", "-out", catfile(".", $test_name, "server_sign.crt"),
    "-cert", catfile(".", $test_name, "subca.crt"),
    "-keyfile", catfile(".", $test_name, "subca.key"),
    "-md", "sm3",
    "-vfyopt", "distid:1234567812345678",
    "-batch"])));
```
