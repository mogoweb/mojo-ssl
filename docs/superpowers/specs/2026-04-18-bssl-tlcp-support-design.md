# bssl命令行工具TLCP协议支持设计

**Date:** 2026-04-18
**Status:** Draft
**Scope:** 为bssl client和server命令添加TLCP协议支持

## Overview

为bssl命令行工具添加TLCP (Transport Layer Cryptography Protocol, GB/T 38636-2020) 协议支持，使其能够作为TLCP客户端和服务器进行通信，支持ECC_SM2_SM4_CBC_SM3密码套件。

## 目标

- bssl client和server都支持TLCP协议
- 支持ECC_SM2_SM4_CBC_SM3密码套件
- 支持TLCP双证书机制（签名证书+加密证书）
- 采用测试驱动开发（TDD）流程

## 功能设计

### 1. 命令行参数

#### 新增参数（client和server）

| 参数 | 类型 | 描述 |
|------|------|------|
| `-tlcp` | Boolean | 启用TLCP模式 |
| `-tlcp-sign-cert <file>` | Required (当使用-tlcp) | TLCP签名证书（PEM格式） |
| `-tlcp-sign-key <file>` | Required (当使用-tlcp) | TLCP签名私钥（PEM格式） |
| `-tlcp-enc-cert <file>` | Required (当使用-tlcp) | TLCP加密证书（PEM格式） |
| `-tlcp-enc-key <file>` | Required (当使用-tlcp) | TLCP加密私钥（PEM格式） |

#### 密码套件行为

- 当使用`-tlcp`时，默认密码套件为`ECC-SM2-SM4-CBC-SM3`
- 可通过`-cipher`参数覆盖默认值
- 如果使用`-tlcp`但未指定`-cipher`，则使用默认密码套件

#### 版本参数

- 使用`-tlcp`时会自动设置协议版本为TLCP
- `-min-version`和`-max-version`可以设置为"tlcp"

### 2. 使用示例

#### 客户端连接

```bash
bssl client -tlcp \
  -tlcp-enc-cert client_enc.pem \
  -tlcp-enc-key client_enc.key \
  -connect localhost:8443
```

#### 服务器监听

```bash
bssl server -tlcp \
  -tlcp-sign-cert server_sign.pem \
  -tlcp-sign-key server_sign.key \
  -tlcp-enc-cert server_enc.pem \
  -tlcp-enc-key server_enc.key \
  -accept 8443
```

#### 指定密码套件

```bash
bssl client -tlcp \
  -tlcp-enc-cert client_enc.pem \
  -tlcp-enc-key client_enc.key \
  -cipher ECC-SM2-SM4-CBC-SM3 \
  -connect localhost:8443
```

### 3. 参数验证规则

1. **TLCP标志一致性检查：**
   - 如果指定了任何`-tlcp-*`参数，必须也指定`-tlcp`标志
   - 如果指定了`-tlcp`标志，必须指定所有TLCP证书和密钥参数

2. **证书文件验证：**
   - 签名证书和密钥必须匹配（验证签名）
   - 加密证书和密钥必须匹配
   - 签名证书必须具有digitalSignature key usage
   - 加密证书必须具有keyEncipherment key usage

3. **密码套件验证：**
   - 如果使用`-tlcp`，密码套件必须是TLCP密码套件
   - 默认密码套件为`ECC-SM2-SM4-CBC-SM3`

## 实现位置

### 修改文件

1. **tool/client.cc**
   - 添加TLCP参数定义
   - 添加TLCP参数解析逻辑
   - 添加TLCP SSL_CTX配置
   - 添加参数验证

2. **tool/server.cc**
   - 添加TLCP参数定义
   - 添加TLCP参数解析逻辑
   - 添加TLCP SSL_CTX配置
   - 添加参数验证

3. **tool/transport_common.cc**
   - 扩展`VersionFromString()`函数支持"tlcp"字符串

### 新增文件

1. **tool/test/client_test.cc** - bssl client参数解析单元测试
2. **tool/test/server_test.cc** - bssl server参数解析单元测试
3. **tool/test/bssl_tlcp_test.cc** - TLCP集成测试

## 组件设计

### TLCP参数结构

```cpp
struct TLCPConfig {
  bool enabled = false;
  std::string sign_cert_file;
  std::string sign_key_file;
  std::string enc_cert_file;
  std::string enc_key_file;
  std::string cipher_suite = "ECC-SM2-SM4-CBC-SM3";
};
```

### 参数验证函数

```cpp
bool ValidateTLCPConfig(const TLCPConfig &config, std::string *error_msg);
```

### SSL_CTX配置函数

```cpp
bool ConfigureTLCPContext(SSL_CTX *ctx, const TLCPConfig &config);
```

## 错误处理

### 错误消息

| 错误场景 | 错误消息 |
|----------|----------|
| 缺少-tlcp标志但指定了TLCP参数 | "TLCP parameters require -tlcp flag" |
| 使用-tlcp但缺少签名证书 | "-tlcp-sign-cert is required when using -tlcp" |
| 使用-tlcp但缺少签名密钥 | "-tlcp-sign-key is required when using -tlcp" |
| 使用-tlcp但缺少加密证书 | "-tlcp-enc-cert is required when using -tlcp" |
| 使用-tlcp但缺少加密密钥 | "-tlcp-enc-key is required when using -tlcp" |
| 证书文件不存在 | "Failed to load TLCP certificate: <file>" |
| 密钥文件不存在 | "Failed to load TLCP key: <file>" |
| 证书和密钥不匹配 | "TLCP certificate and key do not match" |

## 测试策略

### 1. 单元测试

#### 参数解析测试（client_test.cc, server_test.cc）

- 测试`-tlcp`标志解析
- 测试`-tlcp-sign-cert`参数解析
- 测试`-tlcp-sign-key`参数解析
- 测试`-tlcp-enc-cert`参数解析
- 测试`-tlcp-enc-key`参数解析
- 测试参数组合（有效/无效）
- 测试参数验证逻辑
- 测试错误消息输出

#### SSL_CTX配置测试（bssl_tlcp_test.cc）

- 测试TLCP方法选择
- 测试密码套件设置
- 测试双证书加载
- 测试版本设置

### 2. 集成测试

#### 基本握手测试（bssl_tlcp_test.cc）

```cpp
TEST(BSSLLCPTest, ClientServerHandshake) {
  // 启动bssl server with TLCP
  // 使用bssl client with TLCP连接
  // 验证握手成功
}
```

#### 数据传输测试（bssl_tlcp_test.cc）

```cpp
TEST(BSSLLCPTest, DataTransfer) {
  // 建立TLCP连接
  // 发送测试数据
  // 验证数据传输正确
}
```

#### 错误处理测试（bssl_tlcp_test.cc）

- 缺少必需证书
- 证书和密钥不匹配
- 无效的密码套件
- 证书验证失败

## 与现有代码的集成

### 1. 参数解析集成

- 将TLCP参数添加到现有的`kArguments`数组中
- 在`ParseKeyValueArguments`之后添加TLCP参数验证

### 2. SSL_CTX配置集成

- 在创建`SSL_CTX`之后，根据配置选择方法：
  - TLCP模式：`SSL_CTX_new(TLCP_client_method())`或`SSL_CTX_new(TLCP_server_method())`
  - TLS模式：`SSL_CTX_new(TLS_method())`

### 3. 证书加载集成

- 使用新增的TLCP专用API加载双证书：
  - `SSL_CTX_use_tlcp_sign_certificate()`
  - `SSL_CTX_use_tlcp_enc_certificate()`

## 测试证书准备

为了测试，需要准备以下证书文件：

1. **服务器签名证书和密钥** (`server_sign.pem`, `server_sign.key`)
2. **服务器加密证书和密钥** (`server_enc.pem`, `server_enc.key`)
3. **客户端加密证书和密钥** (`client_enc.pem`, `client_enc.key`)

这些证书可以使用工具目录中的SM2工具生成。

## 性能考虑

- TLCP参数解析和验证与现有TLS参数处理性能相当
- TLCP SSL_CTX配置使用已有的TLCP API，性能与TLS配置一致
- 不引入额外的运行时开销

## 安全考虑

1. **证书验证：**
   - 验证签名证书和密钥匹配
   - 验证加密证书和密钥匹配
   - 验证证书的key usage扩展

2. **密钥安全：**
   - 私钥文件使用PEM格式，与现有TLS证书保持一致
   - 不在内存中持久化私钥

3. **协议安全：**
   - 使用TLCP标准实现，不降低安全级别
   - 支持所有TLCP标准密码套件

## 兼容性考虑

1. **向后兼容：**
   - 不影响现有TLS功能
   - TLCP功能仅在指定`-tlcp`标志时启用

2. **跨平台：**
   - 参数解析使用标准C++库
   - SSL_CTX配置使用跨平台API

3. **与Tongsuo互操作：**
   - 使用相同的TLCP协议版本
   - 使用相同的密码套件标识
   - 使用相同的双证书机制

## 未来扩展

1. **支持的密码套件扩展：**
   - ECC_SM2_SM4_GCM_SM3

2. **客户端认证：**
   - 支持TLCP客户端证书

3. **会话恢复：**
   - 支持TLCP会话票证

4. **更多测试：**
   - 与Tongsuo的互操作性测试
   - 性能测试

## 实现约束

1. **仅实现核心功能：**
   - 支持ECC_SM2_SM4_CBC_SM3密码套件
   - 支持双证书机制
   - 支持基本握手和数据传输

2. **不实现：**
   - ECC_SM2_SM4_GCM_SM3密码套件
   - 客户端认证
   - 会话恢复
   - 其他TLCP密码套件

## 参考资料

- TLCP头文件：`include/openssl/tlcp.h`
- TLCP实现：`ssl/tlcp_*.cc`
- bssl工具：`tool/client.cc`, `tool/server.cc`
- 参数解析：`tool/args.cc`
- TLCP协议设计：`docs/tongsuo/tlcp.md`
