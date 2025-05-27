# MojoSSL

MojoSSL 是一个支持国家商用密码算法的 SSL 库，基于 BoringSSL 开发，可用于开发支持国密的浏览器。如果希望使用支持国密的浏览器，请访问我的另外一个项目：[Mojo Browser](https://github.com/mogoweb/mojo-browser)。

## 特性 (Features)
- 支持 SM2、SM3、SM4 国家商用密码算法
- 支持 TLCP 协议
- 基于 BoringSSL 开发，保持与 BoringSSL 的兼容性
- 移植自铜锁 (Tongsuo) 项目的国密算法实现
- SM4 对称加密算法当前支持 CBC 分组模式
- 支持国密密码套件 ECC_SM4_CBC_SM3 和 ECDHE_SM4_CBC_SM3

## 构建 MojoSSL (Building MojoSSL)

### 依赖安装 (Prerequisites)
在开始构建之前，请确保您已安装以下依赖：
```bash
sudo apt install cmake ninja-build clang
```

### 构建步骤 (Build Steps)
1. 克隆 MojoSSL 仓库（如果尚未克隆）：
   ```bash
   git clone https://github.com/mogoweb/mojo-ssl.git
   # 进入克隆的 mojo-ssl 目录
   cd mojo-ssl
   ```
2. 执行构建命令：
   ```bash
   # 假设您当前位于项目根目录 (mojo-ssl/)
   cmake -GNinja -B build
   ninja -C build
   ```
3. 构建完成后，编译出来的可执行程序和库文件位于 `build` 目录。
4. MojoSSL (基于 BoringSSL) 也提供了一个命令行工具 `bssl`，构建成功后通常位于 `build/bssl`。

## 使用方法 (Usage)

构建成功后，可以使用 `bssl` 命令行工具测试与支持国密算法的服务器进行通信。例如，访问沃通 (WoSign) 提供的国密测试站点：

```bash
build/bssl s_client -ntls -connect sm2only.ovssl.cn:443 -server-name sm2only.ovssl.cn -cipher ECC_SM4_CBC_SM3
```

**注意:** 
- 上述命令假设您的 `bssl` 工具位于 `build/bssl`。如果路径不同，请相应调整。
- `-ntls` 参数表示使用 TLCP 协议。
- `-cipher ECC_SM4_CBC_SM3` 指定了密码套件。

## 贡献 (Contributing)
我们欢迎社区的贡献！如果你发现任何 bug、有功能建议或希望改进代码，请遵循以下步骤：
1. Fork 本仓库。
2. 创建一个新的分支 (git checkout -b feature/your-feature-name)。
3. 提交你的修改 (git commit -am 'Add some feature')。
4. 推送到你的分支 (git push origin feature/your-feature-name)。
5. 创建一个新的 Pull Request。

请确保你的代码符合项目的编码风格，并提供清晰的提交信息。

## 许可证 (License)
本项目基于 BoringSSL 开发，因此 MojoSSL 的许可证与 BoringSSL 保持一致，采用 OpenSSL 风格的许可证。
国密算法部分的实现移植自铜锁项目，其许可证信息请参考铜锁项目的官方说明。
请查看项目中的 `LICENSE` 文件（如果存在）获取详细信息。如果 `LICENSE` 文件缺失，后续会补充。
