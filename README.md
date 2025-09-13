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
$ build/bssl s_client -ntls -connect sm2only.ovssl.cn:443 -server-name sm2only.ovssl.cn -cipher ECC_SM4_CBC_SM3
Connecting to 61.172.183.11:443
cert_num: 4
found encrypt cert
Connected.
  Version: NTLS
  Resumed session: no
  Cipher: ECC_SM4_CBC_SM3
  Secure renegotiation: yes
  Extended master secret: no
  Next protocol negotiated: 
  ALPN protocol: 
  OCSP staple: no
  SCT list: no
  Early data: no
  Encrypted ClientHello: no
  Cert subject: C = CN, ST = \E5\B9\BF\E4\B8\9C\E7\9C\81, L = \E6\B7\B1\E5\9C\B3\E5\B8\82, O = \E6\B2\83\E9\80\9A\E7\94\B5\E5\AD\90\E8\AE\A4\E8\AF\81\E6\9C\8D\E5\8A\A1\E6\9C\89\E9\99\90\E5\85\AC\E5\8F\B8, CN = sm2only.ovssl.cn
  Cert issuer: C = CN, O = \E6\B2\83\E9\80\9A\E7\94\B5\E5\AD\90\E8\AE\A4\E8\AF\81\E6\9C\8D\E5\8A\A1\E6\9C\89\E9\99\90\E5\85\AC\E5\8F\B8, CN = \E5\9B\BD\E5\AF\86SM2\E6\9C\8D\E5\8A\A1\E5\99\A8\E6\A0\B9\E8\AF\81\E4\B9\A6V3
```

**注意:** 
- 上述命令假设您的 `bssl` 工具位于 `build/bssl`。如果路径不同，请相应调整。
- `-ntls` 参数表示使用 TLCP 协议。
- `-cipher ECC_SM4_CBC_SM3` 指定了密码套件。

如果接着输 HTTP 交互命令，可以像浏览器一样，获取服务器端的页面，比如：

```
GET / HTTP/1.1
Host: sm2only.ovssl.cn
Connection: close

```
最后要多敲一个空行（也就是输入两次回车），表示 HTTP 头部结束。

可以得到如下回应：

```html
HTTP/1.1 200 OK
Server: nginx/1.24.0
Date: Sat, 13 Sep 2025 02:32:11 GMT
Content-Type: text/html
Content-Length: 1947
Last-Modified: Fri, 18 Jul 2025 09:23:06 GMT
Connection: close
ETag: "687a127a-79b"
Guomissl: type=2
Accept-Ranges: bytes

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<!-- InstanceBegin template="/Templates/theme.dwt" codeOutsideHTMLIsLocked="false" -->

<head>
	<!-- InstanceBeginEditable name="title" -->
	<title>欢迎访问沃通基于国密算法的https加密解决方案演示网站</title>
	<meta name="keywords" content="欢迎访问沃通基于国密算法的https加密解决方案演示网站" />
	<meta name="description" content="欢迎访问沃通基于国密算法的https加密解决方案演示网站" />
	<!-- InstanceEndEditable -->
	<meta name="viewport" content="width=device-width,height=device-height,initial-scale=1.0" />
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<meta name="applicable-device" content="pc,mobile" />
	<meta http-equiv="Cache-Control" content="no-transform" />
	<meta http-equiv="Cache-Control" content="no-siteapp" />
	<meta http-equiv="Content-Language" content="zh-cn" />
	<meta content="telephone=yes" name="format-detection" />
	<meta content="email=no" name="format-detection" />
	<link href="images/favicon.ico" rel="shortcut icon" />
	<link rel="stylesheet" href="style.css">
	<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1" />
</head>
<body>
	<div class="gm_top">
		<div class="gm_logo gm_990">
			<img src="images/logo.jpg">
		</div>
	</div>
	<div class="gm_main">
		<div class="bri bri_01"></div>
		<div class="bri bri_02"></div>
		<div class="bri bri_03"></div>
		<div class="gm_banner">
			
		</div>
		<div class="gm_con gm_990">
			<p>本演示网站基于国产密码算法和相关协议搭建的Web站点，采用SM2单证书模式，支持SM2证书和国密套件进行https SSL加密通信。</p>
		</div>
		<div class="gm_footer gm_990">
			<a href="https://www.miitbeian.gov.cn/">粤ICP备15002424号-15</a>
		</div>
	</div>
</body>
</html>
```
和使用国密浏览器得到的页面一样。

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
