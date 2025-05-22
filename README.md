# MojoSSL

MojoSSL 是一个支持国家商用密码算法的 SSL 库，基于 BoringSSL 开发，可用于开发支持国密的浏览器。如果希望使用支持国密的浏览器，请参考我的另外一个项目：[Mojo Browser](https://github.com/mogoweb/mojo-browser)。

MojoSSL 支持国密算法 SM2、SM3、SM4。同时支持 TLCP 协议。国密算法移植自[铜锁](https://tongsuo.net)，对称加密算法 SM4 目前只实现了 CBC 分组模式，国密密码套件实现了 ECC_SM4_CBC_SM3 和 ECDHE_SM4_CBC_SM3 两种。

