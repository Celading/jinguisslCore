<p align="center">
  <img src="https://img.shields.io/badge/Cangjie-JinguiSSL%20Core-c96b2c?style=for-the-badge&labelColor=1f2430" alt="JinguiSSL Core" />
  <img src="https://img.shields.io/badge/package-static-2f855a?style=for-the-badge&labelColor=1f2430" alt="Static Package" />
  <img src="https://img.shields.io/badge/focus-crypto%20%2B%20protocol-3182ce?style=for-the-badge&labelColor=1f2430" alt="Crypto and Protocol" />
  <img src="https://img.shields.io/badge/license-Apache%202.0-1f9d55?style=for-the-badge&labelColor=1f2430" alt="Apache 2.0" />
</p>
<div align="center">
<span style="font-weight:300;font-size:36px">JinguiSSL Core</span><br/>
<span style="font-weight:100;font-size:24px">JinguiSSL 的算法与协议底层实现</span>
<p align="center">
  <strong>面向需要直接控制密码原语、X.509、TLS 与 SSH 细节的仓颉开发者</strong><br/>
  <sub>AES · ChaCha20-Poly1305 · RSA · ECC · Ed25519 · X25519 · X.509 · TLS · SSH</sub>
</p>
</div>

## 这是什么

`JinguiSSL-core` 是 JinguiSSL 系列的底层仓。

如果 `JinguiSSL-contract` 解决的是“应用层怎么稳定地接入安全能力”，那 `JinguiSSL-core` 解决的就是：

- 算法原语怎么实现
- 证书链、TLS、SSH 等协议细节怎么落地
- 更底层、更直接的密码学 API 如何在仓颉里组织

如果你需要自己掌控协议流、握手细节、密钥派生、record 层或结构化签名校验，这里才是主战场。

## 能力范围

- 对称密码：`AES`、`ChaCha20`、`Poly1305`、`SM4`
- 摘要与派生：`MD5`、`SHA-1`、`SHA-256/384/512`、`HMAC`、`HKDF`
- 非对称密码：`RSA`、`ECC`、`Ed25519`、`X25519`
- 证书与合规：`X.509`、PEM/DER 解析、证书链验证、FIPS profile
- 协议能力：`TLS 1.2`、`TLS 1.3`、`SSH transport / handshake`
- 工具与性能：大数兼容层、性能基准、测试向量与协议流测试

## 快速开始

### 依赖

当前更推荐以 sibling checkout 的方式直接引用。  
公开托管地址与统一文档站后续会再统一收口到独立文档面，因此这里不再保留占位的假 `git` 地址。

```toml
[dependencies]
jinguissl_core = { path = "../JinguiSSL-core" }
```

### 示例：Ed25519 签名与验签

```cangjie
import jinguissl_core.jinguissl.crypto.digest.bytesToHexLower
import jinguissl_core.jinguissl.crypto.ed25519.*

main() {
    let seed = ed25519GeneratePrivateKeySeed()
    let publicKey = ed25519PublicKeyFromSeed(seed)
    let message = "hello jingui".toArray()
    let signature = ed25519Sign(seed, message)

    println(bytesToHexLower(publicKey))
    println(ed25519Verify(publicKey, message, signature))
}
```

## 模块分层

| 模块 | 内容 |
|:--|:--|
| `crypto/aes` | AES block / CTR / GCM 相关实现 |
| `crypto/chacha20` | ChaCha20 / Poly1305 / AEAD |
| `crypto/digest` | Hash、HMAC、HKDF |
| `crypto/rsa` / `crypto/ecc` / `crypto/ed25519` / `crypto/x25519` | 主流非对称能力 |
| `crypto/x509` | 证书、私钥、链验证 |
| `crypto/tls` | TLS handshake、record、session |
| `crypto/ssh` | SSH transport、host verification、KEX |
| `compat/bn` | 大数兼容与基础支持 |

## 什么时候该直接使用 Core

- 你在写 TLS / SSH / PKI 相关中间层或框架
- 你要自己组织 handshake / record / transcript / key schedule
- 你需要原始算法能力，而不是应用层 facade
- 你在写 benchmark、协议实验、兼容层或桥接层

如果你只是想把 TLS / 证书能力接进业务服务，通常更推荐先从 `JinguiSSL-contract` 开始。

## 构建与测试

```bash
cjpm build
cjpm test
```

## 目录结构

```text
JinguiSSL-core/
├── src/jinguissl_core/jinguissl/
│   ├── compat/
│   ├── crypto/
│   └── tests/
├── testdata/
├── .github/workflows/ci.yml
├── cjpm.toml
└── README.md
```

## 当前定位

这是一个偏库级、偏底层的仓库。  
它适合作为：

- 上层 contract/facade 的实现基础
- 框架或中间件的安全核心
- 仓颉生态里可复用的协议与密码能力底座

## 许可证

本项目采用 `Apache License 2.0`。详见 `LICENSE`。
