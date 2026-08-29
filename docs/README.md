# JinguiSSL Core 使用手册

JinguiSSL Core 是 JinguiSSL 系列的底层密码学库，使用仓颉编程语言编写。
本手册介绍如何集成、配置和使用该库。

## 目录结构

```
docs/
├── README.md              # 本文件 - 目录与快速指引
├── public-testing.md       # 公开测试入口、结果格式与未覆盖边界
├── guide/
│   ├── getting-started.md  # 快速上手指南
│   ├── crypto-primitives.md# 密码原语使用说明
│   ├── gm-crypto.md        # SM2/3/4/9、GM-DRBG、SM2 PKI、TLCP/DTLCP
│   ├── tls-protocol.md     # TLS 1.2/1.3 与 TLCP/DTLCP 协议说明
│   ├── ssh-protocol.md     # SSH 传输层协议说明
│   ├── x509-certificates.md # X.509 证书处理
│   ├── quic-protection.md  # QUIC v1/v2 包保护构件
│   └── compliance.md       # 算法许可与 policy profile
└── api/
    └── modules.md          # 模块 API 参考
```

## 快速链接

- [快速上手](guide/getting-started.md) — 项目集成、构建配置、首个示例
- [密码原语](guide/crypto-primitives.md) — AES、ChaCha20、RSA、ECC、Ed25519、X25519
- [国密能力](guide/gm-crypto.md) — SM2/3/4/9、GM-DRBG、SM2 PKI、TLCP/DTLCP 与证据边界
- [TLS 协议](guide/tls-protocol.md) — TLS 1.2/1.3、TLCP/DTLCP、记录层与会话管理
- [SSH 协议](guide/ssh-protocol.md) — SSH 传输层握手、主机验证、密钥交换
- [X.509 证书](guide/x509-certificates.md) — 证书解析、链验证、PEM/DER
- [QUIC 包保护](guide/quic-protection.md) — Initial、AEAD、Header Protection、Retry integrity
- [能力矩阵](capability-matrix.md) — 公开能力、证据、手册与限制
- [公开测试面](public-testing.md) — 权威入口、CI 证据和未覆盖边界
- [算法许可](guide/compliance.md) — FIPS-oriented policy profile 与算法许可管理
- [API 参考](api/modules.md) — 所有 public API 索引

## 示例项目

参见 [sample/](../sample/) 目录下的独立示例项目，包含以下场景：

- 对称密码：**AES**, **ChaCha20**, **SM4** (ECB/CBC/CTR/CFB/OFB/GCM/CCM/XTS/HCTR)
- 摘要与派生：**Digest** (MD5/SHA/HMAC/HKDF), **SM3** (stream/HMAC/KDF)
- 非对称密码：**RSA**, **ECC**, **Ed25519**, **X25519**, **SM2**, **SM9**
- 密钥封装：**KEM** (RSA-KEM, ECDH-KEM)
- 大数运算：**BigNum** (大整数算术与模运算)
- 证书与策略：**X.509**, **Compliance policy profile**
- 包保护：**QUIC** (v1/v2 Initial、AEAD、Header Protection、Retry integrity)
- 协议能力：**TLS** (会话票据), **SSH** (主机密钥指纹)
- 工具：**Utils** (端序转换、安全比较、CSPRNG)

每个场景对应一个子目录，包含可编译运行的 CangJie 项目。
