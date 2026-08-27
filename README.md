<p align="center">
  <img src="https://img.shields.io/badge/Cangjie-JinguiSSL%20Core-c96b2c?style=for-the-badge&labelColor=1f2430" alt="JinguiSSL Core" />
  <img src="https://img.shields.io/badge/version-0.7.6-c96b2c?style=for-the-badge&labelColor=1f2430" alt="Version 0.7.6" />
  <img src="https://img.shields.io/badge/package-static-2f855a?style=for-the-badge&labelColor=1f2430" alt="Static Package" />
  <img src="https://img.shields.io/badge/focus-crypto%20%2B%20protocol-3182ce?style=for-the-badge&labelColor=1f2430" alt="Crypto and Protocol" />
  <img src="https://img.shields.io/badge/license-LGPL--3.0--only-1f9d55?style=for-the-badge&labelColor=1f2430" alt="LGPL-3.0-only" />
  <a href="https://github.com/Celading/jinguisslCore/actions/workflows/ci.yml"><img src="https://github.com/Celading/jinguisslCore/actions/workflows/ci.yml/badge.svg" alt="JinguiSSL Package CI" /></a>
</p>
<div align="center">
<span style="font-weight:300;font-size:36px">JinguiSSL Core / 金匮内核</span><br/>
<span style="font-weight:100;font-size:24px">JinguiSSL 的算法、证书与协议底层实现</span>
<p align="center">
  <strong>面向需要直接控制密码原语、X.509、TLS、SSH 与 QUIC 包保护细节的仓颉开发者</strong><br/>
  <sub>AES · ChaCha20-Poly1305 · SM2/SM3/SM4/SM9 · GM-DRBG · RSA · ECC · X.509 · TLS/TLCP/DTLCP · SSH · QUIC</sub>
</p>
</div>

## 这是什么

`JinguiSSL-core` 是 JinguiSSL 家族的底层实现仓。它提供密码原语、证书处理和协议构件，适合协议库、框架、中间件、桥接层与安全研究场景。

应用层若只需要较稳定的 facade，通常应先使用 `JinguiSSL-contract`；需要握手、record、key schedule、包保护或底层算法控制时，再直接进入 Core。

## 能力概览

| 领域 | 当前公开面 | 证据边界 |
|:--|:--|:--|
| 基础支撑 | 安全字节工具、错误类型、端序、安全比较、清零、CSPRNG | 支撑层，不代表所有私钥路径均为恒定时间 |
| 摘要与派生 | SHA-256/384/512、HMAC、HKDF；MD5/SHA-1 仅遗留兼容 | known vectors 与协议边界回归 |
| 国密基础算法 | SM2 / SM3 / SM4 / GM-DRBG：签验、C1C3C2、身份绑定密钥交换、摘要/HMAC/KDF、ECB/CBC/CTR/CFB/OFB/GCM/CCM/XTS/HCTR、CMAC/CBC-MAC、SM3 Hash-DRBG 与 SM4-CTR-DRBG | 标准/固定上游向量和失败关闭测试；纯仓颉运行时；无认证声明 |
| SM9 | 双线性对、H1/H2、身份签名、C1-C3-C2 加密、带确认值密钥交换 | 标准附录固定向量、子群/身份/篡改负向；纯仓颉运行时 |
| SM2 PKI | SPKI、SEC1、无加密 PKCS#8、PKCS#10 CSR、证书签发、CRL | 固定 openHiTLS 容器样本、链/吊销/错误密钥与身份负向 |
| 对称密码 | AES、ChaCha20-Poly1305 | 本地向量和边界测试；无认证声明 |
| 椭圆曲线 | ECC / ECDSA / ECDH、Ed25519、X25519 | 功能性覆盖；私钥标量路径无完整恒定时间认证 |
| RSA 与封装 | RSA、PKCS#1 v1.5、PSS、KEM（储备） | RSA-KEM/ECDH-KEM 不等于 ML-KEM/PQC |
| 大数 | BigNum 与大数兼容层 | 依赖标准库 BigInt，不是恒定时间大数后端 |
| 证书 | X.509 / PEM / trust material | 解析、链验证与显式信任材料；非完整 WebPKI/原生系统信任库 |
| TLS | TLS 1.2 / TLS 1.3 握手构件、record、session、RFC 8998 国密 profile 与 ClientHello profile；TLS 1.3 AES-GCM/ChaCha20-Poly1305 record 使用序列化 5 字节 header 作为 AAD | 独立 AEAD 复算与本地协议流测试，不等于浏览器/OpenSSL/curl 在线互操作 |
| 国密传输协议 | TLCP / DTLCP 1.1：四套 SM2/SM3/SM4 密码组、双证书、静态 ECC/SM2 ECDHE、CBC/GCM record、数据报 replay/分片/重传构件 | 固定 openHiTLS 语义的库内端到端闭环；不声明外部线上互操作或网络产品完成 |
| SSH | SSH transport helpers、KEX、packet protection 与 host verification | 无外部 OpenSSH 全流程互操作声明 |
| QUIC | QUIC v1/v2 Initial、显式 AEAD、Header Protection、Retry integrity | 包保护构件，不包含 QUIC transport 或 HTTP/3 |
| 策略 | FIPS-oriented policy profile 与算法许可检查 | 策略辅助，不构成 FIPS 140 模块认证 |
| 工具 | Benchmark support、向量与协议测试 | 非跨平台性能承诺 |

完整、可检验的状态与限制见 [Capability Matrix](docs/capability-matrix.md)。

### TLS 1.3 当前边界

当前覆盖 `TLS_AES_128_GCM_SHA256`、`TLS_AES_256_GCM_SHA384`、`TLS_CHACHA20_POLY1305_SHA256`，以及 RFC 8998 的 `TLS_SM4_GCM_SM3` / `TLS_SM4_CCM_SM3`、`curveSM2` 与 `sm2sig_sm3`。HTTP X25519 ClientHello 会优先携带 `TLS_AES_256_GCM_SHA384`。

当前不声明 `X25519MLKEM768` key share，也不把本地 handshake/record 测试写成浏览器、OpenSSL 或 curl 线上互通成功。

TLS 1.3 AES-GCM 与 ChaCha20-Poly1305 记录层认证线上序列化的 5 字节
`TLSCiphertext` header；最大密文界限包含 `TLSInnerPlaintext` content-type
字节和 16 字节 AEAD tag。回归测试以独立 AEAD 调用复算密文/tag，避免同一
seal/open 实现的自互通掩盖 AAD 偏差。

PSK 除调用方显式提供高熵密钥并验证 binder 的低层路径外，现提供受限的
单进程 opaque ticket owner：wire ticket 仅为 CSPRNG lookup label，并覆盖
ticket nonce 派生、age/lifetime 校验、SNI/ALPN/cipher-hash 绑定、binder 验证、
轮换失效与成功后单次消费。客户端恢复 ClientHello 必须基于已有 PSK+DHE
key_share 构建；验证结果只是交给后续 key schedule 的安全边界，不是已完成握手。

该 owner 需由调用方串行化访问，不提供跨进程 ticket 共享或 replay 协调。
当前 binder surface 仅覆盖首个 ClientHello，不接管 HelloRetryRequest transcript。
0-RTT、完整 resumed-handshake composer、浏览器/OpenSSL/curl 在线互操作仍未开放；
无密钥 PSK 和把含 secret 的本地 session 序列化当作 wire ticket 继续失败关闭。

### 国密完整面

当前国密实现按固定的 openHiTLS 快照
`26f152c627b6b429a73973f762c8b71bb582fa23` 对齐公开算法、PKI 与 TLCP/DTLCP 语义：

- SM2、SM3、SM4 扩展模式/MAC，以及 SM3 Hash-DRBG、SM4-CTR-DRBG；
- SM9 配对、签名、加密和带确认值密钥交换；
- SM2 SPKI/SEC1/PKCS#8、CSR、证书签发和 CRL；
- RFC 8998 TLS 1.3，以及 TLCP/DTLCP 1.1 的双证书、静态 ECC/SM2 ECDHE、SM3 PRF、CBC/GCM record、数据报抗重放、握手分片重组和 flight 重传状态。

这些路径不链接 native/FFI 密码后端。这里的“完整”指固定参考面的代码与本地可复验闭环，
不表示已经完成 openHiTLS 线上互操作、socket client/server、恒定时间证明、硬件接入或商密认证。
ZUC 不在该固定快照的国密公开面内，因此不被虚构为已实现能力。

### 关于 RC4

RC4 不属于当前维护主线。未来若确有旧系统互通需求，应作为独立的 legacy compatibility 线路评估，不能并入现代默认配置。

## 快速开始

```toml
[dependencies]
jinguissl_core = { git = "https://gitcode.com/CjKu/JinguiCore.git" }
```

```cangjie
import jinguissl_core.crypto.digest.{sha256, bytesToHexLower}

main() {
    let digest = sha256("hello jingui".toArray())
    println(bytesToHexLower(digest))
}
```

Ed25519、RSA、ECC、TLS、SSH 与 QUIC 都有公开 API，但它们不是同一种成熟度。开始集成前请先查看能力矩阵和对应手册。

## 模块分层

| 模块 | 内容 |
|:--|:--|
| `crypto/aes` | AES block、CTR、CBC、GCM 与 engine helper |
| `crypto/chacha20` | ChaCha20、Poly1305 与 AEAD |
| `crypto/digest` | Hash、HMAC、HKDF |
| `crypto/sm2` / `crypto/sm3` / `crypto/sm4` / `crypto/drbg` | 国密基础算法、扩展模式/MAC 与 GM-DRBG；详见 [国密算法指南](docs/guide/gm-crypto.md) |
| `crypto/sm9` | SM9 配对、身份签名、加密与密钥交换 |
| `crypto/rsa` / `crypto/ecc` / `crypto/ed25519` / `crypto/x25519` | 非对称与密钥协商能力 |
| `crypto/x509` | 证书、私钥、链验证、SM2 PKI 与 PEM/DER |
| `crypto/tls` | TLS/TLCP/DTLCP handshake、record、session 与 HTTP helper |
| `crypto/ssh` | SSH transport、host verification 与 KEX |
| `crypto/quic` | QUIC Initial、AEAD、Header Protection 与 Retry integrity |
| `crypto/compliance` | 算法许可与 policy profile |
| `compat/bn` / `crypto/bignum` | 大数兼容与基础支持 |

## 系统证书信任材料

Core 可以读取一部分常见 PEM bundle 路径，也允许调用方显式传入 PEM bundle。当前不声明 macOS Keychain、Windows Root Store 或 HarmonyOS 真实设备信任库已经完整接入。

```cangjie
import jinguissl_core.crypto.x509.{x509CreateSystemTrustPolicy, x509SystemTrustMaterialSupportKind}

main() {
    println(x509SystemTrustMaterialSupportKind())
    let policy = x509CreateSystemTrustPolicy(extraPemBundlePaths: ["./roots.pem"])
    println(policy.trustAnchors.size)
}
```

## 构建、测试与提交前门禁

```bash
cjpm build
cjpm test
bash scripts/jinguissl_pre_review.sh <base-ref>
```

提交前门禁会检查公开残留、托管依赖图、依赖锁、能力矩阵、README/manual 同步、构建和完整测试。

本仓不另造测试 runner 或结果数据库。托管 CI 公开每个 commit 的 step 结果，并上传只含
commit/工具链、构建日志和完整测试日志的证据 artifact；详见[公开测试面](docs/public-testing.md)。
Wycheproof、fuzz、恒定时认证和外部协议互操作在真正接入独立 lane 前继续明确标为未覆盖，
不能只看总测试数推导安全成熟度。

## 文档

- [使用手册入口](docs/README.md)
- [能力矩阵](docs/capability-matrix.md)
- [公开测试面与结果契约](docs/public-testing.md)
- [密码原语](docs/guide/crypto-primitives.md)
- [X.509](docs/guide/x509-certificates.md)
- [TLS](docs/guide/tls-protocol.md)
- [SSH](docs/guide/ssh-protocol.md)
- [QUIC 包保护](docs/guide/quic-protection.md)
- [算法许可与 policy profile](docs/guide/compliance.md)

## 安全姿态

本仓库的私钥密码操作尚未通过完整的恒定时间安全认证。ECDSA、ECDH、RSA 私钥变换、Ed25519 与 X25519 等路径仍有 BigInt/BigNum 后端或条件分支的时序非声明。

当前可诚实描述为功能性密码学与协议实现，以及面向集成、评估和审计的底层候选。不要把它描述成已认证的生产级密码后端、OpenSSL 替代或完整浏览器级 TLS/QUIC 栈。

## 许可证

当前源码线采用 `LGPL-3.0-only`，详见 `LICENSE`。历史上已按 `Apache-2.0` 发布的版本继续保留其既有授权，但属于旧发布线，不代表当前维护、安全或兼容状态。
