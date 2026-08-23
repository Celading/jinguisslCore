<p align="center">
  <img src="https://img.shields.io/badge/Cangjie-JinguiSSL%20Core-c96b2c?style=for-the-badge&labelColor=1f2430" alt="JinguiSSL Core" />
  <img src="https://img.shields.io/badge/version-0.7.6-c96b2c?style=for-the-badge&labelColor=1f2430" alt="Version 0.7.6" />
  <img src="https://img.shields.io/badge/package-static-2f855a?style=for-the-badge&labelColor=1f2430" alt="Static Package" />
  <img src="https://img.shields.io/badge/focus-crypto%20%2B%20protocol-3182ce?style=for-the-badge&labelColor=1f2430" alt="Crypto and Protocol" />
  <img src="https://img.shields.io/badge/license-LGPL--3.0--only-1f9d55?style=for-the-badge&labelColor=1f2430" alt="LGPL-3.0-only" />
</p>
<div align="center">
<span style="font-weight:300;font-size:36px">JinguiSSL Core / 金匮内核</span><br/>
<span style="font-weight:100;font-size:24px">JinguiSSL 的算法、证书与协议底层实现</span>
<p align="center">
  <strong>面向需要直接控制密码原语、X.509、TLS、SSH 与 QUIC 包保护细节的仓颉开发者</strong><br/>
  <sub>AES · ChaCha20-Poly1305 · RSA · ECC · X25519 · X.509 · TLS · SSH · QUIC</sub>
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
| 对称密码 | AES、ChaCha20-Poly1305、SM3 / SM4 | 本地向量和边界测试；无认证声明 |
| 椭圆曲线 | ECC / ECDSA / ECDH、Ed25519、X25519 | 功能性覆盖；私钥标量路径无完整恒定时间认证 |
| RSA 与封装 | RSA、PKCS#1 v1.5、PSS、KEM（储备） | RSA-KEM/ECDH-KEM 不等于 ML-KEM/PQC |
| 大数 | BigNum 与大数兼容层 | 依赖标准库 BigInt，不是恒定时间大数后端 |
| 证书 | X.509 / PEM / trust material | 解析、链验证与显式信任材料；非完整 WebPKI/原生系统信任库 |
| TLS | TLS 1.2 / TLS 1.3 握手构件、record、session 与 ClientHello profile | 本地协议流测试，不等于浏览器/OpenSSL/curl 在线互操作 |
| SSH | SSH transport helpers、KEX、packet protection 与 host verification | 无外部 OpenSSH 全流程互操作声明 |
| QUIC | QUIC v1/v2 Initial、显式 AEAD、Header Protection、Retry integrity | 包保护构件，不包含 QUIC transport 或 HTTP/3 |
| 策略 | FIPS-oriented policy profile 与算法许可检查 | 策略辅助，不构成 FIPS 140 模块认证 |
| 工具 | Benchmark support、向量与协议测试 | 非跨平台性能承诺 |

完整、可检验的状态与限制见 [Capability Matrix](docs/capability-matrix.md)。

### TLS 1.3 当前边界

当前覆盖 `TLS_AES_128_GCM_SHA256`、`TLS_AES_256_GCM_SHA384` 与 `TLS_CHACHA20_POLY1305_SHA256`。HTTP X25519 ClientHello 会优先携带 `TLS_AES_256_GCM_SHA384`。

当前不声明 `X25519MLKEM768` key share，也不把本地 handshake/record 测试写成浏览器、OpenSSL 或 curl 线上互通成功。

PSK 当前只保留调用方显式提供高熵密钥并验证 binder 的低层路径。无密钥的
PSK 选择和把本地 session 序列化直接当作 wire ticket 的便捷接口会失败关闭；
在 opaque protected-ticket backend、ticket nonce 派生、ticket age 与 0-RTT
策略完成前，不声明 TLS 1.3 session-ticket resumption 或 0-RTT 可用。

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
| `crypto/rsa` / `crypto/ecc` / `crypto/ed25519` / `crypto/x25519` | 非对称与密钥协商能力 |
| `crypto/x509` | 证书、私钥、链验证与 PEM/DER |
| `crypto/tls` | TLS handshake、record、session 与 HTTP helper |
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

## 文档

- [使用手册入口](docs/README.md)
- [能力矩阵](docs/capability-matrix.md)
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
