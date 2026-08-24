# TLS 协议支持说明

`jinguissl_core.crypto.tls` 提供 TLS 1.2 和 TLS 1.3 的握手、记录层和会话管理。

## 整体架构

```
TLS Layer
├── Handshake (tls12.cj, tls13.cj)
│   ├── ClientHello / ServerHello
│   ├── Certificate / CertificateVerify
│   ├── Key Exchange (ECDHE, X25519)
│   └── Finished
├── Record (record.cj)
│   ├── Content types (handshake, application data, alert)
│   ├── Encryption / Decryption
│   └── SeqNum management
├── Session (session.cj)
│   ├── Session state
│   ├── Cipher suite negotiation
│   └── Key schedule
├── TLCP / DTLCP (tlcp.cj, tlcp_record.cj, dtlcp.cj)
│   ├── Dual-certificate ECC / ECDHE handshake
│   ├── SM3 PRF and SM4-CBC/GCM record
│   └── Datagram replay, fragmentation and retransmission state
└── HTTP (http.cj)
    └── Application data encoding
```

## TLS 1.3 支持

### Cipher Suites

| Suite | 值 | 状态 |
|:--|:--|:--|
| TLS_AES_128_GCM_SHA256 | 0x1301 | 已实现 |
| TLS_AES_256_GCM_SHA384 | 0x1302 | 已实现 |
| TLS_CHACHA20_POLY1305_SHA256 | 0x1303 | 已实现 |
| TLS_SM4_GCM_SM3 | 0x00C6 | RFC 8998 本地闭环 |
| TLS_SM4_CCM_SM3 | 0x00C7 | RFC 8998 本地闭环 |

### 常量

| 名称 | 值 | 说明 |
|:--|:--|:--|
| `TLS13_CIPHER_SUITE_AES_128_GCM_SHA256` | 0x1301 | |
| `TLS13_CIPHER_SUITE_AES_256_GCM_SHA384` | 0x1302 | |
| `TLS13_CIPHER_SUITE_CHACHA20_POLY1305_SHA256` | 0x1303 | |
| `TLS13_CIPHER_SUITE_SM4_GCM_SM3` | 0x00C6 | RFC 8998 |
| `TLS13_CIPHER_SUITE_SM4_CCM_SM3` | 0x00C7 | RFC 8998 |
| `TLS13_GROUP_CURVE_SM2` | 41 | curveSM2 |
| `TLS13_SHA256_HASH_LEN` | 32 | |
| `TLS13_SHA384_HASH_LEN` | 48 | |
| `TLS13_DEFAULT_AEAD_KEY_LEN` | 16 | |
| `TLS13_DEFAULT_AEAD_IV_LEN` | 12 | |

### 签名算法

| 名称 | 值 |
|:--|:--|
| `TLS13_SIG_SCHEME_ECDSA_SECP256R1_SHA256` | 0x0403 |
| `TLS13_SIG_SCHEME_ECDSA_SECP384R1_SHA384` | 0x0503 |
| `TLS13_SIG_SCHEME_RSA_PSS_RSAE_SHA256` | 0x0804 |
| `TLS13_SIG_SCHEME_SM2_SM3` | 0x0708 |

RFC 8998 路径提供 curveSM2 ClientHello/ServerHello、显式 SM3 HKDF 身份、SM4-GCM/CCM record、`TLSv1.3+GM+Cipher+Suite` 身份绑定的 SM2 CertificateVerify，以及 SM2/SM3 X.509 解析、签发与验证。当前证据是本地协议闭环；不声明外部 TLS 实现互操作。

### 密钥更新

```cangjie
let TLS13_KEY_UPDATE_NOT_REQUESTED: Int64 = 0
let TLS13_KEY_UPDATE_REQUESTED: Int64 = 1
```

### 客户端 Hello 互操作检测

```cangjie
import jinguissl_core.crypto.tls.*

let summary = tls13SummarizeClientHello(encodedClientHello)
// 或
let summary = tls13SummarizeDecodedClientHello(clientHello)
```

## TLS 1.2 支持

TLS 1.2 提供库内握手流构件，覆盖 ECDHE 密钥交换和服务端/客户端证书相关阶段。
这不等同于浏览器级 HTTPS、外部实现互操作或完整网络产品证明。

### 握手状态

```
TLS 1.2 Handshake
├── ClientHello → ServerHello
├── Certificate → ServerKeyExchange → CertificateRequest
├── ServerHelloDone
├── ClientCertificate → ClientKeyExchange → CertificateVerify
└── ChangeCipherSpec → Finished
```

## TLCP / DTLCP 1.1

TLCP 使用协议版本 `0x0101`、签名/加密双证书和 SM3 PRF。本仓对齐固定
openHiTLS 快照中的四套密码组：

| Suite | 值 | 密钥交换 | Record protection |
|:--|--:|:--|:--|
| `ECDHE_SM4_CBC_SM3` | 0xE011 | 带静态身份的 SM2 ECDHE | HMAC-SM3 + SM4-CBC |
| `ECC_SM4_CBC_SM3` | 0xE013 | 加密证书 SM2 静态交换 | HMAC-SM3 + SM4-CBC |
| `ECDHE_SM4_GCM_SM3` | 0xE051 | 带静态身份的 SM2 ECDHE | SM4-GCM |
| `ECC_SM4_GCM_SM3` | 0xE053 | 加密证书 SM2 静态交换 | SM4-GCM |

核心 API 按阶段拆分：

- `tlcpEncode/DecodeClientHello`、`tlcpEncode/DecodeServerHello` 与 server preference suite selection；
- `tlcpBuild/Parse/VerifyDualCertificateHandshake`，分别检查 signing/encryption leaf 的 keyUsage 和链；
- 静态 ECC 与 ECDHE `ServerKeyExchange` / `ClientKeyExchange`；
- `tlcpDeriveSecretsFromPreMaster`、SM3 PRF 和 12 字节 Finished；
- `TlcpRecordLayer` 的方向性 key block、序号、CBC MAC-then-encrypt 与 GCM AEAD。

静态 ECC 的 SM2 密文在 wire 上使用 ASN.1 `SM2Cipher`。私钥解密或 premaster
版本检查失败会走 48 字节随机 fallback；record 认证失败不会推进读取序号。

DTLCP 使用 13 字节 record header（type、`0x0101`、epoch、48 位 sequence、length）。
`DtlcpRecordLayer` 支持当前 epoch 内乱序到达和 64 包 anti-replay window；
`DtlcpHandshakeReassembler` 处理 12 字节握手分片头、乱序片段和一致 overlap；
`DtlcpFlightRetransmitter` 提供缓存 flight、最大次数和指数退避状态。

这些是库内可组合协议构件，不含 socket client/server、定时器、MTU/拥塞策略，也不声明
已经通过 openHiTLS 线上互操作或商密认证。更完整的算法与 PKI 边界见
[国密能力指南](gm-crypto.md)。

## 记录层

`record.cj` 提供 TLS 记录层的加密和解密。

### 记录层功能
- 内容类型编码（handshake, alert, application_data, change_cipher_spec）
- 记录序列号管理
- AEAD 加密与解密
- 记录分片与重组

## 会话管理

`session.cj` 管理 TLS 会话状态，包括：
- 会话 ID
- 密码套件协商
- 密钥计划
- 有限容量的进程内 session cache

`tlsEncodeSessionTicket` / `tlsDecodeSessionTicket` 是受信任进程内的本地
序列化构件，会包含 session secret，不能作为网络上的 TLS 1.3 ticket。
网络 ticket 应是 opaque 数据库索引，或由拥有方自加密且自认证的值。
当前无密钥 PSK ServerHello、self-describing session-ticket ClientHello /
NewSessionTicket 和自动 ticket selection 接口均失败关闭。除显式 PSK 路径外，
`Tls13OpaqueTicketStore` 提供受限的单进程 opaque ticket owner：wire ticket 是
32 字节 CSPRNG lookup label，服务端保存由 resumption master secret 与随机 nonce
派生的 PSK，并校验 lifetime、obfuscated age、SNI、ALPN、cipher/hash 与 binder。
成功验证会单次消费 ticket，`rotate()` 会清空旧 generation；调用方必须负责
串行化 store 访问，不能据此声称跨进程 replay 协调。

`tls13BuildClientHelloFromResumptionTicket` 只接受已经带有匹配 cipher 与 key_share
的 PSK+DHE base ClientHello。`validateAndConsumeClientHello` 返回的只是经验证的
PSK 与上下文，后续仍必须完成 PSK+DHE key schedule、ServerHello 与完整 transcript。
当前 binder surface 仅覆盖首个 ClientHello，不接管 HelloRetryRequest transcript；
也不提供完整 resumed-handshake composer 或声明浏览器/OpenSSL/curl 在线互通。
0-RTT ticket、ClientHello early_data 和 0-RTT compliance mode 均失败关闭。

恢复 PSK 派生由 RFC 8448 官方向量回归；票据 age/lifetime/binder/binding/single-use/
rotation 与 0-RTT 拒绝由本地安全测试覆盖。required mTLS 另有缺失客户端 flight、
不受信链、CertificateVerify 篡改、transcript 不匹配与 Finished 篡改的负向回归。
