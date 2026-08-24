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

### 常量

| 名称 | 值 | 说明 |
|:--|:--|:--|
| `TLS13_CIPHER_SUITE_AES_128_GCM_SHA256` | 0x1301 | |
| `TLS13_CIPHER_SUITE_AES_256_GCM_SHA384` | 0x1302 | |
| `TLS13_CIPHER_SUITE_CHACHA20_POLY1305_SHA256` | 0x1303 | |
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
