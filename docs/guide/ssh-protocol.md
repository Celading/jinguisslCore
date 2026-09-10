# SSH 协议支持说明

`jinguissl_core.crypto.ssh` 提供 SSH 传输层握手、主机验证和密钥交换。

## 整体架构

```
SSH Layer
├── Version Banner (version exchange)
├── Key Exchange (KEX)
│   ├── KEX_INIT → KEX_REPLY
│   ├── ECDH key exchange
│   ├── Host key verification
│   └── Derived session keys
├── Encryption Layer
│   ├── Packet protection (AES-CTR, ChaCha20)
│   ├── Sequence numbering
│   └── HMAC / AEAD（不声明 ETM）
└── Transport Protocol
    ├── Packet framing
    ├── Compression negotiation (no deflate runtime claim)
    └── Rekeying
```

## 核心类型

### SshVersionBanner

SSH 版本交换。

```cangjie
let banner = SshVersionBanner("SSH-2.0-JinguiSSL_1.0")
```

### SshKexInitMessage / SshKexEcdhInitMessage / SshKexEcdhReplyMessage

KEX 初始化消息。

### SshNegotiatedAlgorithms

协商的算法集合，包含：
- 密钥交换算法
- 主机密钥算法
- 加密算法（C2S, S2C）
- MAC 算法（C2S, S2C）
- 压缩算法

### SshHandshakeCoordinator

协调库内 SSH 传输握手状态与密钥材料流转。

### SshHostVerificationConfig / SshHostVerificationPolicy / SshHostVerificationResult

主机验证配置与结果。

### SshPacketProtectionLayer

SSH 传输层包保护。

### SshDerivedSessionKeys / SshDirectionKeyMaterial

导出的 SSH 会话密钥材料。

## 使用流程

```
1. 版本交换 (Version Banner)
2. KEX 初始化 (发送 KEX_INIT)
3. KEX 回复 (接收 KEX_REPLY)
4. ECDH 密钥交换
5. 主机密钥验证
6. 派生会话密钥
7. 加密通信
```

当前文档描述库内构件与状态流，不代表已经完成外部 OpenSSH client/server
全流程互操作、用户会话管理或产品级 SSH 服务实现。

## 分组保护与迁移

当前可执行 KEX 为 `curve25519-sha256`；默认和协商不再提供未实现的
P-256、group14 或压缩路径。协商采用客户端偏好顺序，不静默回退到未选中的算法。
KDF 按 RFC 4253/8731 使用规范正数 mpint 和原始 hash/session-id 字节。

- OpenSSH ChaCha20-Poly1305 使用 64 字节密钥、空派生 IV，分别保护长度和正文；
  序号作为 nonce，认证整个加密分组，不使用 IETF AEAD 的 AAD 格式。
- AES-GCM 使用 12 字节 IV、16 字节 tag，明文四字节长度为 AAD；
  只加密正文并递增 IV 的低 64 位，正文按 16 字节对齐。
- 普通 transport / AES-CTR 的对齐包含四字节长度；AEAD 正文对齐不包含长度。
  这修正了旧格式，不能和依赖旧错误线格式的实现互通。

分组状态由调用方串行持有，复制输入密钥材料，不支持并发 seal/open/reset。
已使用或失败的状态不能 reset；认证/结构失败及序号/nonce 耗尽后必须弃用。
独立 transport 可以通过 `SshPacketProtectionLayer` 的
`initialWriteSequence` / `initialReadSequence` 传入已交换分组计数。
默认为零只适用于零起点的构件测试；上层负责计入明文握手和 rekey 分组，
本库的消息级 coordinator 不会替 transport 统计它未接收的线上分组。

测试固定了 OpenSSH portable 10.0p1（2593769fb291fe6c542173927698c69e9f9a08b9）
三种 AEAD 的序号 0/1 分组结果，并用独立 OpenSSL oracle 交叉复算。
这是保护分组差分，不是在线 SSH 登录或完整握手互操作认证。
