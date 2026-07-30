# QUIC v1/v2 Packet Protection

`jinguissl_core.crypto.quic` 提供 QUIC v1/v2 的密码与包保护构件：

- Initial secret、key、IV 与 Header Protection key 派生
- 显式选择 `AES-128-GCM`、`AES-256-GCM` 或 `ChaCha20-Poly1305`
- AES 与 ChaCha20 Header Protection mask
- Retry Integrity Tag 计算与验证

调用 AEAD 接口时必须显式选择算法。算法与密钥长度不匹配、IV 长度错误、
负 packet number、过短 ciphertext/tag 等输入会被拒绝。当前测试包含 RFC 9001
向量、v1/v2 Initial/Retry 覆盖，以及算法/密钥长度不匹配回归。

这组接口只负责 QUIC 的密码构件。它不实现 QUIC transport、拥塞控制、流管理、
HTTP/3 或网络互操作，因此不能据此宣称已经提供完整 QUIC/HTTP3 协议栈。

常用入口：

- `quicInitialSecrets(...)`
- `quicInitialKeyIv(...)`
- `quicInitialHpKey(...)`
- `quicAeadEncrypt(...)`
- `quicAeadDecrypt(...)`
- `quicHpAesEncrypt(...)`
- `quicHpChaChaEncrypt(...)`
- `quicRetryIntegrityTag(...)`
- `quicVerifyRetryIntegrity(...)`
