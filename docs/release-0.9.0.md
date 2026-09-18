# 0.9.0

中心仓包名 `jinguissl_core`。应用优先使用主桥 `jinguissl = "0.9.0"`，
无需直接导入核心；底层协议实现可以直接使用 `jinguissl_core = "0.9.0"`。
版本说明描述源码内容，不代表中心仓审核或索引已经完成。

## 更新 / Changes

- BLAKE2s：带密钥、可变长度摘要和增量上下文。
- HChaCha20 与 XChaCha20-Poly1305；实现不依赖原生密码后端。
- 有界 SSH 流拆包与粘包；前缀长度探测不消耗序号或 CTR 状态。
- 保留 DTLS 1.2 双角色、TLS/QUIC 客户端能力和国密公开面。
- 修正 LGPL-3.0-only 包元数据类型；许可条款未改变。

Adds keyed and variable-length BLAKE2s, HChaCha20, XChaCha20-Poly1305,
and bounded SSH stream framing. Existing DTLS, TLS/QUIC and Chinese
cryptography APIs remain available. Package license metadata now uses the
registry's array format; license terms are unchanged.

本版不新增生产认证、恒定时间证明或完整 SSH 客户端承诺。
接口成熟度、协议覆盖和独立互通边界仍以 [能力矩阵](capability-matrix.md) 为准。
This release does not claim certification, constant-time verification,
or a complete SSH client.
