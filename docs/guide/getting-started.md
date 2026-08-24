# 快速上手指南

## 环境要求

- CangJie SDK 1.0.0+
- `cjpm` 构建工具

## 添加依赖

在项目的 `cjpm.toml` 中添加：

```toml
[dependencies]
jinguissl_core = { git = "https://gitcode.com/CjKu/JinguiCore.git" }
```

本地开发时也可以使用路径依赖：

```toml
[dependencies]
jinguissl_core = { path = "../JinguiCore" }
```

## 第一个示例：SHA-256

```cangjie
import jinguissl_core.crypto.digest.{sha256, bytesToHexLower}

main() {
    let digest = sha256("hello jingui".toArray())
    println(bytesToHexLower(digest))
}
```

## 构建与测试

```bash
# 构建库
cjpm build

# 运行所有单测
cjpm test

# 运行仓内示例（参见 sample/ 目录）
cd sample/aes
cjpm build && cjpm run
```

## 模块导入路径

所有 public API 均位于 `jinguissl_core` 根包下：

| 导入路径 | 模块 |
|:--|:--|
| `jinguissl_core.crypto.aes.*` | AES 加密 |
| `jinguissl_core.crypto.chacha20.*` | ChaCha20/Poly1305 |
| `jinguissl_core.crypto.digest.*` | 摘要算法 |
| `jinguissl_core.crypto.rsa.*` | RSA 签名 |
| `jinguissl_core.crypto.ecc.*` | ECC/ECDSA/ECDH |
| `jinguissl_core.crypto.ed25519.*` | Ed25519 |
| `jinguissl_core.crypto.x25519.*` | X25519 |
| `jinguissl_core.crypto.sm2.*` | SM2 签验、C1C3C2 与密钥交换 |
| `jinguissl_core.crypto.sm3.*` | SM3 哈希 |
| `jinguissl_core.crypto.sm4.*` | SM4 分组与 AEAD 模式 |
| `jinguissl_core.crypto.x509.*` | X.509 证书 |
| `jinguissl_core.crypto.tls.*` | TLS 协议 |
| `jinguissl_core.crypto.ssh.*` | SSH 协议 |
| `jinguissl_core.crypto.quic.*` | QUIC v1/v2 包保护构件 |
| `jinguissl_core.crypto.kem.*` | KEM 封装 |
| `jinguissl_core.crypto.compliance.*` | 算法许可与 policy profile |
| `jinguissl_core.crypto.utils.*` | 工具函数 |
| `jinguissl_core.crypto.base.*` | 基础类型 |
| `jinguissl_core.crypto.error.*` | 异常类型 |

不同模块的成熟度并不相同。直接使用私钥算法、TLS/SSH/QUIC 或 KEM 前，
请先查看 [能力矩阵](../capability-matrix.md) 与对应指南。
