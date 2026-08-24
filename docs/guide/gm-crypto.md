# 国密基础算法指南

JinguiSSL Core 的国密基础算法栈由仓颉运行时实现，不链接或加载 C、汇编、FFI
密码后端。当前公开面覆盖 SM2、SM3 和 SM4；这表示实现与本地标准向量已经通过，
不表示获得商密检测、监管认证或恒定时间认证。

## 支持范围

| 算法 | 公开能力 | 当前证据 |
|:--|:--|:--|
| SM2 | sm2p256v1 密钥、ZA、签验、原始 C1C3C2、共享点、带身份与确认值的密钥交换 | GB/T 32918.5 向量、随机往返、篡改与错误身份负向测试 |
| SM3 | 一次性与增量摘要、HMAC-SM3、计数 KDF | 标准摘要向量、独立 HMAC/KDF 向量、跨分组测试 |
| SM4 | block、ECB、CBC、CTR、GCM、CCM | GB/T 模式向量、RFC 8998 GCM/CCM 向量、标签与填充负向测试 |

不在当前范围内：SM9、ZUC、GM-DRBG、TLCP/DTLCP、SM2 X.509/PKCS 集成、
ASN.1 SM2 密文以及硬件加速。

## SM2

签名和密钥交换必须显式提供身份字节，库不会悄悄替调用方选择默认 ID。

```cangjie
import jinguissl_core.crypto.sm2.*

let identity = "1234567812345678".toArray()
let privateKey = sm2GeneratePrivateKey()
let publicKey = sm2PublicKey(privateKey)
let message = "message digest".toArray()

let (r, s) = sm2Sign(privateKey, identity, message)
let valid = sm2Verify(publicKey, identity, message, r, s)

let ciphertext = sm2Encrypt(publicKey, message)
let plaintext = sm2Decrypt(privateKey, ciphertext)
```

`sm2Encrypt` 固定输出 `C1C3C2`：C1 是 65 字节未压缩点，C3 是 32 字节
SM3 摘要，其余为 C2。它不是 ASN.1 `SM2Cipher`；需要 ASN.1 的上层协议必须显式转换。
解密会先验证点、KDF 和 C3，再返回明文。

密钥交换分为 `sm2InitiatorKeyExchange` 与 `sm2ResponderKeyExchange`。两者都接收
本端静态/临时私钥、对端静态/临时公钥、双方身份和派生长度，并返回：

- `key`：ZA/ZB 绑定的派生密钥；
- `sendConfirmation`：本端应发送的确认值；
- `expectedPeerConfirmation`：本端应以常量时间比较语义校验的对端确认值。

调用方必须在使用派生密钥前通过 `sm2VerifyConfirmation` 完成对端确认值校验。

## SM3

```cangjie
import jinguissl_core.crypto.sm3.*

let context = Sm3Context()
context.update(header)
context.update(body)
let digest = context.finish()

let mac = hmacSm3(key, body)
let derived = sm3Kdf(sharedPoint, 32)
```

`finish` 后继续 `update` 或再次 `finish` 会抛出异常；调用 `reset` 后可以复用上下文。

## SM4

```cangjie
import jinguissl_core.crypto.sm4.*

let (ciphertext, tag) = sm4GcmEncrypt(key, nonce, plaintext, aad: aad)
let recovered = sm4GcmDecrypt(key, nonce, ciphertext, tag, aad: aad)
```

现代新协议优先使用 GCM 或 CCM。ECB/CBC 只提供分组机密性，CBC 的 PKCS#7 是可选项；
二者都不自带认证或抗重放能力。CTR 的计数块不得在同一密钥下复用。GCM 解密接受
12–16 字节标签；CCM 接受 7–13 字节 nonce 和 4–16 字节偶数长度标签。标签错误时
API 抛出异常，不返回未经认证的明文。

## 实现与安全边界

算法源码、模式组合和测试均在仓颉包内；构建图没有为国密能力增加 native/FFI 依赖。
SM4 和 SM3 的循环是运行时实现。SM2 复用 Core 的仓颉 projective ECC 与 BigNum 层；
BigNum 依赖仓颉标准库 `BigInt`，其分配、乘法、取模与逆元时序不在 JinguiSSL 的
完整控制范围内。因此这些 API 不能描述为“已证明恒定时间”，也不能仅凭测试结果
描述为通过密码模块认证。
