# 国密能力指南

JinguiSSL Core 的国密实现由仓颉运行时完成，不链接或加载 C、汇编、FFI 密码后端。
当前代码面按固定 openHiTLS 快照
`26f152c627b6b429a73973f762c8b71bb582fa23` 对齐算法、PKI 与 TLCP/DTLCP 公开语义，
并通过仓内固定向量和端到端协议测试。

这表示固定参考面的实现与本地复验已经闭环，不表示获得商密检测、监管认证、
完整恒定时间证明或外部协议互操作认证。

## 支持范围

| 领域 | 公开能力 | 当前证据 |
|:--|:--|:--|
| SM2 | sm2p256v1 密钥、ZA、签验、原始 C1C3C2、共享点、带身份和确认值的密钥交换 | GB/T 32918.5 固定向量、随机往返、点/密钥/身份/篡改负向 |
| SM3 | 一次性与增量摘要、HMAC-SM3、计数 KDF | 标准摘要、独立 HMAC/KDF 与跨分组向量 |
| SM4 | block、ECB/CBC/CTR/CFB/OFB/GCM/CCM/XTS/HCTR、CMAC、CBC-MAC | 固定模式/MAC 向量、partial-block 往返、标签/填充/密钥边界负向 |
| GM-DRBG | SM3 Hash-DRBG、SM4-CTR-DRBG、显式熵/nonce、additional input、reseed/uninstantiate | 确定性状态回放、分段请求、reseed limit 与失效状态负向 |
| SM9 | 双线性对、H1/H2、主密钥/用户密钥、签名、C1-C3-C2 加密、带确认值密钥交换 | 标准附录固定向量、双线性、子群、错误身份、篡改与确认值负向 |
| SM2 PKI | SPKI、SEC1、无加密 PKCS#8、PKCS#10 CSR、颁发者签发证书、CRL | 固定 openHiTLS 容器样本、DER/PEM 往返、链/吊销/错误密钥与身份负向 |
| RFC 8998 | curveSM2、SM3 key schedule、SM4-GCM/CCM record、sm2sig_sm3、SM2 X.509 | 本地握手/record/CertificateVerify 闭环和失败关闭测试 |
| TLCP/DTLCP 1.1 | 四套 SM2/SM3/SM4 suite、签名/加密双证书、静态 ECC/SM2 ECDHE、PRF/Finished、CBC/GCM record、epoch/replay/fragment/retransmit | 固定 openHiTLS wire/状态语义、双向端到端流、篡改/身份/重放/分片负向 |

ZUC 不在该固定 openHiTLS 快照的国密公开面内，本仓不会把未实现项写成已支持。

## SM2

基础签名和密钥交换 API 必须显式提供身份字节，库不会替调用方悄悄选择 ID。

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

`sm2Encrypt` 固定输出原始 `C1C3C2`：C1 是 65 字节未压缩点，C3 是 32 字节
SM3 摘要，其余为 C2。TLCP 静态 ECC 路径会在协议边界严格转换为 ASN.1
`SM2Cipher`；基础 API 本身不改变编码。解密验证点、KDF 和 C3 后才返回明文。

密钥交换由 `sm2InitiatorKeyExchange`、`sm2ResponderKeyExchange` 和
`sm2VerifyConfirmation` 组成。调用方在使用派生密钥前应校验对端确认值；TLCP
另以 Finished 覆盖完整握手 transcript。

## SM3 与 GM-DRBG

```cangjie
import jinguissl_core.crypto.sm3.*
import jinguissl_core.crypto.drbg.*

let context = Sm3Context()
context.update(header)
context.update(body)
let digest = context.finish()

let hashDrbg = sm3HashDrbgFromSystem(personalization: "service-a".toArray())
let nonce = hashDrbg.generateBytes(48)
hashDrbg.reseedFromSystem()
hashDrbg.uninstantiate()

let ctrDrbg = sm4CtrDrbgFromSystem()
let keyMaterial = ctrDrbg.generateBytes(32)
```

单次 `Sm3HashDrbg.generate` 最多返回 32 字节，单次 `Sm4CtrDrbg.generate` 最多
返回 16 字节；`generateBytes` 会按限制分段。上下文是可变且非线程安全的，超过
reseed interval 或 `uninstantiate` 后继续生成会失败关闭。

## SM4 扩展模式与 MAC

```cangjie
import jinguissl_core.crypto.sm4.*

let (ciphertext, tag) = sm4GcmEncrypt(key, nonce, plaintext, aad: aad)
let recovered = sm4GcmDecrypt(key, nonce, ciphertext, tag, aad: aad)

let xtsCiphertext = sm4XtsEncrypt(key1AndKey2, dataUnitTweak, sector)
let authenticatedTag = sm4Cmac(macKey, message)
```

- GCM/CCM 是认证加密；标签错误时不返回明文。
- ECB/CBC/CTR/CFB/OFB/XTS/HCTR 只提供机密性或兼容变换，不自带认证或抗重放。
- XTS 使用 32 字节 `K1 || K2`，拒绝相同 key halves，并支持末尾 ciphertext stealing。
- HCTR 是固定 openHiTLS profile 的宽块兼容原语，不是 AEAD。
- `sm4CbcMac` 只适用于固定长度或已做域分离的消息；一般变长消息使用 `sm4Cmac`。

## SM9

```cangjie
import jinguissl_core.crypto.sm9.*

let identity = "Alice".toArray()
let signMasterPrivate = sm9GenerateSignMasterPrivateKey()
let signMasterPublic = sm9SignMasterPublicKey(signMasterPrivate)
let userSigningKey = sm9ExtractSignUserPrivateKey(signMasterPrivate, identity)
let signature = sm9Sign(userSigningKey, message)
let valid = sm9Verify(signMasterPublic, identity, message, signature)

let encMasterPrivate = sm9GenerateEncryptionMasterPrivateKey()
let encMasterPublic = sm9EncryptionMasterPublicKey(encMasterPrivate)
let userEncryptionKey = sm9ExtractEncryptionUserPrivateKey(encMasterPrivate, identity)
let encrypted = sm9Encrypt(encMasterPublic, identity, message)
let decrypted = sm9Decrypt(userEncryptionKey, identity, encrypted)
```

SM9 点解码会验证曲线、子群和 infinity 边界。密文采用原始 `C1 || C3 || C2`；
C3 认证通过前不释放明文。`sm9BeginKeyExchange` / `sm9CompleteKeyExchange` 返回
派生密钥、发送确认值与期望对端确认值，后者用
`sm9VerifyKeyExchangeConfirmation` 校验。

## SM2 PKI 与密钥容器

`jinguissl_core.crypto.x509` 提供以下国密容器和签发面：

- `x509Encode/ParseSm2PublicKeyDer/Pem`：X.509 SubjectPublicKeyInfo；
- `x509Encode/ParseSm2PrivateKeySec1Der/Pem`：SEC1 ECPrivateKey；
- `x509Encode/ParseSm2PrivateKeyPkcs8Der/Pem`：无加密 PKCS#8；
- `x509Create/Parse/VerifySm2CertificateRequest`：PKCS#10 CSR；
- `x509CreateSm2Certificate`：颁发者签发的 SM2 证书；
- `x509CreateSm2Crl` 与 SM2 CRL 验签。

SEC1/PKCS#8 解析会交叉检查私钥标量、曲线 OID 和嵌入公钥。签发、CSR 与 CRL
均允许显式传入 SM2 signer identity；错误密钥、错误身份、篡改和吊销路径失败关闭。
当前 PKCS#8 不提供口令加密容器。

## TLCP / DTLCP 1.1

固定参考面包含四套密码组：

| Suite | Wire value | 交换 | Record |
|:--|--:|:--|:--|
| `ECDHE_SM4_CBC_SM3` | `0xE011` | SM2 authenticated ECDHE | HMAC-SM3 + SM4-CBC |
| `ECC_SM4_CBC_SM3` | `0xE013` | 静态 SM2 encryption certificate | HMAC-SM3 + SM4-CBC |
| `ECDHE_SM4_GCM_SM3` | `0xE051` | SM2 authenticated ECDHE | SM4-GCM |
| `ECC_SM4_GCM_SM3` | `0xE053` | 静态 SM2 encryption certificate | SM4-GCM |

`TlcpCertificateBundle` 要求第一张 leaf 为签名证书、第二张为加密证书，并分别校验
keyUsage 和证书链。静态 ECC 会把 48 字节 premaster 编码为 ASN.1 `SM2Cipher`，
解密或版本检查失败时返回同尺寸随机 fallback，避免直接形成 oracle。

`TlcpRecordLayer` 使用 5 字节 `0x0101` record header、方向性 key block 和序号状态。
CBC 是 MAC-then-encrypt 并使用显式随机 IV；GCM 使用 4 字节 fixed IV、8 字节显式序号
和 16 字节 tag。认证失败不会推进读取序号。

`DtlcpRecordLayer` 使用 13 字节 record header，将 epoch 与 48 位序号同时绑定到 AAD，
并提供 64 包 anti-replay window。`DtlcpHandshakeReassembler` 支持乱序和一致 overlap，
拒绝冲突 overlap；`DtlcpFlightRetransmitter` 只管理缓存 flight 与指数退避状态，计时和
网络发送仍由调用方 event loop 负责。

当前公开面是可组合的握手消息、密钥计划和记录层，不包括 socket client/server、
MTU/拥塞策略或 openHiTLS 在线互操作声明。

## 实现与安全边界

SM3、SM4、DRBG、SM9、SM2 PKI 和协议组合都在仓颉包内。SM2 与 SM9 的私钥、
椭圆曲线和配对路径依赖 Core BigNum / 仓颉标准库 `BigInt`；其分配、乘法、取模、
逆元与分支时序不在 JinguiSSL 的完整控制范围内。因此这些 API 不能描述为
“已证明恒定时间”，也不能仅凭 `cjpm test` 结果描述为通过密码模块认证。
