# 密码原语使用说明

## AES (Advanced Encryption Standard)

`jinguissl_core.crypto.aes` 提供 AES 加密的多种模式。

### 支持的模式

| 模式 | 描述 | 安全等级 |
|:--|:--|:--|
| ECB | 电子密码本模式 | 不安全，仅兼容遗留系统 |
| CBC | 密码分组链接模式 | 需要 IV，抗重放 |
| CTR | 计数器模式 | 流模式，可并行 |
| GCM | 伽罗瓦计数器模式 | AEAD，推荐 |

### AES-ECB 示例

```cangjie
import jinguissl_core.crypto.aes.{aesEcbEncrypt, aesEcbDecrypt}

let key: Array<Byte> = Array<Byte>(16, repeat: UInt8(0x00))
let plaintext: Array<Byte> = Array<Byte>(16, repeat: UInt8(0x42))
let ciphertext = aesEcbEncrypt(key, plaintext)
let decrypted = aesEcbDecrypt(key, ciphertext)
```

### AES-CBC 示例

```cangjie
import jinguissl_core.crypto.aes.{aesCbcEncrypt, aesCbcDecrypt}

let key: Array<Byte> = Array<Byte>(16, repeat: UInt8(0x00))
let iv: Array<Byte> = Array<Byte>(16, repeat: UInt8(0x00))
let plaintext: Array<Byte> = Array<Byte>(32, repeat: UInt8(0x42))
let ciphertext = aesCbcEncrypt(key, iv, plaintext)
let decrypted = aesCbcDecrypt(key, iv, ciphertext)
```

### AES-GCM 示例 (AEAD)

```cangjie
import jinguissl_core.crypto.aes.{aesGcmEncrypt, aesGcmDecrypt, aesNewGcmContext, aesGcmEncryptWithContext, aesGcmDecryptWithContext}

let key: Array<Byte> = Array<Byte>(16, repeat: UInt8(0x00))
let nonce: Array<Byte> = Array<Byte>(12, repeat: UInt8(0x00))
let aad: Array<Byte> = "additional data".toArray()
let plaintext: Array<Byte> = "Hello AES-GCM".toArray()

// 一次加密
let (ciphertext, tag) = aesGcmEncrypt(key, nonce, plaintext, aad)
let (decrypted, valid) = aesGcmDecrypt(key, nonce, ciphertext, aad, tag)

// 使用 Context（可复用密钥）
let ctx = aesNewGcmContext(key)
let (ct, t) = aesGcmEncryptWithContext(ctx, nonce, plaintext, aad)
let (pt, v) = aesGcmDecryptWithContext(ctx, nonce, ct, aad, t)
```

### AES GCM 加密检查 (Checked 版本)

每个 GCM 函数都有对应的 `Checked` 变体，提供更严格的参数校验：

```cangjie
import jinguissl_core.crypto.aes.{aesGcmEncryptChecked, aesGcmDecryptChecked}
```

---

## ChaCha20 / Poly1305

`jinguissl_core.crypto.chacha20` 提供 ChaCha20 流密码和 Poly1305 MAC。

### 常量

| 常量 | 值 |
|:--|:--|
| `CHACHA20_KEY_LEN` | 32 |
| `CHACHA20_NONCE_LEN` | 12 |
| `CHACHA20_BLOCK_LEN` | 64 |
| `POLY1305_KEY_LEN` | 32 |
| `POLY1305_TAG_LEN` | 16 |

### ChaCha20 流加密

```cangjie
import jinguissl_core.crypto.chacha20.*

let key = Array<Byte>(CHACHA20_KEY_LEN, repeat: UInt8(0x00))
let nonce = Array<Byte>(CHACHA20_NONCE_LEN, repeat: UInt8(0x00))
let plaintext = "Hello ChaCha20".toArray()

// 加密（XOR）
let ciphertext = chacha20Xor(key, 0, nonce, plaintext)
// 解密（再次 XOR）
let decrypted = chacha20Xor(key, 0, nonce, ciphertext)
```

### ChaCha20-Poly1305 AEAD

```cangjie
import jinguissl_core.crypto.chacha20.*

let key = Array<Byte>(CHACHA20_KEY_LEN, repeat: UInt8(0x00))
let nonce = Array<Byte>(CHACHA20_NONCE_LEN, repeat: UInt8(0x00))
let aad = "auth".toArray()
let plaintext = "Hello AEAD".toArray()

// 一次加密
let (ciphertext, tag) = chacha20Poly1305Encrypt(key, nonce, plaintext, aad)
let (decrypted, valid) = chacha20Poly1305Decrypt(key, nonce, ciphertext, aad, tag)

// 使用 Context
let ctx = chacha20Poly1305NewContext(key)
let (ct, t) = chacha20Poly1305EncryptWithContext(ctx, nonce, plaintext, aad)
let (pt, v) = chacha20Poly1305DecryptWithContext(ctx, nonce, ct, aad, t)
```

### 生成 ChaCha20 块

```cangjie
let block = chacha20Block(key, counter: 0, nonce)
```

### Poly1305 MAC

```cangjie
let macKey: Array<Byte> = Array<Byte>(32, repeat: UInt8(0x00))
let mac = poly1305Mac(macKey, message)
```

---

## 摘要算法 (Digest)

`jinguissl_core.crypto.digest` 提供哈希、HMAC、HKDF 等。

### 支持的算法

| 算法 | 输出长度 | 安全状态 |
|:--|:--|:--|
| MD5 | 16 字节 | 不安全，仅兼容遗留系统 |
| SHA-1 | 20 字节 | 不安全，仅兼容遗留系统 |
| SHA-256 | 32 字节 | 安全，推荐 |
| SHA-384 | 48 字节 | 安全，推荐 |
| SHA-512 | 64 字节 | 安全，推荐 |

### 哈希函数

```cangjie
import jinguissl_core.crypto.digest.*
import jinguissl_core.crypto.digest.HashAlgorithm

let data = "Hello".toArray()
let h1 = md5(data)       // MD5
let h2 = sha1(data)      // SHA-1
let h3 = sha256(data)    // SHA-256
let h4 = sha384(data)    // SHA-384
let h5 = sha512(data)    // SHA-512
let h6 = hash(HashAlgorithm.SHA256, data)  // 通用接口
```

### HMAC

```cangjie
let key = "secret".toArray()
let data = "message".toArray()
let result = hmac(HashAlgorithm.SHA256, key, data)
```

### HKDF (提取-扩展)

```cangjie
// 一步到位
let derived = hkdf(HashAlgorithm.SHA256, ikm, salt, info, 32)

// 分两步
let prk = hkdfExtract(HashAlgorithm.SHA256, ikm, salt)
let expanded = hkdfExpand(HashAlgorithm.SHA256, prk, info, 48)
```

### 工具函数

```cangjie
let hex = bytesToHexLower(bytes)  // 字节数组转小写十六进制
```

---

## RSA

`jinguissl_core.crypto.rsa` 提供 RSA 密钥生成与签名。

### 密钥生成

```cangjie
import jinguissl_core.crypto.rsa.*

// 生成 2048 位密钥对
let (privateKey, publicKey) = rsaGenerateKey(2048)
```

### 从十六进制加载密钥

```cangjie
let pubKey = rsaPublicKeyFromHex(modulusHex, exponentHex)
let privKey = rsaPrivateKeyFromHex(modulusHex, exponentHex, privateExponentHex)
```

### PKCS1v1.5 签名

```cangjie
let digest = sha256(message)
let signature = rsaSignPkcs1v15(privateKey, digest)
let valid = rsaVerifyPkcs1v15(publicKey, digest, signature)
```

### PKCS1v1.5 含哈希算法标识

```cangjie
let sig = rsaSignPkcs1v15WithHash(privateKey, RsaHashAlgorithm.SHA256, message)
let valid = rsaVerifyPkcs1v15WithHash(publicKey, RsaHashAlgorithm.SHA256, message, sig)
```

### PSS 签名

```cangjie
let sig = rsaSignPss(privateKey, digest)
let valid = rsaVerifyPss(publicKey, digest, sig)
```

### 算法枚举

```cangjie
enum RsaHashAlgorithm { SHA256, SHA384, SHA512 }
enum RsaSignatureScheme { PKCS1v15, PSS }
```

---

## ECC (椭圆曲线密码学)

`jinguissl_core.crypto.ecc` 提供 ECDSA 签名和 ECDH 密钥协商。

### 支持的曲线

| 曲线 | 名称 | FIPS |
|:--|:--|:--|
| P256 | prime256v1 | 是 |
| P384 | secp384r1 | 是 |
| P521 | secp521r1 | 是 |
| secp256k1 | secp256k1 | 否 |

### ECDSA 签名

```cangjie
import jinguissl_core.crypto.ecc.*
import jinguissl_core.crypto.bignum.BigNum

let curve = NamedCurve.P256
let d = BigNum.fromHex("私钥十六进制")
let privateKey = EcPrivateKey(curve, d)
let publicKey = ecPublicFromPrivateKey(privateKey)

let digest = sha256("message".toArray())
let (r, s) = ecdsaSign(privateKey, digest)
let valid = ecdsaVerify(publicKey, digest, r, s)
```

### ECDH 密钥协商

```cangjie
let sharedSecret = ecdhDeriveSharedSecret(myPrivateKey, peerPublicKey)
```

### 曲线文本解析

```cangjie
let curve = namedCurveFromText("P256")  // 不区分大小写
let fips = isFipsCurve(curve)          // 是否为 FIPS 曲线
requireFipsCurve(curve)                // 非 FIPS 曲线时抛出异常
```

---

## Ed25519

`jinguissl_core.crypto.ed25519` 提供 Ed25519 签名。

### 常量

| 常量 | 值 |
|:--|:--|
| `ED25519_SEED_LEN` | 32 |
| `ED25519_PUBLIC_KEY_LEN` | 32 |
| `ED25519_SIGNATURE_LEN` | 64 |

### 密钥生成

```cangjie
import jinguissl_core.crypto.ed25519.*

// 生成随机私钥种子
let seed = ed25519GeneratePrivateKeySeed()
// 派生公钥
let publicKey = ed25519PublicKeyFromSeed(seed)
```

### 签名与验签

```cangjie
let message = "message".toArray()
let signature = ed25519Sign(seed, message)
let valid = ed25519Verify(publicKey, message, signature)
```

---

## X25519

`jinguissl_core.crypto.x25519` 提供 X25519 ECDH 密钥协商。

### 常量

| 常量 | 值 |
|:--|:--|
| `X25519_KEY_LEN` | 32 |
| `X25519_SHARED_SECRET_LEN` | 32 |

### 密钥生成与协商

```cangjie
import jinguissl_core.crypto.x25519.*

let alicePriv = x25519GeneratePrivateKey()
let alicePub = x25519PublicFromPrivate(alicePriv)

let bobPriv = x25519GeneratePrivateKey()
let bobPub = x25519PublicFromPrivate(bobPriv)

let aliceShared = x25519DeriveSharedSecret(alicePriv, bobPub)
let bobShared = x25519DeriveSharedSecret(bobPriv, alicePub)
// aliceShared == bobShared
```

### 密钥钳制

```cangjie
let clampedKey = x25519ClampPrivateKey(rawKey)
```
