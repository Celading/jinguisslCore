# 算法许可与 FIPS-oriented Policy Profile

`jinguissl_core.crypto.compliance` 提供算法许可、TLS 版本与
FIPS-oriented profile 检查。它用于组织调用侧策略，不构成 FIPS 140
密码模块认证、实验室验证或合规证明。

## FipsProfile

FIPS Profile 控制允许使用的密码算法集合。

### 默认 Profile

```cangjie
import jinguissl_core.crypto.compliance.FipsProfile

let profile = FipsProfile.phase1Default()
```

默认允许的算法：
- SHA-256, SHA-384, SHA-512
- HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512
- AES-CTR, AES-CBC, AES-GCM
- RSA, ECDSA, ECDH
- RSA-KEM, ECDH-KEM
- TLS1.2, TLS1.3

### 从文本创建

```cangjie
let text = "SHA-256\nAES-GCM\n# 注释行\nTLS1.3"
let profile = FipsProfile.fromText(text)
```

支持 `#` 注释、逗号分隔、空白行。

### 算法检查

```cangjie
import jinguissl_core.crypto.compliance.requireAllowed

// 检查算法是否允许（不匹配时抛出 ComplianceRejected）
requireAllowed("SHA-256")

// 或使用 profile 实例检查
profile.requireAllowed("AES-GCM")
```

## TLS 版本

```cangjie
import jinguissl_core.crypto.compliance.{TlsVersion, TLS_VERSION_1_2, TLS_VERSION_1_3}

match (version) {
    case TLS_VERSION_1_2 => println("TLS 1.2")
    case TLS_VERSION_1_3 => println("TLS 1.3")
}
```

## 模块级策略检查

各密码模块提供对应的合规检查函数：

```cangjie
// AES
requireAesAllowed(profile, mode)

// ChaCha20-Poly1305
requireChacha20Poly1305Allowed(profile)

// RSA
rsaRequireAllowed(profile)

// ECDSA / ECDH
ecdsaRequireAllowed(profile)
ecdhRequireAllowed(profile)

// KEM
ecdhKemRequireAllowed(profile)
rsaKemRequireAllowed(profile)
```

这些函数只能证明输入符合当前代码中的 profile 规则。最终算法选择、密钥管理、
运行环境、模块边界和认证状态仍需由部署方单独核对。
