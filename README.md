# JinguiSSL-core

`JinguiSSL-core` 是 Jingui family 未来的 core sibling project target。

## Current State

- `foundation packet landed`
- `post-foundation continuation method frozen in family shared memory`
- `compat.bn + crypto.bignum seam packet landed`
- current shape:
  - `core foundation + first algorithm seam` extracted into a buildable static package
  - current extracted core surface covers:
    - `jinguissl.crypto.error`
    - `jinguissl.crypto.base`
    - `jinguissl.crypto.utils`
    - `jinguissl.compat.bn`
    - `jinguissl.crypto.bignum`
  - target-local tests now cover:
    - `CryptoErrorCode / CryptoException`
    - `SecureBytes / ByteBuffer`
    - endian conversion / secure copy / secure zero / constant-time compare
    - random-seed / CSPRNG availability boundary
    - `BN_*` wrapper seam
    - focused `BigNum` arithmetic / gcd / modSqrt / boundary failures

## Intended Scope

- `src/jinguissl/crypto/**`
- `src/jinguissl/compat/**`
- algorithm primitives
- TLS / SSH / X.509 low-level implementation
- record / handshake / session-state core
- backend and performance-sensitive internals

## Current Extraction Boundary

当前 landed surface 目前覆盖 `core foundation + compat.bn + crypto.bignum seam`：

- `CryptoErrorCode`
- `CryptoException`
- `Endian`
- `SecureBytes`
- `ByteBuffer`
- `BN`
- `BN_new()`
- `BN_bin2bn()`
- `BN_bn2bin()`
- `BN_add()`
- `BN_sub()`
- `BN_mul()`
- `BN_div()`
- `BN_mod()`
- `BN_exp()`
- `BN_mod_exp()`
- `BN_mod_inverse()`
- `BN_lshift()`
- `BN_rshift()`
- `BigNum`
- `BigNum.fromHex()`
- `BigNum.fromBytesBE()`
- `BigNum.toBytesBE()`
- `BigNum.toHex()`
- `BigNum.add()/sub()/mul()/divMod()/mod()/exp()/modExp()/modInverse()`
- `BigNum.lshift()/rshift()/cmp()/gcd()/modSqrt()`
- `bytesToUInt32BE()`
- `bytesToUInt32LE()`
- `uInt32ToBytesBE()`
- `uInt32ToBytesLE()`
- `secureCopy()`
- `secureCopyInto()`
- `secureZero()`
- `constantTimeEquals()`
- `randomSeed()`
- `csprngBytes()`
- `csprngIsAvailable()`

这轮继续明确不做：

- `AES / digest / ECC / RSA / Ed25519 / X25519 / KEM`
- `TLS / SSH / X.509`
- whole `src/jinguissl/crypto/**` rehome
- old live source 退役

## Current Continuation Hint

当前 next-packet guidance 继续保持最小化表达：

- recommended next candidate:
  - `digest`
- fallback candidate:
  - `symmetric / compliance / perf`

这段提示只用于帮助下一次 code packet continuation，
不把 internal `_helper` issue / audit / changelog 带进 target code area。

## Current Package Topology

当前 target-local package topology 为：

- `jinguissl_core`
- `jinguissl_core.jinguissl`
- `jinguissl_core.jinguissl.crypto`
- `jinguissl_core.jinguissl.crypto.error`
- `jinguissl_core.jinguissl.crypto.base`
- `jinguissl_core.jinguissl.crypto.utils`
- `jinguissl_core.jinguissl.compat`
- `jinguissl_core.jinguissl.compat.bn`
- `jinguissl_core.jinguissl.crypto.bignum`
- `jinguissl_core.jinguissl.tests`

## Current Live Source

当前真实源码 owner 仍在：

- `/Users/cinyu/Documents/Work0/CureateX/jinkuiSSL/jinguiSSL`

## Validation

当前目标完成判据为：

```bash
cjpm build
cjpm test
```

latest verified result:

- `TOTAL: 15`
- `PASSED: 15`
- `FAILED: 0`

## Notes

- 这不是 whole-core migration。
- 当前 lane 仍然不是 whole-core migration；它只是把 `foundation -> compat.bn + crypto.bignum seam` 继续向前推进了一张 issue-sized packet。
- 下一张 packet 仍应保持 issue-sized，不要把 `AES / digest / ecc / tls` 一次性打包。
