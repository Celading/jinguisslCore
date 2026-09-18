# BLAKE2s, HChaCha20 and extended-nonce AEAD

`jinguissl_core.crypto.digest` supplies `blake2s(input, key: [], digestLength: 32)`
and the serialized `Blake2sContext`. The sequential construction follows
[RFC 7693](https://www.rfc-editor.org/rfc/rfc7693). Digest size is 1..32 and key
size is 0..32 bytes; empty key means unkeyed hash. Native short digest length is
not truncation. `finalDigest()` finalizes once and destroys owned mutable state;
`destroy()` is idempotent. Runtime copies are not guaranteed erased.

`jinguissl_core.crypto.chacha20` supplies `hchacha20(key, nonce16)` and
`xchacha20Poly1305Encrypt/Decrypt(key, nonce24, ...)` with 32-byte keys and
16-byte AEAD tags, following
[draft-irtf-cfrg-xchacha-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03).
XChaCha remains a draft construction, not a finalized RFC or certification.
Nonce uniqueness and protocol replay policy belong to callers. The runtime is
pure Cangjie and reuses the existing ChaCha20/Poly1305 implementation.

Validation includes the RFC BLAKE2s `abc` digest, independent hashlib keyed and
variable-length vectors at block boundaries, bytewise streaming, draft HChaCha
and XChaCha AEAD vectors, invalid parameters, lifecycle and tampering rejection.
These primitives do not implement the WireGuard protocol or certify timing behavior.

Applications and protocol libraries can use the equivalent owned public
interfaces in JinguiSSLContract without importing Core directly.
