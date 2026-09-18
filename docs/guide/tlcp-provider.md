# Experimental TLCP 1.1 provider

`TlcpIdentity`, `TlcpProviderPolicy` and `TlcpSession` implement a pure-Cangjie,
transport-independent full handshake. The caller owns a reliable byte stream,
certificate-validation wall time and monotonic millisecond clock. Applications
should consume the corresponding `ContractTlcp*` API through JinguiSSL.

Supported suites are `E011`, `E013`, `E051`, `E053`: SM2 ECDHE/static ECC ×
SM4-CBC/GCM with SM3. Both client and server roles are implemented. ECDHE requires
client and server dual identities; static ECC can authenticate only the server,
or both peers when `requireClientCertificate` is true.

## Ownership and authentication

1. Construct `TlcpIdentity` with distinct signing/encryption certificates, their
   matching 32-byte private scalars and optional intermediate certificates.
2. Construct `TlcpSession` with explicit trust anchors and certificate validation
   time. Clients must supply the expected peer DNS name. The session copies the
   identity; destroying the original does not revoke existing sessions.
3. Call `start(nowMs)`, drain `takeOutput()` in order, then feed received bytes to
   `receive(bytes, nowMs)`. Send every returned output record before application
   writes. Call `onTimeout(nowMs)` even when the network is idle.
4. `handshakeComplete` means Finished was verified. `peerAuthenticated` also
   requires verified peer credentials. A static-ECC server allowing anonymous
   clients can complete with `peerAuthenticated == false`.
5. Only after completion, use `sealApplicationData()` and plaintext returned by
   `receive()`. Certificates exposed by `peerCertificateHandshake()` are snapshots.
6. Drain `closeNotify()` output before closing the transport. Report EOF through
   `endOfInput()`; EOF without authenticated peer close is a truncation refusal.
   `close()` is idempotent and aborts locally; pending output remains drainable.

Handshake timeout is 1–120000 ms (default 30000). Input chunks are at most 65536
bytes; buffered records 83973, handshake messages 262144, transcript 1048576 and
queued output 262144 bytes. Split larger network reads and drain output regularly.
Clock rollback, malformed ordering, invalid certificates/signatures/Finished,
record authentication failures and budget exhaustion fail closed.

Handshake secrets retire after Finished; traffic keys retire on close/failure.
Destruction overwrites owned byte buffers, not caller copies or managed BigNum
temporaries. Methods on a session are serialized; low-level record primitives
remain caller-serialized. This is not a constant-time or complete-erasure claim.

## Independent replay

Reference: official [openHiTLS](https://github.com/openHiTLS/openHiTLS/tree/586d8aa6e8581a23a202d107e0e2af8087c18829)
at `586d8aa6e8581a23a202d107e0e2af8087c18829`, built without source changes.
`scripts/tlcp_reference_peer.c` is a test-only socket adapter calling its public
API. OpenSSL 3 generates fresh CA and distinct dual-certificate fixtures. Neither
native library is a JinguiSSL runtime dependency.

```sh
git clone https://github.com/openHiTLS/openHiTLS.git reference-openhitls
git -C reference-openhitls checkout --detach 586d8aa6e8581a23a202d107e0e2af8087c18829
bash scripts/tlcp_build_reference.sh reference-openhitls
(cd examples/tlcp-peer && cjpm build -j1)
python3 scripts/tlcp_openhitls_interop.py \
  --binary examples/tlcp-peer/target/release/bin/main \
  --reference reference-openhitls/build/tlcp-reference-peer --openssl openssl
```

The local macOS arm64 STS 1.1.3 replay passed all eight suite/role combinations,
with both peers verifying certificates and exchanging application bytes in both
directions. A separate Contract-only consumer passed the same eight combinations.
CI repeats this test in the existing LTS/STS/nightly lanes; local results are not
a hosted-CI result. The runner does not claim external close-notify or negative
attack coverage; those cases have local regression tests.

The independent replay corrected the ECDHE ClientKeyExchange curve prefix and
SM2 exchange role ordering (TLCP server is the SM2 initiator). Secure-renegotiation
SCSV/empty initial extension and fresh server session IDs are accepted during full
handshakes; no renegotiation or resumption is implemented.

## Explicit limits

No ALPN, HTTP/2, session resumption, renegotiation, early data, automatic protocol
downgrade, socket pool, HTTP parser or certification. Requested unsupported policy
features throw `TlcpProviderException` with a stable reason. Alert numbers are
suggested wire mappings, not proof that a caller transmitted an alert.
HTTP/1.1 use requires an explicit application policy outside the provider; do not
invent an ALPN result. DTLCP remains a separate local primitive surface and has
no external-interoperability claim from this test.
