# DTLS 1.2 association

The pure-Cangjie `jinguissl_core.crypto.dtls.DtlsAssociation` owns handshake,
identity copy, record counters, replay window, retransmission and authentication
state. Application consumers should use `jinguissl.contract.ContractDtlsSession`.
The lower-level mutable protocol structs remain construction/testing primitives;
do not expose them as application authentication authorities.

Supported profile: DTLS 1.2, X25519, ECDSA-P256/SHA-256,
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, mandatory extended master secret, and
RFC 5764 SRTP key export. Independently verified SRTP profiles are 7 and 1.
Server mode requires a client certificate and CertificateVerify. Client mode
authenticates the server and sends client proof when requested. Trust is an
explicit SHA-256 certificate fingerprint obtained through authenticated signaling,
not PKIX, hostname validation or an implicit system trust store.

Create `DtlsIdentity` from matching PKCS#8 PEM + DER, or generate a self-signed
P-256 identity. Each association clones it. Supply one canonical peer endpoint
binding of 1–64 bytes. The transport owner must demultiplex datagrams consistently.
Use `start`, `receive`, `onTimeout` with monotonic milliseconds, then drain
`takeOutput`. Poll timers at least every 200 ms while negotiating. A returned
array is one UDP datagram; fragmented handshake messages use bounded reassembly.
Retransmission uses fresh record sequence numbers and unchanged handshake sequence
numbers/transcript bytes. One-second initial timeout backs off with a retry limit.

Before `authenticated`, application data and exporter access are rejected. After
authentication, `exportSrtp` returns caller-owned client/server key and salt copies.
Callers must erase exported copies when finished. `closeNotify` queues a protected
alert after any pending final flight and then retires secrets; `takeOutput` remains
drainable after close. UDP close delivery is not guaranteed. `close` retires locally.
Managed-runtime wiping is best-effort, including no erasure claim for BigNum copies.

No PSK, resumption, renegotiation, CID, DTLS 1.3, RTP/SRTP packets, SCTP, SDP or ICE.
The handshake budget is 64 KiB per message, at most nine in-flight reassemblies,
256 KiB transcript and 128 records per outbound flight. Application records accept
up to 16 KiB; applications must separately respect UDP path MTU.

## Reproduce independent evidence

Build `examples/dtls-peer`, then run `python3 scripts/dtls_openssl_interop.py`
with `CANGJIE_HOME` set to the build SDK and OpenSSL on PATH (or `--openssl`).
The runner uses ephemeral P-256 certificates and loopback UDP, testing both roles
and SRTP profiles 7/1, mutual private-key proof, Finished, application records and
byte-exact exporter equality. OpenSSL is a test-only reference, never a runtime
backend. The diagnostic can print ephemeral exporter bytes; do not use production
keys with it. CI runs the same test for its configured LTS, STS and nightly lanes.

Normative references: [DTLS 1.2](https://www.rfc-editor.org/rfc/rfc6347),
[DTLS-SRTP](https://www.rfc-editor.org/rfc/rfc5764),
[extended master secret](https://www.rfc-editor.org/rfc/rfc7627), and
[AES-GCM TLS records](https://www.rfc-editor.org/rfc/rfc5288).
