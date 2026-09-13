package jinguissl_core.crypto.dtls

import std.net.*
import std.time.*
import std.sync.*
import std.collection.ArrayList
import std.overflow.*
import jinguissl_core.crypto.x25519.{x25519GeneratePrivateKey, x25519PublicFromPrivate, x25519DeriveSharedSecret, x25519ValidatePublicKey, X25519_KEY_LEN}
import jinguissl_core.crypto.digest.{hmac, sha256, HashAlgorithm}
import jinguissl_core.crypto.aes.{aesGcmEncryptIntoWithContext, aesGcmDecryptIntoWithContext, aesNewGcmContext}
import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}
import jinguissl_core.crypto.x509.{x509ParseDer, x509ExtractEcPublicKey}
import jinguissl_core.crypto.ecc.{EcPublicKey, ecdsaVerify}
import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.digest.bytesToHexLower

// ============================================================================
// TLS 1.2 PRF (PRF_SHA256) — proper P_SHA256 expansion
// ============================================================================

/// TLS 1.2 PRF using HMAC-SHA256 (RFC 5246 Section 5)
public func dtlsPrf(secret: Array<Byte>, label: String, seed: Array<Byte>,
    length: Int64): Array<Byte> {
    let labelBytes = label.toArray()
    let labelSeed = Array<Byte>(labelBytes.size + seed.size, repeat: 0)
    for (i in 0..labelBytes.size) { labelSeed[i] = labelBytes[i] }
    for (i in 0..seed.size) { labelSeed[labelBytes.size + i] = seed[i] }

    // A(0) = label_seed
    var a = hmac(HashAlgorithm.SHA256, secret, labelSeed)
    let result = ArrayList<Byte>()

    while (result.size < length) {
        // P_hash = HMAC-SHA256(secret, A(i) || label_seed)
        let input = Array<Byte>(a.size + labelSeed.size, repeat: 0)
        for (i in 0..a.size) { input[i] = a[i] }
        for (i in 0..labelSeed.size) { input[a.size + i] = labelSeed[i] }
        let p = hmac(HashAlgorithm.SHA256, secret, input)
        for (b in p) { result.add(b) }
        // A(i+1) = HMAC-SHA256(secret, A(i))
        a = hmac(HashAlgorithm.SHA256, secret, a)
    }

    let out = Array<Byte>(length, repeat: 0)
    for (i in 0..length) { out[i] = result[i] }
    out
}

// ============================================================================
// DTLS ECDHE Key Exchange State
// ============================================================================

public class DtlsEcdheKeyExchange {
    public var privateKey: Array<Byte>
    public var publicKey: Array<Byte>
    public var peerPublicKey: ?Array<Byte> = None
    public var sharedSecret: ?Array<Byte> = None

    public init() {
        this.privateKey = x25519GeneratePrivateKey()
        this.publicKey = x25519PublicFromPrivate(privateKey)
    }

    /// Process peer's public key and derive shared secret.
    public func processPeerPublicKey(peerPub: Array<Byte>): Array<Byte> {
        x25519ValidatePublicKey(peerPub)
        peerPublicKey = peerPub
        let secret = x25519DeriveSharedSecret(privateKey, peerPub)
        sharedSecret = secret
        secret
    }

    public func hasSharedSecret(): Bool {
        match (sharedSecret) {
            case Some(_) => true
            case None => false
        }
    }
}

// ============================================================================
// DTLS 1.2 Master Secret Derivation (RFC 5246 Section 8.1)
// ============================================================================

/// Derive master secret from pre-master secret and client/server randoms.
/// master_secret = PRF(pre_master_secret, "master secret",
///                      client_random || server_random)[0..48]
public func dtlsDeriveMasterSecret(preMasterSecret: Array<Byte>,
    clientRandom: Array<Byte>, serverRandom: Array<Byte>): Array<Byte> {
    let seed = Array<Byte>(clientRandom.size + serverRandom.size, repeat: 0)
    for (i in 0..clientRandom.size) { seed[i] = clientRandom[i] }
    for (i in 0..serverRandom.size) { seed[clientRandom.size + i] = serverRandom[i] }
    dtlsPrf(preMasterSecret, "master secret", seed, 48)
}

/// Derive keying material from master secret (RFC 5246 Section 6.3 + RFC 5764)
/// key_block = PRF(master_secret, "key expansion",
///                  server_random || client_random)
public func dtlsDeriveKeyBlock(masterSecret: Array<Byte>,
    clientRandom: Array<Byte>, serverRandom: Array<Byte>,
    length: Int64): Array<Byte> {
    // Note: for key expansion, seed = server_random || client_random (reversed!)
    let seed = Array<Byte>(serverRandom.size + clientRandom.size, repeat: 0)
    for (i in 0..serverRandom.size) { seed[i] = serverRandom[i] }
    for (i in 0..clientRandom.size) { seed[serverRandom.size + i] = clientRandom[i] }
    dtlsPrf(masterSecret, "key expansion", seed, length)
}

// ============================================================================
// DTLS-SRTP Keying Material Extraction (RFC 5764 Section 4.2)
// ============================================================================

/// Extract DTLS-SRTP keying material using the proper TLS 1.2 PRF.
/// keying_material = PRF(master_secret, "EXTRACTOR-dtls_srtp",
//                        client_random || server_random)
public func dtlsSrtpExtractKeyingMaterialProper(masterSecret: Array<Byte>,
    clientRandom: Array<Byte>, serverRandom: Array<Byte>,
    profile: DtlsSrtpProtectionProfile): DtlsSrtpKeyingMaterial {
    let seed = Array<Byte>(clientRandom.size + serverRandom.size, repeat: 0)
    for (i in 0..clientRandom.size) { seed[i] = clientRandom[i] }
    for (i in 0..serverRandom.size) { seed[clientRandom.size + i] = serverRandom[i] }

    let totalLen = profile.keyLen() * 2 + profile.saltLen() * 2
    let material = dtlsPrf(masterSecret, "EXTRACTOR-dtls_srtp", seed, totalLen)

    let keyLen = profile.keyLen()
    let saltLen = profile.saltLen()
    let clientKey = Array<Byte>(keyLen, repeat: 0)
    let serverKey = Array<Byte>(keyLen, repeat: 0)
    let clientSalt = Array<Byte>(saltLen, repeat: 0)
    let serverSalt = Array<Byte>(saltLen, repeat: 0)

    var offset = 0
    for (i in 0..keyLen) { clientKey[i] = material[offset + i] }
    offset += keyLen
    for (i in 0..keyLen) { serverKey[i] = material[offset + i] }
    offset += keyLen
    for (i in 0..saltLen) { clientSalt[i] = material[offset + i] }
    offset += saltLen
    for (i in 0..saltLen) { serverSalt[i] = material[offset + i] }

    DtlsSrtpKeyingMaterial(clientKey, serverKey, clientSalt, serverSalt, profile)
}

// ============================================================================
// DTLS 1.2 Key Block (client/server write key + IV for AEAD)
// ============================================================================

public class DtlsKeyBlock {
    public let clientWriteKey: Array<Byte>
    public let serverWriteKey: Array<Byte>
    public let clientWriteIv: Array<Byte>
    public let serverWriteIv: Array<Byte>

    public init(clientWriteKey: Array<Byte>, serverWriteKey: Array<Byte>,
        clientWriteIv: Array<Byte>, serverWriteIv: Array<Byte>) {
        this.clientWriteKey = clientWriteKey
        this.serverWriteKey = serverWriteKey
        this.clientWriteIv = clientWriteIv
        this.serverWriteIv = serverWriteIv
    }
}

/// Derive AEAD key block: 2 * (key_len + iv_len) bytes
/// For AES-128-GCM: key=16, IV=4 (explicit nonce is 8 bytes from record seq)
public func dtlsDeriveAeadKeyBlock(masterSecret: Array<Byte>,
    clientRandom: Array<Byte>, serverRandom: Array<Byte>,
    keyLen: Int64, ivLen: Int64): DtlsKeyBlock {
    let totalLen = keyLen * 2 + ivLen * 2
    let keyBlock = dtlsDeriveKeyBlock(masterSecret, clientRandom, serverRandom, totalLen)

    let clientKey = Array<Byte>(keyLen, repeat: 0)
    let serverKey = Array<Byte>(keyLen, repeat: 0)
    let clientIv = Array<Byte>(ivLen, repeat: 0)
    let serverIv = Array<Byte>(ivLen, repeat: 0)

    var offset = 0
    for (i in 0..keyLen) { clientKey[i] = keyBlock[offset + i] }
    offset += keyLen
    for (i in 0..keyLen) { serverKey[i] = keyBlock[offset + i] }
    offset += keyLen
    for (i in 0..ivLen) { clientIv[i] = keyBlock[offset + i] }
    offset += ivLen
    for (i in 0..ivLen) { serverIv[i] = keyBlock[offset + i] }

    DtlsKeyBlock(clientKey, serverKey, clientIv, serverIv)
}

// ============================================================================
// DTLS Record AEAD Encrypt/Decrypt (AES-128-GCM)
// ============================================================================
//
// Per RFC 6347 §4.1 and RFC 5116, the AEAD nonce and AAD for a DTLS 1.2
// record MUST be derived from the authenticated record header fields:
//
//   nonce  = write_iv (4 bytes) || explicit_nonce (8 bytes)
//            where explicit_nonce = epoch (2 bytes) || seq_num (6 bytes)
//
//   AAD    = epoch (2) || seq_num (6) || content_type (1) ||
//            version (2) || plaintext_length (2)   = 13 bytes
//
// The decrypt path MUST:
//   1. parse the explicit nonce from the ciphertext blob
//   2. use the transmitted explicit nonce (RFC 5288 allows other unique values)
//   3. derive the AAD from the parsed record header only — never from a
//      caller-supplied buffer
//
// Any mismatch is a fatal CryptoException(InvalidArgument). No partial
// state escapes on failure.
// ============================================================================

/// Build the 12-byte AEAD nonce for DTLS 1.2:
/// IV (4 bytes) || explicit nonce (8 bytes from epoch || seq_num)
public func dtlsBuildAeadNonce(iv: Array<Byte>, epoch: UInt16,
    seqNum: UInt48): Array<Byte> {
    if (iv.size != 4) {
        throw CryptoException(CryptoErrorCode.InvalidArgument, "DTLS GCM fixed IV must be four bytes")
    }
    let nonce = Array<Byte>(12, repeat: 0)
    for (i in 0..iv.size) {
        if (i < 12) { nonce[i] = iv[i] }
    }
    // Explicit nonce: epoch (2 bytes) || sequence number (6 bytes)
    let seq64 = seqNum.toUInt64()
    nonce[4] = UInt8((epoch >> 8) & 0xFF)
    nonce[5] = UInt8(epoch & 0xFF)
    nonce[6] = UInt8((seq64 >> 40) & 0xFF)
    nonce[7] = UInt8((seq64 >> 32) & 0xFF)
    nonce[8] = UInt8((seq64 >> 24) & 0xFF)
    nonce[9] = UInt8((seq64 >> 16) & 0xFF)
    nonce[10] = UInt8((seq64 >> 8) & 0xFF)
    nonce[11] = UInt8(seq64 & 0xFF)
    nonce
}

/// Derive the 8-byte explicit nonce (epoch || seq_num) that the encrypt
/// path embeds in the ciphertext blob and the decrypt path must verify.
public func dtlsBuildExplicitNonce(epoch: UInt16, seqNum: UInt48): Array<Byte> {
    let out = Array<Byte>(8, repeat: 0)
    let seq64 = seqNum.toUInt64()
    out[0] = UInt8((epoch >> 8) & 0xFF)
    out[1] = UInt8(epoch & 0xFF)
    out[2] = UInt8((seq64 >> 40) & 0xFF)
    out[3] = UInt8((seq64 >> 32) & 0xFF)
    out[4] = UInt8((seq64 >> 24) & 0xFF)
    out[5] = UInt8((seq64 >> 16) & 0xFF)
    out[6] = UInt8((seq64 >> 8) & 0xFF)
    out[7] = UInt8(seq64 & 0xFF)
    out
}

/// Derive the 13-byte AAD from the authenticated record header fields.
/// Per RFC 6347 §4.1 the AAD is:
///   epoch (2) || seq_num (6) || content_type (1) ||
///   version (2) || plaintext_length (2)
///
/// `plaintextLength` is the length of the plaintext that was encrypted
/// (i.e. the ciphertext length, since AEAD does not expand plaintext).
public func dtlsBuildAeadAad(epoch: UInt16, seqNum: UInt48,
    contentType: DtlsContentType, version: UInt16,
    plaintextLength: Int64): Array<Byte> {
    // bound plaintextLength against DTLS_MAX_PLAINTEXT_LEN so
    // the AAD length field (2 bytes) cannot overflow and the ciphertext
    // boundary is provably exact.
    if (plaintextLength < 0 || plaintextLength > DTLS_MAX_PLAINTEXT_LEN) {
        throw CryptoException(CryptoErrorCode.InvalidArgument,
            "DTLS AEAD plaintext length out of range: " + plaintextLength.toString())
    }
    let out = Array<Byte>(13, repeat: 0)
    out[0] = UInt8((epoch >> 8) & UInt16(0xFF))
    out[1] = UInt8(epoch & UInt16(0xFF))
    let seq64 = seqNum.toUInt64()
    out[2] = UInt8((seq64 >> 40) & 0xFF)
    out[3] = UInt8((seq64 >> 32) & 0xFF)
    out[4] = UInt8((seq64 >> 24) & 0xFF)
    out[5] = UInt8((seq64 >> 16) & 0xFF)
    out[6] = UInt8((seq64 >> 8) & 0xFF)
    out[7] = UInt8(seq64 & 0xFF)
    out[8] = UInt8(contentType.toUInt8())
    out[9] = UInt8((version >> 8) & UInt16(0xFF))
    out[10] = UInt8(version & UInt16(0xFF))
    let len16 = UInt16(plaintextLength)
    out[11] = UInt8((len16 >> 8) & UInt16(0xFF))
    out[12] = UInt8(len16 & UInt16(0xFF))
    out
}

/// Verify that the explicit nonce parsed from the ciphertext blob matches
/// the epoch || seq_num derived from the authenticated record header.
/// Throws CryptoException(InvalidArgument) on mismatch — this is the
/// optional local sequence-derived nonce policy; not required of peers by RFC 5288.
public func dtlsVerifyExplicitNonce(expected: Array<Byte>, actual: Array<Byte>): Unit {
    if (expected.size != 8 || actual.size != 8) {
        throw CryptoException(CryptoErrorCode.InvalidArgument,
            "explicit nonce size mismatch: expected " + expected.size.toString() +
            " actual " + actual.size.toString())
    }
    for (i in 0..8) {
        if (expected[i] != actual[i]) {
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "DTLS explicit nonce / header mismatch at byte " + i.toString() +
                ": expected 0x" + expected[i].toString() +
                " got 0x" + actual[i].toString())
        }
    }
}

/// DTLS record AEAD encrypt.
///
/// The nonce is derived from (writeIv, epoch, seqNum). The AAD is derived
/// from (epoch, seqNum, contentType, version, plaintext.size). The caller
/// must supply the actual outgoing header fields and a never-reused sequence.
///
/// Output layout: explicit_nonce (8 bytes) || ciphertext || tag (16 bytes).
public func dtlsAeadEncrypt(writeKey: Array<Byte>, writeIv: Array<Byte>,
    epoch: UInt16, seqNum: UInt48,
    contentType: DtlsContentType, version: UInt16,
    plaintext: Array<Byte>): Array<Byte> {
    // exact plaintext boundary. plaintext.size MUST be in
    // [0, DTLS_MAX_PLAINTEXT_LEN]; the resulting ciphertext blob is
    //   explicit_nonce(8) || ciphertext(=plaintext.size) || tag(16)
    // and MUST fit in DTLS_MAX_CIPHERTEXT_LEN. Reject before any
    // allocation so no partial state is produced on rejection.
    if (plaintext.size < 0 || plaintext.size > DTLS_MAX_PLAINTEXT_LEN) {
        throw CryptoException(CryptoErrorCode.InvalidArgument,
            "DTLS AEAD plaintext out of bounds: size=" + plaintext.size.toString() +
            " max=" + DTLS_MAX_PLAINTEXT_LEN.toString())
    }
    let nonce = dtlsBuildAeadNonce(writeIv, epoch, seqNum)
    let aad = dtlsBuildAeadAad(epoch, seqNum, contentType, version,
        plaintext.size)
    let ctx = aesNewGcmContext(writeKey)
    let ciphertext = Array<Byte>(plaintext.size, repeat: 0)
    let tag = Array<Byte>(16, repeat: 0)
    aesGcmEncryptIntoWithContext(ctx, nonce, plaintext, ciphertext, tag,
        aad: aad, tagLen: 16)

    // Output: explicit nonce (8 bytes) || ciphertext || tag
    let explicitNonce = dtlsBuildExplicitNonce(epoch, seqNum)
    let result = Array<Byte>(8 + ciphertext.size + 16, repeat: 0)
    for (i in 0..8) { result[i] = explicitNonce[i] }
    for (i in 0..ciphertext.size) { result[8 + i] = ciphertext[i] }
    for (i in 0..16) { result[8 + ciphertext.size + i] = tag[i] }
    result
}

/// DTLS record AEAD decrypt.
///
/// The explicit nonce comes from the ciphertext blob. AAD authenticates the
/// actual incoming epoch, sequence, type, version and plaintext length.
/// The caller must pass fields from the parsed incoming record.
///
/// Input layout: explicit_nonce (8 bytes) || ciphertext || tag (16 bytes).
public func dtlsAeadDecrypt(readKey: Array<Byte>, readIv: Array<Byte>,
    epoch: UInt16, seqNum: UInt48,
    contentType: DtlsContentType, version: UInt16,
    ciphertextBlob: Array<Byte>): Array<Byte> {
    if (readIv.size != 4) {
        throw CryptoException(CryptoErrorCode.InvalidArgument, "DTLS GCM fixed IV must be four bytes")
    }
    // exact ciphertext boundary. The blob MUST be in
    // [DTLS_MIN_AEAD_CIPHERTEXT_LEN, DTLS_MAX_CIPHERTEXT_LEN], i.e.
    //   24 <= size <= DTLS_MAX_PLAINTEXT_LEN + 8 + 16 = 16408.
    // The lower bound proves explicit-nonce(8)+tag(16) are present; the
    // upper bound proves the plaintext did not exceed the protocol max.
    // Reject before any allocation so no partial state is produced.
    if (ciphertextBlob.size < DTLS_MIN_AEAD_CIPHERTEXT_LEN) {
        throw CryptoException(CryptoErrorCode.InvalidArgument,
            "DTLS AEAD ciphertext too short: " + ciphertextBlob.size.toString() +
            " min=" + DTLS_MIN_AEAD_CIPHERTEXT_LEN.toString())
    }
    if (ciphertextBlob.size > DTLS_MAX_CIPHERTEXT_LEN) {
        throw CryptoException(CryptoErrorCode.InvalidArgument,
            "DTLS AEAD ciphertext too long: " + ciphertextBlob.size.toString() +
            " max=" + DTLS_MAX_CIPHERTEXT_LEN.toString())
    }
    // explicit-nonce length MUST be exactly 8 bytes. The blob
    // layout is fixed, so this is implied by the min-length check above,
    // but assert defensively to fail closed on any future regression.
    // AEAD tag length MUST be exactly 16 bytes. The blob
    // length minus explicit-nonce minus ciphertext must equal 16; this
    // is enforced by the min-length check (size >= 24) and the explicit
    // tag extraction below. A blob whose trailing 16 bytes are not a
    // valid tag will fail AES-GCM verification.
    let actualExplicitNonce = Array<Byte>(8, repeat: 0)
    for (i in 0..8) { actualExplicitNonce[i] = ciphertextBlob[i] }

    // RFC 5288 permits a peer to choose any unique explicit nonce.
    // The record sequence remains independently authenticated in the AAD.

    let ciphertextLen = ciphertextBlob.size - 8 - 16
    let ciphertext = Array<Byte>(ciphertextLen, repeat: 0)
    for (i in 0..ciphertextLen) { ciphertext[i] = ciphertextBlob[8 + i] }
    let tag = Array<Byte>(16, repeat: 0)
    for (i in 0..16) { tag[i] = ciphertextBlob[8 + ciphertextLen + i] }

    // Reconstruct full nonce: IV || explicit nonce (already verified).
    let nonce = Array<Byte>(12, repeat: 0)
    for (i in 0..readIv.size) {
        if (i < 12) { nonce[i] = readIv[i] }
    }
    for (i in 0..8) { nonce[4 + i] = actualExplicitNonce[i] }

    // Derive AAD from the authenticated record header fields only.
    let aad = dtlsBuildAeadAad(epoch, seqNum, contentType, version,
        ciphertextLen)

    let ctx = aesNewGcmContext(readKey)
    let plaintext = Array<Byte>(ciphertextLen, repeat: 0)
    aesGcmDecryptIntoWithContext(ctx, nonce, ciphertext, tag, plaintext,
        aad: aad)
    plaintext
}

// ============================================================================
// Low-level DTLS cryptographic context; not a datagram association or flight driver.
// ============================================================================

public class DtlsHandshakeContext {
    private var exportReady: Bool = false
    private var peerSignatureVerified: Bool = false
    private var peerFinishedVerified: Bool = false
    public var role: DtlsRole
    public var clientRandom: Array<Byte>
    public var serverRandom: Array<Byte>
    public var keyExchange: DtlsEcdheKeyExchange
    public var masterSecret: ?Array<Byte> = None
    public var keyBlock: ?DtlsKeyBlock = None
    public var srtpKeyingMaterial: ?DtlsSrtpKeyingMaterial = None
    public var state: DtlsConnectionState
    public var flightTimer: DtlsFlightTimer
    public var currentFlight: DtlsFlightType
    public var messageSeq: UInt16
    // handshake completion security gate fields
    public var transcriptMessages: ArrayList<Byte>
    public var peerCertDer: ?Array<Byte> = None
    public var expectedFingerprint: ?String = None
    public var finishedVerified: Bool = false
    public var lastFatalAlert: ?DtlsAlert = None

    public init(role: DtlsRole) {
        this.role = role
        this.clientRandom = Array<Byte>(32, repeat: 0)
        this.serverRandom = Array<Byte>(32, repeat: 0)
        this.keyExchange = DtlsEcdheKeyExchange()
        this.state = DtlsConnectionState.Idle
        this.flightTimer = DtlsFlightTimer()
        this.currentFlight = DtlsFlightType.Flight0
        this.messageSeq = UInt16(0)
        this.transcriptMessages = ArrayList<Byte>()
        this.finishedVerified = false
    }

    /// Generate client random (called by client).
    /// Per RFC 6347 §4.1.2 the random field is 32 bytes = 4-byte GMT unix
    /// time + 28-byte random. We store the full 32-byte encoded form in
    /// `clientRandom` so PRF inputs match RFC 5246 §8.1, and the DtlsRandom
    /// constructor only ever sees the 28-byte random part.
    public func generateClientRandom(): Unit {
        let rand = DtlsRandom.generate()
        clientRandom = rand.encode()
    }

    /// Generate server random (called by server). See generateClientRandom.
    public func generateServerRandom(): Unit {
        let rand = DtlsRandom.generate()
        serverRandom = rand.encode()
    }

    /// Set peer's X25519 public key and derive shared secret
    public func processPeerKeyExchange(peerPublicKey: Array<Byte>, sessionHash!: Array<Byte> = []): Unit {
        let preMaster = keyExchange.processPeerPublicKey(peerPublicKey)
        // Derive master secret
        dtlsRequire(sessionHash.size == 0 || sessionHash.size == 32, "invalid DTLS session hash")
        let ms = if (sessionHash.size == 32) {
            dtlsPrf(preMaster, "extended master secret", sessionHash, 48)
        } else { dtlsDeriveMasterSecret(preMaster, clientRandom, serverRandom) }
        masterSecret = ms

        // Derive AEAD key block (AES-128-GCM: key=16, IV=4)
        let kb = dtlsDeriveAeadKeyBlock(ms, clientRandom, serverRandom, 16, 4)
        keyBlock = kb
    }

    /// Extract DTLS-SRTP keying material after handshake
    public func extractSrtpKeyingMaterial(profile: DtlsSrtpProtectionProfile): DtlsSrtpKeyingMaterial {
        if (!exportReady || state != DtlsConnectionState.Established || !finishedVerified) {
            throw CryptoException(CryptoErrorCode.InvalidArgument, "authenticate DTLS before SRTP export")
        }
        match (masterSecret) {
            case Some(ms) =>
                let km = dtlsSrtpExtractKeyingMaterialProper(ms, clientRandom,
                    serverRandom, profile)
                srtpKeyingMaterial = km
                km
            case None =>
                throw CryptoException(CryptoErrorCode.InvalidArgument,
                    "master secret not yet derived")
        }
    }

    /// Check if handshake is complete (master secret + key block derived)
    public func isHandshakeComplete(): Bool {
        match (masterSecret) {
            case Some(_) =>
                match (keyBlock) {
                    case Some(_) => true
                    case None => false
                }
            case None => false
        }
    }

    // ========================================================================
    // Handshake Completion Security Gate
    // ========================================================================
    //
    // The following methods enforce the mandatory security checks that must
    // pass before the connection may transition to Established or export
    // DTLS-SRTP keying material:
    //   - transcript hash accumulation over the full handshake flight sequence
    //   - peer certificate identity + fingerprint policy
    //   - signed ServerKeyExchange verification against the peer certificate
    //   - Finished verify_data validation (both client and server)
    //   - fatal alert emission on any failure path
    // Any failure raises CryptoException and records a fatal DtlsAlert on
    // lastFatalAlert; the caller is expected to map that to a wire Alert
    // record and tear down the session.

    /// Record a reassembled handshake message into the transcript.
    /// RFC 6347: hash the normalized DTLS header including message_seq.
    public func recordHandshakeMessage(msgType: DtlsHandshakeType,
        messageSeq: UInt16, body: Array<Byte>): Unit {
        let len = body.size
        if (len > DTLS_MAX_HANDSHAKE_MSG_LEN) {
            throw CryptoException(CryptoErrorCode.InvalidArgument, "DTLS transcript message exceeds budget")
        }
        let entry = dtlsEncodeHandshakeFragment(DtlsHandshakeFragment(msgType,
            UInt32(len), messageSeq, UInt32(0), UInt32(len), body))
        for (b in entry) {
            transcriptMessages.add(b)
        }
    }

    /// Compute SHA-256 over the accumulated transcript messages.
    public func computeTranscriptHash(): Array<Byte> {
        let buf = Array<Byte>(transcriptMessages.size, repeat: 0)
        var i = 0
        for (b in transcriptMessages) {
            buf[i] = b
            i += 1
        }
        sha256(buf)
    }

    /// Set the peer certificate DER blob (Client sets it after receiving
    /// Server Certificate; Server may set it when Client auth is requested).
    public func setPeerCertificate(certDer: Array<Byte>): Unit {
        if (certDer.size == 0) {
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "peer certificate DER must not be empty")
        }
        peerCertDer = certDer
    }

    /// Set the expected SHA-256 fingerprint of the peer certificate, as a
    /// lowercase hex string (no separators). WebRTC SDP fingerprint format
    /// uses uppercase hex with colon separators; callers must normalize.
    public func setExpectedFingerprint(fp: String): Unit {
        let normalized = fp.trimAscii().toAsciiLower()
        if (normalized.size != 64) {
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "expected fingerprint must be 64 hex chars (SHA-256), got " +
                normalized.size.toString())
        }
        for (b in normalized.toArray()) {
            dtlsRequire((b >= 48 && b <= 57) || (b >= 97 && b <= 102), "invalid SHA-256 fingerprint hex")
        }
        expectedFingerprint = normalized
    }

    /// Verify the peer certificate fingerprint against the expected one.
    /// On success: silent return. On failure: throw + record fatal alert.
    public func verifyPeerCertificateFingerprint(): Unit {
        let der = match (peerCertDer) {
            case Some(d) => d
            case None =>
                recordFatalAlertInternal(DtlsAlertDescription.HandshakeFailure,
                    "peer certificate not set before fingerprint verification")
                throw CryptoException(CryptoErrorCode.InvalidArgument,
                    "peer certificate not set before fingerprint verification")
        }
        let expected = match (expectedFingerprint) {
            case Some(fp) => fp
            case None =>
                recordFatalAlertInternal(DtlsAlertDescription.HandshakeFailure,
                    "expected fingerprint not configured")
                throw CryptoException(CryptoErrorCode.InvalidArgument,
                    "expected fingerprint not configured")
        }
        let actualHash = sha256(der)
        let actual = bytesToHexLower(actualHash)
        if (actual != expected) {
            recordFatalAlertInternal(DtlsAlertDescription.BadCertificate,
                "peer certificate fingerprint mismatch: expected " + expected +
                " got " + actual)
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "peer certificate fingerprint mismatch")
        }
    }

    /// Verify the ECDSA signature over a ServerKeyExchange message body.
    /// Signed content per RFC 4492 4.2 + RFC 5246 7.4.3:
    ///   SHA-256(client_random || server_random || ServerKeyExchange.params)
    /// Signature is the raw (r || s) pair, each 32 bytes for P-256.
    public func verifyServerKeyExchangeSignature(skeBody: Array<Byte>,
        r: BigNum, s: BigNum): Unit {
        if (role != DtlsRole.Client) {
            recordFatalAlertInternal(DtlsAlertDescription.IllegalParameter,
                "verifyServerKeyExchangeSignature called on non-client role")
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "SKE signature verification is client-only")
        }
        let der = match (peerCertDer) {
            case Some(d) => d
            case None =>
                recordFatalAlertInternal(DtlsAlertDescription.HandshakeFailure,
                    "peer certificate not set before SKE signature verification")
                throw CryptoException(CryptoErrorCode.InvalidArgument,
                    "peer certificate not set before SKE signature verification")
        }
        let cert = x509ParseDer(der)
        let pub = x509ExtractEcPublicKey(cert)

        // Build signed content: client_random || server_random || skeBody
        let signed = Array<Byte>(clientRandom.size + serverRandom.size + skeBody.size,
            repeat: 0)
        for (i in 0..clientRandom.size) { signed[i] = clientRandom[i] }
        for (i in 0..serverRandom.size) { signed[clientRandom.size + i] = serverRandom[i] }
        for (i in 0..skeBody.size) {
            signed[clientRandom.size + serverRandom.size + i] = skeBody[i]
        }
        let digest = sha256(signed)
        if (!ecdsaVerify(pub, digest, r, s)) {
            recordFatalAlertInternal(DtlsAlertDescription.HandshakeFailure,
                "ServerKeyExchange signature does not verify against peer certificate")
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "ServerKeyExchange signature verification failed")
        }
        peerSignatureVerified = true
    }

    /** Verify a client's TLS 1.2 CertificateVerify over the current DTLS transcript. */
    public func verifyClientCertificateSignature(r: BigNum, s: BigNum): Unit {
        if (role != DtlsRole.Server) {
            throw CryptoException(CryptoErrorCode.InvalidArgument, "client CertificateVerify is server-only")
        }
        verifyPeerCertificateFingerprint()
        let der = match (peerCertDer) {
            case Some(value) => value
            case None => throw CryptoException(CryptoErrorCode.InvalidArgument, "missing client certificate")
        }
        if (!ecdsaVerify(x509ExtractEcPublicKey(x509ParseDer(der)), computeTranscriptHash(), r, s)) {
            recordFatalAlertInternal(DtlsAlertDescription.HandshakeFailure, "invalid client CertificateVerify")
            throw CryptoException(CryptoErrorCode.InvalidArgument, "invalid client CertificateVerify")
        }
        peerSignatureVerified = true
    }

    /// Compute Finished verify_data for the given label.
    /// RFC 5246 7.4.9:
    ///   verify_data = PRF(master_secret, finished_label,
    ///                     Hash(handshake_messages))[0..verify_data_length-1]
    /// verify_data_length = 12 for DTLS 1.2 (RFC 6347 4.2.6).
    /// finished_label = "client finished" for ClientFinished,
    ///                  "server finished" for ServerFinished.
    public func computeFinishedVerifyData(label: String): Array<Byte> {
        let ms = match (masterSecret) {
            case Some(m) => m
            case None =>
                throw CryptoException(CryptoErrorCode.InvalidArgument,
                    "master secret not derived before computing Finished")
        }
        let transcriptHash = computeTranscriptHash()
        dtlsPrf(ms, label, transcriptHash, 12)
    }

    /// Verify the peer's Finished verify_data. On success, sets
    /// finishedVerified = true. On failure, records a fatal alert.
    /// peerLabel = "server finished" if local role is Client,
    ///           = "client finished" if local role is Server.
    public func verifyPeerFinished(receivedVerifyData: Array<Byte>,
        peerLabel: String): Unit {
        let requiredLabel = if (role == DtlsRole.Client) { "server finished" } else { "client finished" }
        if (peerLabel != requiredLabel) {
            recordFatalAlertInternal(DtlsAlertDescription.HandshakeFailure, "wrong Finished role")
            throw CryptoException(CryptoErrorCode.InvalidArgument, "wrong Finished role")
        }
        if (receivedVerifyData.size != 12) {
            recordFatalAlertInternal(DtlsAlertDescription.HandshakeFailure,
                "peer Finished verify_data length must be 12, got " +
                receivedVerifyData.size.toString())
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "invalid Finished verify_data length")
        }
        let expected = computeFinishedVerifyData(peerLabel)
        var ok = true
        for (i in 0..12) {
            if (expected[i] != receivedVerifyData[i]) {
                ok = false
            }
        }
        if (!ok) {
            recordFatalAlertInternal(DtlsAlertDescription.HandshakeFailure,
                "peer Finished verify_data mismatch")
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "peer Finished verify_data mismatch")
        }
        finishedVerified = true
        peerFinishedVerified = true
    }

    /// Final security gate: all mandatory checks must pass before the
    /// connection may transition to Established and before DTLS-SRTP keying
    /// material may be exported. Throws + records fatal alert on any failure.
    public func finalizeHandshake(): Unit {
        // Gate 1: peer certificate must be set and verified (fingerprint).
        match (peerCertDer) {
            case Some(_) => ()
            case None =>
                recordFatalAlertInternal(DtlsAlertDescription.HandshakeFailure,
                    "finalizeHandshake: peer certificate not set")
                throw CryptoException(CryptoErrorCode.InvalidArgument,
                    "finalizeHandshake: peer certificate not set")
        }
        match (expectedFingerprint) {
            case Some(_) => ()
            case None =>
                recordFatalAlertInternal(DtlsAlertDescription.HandshakeFailure,
                    "finalizeHandshake: expected fingerprint not configured")
                throw CryptoException(CryptoErrorCode.InvalidArgument,
                    "finalizeHandshake: expected fingerprint not configured")
        }
        // Note: verifyPeerCertificateFingerprint() should have been called
        // immediately after setPeerCertificate(); we re-run it here as a
        // defense-in-depth gate.
        verifyPeerCertificateFingerprint()

        // Gate 2: master secret + key block must be derived.
        if (!isHandshakeComplete()) {
            recordFatalAlertInternal(DtlsAlertDescription.HandshakeFailure,
                "finalizeHandshake: master secret / key block not derived")
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "finalizeHandshake: handshake not complete")
        }

        // Gate 3: peer Finished must have been verified.
        if (!finishedVerified || !peerFinishedVerified || !peerSignatureVerified) {
            recordFatalAlertInternal(DtlsAlertDescription.HandshakeFailure,
                "finalizeHandshake: peer Finished not verified")
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "finalizeHandshake: peer Finished not verified")
        }

        // All gates passed: validate state machine transition to Established.
        // dtlsIsValidStateTransition enforces RFC 6347 handshake ordering so
        // we cannot skip security checkpoints by jumping into Established.
        if (!dtlsIsValidStateTransition(role, state,
            DtlsConnectionState.Established)) {
            recordFatalAlertInternal(DtlsAlertDescription.InternalError,
                "finalizeHandshake: illegal state transition " +
                state.toString() + " -> Established for role " +
                role.toString())
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "finalizeHandshake: illegal state transition to Established")
        }
        state = DtlsConnectionState.Established
        exportReady = true
    }

    /// Record a fatal alert on the context and update session state to Failed
    /// if applicable. Does not throw.
    ///
    /// DTLS clean-failure requirement (RFC 6347 §7.2.2 / gate):
    /// any handshake failure MUST leave the connection in a terminal error
    /// state with no residual keys, no residual SRTP material, and no
    /// half-established state. We zeroize all derived secret material on
    /// every fatal alert so a failed handshake cannot leak master secret,
    /// key block, SRTP keys, or the ECDHE shared secret to a later caller.
    /// The context-owned ephemeral X25519 private key is also cleared.
    public func recordFatalAlert(description: DtlsAlertDescription,
        message: String): Unit {
        lastFatalAlert = dtlsFatalAlert(description)
        if (state != DtlsConnectionState.Failed &&
            state != DtlsConnectionState.Closed) {
            state = DtlsConnectionState.Failed
        }
        zeroizeSecrets()
    }

    // Internal helper that records a fatal alert without state mutation noise.
    private func recordFatalAlertInternal(description: DtlsAlertDescription,
        message: String): Unit {
        lastFatalAlert = dtlsFatalAlert(description)
        if (state != DtlsConnectionState.Failed &&
            state != DtlsConnectionState.Closed) {
            state = DtlsConnectionState.Failed
        }
        zeroizeSecrets()
    }

    /// Zeroize all derived secret material so a failed handshake leaves no
    /// residual keys, no residual SRTP material, and no half-established
    /// state. Idempotent: safe to call on an already-failed context.
    private func zeroizeSecrets(): Unit {
        exportReady = false
        peerSignatureVerified = false
        peerFinishedVerified = false
        for (i in 0..keyExchange.privateKey.size) { keyExchange.privateKey[i] = 0 }
        // Zeroize master secret bytes before dropping the reference.
        match (masterSecret) {
            case Some(ms) =>
                for (i in 0..ms.size) { ms[i] = 0 }
                masterSecret = None
            case None => ()
        }
        // Zeroize key block keys/IVs before dropping the reference.
        match (keyBlock) {
            case Some(kb) =>
                for (i in 0..kb.clientWriteKey.size) { kb.clientWriteKey[i] = 0 }
                for (i in 0..kb.serverWriteKey.size) { kb.serverWriteKey[i] = 0 }
                for (i in 0..kb.clientWriteIv.size) { kb.clientWriteIv[i] = 0 }
                for (i in 0..kb.serverWriteIv.size) { kb.serverWriteIv[i] = 0 }
                keyBlock = None
            case None => ()
        }
        // Zeroize SRTP keying material before dropping the reference.
        match (srtpKeyingMaterial) {
            case Some(km) =>
                for (i in 0..km.clientWriteKey.size) { km.clientWriteKey[i] = 0 }
                for (i in 0..km.serverWriteKey.size) { km.serverWriteKey[i] = 0 }
                for (i in 0..km.clientWriteSalt.size) { km.clientWriteSalt[i] = 0 }
                for (i in 0..km.serverWriteSalt.size) { km.serverWriteSalt[i] = 0 }
                srtpKeyingMaterial = None
            case None => ()
        }
        // Zeroize ECDHE shared secret; its ephemeral private key was cleared above.
        match (keyExchange.sharedSecret) {
            case Some(ss) =>
                for (i in 0..ss.size) { ss[i] = 0 }
                keyExchange.sharedSecret = None
            case None => ()
        }
        // Drop peer public key reference; not secret, but clears half-state.
        keyExchange.peerPublicKey = None
        // Clear transcript so a replayed Finished cannot be replayed post-fail.
        transcriptMessages.clear()
        // Reset Finished-verified flag so no caller can read a stale verdict.
        finishedVerified = false
    }

    public func toString(): String {
        "DtlsHandshakeContext(role=" + role.toString() +
        ", state=" + state.toString() +
        ", ecdhe=" + keyExchange.hasSharedSecret().toString() +
        ", masterSecret=" + isHandshakeComplete().toString() + ")"
    }
}

// ============================================================================
// DTLS UDP Transport — real network send/receive of DTLS records
// ============================================================================

public class DtlsUdpTransport {
    public var socket: ?UdpSocket = None
    public var localPort: UInt16 = UInt16(0)

    public init() {
    }

    public func bind(host!: String = "127.0.0.1", port!: UInt16 = UInt16(0)): Unit {
        let addr = IPSocketAddress(IPv4Address.parse(host), port)
        let sock = UdpSocket(bindAt: addr)
        sock.bind()
        socket = sock
        match (sock.localAddress as IPSocketAddress) {
            case Some(ipAddr) => localPort = ipAddr.port
            case None => ()
        }
    }

    public func sendTo(host: String, port: UInt16, data: Array<Byte>): Unit {
        match (socket) {
            case Some(sock) =>
                let addr = IPSocketAddress(IPv4Address.parse(host), port)
                sock.sendTo(addr, data)
            case None => throw CryptoException(CryptoErrorCode.InvalidArgument, "not bound")
        }
    }

    public func receiveFrom(timeoutMs!: Int64 = 3000): ?(String, UInt16, Array<Byte>) {
        match (socket) {
            case Some(sock) =>
                sock.receiveTimeout = Duration.millisecond * timeoutMs
                let buf = Array<Byte>(4096, repeat: 0)
                try {
                    let (from, n) = sock.receiveFrom(buf)
                    match (from as IPSocketAddress) {
                        case Some(ipAddr) =>
                            let data = Array<Byte>(n, repeat: 0)
                            for (i in 0..n) { data[i] = buf[i] }
                            return (ipAddr.address.toString(), ipAddr.port, data)
                        case None => return None
                    }
                } catch (e: SocketTimeoutException) {
                    return None
                }
            case None => return None
        }
    }

    public func close(): Unit {
        match (socket) {
            case Some(sock) => sock.close()
            case None => ()
        }
        socket = None
    }
}

// ============================================================================
// DTLS ClientHello/ServerHello with X25519 key exchange (complete encode)
// ============================================================================

/// Build a complete DTLS ClientHello with X25519 key exchange and use_srtp.
public func dtlsBuildClientHelloWithEcdhe(context: DtlsHandshakeContext,
    srtpProfiles: Array<UInt16>): DtlsClientHello {
    context.generateClientRandom()
    let random = DtlsRandom.decode(context.clientRandom)
    DtlsClientHello(DTLS_VERSION_1_2, random,
        Array<Byte>(),  // no session id
        Array<Byte>(),  // no cookie
        [DTLS_CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256],
        [UInt8(0)],  // null compression
        srtpProfiles)
}

/// Build a complete DTLS ServerHello with X25519 key exchange and use_srtp.
public func dtlsBuildServerHelloWithEcdhe(context: DtlsHandshakeContext,
    selectedSrtpProfile: UInt16): DtlsServerHello {
    context.generateServerRandom()
    let random = DtlsRandom.decode(context.serverRandom)
    DtlsServerHello(DTLS_VERSION_1_2, random,
        Array<Byte>(),
        DTLS_CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256,
        UInt8(0),
        selectedSrtpProfile)
}

/// Build a ServerKeyExchange message body containing X25519 public key.
/// Format: EC curve type(1) + named_curve(2) + pubkey_len(1) + pubkey(32)
public func dtlsBuildServerKeyExchangeEcdhe(publicKey: Array<Byte>): Array<Byte> {
    let body = Array<Byte>(4 + publicKey.size, repeat: 0)
    body[0] = UInt8(3)  // named_curve type
    body[1] = UInt8(0x00)  // X25519 = 0x001D
    body[2] = UInt8(0x1D)
    body[3] = UInt8(publicKey.size)
    for (i in 0..publicKey.size) {
        body[4 + i] = publicKey[i]
    }
    body
}

/// Parse a ServerKeyExchange message body to extract X25519 public key.
public func dtlsParseServerKeyExchangeEcdhe(body: Array<Byte>): Array<Byte> {
    if (body.size < 4) {
        throw CryptoException(CryptoErrorCode.InvalidArgument, "ServerKeyExchange too short")
    }
    let curveType = body[0]
    let namedCurve = (UInt16(body[1]) << 8) | UInt16(body[2])
    let pubKeyLen = Int64(body[3])
    if (body.size < 4 + pubKeyLen) {
        throw CryptoException(CryptoErrorCode.InvalidArgument, "ServerKeyExchange pubkey truncated")
    }
    let pubKey = Array<Byte>(pubKeyLen, repeat: 0)
    for (i in 0..pubKeyLen) {
        pubKey[i] = body[4 + i]
    }
    pubKey
}

/// Build a ClientKeyExchange message body containing X25519 public key.
/// Format: pubkey_len(1) + pubkey(32)
public func dtlsBuildClientKeyExchangeEcdhe(publicKey: Array<Byte>): Array<Byte> {
    let body = Array<Byte>(1 + publicKey.size, repeat: 0)
    body[0] = UInt8(publicKey.size)
    for (i in 0..publicKey.size) {
        body[1 + i] = publicKey[i]
    }
    body
}

/// Parse a ClientKeyExchange message body to extract X25519 public key.
public func dtlsParseClientKeyExchangeEcdhe(body: Array<Byte>): Array<Byte> {
    if (body.size < 1) {
        throw CryptoException(CryptoErrorCode.InvalidArgument, "ClientKeyExchange too short")
    }
    let pubKeyLen = Int64(body[0])
    if (body.size < 1 + pubKeyLen) {
        throw CryptoException(CryptoErrorCode.InvalidArgument, "ClientKeyExchange pubkey truncated")
    }
    let pubKey = Array<Byte>(pubKeyLen, repeat: 0)
    for (i in 0..pubKeyLen) {
        pubKey[i] = body[1 + i]
    }
    pubKey
}
