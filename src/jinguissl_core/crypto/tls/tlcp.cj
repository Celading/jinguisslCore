package jinguissl_core.crypto.tls

import std.collection.ArrayList
import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.digest.{hash, hmac, HashAlgorithm}
import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}
import jinguissl_core.crypto.sm2.{
    Sm2PrivateKey,
    Sm2PublicKey,
    sm2Decrypt,
    sm2Encrypt,
    sm2InitiatorKeyExchange,
    sm2PublicKeyFromUncompressed,
    sm2PublicKeyToUncompressed,
    sm2ResponderKeyExchange,
    sm2Sign,
    sm2Verify
}
import jinguissl_core.crypto.utils.{constantTimeEquals, randomSeed, secureCopyInto}
import jinguissl_core.crypto.x509.{
    X509Certificate,
    X509VerificationPolicy,
    X509VerificationResult,
    X509_KEY_USAGE_CONTENT_COMMITMENT,
    X509_KEY_USAGE_DATA_ENCIPHERMENT,
    X509_KEY_USAGE_DIGITAL_SIGNATURE,
    X509_KEY_USAGE_KEY_AGREEMENT,
    X509_KEY_USAGE_KEY_ENCIPHERMENT,
    X509_OID_KEY_USAGE,
    x509DecodeKeyUsageFromExtension,
    x509ExtractSm2PublicKey,
    x509FindExtension,
    x509ParseDer,
    x509VerifyCertificateChain
}

/** GM/T 0024 TLCP 1.1 protocol version. */
public let TLCP_VERSION: Int64 = 0x0101
public let TLCP_SM2_NAMED_GROUP: Int64 = 41
public let TLCP_PREMASTER_SECRET_LEN: Int64 = 48
public let TLCP_MASTER_SECRET_LEN: Int64 = 48
public let TLCP_FINISHED_VERIFY_DATA_LEN: Int64 = 12
public let TLCP_DEFAULT_SM2_IDENTITY: String = "1234567812345678"

/** The four TLCP suites implemented by the pinned openHiTLS reference surface. */
public enum TlcpCipherSuite <: Equatable<TlcpCipherSuite> & ToString {
    | ECDHE_SM4_CBC_SM3
    | ECC_SM4_CBC_SM3
    | ECDHE_SM4_GCM_SM3
    | ECC_SM4_GCM_SM3

    public operator func ==(right: TlcpCipherSuite): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: TlcpCipherSuite): Bool { !(this == right) }

    public func ordinalValue(): Int64 {
        match (this) {
            case ECDHE_SM4_CBC_SM3 => 0
            case ECC_SM4_CBC_SM3 => 1
            case ECDHE_SM4_GCM_SM3 => 2
            case ECC_SM4_GCM_SM3 => 3
        }
    }

    public func wireValue(): Int64 {
        match (this) {
            case ECDHE_SM4_CBC_SM3 => 0xe011
            case ECC_SM4_CBC_SM3 => 0xe013
            case ECDHE_SM4_GCM_SM3 => 0xe051
            case ECC_SM4_GCM_SM3 => 0xe053
        }
    }

    public func usesEcdhe(): Bool {
        this == ECDHE_SM4_CBC_SM3 || this == ECDHE_SM4_GCM_SM3
    }

    public func usesGcm(): Bool {
        this == ECDHE_SM4_GCM_SM3 || this == ECC_SM4_GCM_SM3
    }

    public func toString(): String {
        match (this) {
            case ECDHE_SM4_CBC_SM3 => "TLCP_ECDHE_SM4_CBC_SM3"
            case ECC_SM4_CBC_SM3 => "TLCP_ECC_SM4_CBC_SM3"
            case ECDHE_SM4_GCM_SM3 => "TLCP_ECDHE_SM4_GCM_SM3"
            case ECC_SM4_GCM_SM3 => "TLCP_ECC_SM4_GCM_SM3"
        }
    }
}

public func tlcpCipherSuiteFromWire(value: Int64): TlcpCipherSuite {
    if (value == 0xe011) { return ECDHE_SM4_CBC_SM3 }
    if (value == 0xe013) { return ECC_SM4_CBC_SM3 }
    if (value == 0xe051) { return ECDHE_SM4_GCM_SM3 }
    if (value == 0xe053) { return ECC_SM4_GCM_SM3 }
    throw CryptoException(Unsupported, "unsupported TLCP cipher suite: ${value}")
}

public func tlcpDefaultCipherSuites(): Array<TlcpCipherSuite> {
    [ECDHE_SM4_CBC_SM3, ECC_SM4_CBC_SM3, ECDHE_SM4_GCM_SM3, ECC_SM4_GCM_SM3]
}

public class TlcpClientHello {
    public let random: Array<Byte>
    public let sessionId: Array<Byte>
    public let cipherSuites: Array<TlcpCipherSuite>
    public let extensions: Array<TlsExtension>

    public init(
        random: Array<Byte>,
        cipherSuites: Array<TlcpCipherSuite>,
        sessionId!: Array<Byte> = [],
        extensions!: Array<TlsExtension> = []
    ) {
        tlcpRequireHelloFields(random, sessionId, cipherSuites)
        this.random = random.clone()
        this.sessionId = sessionId.clone()
        this.cipherSuites = cipherSuites.clone()
        this.extensions = extensions.clone()
    }
}

public class TlcpServerHello {
    public let random: Array<Byte>
    public let sessionId: Array<Byte>
    public let cipherSuite: TlcpCipherSuite
    public let extensions: Array<TlsExtension>

    public init(
        random: Array<Byte>,
        cipherSuite: TlcpCipherSuite,
        sessionId!: Array<Byte> = [],
        extensions!: Array<TlsExtension> = []
    ) {
        tlcpRequireHelloFields(random, sessionId, [cipherSuite])
        this.random = random.clone()
        this.sessionId = sessionId.clone()
        this.cipherSuite = cipherSuite
        this.extensions = extensions.clone()
    }
}

public func tlcpBuildClientHello(
    cipherSuites!: Array<TlcpCipherSuite> = tlcpDefaultCipherSuites(),
    sessionId!: Array<Byte> = [],
    extensions!: Array<TlsExtension> = []
): Array<Byte> {
    tlcpEncodeClientHello(TlcpClientHello(
        randomSeed(size: TLS_HELLO_RANDOM_LEN),
        cipherSuites,
        sessionId: sessionId,
        extensions: extensions
    ))
}

public func tlcpBuildServerHello(
    encodedClientHello: Array<Byte>,
    supportedSuites!: Array<TlcpCipherSuite> = tlcpDefaultCipherSuites(),
    extensions!: Array<TlsExtension> = []
): Array<Byte> {
    let client = tlcpDecodeClientHello(encodedClientHello)
    let selected = tlcpSelectCipherSuite(client.cipherSuites, supportedSuites)
    tlcpEncodeServerHello(TlcpServerHello(
        randomSeed(size: TLS_HELLO_RANDOM_LEN),
        selected,
        sessionId: client.sessionId,
        extensions: extensions
    ))
}

public func tlcpEncodeClientHello(hello: TlcpClientHello): Array<Byte> {
    let body = ArrayList<Byte>()
    tlcpAppend(body, tlcpEncodeUInt16(TLCP_VERSION))
    tlcpAppend(body, hello.random)
    body.add(UInt8(hello.sessionId.size))
    tlcpAppend(body, hello.sessionId)
    let suites = ArrayList<Byte>()
    for (suite in hello.cipherSuites) {
        tlcpAppend(suites, tlcpEncodeUInt16(suite.wireValue()))
    }
    tlcpAppend(body, tlcpEncodeVector16(suites.toArray(), "TLCP cipher suites"))
    body.add(UInt8(1))
    body.add(UInt8(0))
    tlcpAppend(body, tlcpEncodeExtensions(hello.extensions))
    tlcpEncodeHandshake(UInt8(0x01), body.toArray())
}

public func tlcpDecodeClientHello(encoded: Array<Byte>): TlcpClientHello {
    let body = tlcpDecodeHandshake(encoded, UInt8(0x01), "TLCP ClientHello")
    if (body.size < 38) {
        throw CryptoException(ParseError, "TLCP ClientHello is too short")
    }
    tlcpRequireVersion(body, 0, "TLCP ClientHello")
    let random = body[2..34]
    var offset: Int64 = 34
    let sessionLen = Int64(UInt8(body[offset]))
    offset += 1
    if (sessionLen > TLS_SESSION_ID_MAX_LEN || offset + sessionLen > body.size) {
        throw CryptoException(ParseError, "TLCP ClientHello session id length is invalid")
    }
    let sessionId = body[offset..(offset + sessionLen)]
    offset += sessionLen
    let (suiteBytes, afterSuites) = tlcpDecodeVector16At(body, offset, "TLCP cipher suites")
    offset = afterSuites
    if (suiteBytes.size == 0 || (suiteBytes.size % 2) != 0) {
        throw CryptoException(ParseError, "TLCP cipher suite vector is invalid")
    }
    let suites = ArrayList<TlcpCipherSuite>()
    var suiteOffset: Int64 = 0
    while (suiteOffset < suiteBytes.size) {
        suites.add(tlcpCipherSuiteFromWire(tlcpDecodeUInt16(suiteBytes, suiteOffset)))
        suiteOffset += 2
    }
    if (offset >= body.size) {
        throw CryptoException(ParseError, "TLCP ClientHello compression methods are missing")
    }
    let compressionLen = Int64(UInt8(body[offset]))
    offset += 1
    if (compressionLen == 0 || offset + compressionLen > body.size) {
        throw CryptoException(ParseError, "TLCP ClientHello compression vector is invalid")
    }
    var hasNullCompression = false
    for (method in body[offset..(offset + compressionLen)]) {
        if (method == UInt8(0)) { hasNullCompression = true }
    }
    if (!hasNullCompression) {
        throw CryptoException(Unsupported, "TLCP ClientHello does not offer null compression")
    }
    offset += compressionLen
    let extensions = tlcpDecodeOptionalExtensions(body, offset, "TLCP ClientHello")
    TlcpClientHello(random, suites.toArray(), sessionId: sessionId, extensions: extensions)
}

public func tlcpEncodeServerHello(hello: TlcpServerHello): Array<Byte> {
    let body = ArrayList<Byte>()
    tlcpAppend(body, tlcpEncodeUInt16(TLCP_VERSION))
    tlcpAppend(body, hello.random)
    body.add(UInt8(hello.sessionId.size))
    tlcpAppend(body, hello.sessionId)
    tlcpAppend(body, tlcpEncodeUInt16(hello.cipherSuite.wireValue()))
    body.add(UInt8(0))
    tlcpAppend(body, tlcpEncodeExtensions(hello.extensions))
    tlcpEncodeHandshake(UInt8(0x02), body.toArray())
}

public func tlcpDecodeServerHello(encoded: Array<Byte>): TlcpServerHello {
    let body = tlcpDecodeHandshake(encoded, UInt8(0x02), "TLCP ServerHello")
    if (body.size < 38) {
        throw CryptoException(ParseError, "TLCP ServerHello is too short")
    }
    tlcpRequireVersion(body, 0, "TLCP ServerHello")
    let random = body[2..34]
    var offset: Int64 = 34
    let sessionLen = Int64(UInt8(body[offset]))
    offset += 1
    if (sessionLen > TLS_SESSION_ID_MAX_LEN || offset + sessionLen + 3 > body.size) {
        throw CryptoException(ParseError, "TLCP ServerHello session id length is invalid")
    }
    let sessionId = body[offset..(offset + sessionLen)]
    offset += sessionLen
    let suite = tlcpCipherSuiteFromWire(tlcpDecodeUInt16(body, offset))
    offset += 2
    if (UInt8(body[offset]) != UInt8(0)) {
        throw CryptoException(Unsupported, "TLCP ServerHello selected non-null compression")
    }
    offset += 1
    let extensions = tlcpDecodeOptionalExtensions(body, offset, "TLCP ServerHello")
    TlcpServerHello(random, suite, sessionId: sessionId, extensions: extensions)
}

public class TlcpCertificateBundle {
    public let signingCertificate: X509Certificate
    public let encryptionCertificate: X509Certificate
    public let intermediates: Array<X509Certificate>

    public init(
        signingCertificate: X509Certificate,
        encryptionCertificate: X509Certificate,
        intermediates!: Array<X509Certificate> = []
    ) {
        if (constantTimeEquals(signingCertificate.der, encryptionCertificate.der)) {
            throw CryptoException(InvalidArgument, "TLCP signing and encryption certificates must be distinct")
        }
        this.signingCertificate = signingCertificate
        this.encryptionCertificate = encryptionCertificate
        this.intermediates = intermediates.clone()
    }
}

public class TlcpDualCertificateVerificationResult {
    public let signingResult: X509VerificationResult
    public let encryptionResult: X509VerificationResult

    public init(signingResult: X509VerificationResult, encryptionResult: X509VerificationResult) {
        this.signingResult = signingResult
        this.encryptionResult = encryptionResult
    }
}

/** Encode signing leaf first, encryption leaf second, followed by shared intermediates. */
public func tlcpBuildDualCertificateHandshake(
    signingCertificateDer: Array<Byte>,
    encryptionCertificateDer: Array<Byte>,
    intermediateDer!: Array<Array<Byte>> = []
): Array<Byte> {
    if (constantTimeEquals(signingCertificateDer, encryptionCertificateDer)) {
        throw CryptoException(InvalidArgument, "TLCP dual certificate leaves must be distinct")
    }
    let certificates = ArrayList<Array<Byte>>()
    certificates.add(signingCertificateDer.clone())
    certificates.add(encryptionCertificateDer.clone())
    for (der in intermediateDer) { certificates.add(der.clone()) }
    tlsEncodeCertificateHandshakeTls12(certificates.toArray())
}

public func tlcpParseDualCertificateHandshake(encoded: Array<Byte>): TlcpCertificateBundle {
    let certDer = tlsDecodeCertificateHandshakeTls12(encoded)
    if (certDer.size < 2) {
        throw CryptoException(ParseError, "TLCP Certificate must carry signing and encryption leaves")
    }
    let intermediates = ArrayList<X509Certificate>()
    var i: Int64 = 2
    while (i < certDer.size) {
        intermediates.add(x509ParseDer(certDer[i]))
        i += 1
    }
    TlcpCertificateBundle(
        x509ParseDer(certDer[0]),
        x509ParseDer(certDer[1]),
        intermediates: intermediates.toArray()
    )
}

public func tlcpVerifyDualCertificateBundle(
    bundle: TlcpCertificateBundle,
    policy: X509VerificationPolicy
): TlcpDualCertificateVerificationResult {
    _ = x509ExtractSm2PublicKey(bundle.signingCertificate)
    _ = x509ExtractSm2PublicKey(bundle.encryptionCertificate)
    tlcpRequireCertificateUsage(
        bundle.signingCertificate,
        X509_KEY_USAGE_DIGITAL_SIGNATURE | X509_KEY_USAGE_CONTENT_COMMITMENT,
        "TLCP signing certificate"
    )
    tlcpRequireCertificateUsage(
        bundle.encryptionCertificate,
        X509_KEY_USAGE_KEY_ENCIPHERMENT |
            X509_KEY_USAGE_DATA_ENCIPHERMENT |
            X509_KEY_USAGE_KEY_AGREEMENT,
        "TLCP encryption certificate"
    )
    // TLCP gives the two leaves different duties. A caller's single-leaf keyUsage
    // constraint cannot be applied unchanged to both leaves; enforce the two role
    // masks above and retain the rest of the caller's chain/identity policy here.
    let merged = tlcpMergeVerificationPolicy(policy, bundle.intermediates, clearLeafKeyUsage: true)
    TlcpDualCertificateVerificationResult(
        x509VerifyCertificateChain(bundle.signingCertificate, merged),
        x509VerifyCertificateChain(bundle.encryptionCertificate, merged)
    )
}

/** Static ECC ServerKeyExchange: signature over randoms and uint24-length encryption certificate. */
public func tlcpBuildEccServerKeyExchange(
    signingPrivateKey: Sm2PrivateKey,
    encryptionCertificate: X509Certificate,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    signerIdentity!: Array<Byte> = TLCP_DEFAULT_SM2_IDENTITY.toArray()
): Array<Byte> {
    let signed = tlcpStaticEccSignatureInput(
        clientRandom, serverRandom, encryptionCertificate.der
    )
    let (r, s) = sm2Sign(signingPrivateKey, signerIdentity, signed)
    let signature = tlcpEncodeSm2SignatureDer(r, s)
    tlcpEncodeHandshake(
        UInt8(0x0c), tlcpEncodeVector16(signature, "TLCP ECC ServerKeyExchange signature")
    )
}

public func tlcpVerifyEccServerKeyExchange(
    encoded: Array<Byte>,
    signingCertificate: X509Certificate,
    encryptionCertificate: X509Certificate,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    signerIdentity!: Array<Byte> = TLCP_DEFAULT_SM2_IDENTITY.toArray()
): Unit {
    let body = tlcpDecodeHandshake(encoded, UInt8(0x0c), "TLCP ECC ServerKeyExchange")
    let signature = tlcpDecodeWholeVector16(body, "TLCP ECC ServerKeyExchange signature")
    let (r, s) = tlcpDecodeSm2SignatureDer(signature)
    let signed = tlcpStaticEccSignatureInput(clientRandom, serverRandom, encryptionCertificate.der)
    if (!sm2Verify(x509ExtractSm2PublicKey(signingCertificate), signerIdentity, signed, r, s)) {
        throw CryptoException(ParseError, "TLCP ECC ServerKeyExchange signature verification failed")
    }
}

/** ECDHE ServerKeyExchange using named group curveSM2 and an SM2 signature. */
public func tlcpBuildEcdheServerKeyExchange(
    ephemeralPublicKey: Sm2PublicKey,
    signingPrivateKey: Sm2PrivateKey,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    signerIdentity!: Array<Byte> = TLCP_DEFAULT_SM2_IDENTITY.toArray()
): Array<Byte> {
    tlcpRequireRandoms(clientRandom, serverRandom)
    let encodedPoint = sm2PublicKeyToUncompressed(ephemeralPublicKey)
    let params = ArrayList<Byte>()
    params.add(UInt8(0x03))
    tlcpAppend(params, tlcpEncodeUInt16(TLCP_SM2_NAMED_GROUP))
    params.add(UInt8(encodedPoint.size))
    tlcpAppend(params, encodedPoint)
    let signed = tlcpConcat(tlcpConcat(clientRandom, serverRandom), params.toArray())
    let (r, s) = sm2Sign(signingPrivateKey, signerIdentity, signed)
    let body = ArrayList<Byte>()
    tlcpAppend(body, params.toArray())
    tlcpAppend(body, tlcpEncodeVector16(
        tlcpEncodeSm2SignatureDer(r, s), "TLCP ECDHE ServerKeyExchange signature"
    ))
    tlcpEncodeHandshake(UInt8(0x0c), body.toArray())
}

public func tlcpParseAndVerifyEcdheServerKeyExchange(
    encoded: Array<Byte>,
    signingCertificate: X509Certificate,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    signerIdentity!: Array<Byte> = TLCP_DEFAULT_SM2_IDENTITY.toArray()
): Sm2PublicKey {
    tlcpRequireRandoms(clientRandom, serverRandom)
    let body = tlcpDecodeHandshake(encoded, UInt8(0x0c), "TLCP ECDHE ServerKeyExchange")
    if (body.size < 4 || UInt8(body[0]) != UInt8(0x03)) {
        throw CryptoException(ParseError, "TLCP ECDHE curve parameters are invalid")
    }
    if (tlcpDecodeUInt16(body, 1) != TLCP_SM2_NAMED_GROUP) {
        throw CryptoException(Unsupported, "TLCP ECDHE named group is not curveSM2")
    }
    let pointLen = Int64(UInt8(body[3]))
    if (pointLen != 65 || 4 + pointLen + 2 > body.size) {
        throw CryptoException(ParseError, "TLCP ECDHE public key length is invalid")
    }
    let paramsEnd = 4 + pointLen
    let point = sm2PublicKeyFromUncompressed(body[4..paramsEnd])
    let (signature, end) = tlcpDecodeVector16At(
        body, paramsEnd, "TLCP ECDHE ServerKeyExchange signature"
    )
    if (end != body.size) {
        throw CryptoException(ParseError, "TLCP ECDHE ServerKeyExchange contains trailing bytes")
    }
    let (r, s) = tlcpDecodeSm2SignatureDer(signature)
    let signed = tlcpConcat(tlcpConcat(clientRandom, serverRandom), body[..paramsEnd])
    if (!sm2Verify(
        x509ExtractSm2PublicKey(signingCertificate), signerIdentity, signed, r, s
    )) {
        throw CryptoException(ParseError, "TLCP ECDHE ServerKeyExchange signature verification failed")
    }
    point
}

public func tlcpBuildEcdheClientKeyExchange(ephemeralPublicKey: Sm2PublicKey): Array<Byte> {
    let point = sm2PublicKeyToUncompressed(ephemeralPublicKey)
    let body = Array<Byte>(1 + point.size, repeat: UInt8(0))
    body[0] = UInt8(point.size)
    secureCopyInto(point, body, dstOffset: 1)
    tlcpEncodeHandshake(UInt8(0x10), body)
}

public func tlcpParseEcdheClientKeyExchange(encoded: Array<Byte>): Sm2PublicKey {
    let body = tlcpDecodeHandshake(encoded, UInt8(0x10), "TLCP ECDHE ClientKeyExchange")
    if (body.size != 66 || UInt8(body[0]) != UInt8(65)) {
        throw CryptoException(ParseError, "TLCP ECDHE ClientKeyExchange point length is invalid")
    }
    sm2PublicKeyFromUncompressed(body[1..])
}

/** Build static ECC ClientKeyExchange with ASN.1 SM2Cipher interoperability encoding. */
public func tlcpBuildEccClientKeyExchange(
    serverEncryptionPublicKey: Sm2PublicKey
): (Array<Byte>, Array<Byte>) {
    let preMaster = tlcpRandomPremasterSecret()
    let c1c3c2 = sm2Encrypt(serverEncryptionPublicKey, preMaster)
    let ciphertextDer = tlcpEncodeSm2CiphertextDer(c1c3c2)
    let body = tlcpEncodeVector16(ciphertextDer, "TLCP ECC ClientKeyExchange ciphertext")
    (tlcpEncodeHandshake(UInt8(0x10), body), preMaster)
}

/**
 * Process static ECC ClientKeyExchange. SM2 decryption/version failure is concealed
 * behind a fresh 48-byte premaster, matching TLCP's no-alert oracle defense.
 */
public func tlcpProcessEccClientKeyExchange(
    serverEncryptionPrivateKey: Sm2PrivateKey,
    encoded: Array<Byte>
): Array<Byte> {
    let body = tlcpDecodeHandshake(encoded, UInt8(0x10), "TLCP ECC ClientKeyExchange")
    let ciphertextDer = tlcpDecodeWholeVector16(body, "TLCP ECC ClientKeyExchange ciphertext")
    let fallback = tlcpRandomPremasterSecret()
    try {
        let c1c3c2 = tlcpDecodeSm2CiphertextDer(ciphertextDer)
        let recovered = sm2Decrypt(serverEncryptionPrivateKey, c1c3c2)
        if (
            recovered.size == TLCP_PREMASTER_SECRET_LEN &&
            UInt8(recovered[0]) == UInt8(0x01) && UInt8(recovered[1]) == UInt8(0x01)
        ) {
            return recovered
        }
    } catch (_: CryptoException) {
        // Deliberately return the indistinguishable fallback below.
    }
    fallback
}

public func tlcpDeriveEcdheClientSecrets(
    clientStaticPrivateKey: Sm2PrivateKey,
    clientEphemeralPrivateKey: Sm2PrivateKey,
    serverStaticPublicKey: Sm2PublicKey,
    serverEphemeralPublicKey: Sm2PublicKey,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    cipherSuite: TlcpCipherSuite,
    clientIdentity!: Array<Byte> = TLCP_DEFAULT_SM2_IDENTITY.toArray(),
    serverIdentity!: Array<Byte> = TLCP_DEFAULT_SM2_IDENTITY.toArray()
): TlcpHandshakeSecrets {
    if (!cipherSuite.usesEcdhe()) {
        throw CryptoException(InvalidArgument, "TLCP ECDHE derivation requires an ECDHE suite")
    }
    let exchange = sm2InitiatorKeyExchange(
        clientStaticPrivateKey,
        clientEphemeralPrivateKey,
        serverStaticPublicKey,
        serverEphemeralPublicKey,
        clientIdentity,
        serverIdentity,
        TLCP_PREMASTER_SECRET_LEN
    )
    tlcpDeriveSecretsFromPreMaster(exchange.key, clientRandom, serverRandom, cipherSuite)
}

public func tlcpDeriveEcdheServerSecrets(
    serverStaticPrivateKey: Sm2PrivateKey,
    serverEphemeralPrivateKey: Sm2PrivateKey,
    clientStaticPublicKey: Sm2PublicKey,
    clientEphemeralPublicKey: Sm2PublicKey,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    cipherSuite: TlcpCipherSuite,
    clientIdentity!: Array<Byte> = TLCP_DEFAULT_SM2_IDENTITY.toArray(),
    serverIdentity!: Array<Byte> = TLCP_DEFAULT_SM2_IDENTITY.toArray()
): TlcpHandshakeSecrets {
    if (!cipherSuite.usesEcdhe()) {
        throw CryptoException(InvalidArgument, "TLCP ECDHE derivation requires an ECDHE suite")
    }
    let exchange = sm2ResponderKeyExchange(
        serverStaticPrivateKey,
        serverEphemeralPrivateKey,
        clientStaticPublicKey,
        clientEphemeralPublicKey,
        serverIdentity,
        clientIdentity,
        TLCP_PREMASTER_SECRET_LEN
    )
    tlcpDeriveSecretsFromPreMaster(exchange.key, clientRandom, serverRandom, cipherSuite)
}

public func tlcpPrfSm3(
    secret: Array<Byte>, label: String, seed: Array<Byte>, outputLen: Int64
): Array<Byte> {
    if (secret.size == 0 || outputLen < 0) {
        throw CryptoException(InvalidArgument, "TLCP PRF secret/output length is invalid")
    }
    if (outputLen == 0) { return [] }
    let labelSeed = tlcpConcat(label.toArray(), seed)
    let output = Array<Byte>(outputLen, repeat: UInt8(0))
    var a = labelSeed.clone()
    var offset: Int64 = 0
    while (offset < outputLen) {
        a = hmac(HashAlgorithm.SM3, secret, a)
        let block = hmac(HashAlgorithm.SM3, secret, tlcpConcat(a, labelSeed))
        let take = if (outputLen - offset < block.size) { outputLen - offset } else { block.size }
        var i: Int64 = 0
        while (i < take) {
            output[offset + i] = block[i]
            i += 1
        }
        offset += take
    }
    output
}

public func tlcpFinishedVerifyData(
    masterSecret: Array<Byte>,
    handshakeTranscript: Array<Byte>,
    isClient: Bool
): Array<Byte> {
    let transcriptHash = hash(HashAlgorithm.SM3, handshakeTranscript)
    let label = if (isClient) { "client finished" } else { "server finished" }
    tlcpPrfSm3(masterSecret, label, transcriptHash, TLCP_FINISHED_VERIFY_DATA_LEN)
}

public func tlcpBuildFinishedHandshake(
    masterSecret: Array<Byte>, handshakeTranscript: Array<Byte>, isClient: Bool
): Array<Byte> {
    tlcpEncodeHandshake(
        UInt8(0x14), tlcpFinishedVerifyData(masterSecret, handshakeTranscript, isClient)
    )
}

public func tlcpVerifyFinishedHandshake(
    encodedFinished: Array<Byte>,
    masterSecret: Array<Byte>,
    handshakeTranscript: Array<Byte>,
    isClient: Bool
): Unit {
    let received = tlcpDecodeHandshake(encodedFinished, UInt8(0x14), "TLCP Finished")
    let expected = tlcpFinishedVerifyData(masterSecret, handshakeTranscript, isClient)
    if (!constantTimeEquals(received, expected)) {
        throw CryptoException(ParseError, "TLCP Finished verification failed")
    }
}

func tlcpEncodeHandshake(msgType: Byte, body: Array<Byte>): Array<Byte> {
    if (body.size > TLS_HANDSHAKE_MAX_BODY_LEN) {
        throw CryptoException(OutOfBounds, "TLCP handshake body is too large")
    }
    let output = Array<Byte>(4 + body.size, repeat: UInt8(0))
    output[0] = msgType
    let length = tlcpEncodeUInt24(body.size)
    output[1] = length[0]
    output[2] = length[1]
    output[3] = length[2]
    secureCopyInto(body, output, dstOffset: 4)
    output
}

func tlcpDecodeHandshake(encoded: Array<Byte>, expectedType: Byte, label: String): Array<Byte> {
    if (encoded.size < 4 || UInt8(encoded[0]) != expectedType) {
        throw CryptoException(ParseError, "${label} header/type is invalid")
    }
    let bodyLen = tlcpDecodeUInt24(encoded, 1)
    if (bodyLen != encoded.size - 4) {
        throw CryptoException(ParseError, "${label} body length mismatch")
    }
    encoded[4..]
}

func tlcpEncodeUInt16(value: Int64): Array<Byte> {
    if (value < 0 || value > 0xffff) {
        throw CryptoException(OutOfBounds, "TLCP uint16 value is out of range")
    }
    [UInt8((value >> 8) & 0xff), UInt8(value & 0xff)]
}

func tlcpDecodeUInt16(data: Array<Byte>, offset: Int64): Int64 {
    if (offset < 0 || offset + 2 > data.size) {
        throw CryptoException(ParseError, "TLCP uint16 is truncated")
    }
    (Int64(UInt8(data[offset])) << 8) | Int64(UInt8(data[offset + 1]))
}

func tlcpEncodeUInt24(value: Int64): Array<Byte> {
    if (value < 0 || value > 0x00ff_ffff) {
        throw CryptoException(OutOfBounds, "TLCP uint24 value is out of range")
    }
    [
        UInt8((value >> 16) & 0xff),
        UInt8((value >> 8) & 0xff),
        UInt8(value & 0xff)
    ]
}

func tlcpDecodeUInt24(data: Array<Byte>, offset: Int64): Int64 {
    if (offset < 0 || offset + 3 > data.size) {
        throw CryptoException(ParseError, "TLCP uint24 is truncated")
    }
    (Int64(UInt8(data[offset])) << 16) |
        (Int64(UInt8(data[offset + 1])) << 8) |
        Int64(UInt8(data[offset + 2]))
}

func tlcpEncodeUInt64(value: Int64): Array<Byte> {
    if (value < 0) {
        throw CryptoException(OutOfBounds, "TLCP sequence must be non-negative")
    }
    let output = Array<Byte>(8, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < 8) {
        output[7 - i] = UInt8((value >> (i * 8)) & 0xff)
        i += 1
    }
    output
}

func tlcpEncodeEpochSequence(epoch: Int64, sequence: Int64): Array<Byte> {
    if (epoch < 0 || epoch > 0xffff || sequence < 0 || sequence > 0x0000_ffff_ffff_ffff) {
        throw CryptoException(OutOfBounds, "DTLCP epoch/sequence is out of range")
    }
    let output = Array<Byte>(8, repeat: UInt8(0))
    let epochBytes = tlcpEncodeUInt16(epoch)
    output[0] = epochBytes[0]
    output[1] = epochBytes[1]
    var i: Int64 = 0
    while (i < 6) {
        output[7 - i] = UInt8((sequence >> (i * 8)) & 0xff)
        i += 1
    }
    output
}

private func tlcpRequireHelloFields(
    random: Array<Byte>, sessionId: Array<Byte>, suites: Array<TlcpCipherSuite>
): Unit {
    if (random.size != TLS_HELLO_RANDOM_LEN || sessionId.size > TLS_SESSION_ID_MAX_LEN) {
        throw CryptoException(InvalidArgument, "TLCP hello random/session id length is invalid")
    }
    if (suites.size == 0) {
        throw CryptoException(InvalidArgument, "TLCP hello cipher suites must not be empty")
    }
}

private func tlcpSelectCipherSuite(
    offered: Array<TlcpCipherSuite>, supported: Array<TlcpCipherSuite>
): TlcpCipherSuite {
    if (supported.size == 0) {
        throw CryptoException(InvalidArgument, "TLCP supported suites must not be empty")
    }
    for (suite in supported) {
        for (candidate in offered) {
            if (suite == candidate) { return suite }
        }
    }
    throw CryptoException(ParseError, "TLCP server could not select a cipher suite")
}

private func tlcpEncodeExtensions(extensions: Array<TlsExtension>): Array<Byte> {
    let payload = ArrayList<Byte>()
    for (extension in extensions) {
        tlcpAppend(payload, tlcpEncodeUInt16(extension.extType))
        tlcpAppend(payload, tlcpEncodeVector16(extension.data, "TLCP extension data"))
    }
    tlcpEncodeVector16(payload.toArray(), "TLCP extensions")
}

private func tlcpDecodeOptionalExtensions(
    body: Array<Byte>, offset: Int64, label: String
): Array<TlsExtension> {
    if (offset == body.size) { return [] }
    let (payload, end) = tlcpDecodeVector16At(body, offset, "${label} extensions")
    if (end != body.size) {
        throw CryptoException(ParseError, "${label} contains trailing bytes")
    }
    let extensions = ArrayList<TlsExtension>()
    var current: Int64 = 0
    while (current < payload.size) {
        if (current + 4 > payload.size) {
            throw CryptoException(ParseError, "${label} extension header is truncated")
        }
        let extensionType = tlcpDecodeUInt16(payload, current)
        let (data, next) = tlcpDecodeVector16At(payload, current + 2, "${label} extension")
        extensions.add(TlsExtension(extensionType, data))
        current = next
    }
    extensions.toArray()
}

private func tlcpEncodeVector16(payload: Array<Byte>, label: String): Array<Byte> {
    if (payload.size > 0xffff) {
        throw CryptoException(OutOfBounds, "${label} is too large")
    }
    tlcpConcat(tlcpEncodeUInt16(payload.size), payload)
}

private func tlcpDecodeVector16At(
    payload: Array<Byte>, offset: Int64, label: String
): (Array<Byte>, Int64) {
    let length = tlcpDecodeUInt16(payload, offset)
    let start = offset + 2
    let end = start + length
    if (end > payload.size) {
        throw CryptoException(ParseError, "${label} is truncated")
    }
    (payload[start..end], end)
}

private func tlcpDecodeWholeVector16(payload: Array<Byte>, label: String): Array<Byte> {
    let (value, end) = tlcpDecodeVector16At(payload, 0, label)
    if (end != payload.size) {
        throw CryptoException(ParseError, "${label} contains trailing bytes")
    }
    value
}

private func tlcpRequireVersion(payload: Array<Byte>, offset: Int64, label: String): Unit {
    if (tlcpDecodeUInt16(payload, offset) != TLCP_VERSION) {
        throw CryptoException(Unsupported, "${label} version is not TLCP 1.1")
    }
}

private func tlcpRequireRandoms(clientRandom: Array<Byte>, serverRandom: Array<Byte>): Unit {
    if (clientRandom.size != 32 || serverRandom.size != 32) {
        throw CryptoException(InvalidArgument, "TLCP client/server random must be 32 bytes")
    }
}

private func tlcpRequireCertificateUsage(
    certificate: X509Certificate, allowedMask: Int64, label: String
): Unit {
    let extension = x509FindExtension(certificate, X509_OID_KEY_USAGE)
    if (let Some(keyUsage) <- extension) {
        if ((x509DecodeKeyUsageFromExtension(keyUsage) & allowedMask) == 0) {
            throw CryptoException(ParseError, "${label} keyUsage is incompatible")
        }
    }
}

private func tlcpMergeVerificationPolicy(
    base: X509VerificationPolicy,
    embedded: Array<X509Certificate>,
    clearLeafKeyUsage!: Bool = false
): X509VerificationPolicy {
    let intermediates = ArrayList<X509Certificate>()
    for (cert in base.intermediates) { intermediates.add(cert) }
    for (cert in embedded) { intermediates.add(cert) }
    X509VerificationPolicy(
        base.trustAnchors,
        intermediates: intermediates.toArray(),
        crls: base.crls,
        requireCrlForAllIssuers: base.requireCrlForAllIssuers,
        requireCrlIfDistributionPointsPresent: base.requireCrlIfDistributionPointsPresent,
        requireCrlAuthorityKeyIdentifierMatch: base.requireCrlAuthorityKeyIdentifierMatch,
        requireAuthorityKeyIdentifierMatch: base.requireAuthorityKeyIdentifierMatch,
        requiredLeafKeyUsageMask: if (clearLeafKeyUsage) { Int64(0) } else {
            base.requiredLeafKeyUsageMask
        },
        requiredLeafExtendedKeyUsages: base.requiredLeafExtendedKeyUsages,
        requiredLeafCertificatePolicies: base.requiredLeafCertificatePolicies,
        requiredLeafDnsName: base.requiredLeafDnsName,
        validationTime: base.validationTime,
        revokedSerialHexLower: base.revokedSerialHexLower
    )
}

private func tlcpStaticEccSignatureInput(
    clientRandom: Array<Byte>, serverRandom: Array<Byte>, encryptionCertificateDer: Array<Byte>
): Array<Byte> {
    tlcpRequireRandoms(clientRandom, serverRandom)
    let output = ArrayList<Byte>()
    tlcpAppend(output, clientRandom)
    tlcpAppend(output, serverRandom)
    tlcpAppend(output, tlcpEncodeUInt24(encryptionCertificateDer.size))
    tlcpAppend(output, encryptionCertificateDer)
    output.toArray()
}

private func tlcpRandomPremasterSecret(): Array<Byte> {
    let secret = randomSeed(size: TLCP_PREMASTER_SECRET_LEN)
    secret[0] = UInt8(0x01)
    secret[1] = UInt8(0x01)
    secret
}

private func tlcpEncodeSm2CiphertextDer(raw: Array<Byte>): Array<Byte> {
    if (raw.size < 97 || UInt8(raw[0]) != UInt8(0x04)) {
        throw CryptoException(ParseError, "SM2 C1C3C2 ciphertext is invalid")
    }
    let x = tlcpDerInteger(raw[1..33])
    let y = tlcpDerInteger(raw[33..65])
    let digest = tlcpDerWrap(UInt8(0x04), raw[65..97])
    let cipher = tlcpDerWrap(UInt8(0x04), raw[97..])
    tlcpDerWrap(UInt8(0x30), tlcpConcat(tlcpConcat(x, y), tlcpConcat(digest, cipher)))
}

private func tlcpDecodeSm2CiphertextDer(der: Array<Byte>): Array<Byte> {
    let (rootTag, rootValue, rootEnd) = tlcpDerRead(der, 0, "SM2 ciphertext")
    if (rootTag != UInt8(0x30) || rootEnd != der.size) {
        throw CryptoException(ParseError, "SM2 ciphertext DER root is invalid")
    }
    var offset: Int64 = 0
    let (xTag, xValue, xEnd) = tlcpDerRead(rootValue, offset, "SM2 ciphertext x")
    offset = xEnd
    let (yTag, yValue, yEnd) = tlcpDerRead(rootValue, offset, "SM2 ciphertext y")
    offset = yEnd
    let (hashTag, digest, hashEnd) = tlcpDerRead(rootValue, offset, "SM2 ciphertext hash")
    offset = hashEnd
    let (cipherTag, cipher, cipherEnd) = tlcpDerRead(rootValue, offset, "SM2 ciphertext cipher")
    if (
        xTag != UInt8(0x02) || yTag != UInt8(0x02) ||
        hashTag != UInt8(0x04) || cipherTag != UInt8(0x04) ||
        cipherEnd != rootValue.size || digest.size != 32 || cipher.size == 0
    ) {
        throw CryptoException(ParseError, "SM2 ciphertext DER fields are invalid")
    }
    let x = tlcpDerPositiveIntegerToFixed(xValue, 32, "SM2 ciphertext x")
    let y = tlcpDerPositiveIntegerToFixed(yValue, 32, "SM2 ciphertext y")
    let output = ArrayList<Byte>()
    output.add(UInt8(0x04))
    tlcpAppend(output, x)
    tlcpAppend(output, y)
    tlcpAppend(output, digest)
    tlcpAppend(output, cipher)
    output.toArray()
}

private func tlcpEncodeSm2SignatureDer(r: BigNum, s: BigNum): Array<Byte> {
    tlcpDerWrap(UInt8(0x30), tlcpConcat(tlcpDerInteger(r.toBytesBE()), tlcpDerInteger(s.toBytesBE())))
}

private func tlcpDecodeSm2SignatureDer(der: Array<Byte>): (BigNum, BigNum) {
    let (tag, value, end) = tlcpDerRead(der, 0, "SM2 signature")
    if (tag != UInt8(0x30) || end != der.size) {
        throw CryptoException(ParseError, "SM2 signature DER root is invalid")
    }
    let (rTag, rValue, rEnd) = tlcpDerRead(value, 0, "SM2 signature r")
    let (sTag, sValue, sEnd) = tlcpDerRead(value, rEnd, "SM2 signature s")
    if (rTag != UInt8(0x02) || sTag != UInt8(0x02) || sEnd != value.size) {
        throw CryptoException(ParseError, "SM2 signature DER fields are invalid")
    }
    (
        BigNum.fromBytesBE(tlcpDerPositiveInteger(rValue, "SM2 signature r")),
        BigNum.fromBytesBE(tlcpDerPositiveInteger(sValue, "SM2 signature s"))
    )
}

private func tlcpDerInteger(raw: Array<Byte>): Array<Byte> {
    var start: Int64 = 0
    while (start + 1 < raw.size && UInt8(raw[start]) == UInt8(0)) { start += 1 }
    let magnitude = raw[start..]
    if (magnitude.size == 0) { return tlcpDerWrap(UInt8(0x02), [UInt8(0)]) }
    if ((UInt8(magnitude[0]) & UInt8(0x80)) != UInt8(0)) {
        return tlcpDerWrap(UInt8(0x02), tlcpConcat([UInt8(0)], magnitude))
    }
    tlcpDerWrap(UInt8(0x02), magnitude)
}

private func tlcpDerWrap(tag: Byte, value: Array<Byte>): Array<Byte> {
    tlcpConcat([tag], tlcpConcat(tlcpDerLength(value.size), value))
}

private func tlcpDerLength(length: Int64): Array<Byte> {
    if (length < 0) { throw CryptoException(InvalidArgument, "DER length is negative") }
    if (length < 128) { return [UInt8(length)] }
    if (length <= 0xff) { return [UInt8(0x81), UInt8(length)] }
    if (length <= 0xffff) {
        return [UInt8(0x82), UInt8((length >> 8) & 0xff), UInt8(length & 0xff)]
    }
    throw CryptoException(OutOfBounds, "DER value is too large")
}

private func tlcpDerRead(
    data: Array<Byte>, offset: Int64, label: String
): (Byte, Array<Byte>, Int64) {
    if (offset < 0 || offset + 2 > data.size) {
        throw CryptoException(ParseError, "${label} DER is truncated")
    }
    let tag = UInt8(data[offset])
    let firstLength = UInt8(data[offset + 1])
    var contentOffset = offset + 2
    var length: Int64 = 0
    if ((firstLength & UInt8(0x80)) == UInt8(0)) {
        length = Int64(firstLength)
    } else {
        let count = Int64(firstLength & UInt8(0x7f))
        if (count == 0 || count > 2 || contentOffset + count > data.size) {
            throw CryptoException(ParseError, "${label} DER length is invalid")
        }
        var i: Int64 = 0
        while (i < count) {
            length = (length << 8) | Int64(UInt8(data[contentOffset + i]))
            i += 1
        }
        if (length < 128) {
            throw CryptoException(ParseError, "${label} DER length is not minimal")
        }
        contentOffset += count
    }
    let end = contentOffset + length
    if (end > data.size) {
        throw CryptoException(ParseError, "${label} DER value is truncated")
    }
    (tag, data[contentOffset..end], end)
}

private func tlcpDerPositiveInteger(value: Array<Byte>, label: String): Array<Byte> {
    if (value.size == 0 || (UInt8(value[0]) & UInt8(0x80)) != UInt8(0)) {
        throw CryptoException(ParseError, "${label} is not a positive DER INTEGER")
    }
    var start: Int64 = 0
    if (value.size > 1 && UInt8(value[0]) == UInt8(0)) {
        if ((UInt8(value[1]) & UInt8(0x80)) == UInt8(0)) {
            throw CryptoException(ParseError, "${label} DER INTEGER has redundant padding")
        }
        start = 1
    }
    value[start..]
}

private func tlcpDerPositiveIntegerToFixed(
    value: Array<Byte>, width: Int64, label: String
): Array<Byte> {
    let magnitude = tlcpDerPositiveInteger(value, label)
    if (magnitude.size > width) {
        throw CryptoException(ParseError, "${label} exceeds curve width")
    }
    let output = Array<Byte>(width, repeat: UInt8(0))
    secureCopyInto(magnitude, output, dstOffset: width - magnitude.size)
    output
}

func tlcpConcat(left: Array<Byte>, right: Array<Byte>): Array<Byte> {
    let output = Array<Byte>(left.size + right.size, repeat: UInt8(0))
    secureCopyInto(left, output)
    secureCopyInto(right, output, dstOffset: left.size)
    output
}

func tlcpAppend(target: ArrayList<Byte>, value: Array<Byte>): Unit {
    for (item in value) { target.add(item) }
}
