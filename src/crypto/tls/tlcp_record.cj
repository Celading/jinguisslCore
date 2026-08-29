package jinguissl_core.crypto.tls

import jinguissl_core.crypto.digest.{hmac, HashAlgorithm}
import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}
import jinguissl_core.crypto.sm4.{sm4CbcDecrypt, sm4CbcEncrypt, sm4GcmDecrypt, sm4GcmEncrypt}
import jinguissl_core.crypto.utils.{constantTimeEquals, randomSeed, secureCopyInto}

public let TLCP_RECORD_HEADER_LEN: Int64 = 5
public let TLCP_CBC_MAC_LEN: Int64 = 32
public let TLCP_CBC_IV_LEN: Int64 = 16
public let TLCP_GCM_FIXED_IV_LEN: Int64 = 4
public let TLCP_GCM_EXPLICIT_IV_LEN: Int64 = 8
public let TLCP_GCM_TAG_LEN: Int64 = 16
public let TLCP_SM4_KEY_LEN: Int64 = 16

/** Master secret and directional key block produced by the TLCP SM3 PRF. */
public class TlcpHandshakeSecrets {
    public let cipherSuite: TlcpCipherSuite
    public let masterSecret: Array<Byte>
    public let clientMacKey: Array<Byte>
    public let serverMacKey: Array<Byte>
    public let clientWriteKey: Array<Byte>
    public let serverWriteKey: Array<Byte>
    public let clientWriteIv: Array<Byte>
    public let serverWriteIv: Array<Byte>

    public init(
        cipherSuite: TlcpCipherSuite,
        masterSecret: Array<Byte>,
        clientMacKey: Array<Byte>,
        serverMacKey: Array<Byte>,
        clientWriteKey: Array<Byte>,
        serverWriteKey: Array<Byte>,
        clientWriteIv: Array<Byte>,
        serverWriteIv: Array<Byte>
    ) {
        if (masterSecret.size != TLCP_MASTER_SECRET_LEN) {
            throw CryptoException(InvalidArgument, "TLCP master secret must be 48 bytes")
        }
        if (clientWriteKey.size != TLCP_SM4_KEY_LEN || serverWriteKey.size != TLCP_SM4_KEY_LEN) {
            throw CryptoException(InvalidArgument, "TLCP SM4 traffic keys must be 16 bytes")
        }
        let expectedIvLen = if (cipherSuite.usesGcm()) {
            TLCP_GCM_FIXED_IV_LEN
        } else {
            TLCP_CBC_IV_LEN
        }
        let expectedMacLen = if (cipherSuite.usesGcm()) { Int64(0) } else { TLCP_CBC_MAC_LEN }
        if (
            clientWriteIv.size != expectedIvLen || serverWriteIv.size != expectedIvLen ||
            clientMacKey.size != expectedMacLen || serverMacKey.size != expectedMacLen
        ) {
            throw CryptoException(InvalidArgument, "TLCP key block dimensions do not match cipher suite")
        }
        this.cipherSuite = cipherSuite
        this.masterSecret = masterSecret.clone()
        this.clientMacKey = clientMacKey.clone()
        this.serverMacKey = serverMacKey.clone()
        this.clientWriteKey = clientWriteKey.clone()
        this.serverWriteKey = serverWriteKey.clone()
        this.clientWriteIv = clientWriteIv.clone()
        this.serverWriteIv = serverWriteIv.clone()
    }
}

/** Derive the TLCP master secret and the complete CBC or GCM traffic key block. */
public func tlcpDeriveSecretsFromPreMaster(
    preMasterSecret: Array<Byte>,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    cipherSuite: TlcpCipherSuite
): TlcpHandshakeSecrets {
    if (preMasterSecret.size == 0 || clientRandom.size != 32 || serverRandom.size != 32) {
        throw CryptoException(InvalidArgument, "TLCP premaster/random dimensions are invalid")
    }
    let masterSecret = tlcpPrfSm3(
        preMasterSecret,
        "master secret",
        tlcpConcat(clientRandom, serverRandom),
        TLCP_MASTER_SECRET_LEN
    )
    let keyBlockLen = if (cipherSuite.usesGcm()) { Int64(40) } else { Int64(128) }
    let keyBlock = tlcpPrfSm3(
        masterSecret,
        "key expansion",
        tlcpConcat(serverRandom, clientRandom),
        keyBlockLen
    )
    if (cipherSuite.usesGcm()) {
        return TlcpHandshakeSecrets(
            cipherSuite,
            masterSecret,
            [],
            [],
            keyBlock[0..16],
            keyBlock[16..32],
            keyBlock[32..36],
            keyBlock[36..40]
        )
    }
    TlcpHandshakeSecrets(
        cipherSuite,
        masterSecret,
        keyBlock[0..32],
        keyBlock[32..64],
        keyBlock[64..80],
        keyBlock[80..96],
        keyBlock[96..112],
        keyBlock[112..128]
    )
}

public class TlcpPlainRecord {
    public let contentType: TlsContentType
    public let fragment: Array<Byte>

    public init(contentType: TlsContentType, fragment: Array<Byte>) {
        if (fragment.size > TLS_MAX_PLAINTEXT_LEN) {
            throw CryptoException(OutOfBounds, "TLCP plaintext exceeds max fragment size")
        }
        this.contentType = contentType
        this.fragment = fragment.clone()
    }
}

/** Stateful TLCP 1.1 record protection with directionally separated traffic keys. */
public class TlcpRecordLayer {
    public let cipherSuite: TlcpCipherSuite
    let _writeMacKey: Array<Byte>
    let _readMacKey: Array<Byte>
    let _writeKey: Array<Byte>
    let _readKey: Array<Byte>
    let _writeIv: Array<Byte>
    let _readIv: Array<Byte>
    var _writeSequence: Int64 = 0
    var _readSequence: Int64 = 0

    public init(secrets: TlcpHandshakeSecrets, isClient: Bool) {
        this.cipherSuite = secrets.cipherSuite
        if (isClient) {
            this._writeMacKey = secrets.clientMacKey.clone()
            this._readMacKey = secrets.serverMacKey.clone()
            this._writeKey = secrets.clientWriteKey.clone()
            this._readKey = secrets.serverWriteKey.clone()
            this._writeIv = secrets.clientWriteIv.clone()
            this._readIv = secrets.serverWriteIv.clone()
        } else {
            this._writeMacKey = secrets.serverMacKey.clone()
            this._readMacKey = secrets.clientMacKey.clone()
            this._writeKey = secrets.serverWriteKey.clone()
            this._readKey = secrets.clientWriteKey.clone()
            this._writeIv = secrets.serverWriteIv.clone()
            this._readIv = secrets.clientWriteIv.clone()
        }
    }

    public prop writeSequence: Int64 { get() { _writeSequence } }
    public prop readSequence: Int64 { get() { _readSequence } }

    public func seal(contentType: TlsContentType, plaintext: Array<Byte>): Array<Byte> {
        if (plaintext.size > TLS_MAX_PLAINTEXT_LEN) {
            throw CryptoException(OutOfBounds, "TLCP plaintext exceeds max fragment size")
        }
        let sequence = tlcpRecordSequence(_writeSequence)
        let protected = tlcpProtectFragment(
            cipherSuite,
            _writeMacKey,
            _writeKey,
            _writeIv,
            sequence,
            contentType,
            plaintext
        )
        let encoded = tlcpEncodeRecord(contentType, protected)
        _writeSequence += 1
        encoded
    }

    public func open(encodedRecord: Array<Byte>): TlcpPlainRecord {
        let (contentType, protected) = tlcpDecodeRecord(encodedRecord)
        let sequence = tlcpRecordSequence(_readSequence)
        let plaintext = tlcpOpenProtectedFragment(
            cipherSuite,
            _readMacKey,
            _readKey,
            _readIv,
            sequence,
            contentType,
            protected
        )
        _readSequence += 1
        TlcpPlainRecord(contentType, plaintext)
    }
}

public func tlcpCreateClientRecordLayer(secrets: TlcpHandshakeSecrets): TlcpRecordLayer {
    TlcpRecordLayer(secrets, true)
}

public func tlcpCreateServerRecordLayer(secrets: TlcpHandshakeSecrets): TlcpRecordLayer {
    TlcpRecordLayer(secrets, false)
}

public func tlcpEncodeRecord(contentType: TlsContentType, protectedFragment: Array<Byte>): Array<Byte> {
    if (protectedFragment.size > 0xffff) {
        throw CryptoException(OutOfBounds, "TLCP record ciphertext is too large")
    }
    let output = Array<Byte>(TLCP_RECORD_HEADER_LEN + protectedFragment.size, repeat: UInt8(0))
    output[0] = tlcpContentTypeToWire(contentType)
    output[1] = UInt8(0x01)
    output[2] = UInt8(0x01)
    output[3] = UInt8((protectedFragment.size >> 8) & 0xff)
    output[4] = UInt8(protectedFragment.size & 0xff)
    secureCopyInto(protectedFragment, output, dstOffset: TLCP_RECORD_HEADER_LEN)
    output
}

public func tlcpDecodeRecord(encoded: Array<Byte>): (TlsContentType, Array<Byte>) {
    if (encoded.size < TLCP_RECORD_HEADER_LEN) {
        throw CryptoException(ParseError, "TLCP record header is truncated")
    }
    if (UInt8(encoded[1]) != UInt8(0x01) || UInt8(encoded[2]) != UInt8(0x01)) {
        throw CryptoException(ParseError, "TLCP record version must be 0x0101")
    }
    let length = (Int64(UInt8(encoded[3])) << 8) | Int64(UInt8(encoded[4]))
    if (encoded.size != TLCP_RECORD_HEADER_LEN + length) {
        throw CryptoException(ParseError, "TLCP record length mismatch")
    }
    (tlcpContentTypeFromWire(UInt8(encoded[0])), encoded[TLCP_RECORD_HEADER_LEN..])
}

func tlcpProtectFragment(
    cipherSuite: TlcpCipherSuite,
    macKey: Array<Byte>,
    writeKey: Array<Byte>,
    fixedIv: Array<Byte>,
    sequence: Array<Byte>,
    contentType: TlsContentType,
    plaintext: Array<Byte>
): Array<Byte> {
    tlcpRequireTrafficInputs(cipherSuite, macKey, writeKey, fixedIv, sequence, plaintext.size)
    if (cipherSuite.usesGcm()) {
        let nonce = tlcpConcat(fixedIv, sequence)
        let aad = tlcpRecordAuthenticationData(sequence, contentType, plaintext.size)
        let (ciphertext, tag) = sm4GcmEncrypt(
            writeKey, nonce, plaintext, aad: aad, tagLen: TLCP_GCM_TAG_LEN
        )
        return tlcpConcat(sequence, tlcpConcat(ciphertext, tag))
    }

    let macInput = tlcpConcat(
        tlcpRecordAuthenticationData(sequence, contentType, plaintext.size), plaintext
    )
    let mac = hmac(HashAlgorithm.SM3, macKey, macInput)
    let authenticated = tlcpConcat(plaintext, mac)
    let padded = tlcpTlsCbcPad(authenticated)
    let explicitIv = randomSeed(size: TLCP_CBC_IV_LEN)
    tlcpConcat(explicitIv, sm4CbcEncrypt(writeKey, explicitIv, padded))
}

func tlcpOpenProtectedFragment(
    cipherSuite: TlcpCipherSuite,
    macKey: Array<Byte>,
    readKey: Array<Byte>,
    fixedIv: Array<Byte>,
    sequence: Array<Byte>,
    contentType: TlsContentType,
    protectedFragment: Array<Byte>
): Array<Byte> {
    tlcpRequireTrafficInputs(cipherSuite, macKey, readKey, fixedIv, sequence, 0)
    if (cipherSuite.usesGcm()) {
        if (protectedFragment.size < TLCP_GCM_EXPLICIT_IV_LEN + TLCP_GCM_TAG_LEN) {
            throw tlcpBadRecordMac()
        }
        let explicitIv = protectedFragment[0..TLCP_GCM_EXPLICIT_IV_LEN]
        if (!constantTimeEquals(explicitIv, sequence)) {
            throw tlcpBadRecordMac()
        }
        let cipherLen = protectedFragment.size - TLCP_GCM_EXPLICIT_IV_LEN - TLCP_GCM_TAG_LEN
        if (cipherLen > TLS_MAX_PLAINTEXT_LEN) {
            throw tlcpBadRecordMac()
        }
        let ciphertext = protectedFragment[
            TLCP_GCM_EXPLICIT_IV_LEN..(TLCP_GCM_EXPLICIT_IV_LEN + cipherLen)
        ]
        let tag = protectedFragment[(TLCP_GCM_EXPLICIT_IV_LEN + cipherLen)..]
        let nonce = tlcpConcat(fixedIv, explicitIv)
        let aad = tlcpRecordAuthenticationData(sequence, contentType, cipherLen)
        try {
            return sm4GcmDecrypt(readKey, nonce, ciphertext, tag, aad: aad)
        } catch (_: CryptoException) {
            throw tlcpBadRecordMac()
        }
    }

    if (
        protectedFragment.size < TLCP_CBC_IV_LEN + TLCP_CBC_IV_LEN ||
        ((protectedFragment.size - TLCP_CBC_IV_LEN) % TLCP_CBC_IV_LEN) != 0
    ) {
        throw tlcpBadRecordMac()
    }
    let explicitIv = protectedFragment[0..TLCP_CBC_IV_LEN]
    let ciphertext = protectedFragment[TLCP_CBC_IV_LEN..]
    var padded: Array<Byte>
    try {
        padded = sm4CbcDecrypt(readKey, explicitIv, ciphertext)
    } catch (_: CryptoException) {
        throw tlcpBadRecordMac()
    }
    let authenticated = tlcpTlsCbcUnpad(padded)
    if (authenticated.size < TLCP_CBC_MAC_LEN) {
        throw tlcpBadRecordMac()
    }
    let plainLen = authenticated.size - TLCP_CBC_MAC_LEN
    if (plainLen > TLS_MAX_PLAINTEXT_LEN) {
        throw tlcpBadRecordMac()
    }
    let plaintext = authenticated[..plainLen]
    let receivedMac = authenticated[plainLen..]
    let expectedMac = hmac(
        HashAlgorithm.SM3,
        macKey,
        tlcpConcat(tlcpRecordAuthenticationData(sequence, contentType, plainLen), plaintext)
    )
    if (!constantTimeEquals(receivedMac, expectedMac)) {
        throw tlcpBadRecordMac()
    }
    plaintext
}

func tlcpRecordAuthenticationData(
    sequence: Array<Byte>, contentType: TlsContentType, plaintextLen: Int64
): Array<Byte> {
    if (sequence.size != 8 || plaintextLen < 0 || plaintextLen > 0xffff) {
        throw CryptoException(InvalidArgument, "TLCP record authentication data is invalid")
    }
    let aad = Array<Byte>(13, repeat: UInt8(0))
    secureCopyInto(sequence, aad)
    aad[8] = tlcpContentTypeToWire(contentType)
    aad[9] = UInt8(0x01)
    aad[10] = UInt8(0x01)
    aad[11] = UInt8((plaintextLen >> 8) & 0xff)
    aad[12] = UInt8(plaintextLen & 0xff)
    aad
}

func tlcpContentTypeToWire(contentType: TlsContentType): Byte {
    match (contentType) {
        case ChangeCipherSpec => UInt8(0x14)
        case Alert => UInt8(0x15)
        case Handshake => UInt8(0x16)
        case ApplicationData => UInt8(0x17)
    }
}

func tlcpContentTypeFromWire(value: Byte): TlsContentType {
    if (value == UInt8(0x14)) { return ChangeCipherSpec }
    if (value == UInt8(0x15)) { return Alert }
    if (value == UInt8(0x16)) { return Handshake }
    if (value == UInt8(0x17)) { return ApplicationData }
    throw CryptoException(Unsupported, "unsupported TLCP content type")
}

func tlcpRecordSequence(value: Int64): Array<Byte> {
    if (value < 0 || value == Int64.Max) {
        throw CryptoException(OutOfBounds, "TLCP record sequence exhausted")
    }
    tlcpEncodeUInt64(value)
}

private func tlcpRequireTrafficInputs(
    cipherSuite: TlcpCipherSuite,
    macKey: Array<Byte>,
    key: Array<Byte>,
    fixedIv: Array<Byte>,
    sequence: Array<Byte>,
    plaintextLen: Int64
): Unit {
    if (key.size != TLCP_SM4_KEY_LEN || sequence.size != 8) {
        throw CryptoException(InvalidArgument, "TLCP traffic key/sequence dimensions are invalid")
    }
    if (plaintextLen < 0 || plaintextLen > TLS_MAX_PLAINTEXT_LEN) {
        throw CryptoException(OutOfBounds, "TLCP plaintext exceeds max fragment size")
    }
    if (cipherSuite.usesGcm()) {
        if (macKey.size != 0 || fixedIv.size != TLCP_GCM_FIXED_IV_LEN) {
            throw CryptoException(InvalidArgument, "TLCP GCM traffic material is invalid")
        }
    } else if (macKey.size != TLCP_CBC_MAC_LEN || fixedIv.size != TLCP_CBC_IV_LEN) {
        throw CryptoException(InvalidArgument, "TLCP CBC traffic material is invalid")
    }
}

private func tlcpTlsCbcPad(input: Array<Byte>): Array<Byte> {
    let paddingLen = TLCP_CBC_IV_LEN - ((input.size + 1) % TLCP_CBC_IV_LEN)
    let output = Array<Byte>(input.size + paddingLen + 1, repeat: UInt8(paddingLen))
    secureCopyInto(input, output)
    output
}

private func tlcpTlsCbcUnpad(input: Array<Byte>): Array<Byte> {
    if (input.size == 0) { throw tlcpBadRecordMac() }
    let paddingLen = Int64(UInt8(input[input.size - 1])) + 1
    if (paddingLen > input.size || paddingLen > 256) { throw tlcpBadRecordMac() }
    var mismatch: Int64 = 0
    var i: Int64 = 0
    while (i < paddingLen) {
        mismatch |= Int64(UInt8(input[input.size - 1 - i])) ^ (paddingLen - 1)
        i += 1
    }
    if (mismatch != 0) { throw tlcpBadRecordMac() }
    input[..(input.size - paddingLen)]
}

private func tlcpBadRecordMac(): CryptoException {
    CryptoException(ParseError, "TLCP record authentication failed")
}
