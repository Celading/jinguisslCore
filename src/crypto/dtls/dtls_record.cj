package jinguissl_core.crypto.dtls

import std.collection.ArrayList
import jinguissl_core.crypto.compliance.TlsVersion
import jinguissl_core.crypto.digest.{hmac, sha256, HashAlgorithm}
import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}

// ============================================================================
// DTLS Constants (RFC 6347)
// ============================================================================

public let DTLS_VERSION_1_0: UInt16 = UInt16(0xFEFF) // DTLS 1.0
public let DTLS_VERSION_1_2: UInt16 = UInt16(0xFEFD) // DTLS 1.2
public let DTLS_RECORD_HEADER_LEN: Int64 = 13
public let DTLS_MAX_PLAINTEXT_LEN: Int64 = 16384
// RFC 6347 §4.1.1 / §4.1.2.1: the AEAD ciphertext on the wire is
//   explicit_nonce (8 bytes) || encrypted_plaintext || auth tag (16 bytes).
// The previous definition omitted the 8-byte explicit nonce from the
// maximum ciphertext calculation, so the boundary check on decrypt
// could not prove exact acceptance/rejection. The constant now sums
// all three components.
public let DTLS_EXPLICIT_NONCE_LEN: Int64 = 8
public let DTLS_AEAD_TAG_LEN: Int64 = 16
public let DTLS_MAX_CIPHERTEXT_LEN: Int64 =
    DTLS_MAX_PLAINTEXT_LEN + DTLS_EXPLICIT_NONCE_LEN + DTLS_AEAD_TAG_LEN
// Minimum legal AEAD ciphertext blob: explicit nonce (8) + tag (16),
// with zero-length plaintext. Used by the decrypt boundary check.
public let DTLS_MIN_AEAD_CIPHERTEXT_LEN: Int64 =
    DTLS_EXPLICIT_NONCE_LEN + DTLS_AEAD_TAG_LEN
public let DTLS_HANDSHAKE_HEADER_LEN: Int64 = 12
public let DTLS_MAX_FRAGMENT_LEN: Int64 = 16384
// Upper bound on a single DTLS handshake message length (3-byte length field
// can express up to 2^24-1, but we cap at 1 MiB to prevent unbounded
// allocation driven by attacker-controlled declared lengths).
public let DTLS_MAX_HANDSHAKE_MSG_LEN: Int64 = 1048576
// RFC 5246 §7.4.1.2: session_id length MUST be in [0, 32].
public let DTLS_MAX_SESSION_ID_LEN: Int64 = 32
// RFC 6347 §4.2.2: cookie length MUST be in [0, 255] (single-byte length).
public let DTLS_MAX_COOKIE_LEN: Int64 = 255

// ============================================================================
// DTLS Content Type (same as TLS)
// ============================================================================

public enum DtlsContentType <: Equatable<DtlsContentType> & ToString {
    | ChangeCipherSpec
    | Alert
    | Handshake
    | ApplicationData

    public operator func ==(right: DtlsContentType): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: DtlsContentType): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case ChangeCipherSpec => 0
            case Alert => 1
            case Handshake => 2
            case ApplicationData => 3
        }
    }

    public func toUInt8(): UInt8 {
        match (this) {
            case ChangeCipherSpec => UInt8(20)
            case Alert => UInt8(21)
            case Handshake => UInt8(22)
            case ApplicationData => UInt8(23)
        }
    }

    public static func fromUInt8(b: UInt8): DtlsContentType {
        if (b == UInt8(20)) {
            ChangeCipherSpec
        } else if (b == UInt8(21)) {
            Alert
        } else if (b == UInt8(22)) {
            Handshake
        } else if (b == UInt8(23)) {
            ApplicationData
        } else {
            throw CryptoException(CryptoErrorCode.InvalidArgument, "invalid DTLS content type: " + b.toString())
        }
    }

    public func toString(): String {
        match (this) {
            case ChangeCipherSpec => "ChangeCipherSpec"
            case Alert => "Alert"
            case Handshake => "Handshake"
            case ApplicationData => "ApplicationData"
        }
    }
}

// ============================================================================
// DTLS Record Header (RFC 6347 Section 4.1)
// ============================================================================

public class DtlsRecordHeader {
    public let contentType: DtlsContentType
    public let version: UInt16
    public let epoch: UInt16
    public let sequenceNumber: UInt48
    public let length: UInt16

    public init(contentType: DtlsContentType, version: UInt16,
        epoch: UInt16, sequenceNumber: UInt48, length: UInt16) {
        this.contentType = contentType
        this.version = version
        this.epoch = epoch
        this.sequenceNumber = sequenceNumber
        this.length = length
    }

    public func toString(): String {
        "DtlsRecordHeader(type=" + contentType.toString() +
        ", ver=0x" + version.toString() +
        ", epoch=" + epoch.toString() +
        ", seq=" + sequenceNumber.toString() +
        ", len=" + length.toString() + ")"
    }
}

// ============================================================================
// UInt48 (DTLS sequence number is 48-bit)
// ============================================================================

public struct UInt48 <: Equatable<UInt48> & ToString {
    public let hi: UInt16
    public let lo: UInt32

    public init(hi: UInt16, lo: UInt32) {
        this.hi = hi
        this.lo = lo
    }

    public init(value: UInt64) {
        if (value > UInt64(0xffffffffffff)) {
            throw CryptoException(CryptoErrorCode.InvalidArgument, "DTLS sequence exceeds 48 bits")
        }
        this.hi = UInt16((value >> 32) & UInt64(0xFFFF))
        this.lo = UInt32(value & UInt64(0xFFFF_FFFF))
    }

    public func toUInt64(): UInt64 {
        (UInt64(hi) << 32) | UInt64(lo)
    }

    public operator func ==(right: UInt48): Bool {
        hi == right.hi && lo == right.lo
    }

    public operator func !=(right: UInt48): Bool {
        !(this == right)
    }

    public operator func <(right: UInt48): Bool {
        if (hi != right.hi) {
            return hi < right.hi
        }
        lo < right.lo
    }

    public operator func >(right: UInt48): Bool {
        if (hi != right.hi) {
            return hi > right.hi
        }
        lo > right.lo
    }

    public func toString(): String {
        toUInt64().toString()
    }

    public func next(): UInt48 {
        let v = toUInt64() + UInt64(1)
        UInt48(v)
    }
}

// ============================================================================
// DTLS Record Encoding/Decoding
// ============================================================================

public func dtlsEncodeRecordHeader(header: DtlsRecordHeader): Array<Byte> {
    let out = Array<Byte>(Int64(DTLS_RECORD_HEADER_LEN), repeat: 0)
    out[0] = UInt8(header.contentType.toUInt8())
    // Version (2 bytes big-endian)
    out[1] = UInt8((header.version >> 8) & UInt16(0xFF))
    out[2] = UInt8(header.version & UInt16(0xFF))
    // Epoch (2 bytes big-endian)
    out[3] = UInt8((header.epoch >> 8) & UInt16(0xFF))
    out[4] = UInt8(header.epoch & UInt16(0xFF))
    // Sequence number (6 bytes big-endian)
    let seq64 = header.sequenceNumber.toUInt64()
    out[5] = UInt8((seq64 >> 40) & UInt64(0xFF))
    out[6] = UInt8((seq64 >> 32) & UInt64(0xFF))
    out[7] = UInt8((seq64 >> 24) & UInt64(0xFF))
    out[8] = UInt8((seq64 >> 16) & UInt64(0xFF))
    out[9] = UInt8((seq64 >> 8) & UInt64(0xFF))
    out[10] = UInt8(seq64 & UInt64(0xFF))
    // Length (2 bytes big-endian)
    out[11] = UInt8((header.length >> 8) & UInt16(0xFF))
    out[12] = UInt8(header.length & UInt16(0xFF))
    out
}

public func dtlsDecodeRecordHeader(data: Array<Byte>): DtlsRecordHeader {
    if (data.size < DTLS_RECORD_HEADER_LEN) {
        throw CryptoException(CryptoErrorCode.InvalidArgument,
            "DTLS record header too short: " + data.size.toString())
    }
    let contentType = DtlsContentType.fromUInt8(UInt8(data[0]))
    let version = (UInt16(data[1]) << 8) | UInt16(data[2])
    let epoch = (UInt16(data[3]) << 8) | UInt16(data[4])
    let seq = (UInt64(data[5]) << 40) | (UInt64(data[6]) << 32) |
              (UInt64(data[7]) << 24) | (UInt64(data[8]) << 16) |
              (UInt64(data[9]) << 8) | UInt64(data[10])
    let length = (UInt16(data[11]) << 8) | UInt16(data[12])
    DtlsRecordHeader(contentType, version, epoch, UInt48(seq), length)
}

/// Encode a complete DTLS record (header + fragment).
public func dtlsEncodeRecord(contentType: DtlsContentType, version: UInt16,
    epoch: UInt16, sequenceNumber: UInt48, fragment: Array<Byte>): Array<Byte> {
    let header = DtlsRecordHeader(contentType, version, epoch,
        sequenceNumber, UInt16(fragment.size))
    let headerBytes = dtlsEncodeRecordHeader(header)
    let out = Array<Byte>(headerBytes.size + fragment.size, repeat: 0)
    for (i in 0..headerBytes.size) {
        out[i] = headerBytes[i]
    }
    for (i in 0..fragment.size) {
        out[headerBytes.size + i] = fragment[i]
    }
    out
}

/// Decode a complete DTLS record (header + fragment).
public func dtlsDecodeRecord(data: Array<Byte>): (DtlsRecordHeader, Array<Byte>) {
    let header = dtlsDecodeRecordHeader(data)
    if (data.size < DTLS_RECORD_HEADER_LEN + Int64(header.length)) {
        throw CryptoException(CryptoErrorCode.InvalidArgument,
            "DTLS record truncated: header says " + header.length.toString() +
            " bytes but only " + (data.size - DTLS_RECORD_HEADER_LEN).toString() + " available")
    }
    let fragment = Array<Byte>(Int64(header.length), repeat: 0)
    for (i in 0..Int64(header.length)) {
        fragment[i] = data[DTLS_RECORD_HEADER_LEN + i]
    }
    (header, fragment)
}

// ============================================================================
// DTLS Handshake Fragment Header (RFC 6347 Section 4.2.2)
// ============================================================================

public enum DtlsHandshakeType <: Equatable<DtlsHandshakeType> & ToString {
    | HelloRequest
    | ClientHello
    | ServerHello
    | HelloVerifyRequest
    | Certificate
    | ServerKeyExchange
    | CertificateRequest
    | ServerHelloDone
    | CertificateVerify
    | ClientKeyExchange
    | Finished

    public operator func ==(right: DtlsHandshakeType): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: DtlsHandshakeType): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case HelloRequest => 0
            case ClientHello => 1
            case ServerHello => 2
            case HelloVerifyRequest => 3
            case Certificate => 4
            case ServerKeyExchange => 5
            case CertificateRequest => 6
            case ServerHelloDone => 7
            case CertificateVerify => 8
            case ClientKeyExchange => 9
            case Finished => 10
        }
    }

    public func toUInt8(): UInt8 {
        match (this) {
            case HelloRequest => UInt8(0)
            case ClientHello => UInt8(1)
            case ServerHello => UInt8(2)
            case HelloVerifyRequest => UInt8(3)
            case Certificate => UInt8(11)
            case ServerKeyExchange => UInt8(12)
            case CertificateRequest => UInt8(13)
            case ServerHelloDone => UInt8(14)
            case CertificateVerify => UInt8(15)
            case ClientKeyExchange => UInt8(16)
            case Finished => UInt8(20)
        }
    }

    public static func fromUInt8(b: UInt8): DtlsHandshakeType {
        if (b == UInt8(0)) { HelloRequest }
        else if (b == UInt8(1)) { ClientHello }
        else if (b == UInt8(2)) { ServerHello }
        else if (b == UInt8(3)) { HelloVerifyRequest }
        else if (b == UInt8(11)) { Certificate }
        else if (b == UInt8(12)) { ServerKeyExchange }
        else if (b == UInt8(13)) { CertificateRequest }
        else if (b == UInt8(14)) { ServerHelloDone }
        else if (b == UInt8(15)) { CertificateVerify }
        else if (b == UInt8(16)) { ClientKeyExchange }
        else if (b == UInt8(20)) { Finished }
        else { throw CryptoException(CryptoErrorCode.InvalidArgument,
            "invalid DTLS handshake type: " + b.toString()) }
    }

    public func toString(): String {
        match (this) {
            case HelloRequest => "HelloRequest"
            case ClientHello => "ClientHello"
            case ServerHello => "ServerHello"
            case HelloVerifyRequest => "HelloVerifyRequest"
            case Certificate => "Certificate"
            case ServerKeyExchange => "ServerKeyExchange"
            case CertificateRequest => "CertificateRequest"
            case ServerHelloDone => "ServerHelloDone"
            case CertificateVerify => "CertificateVerify"
            case ClientKeyExchange => "ClientKeyExchange"
            case Finished => "Finished"
        }
    }
}

// ============================================================================
// DTLS Handshake Fragment Header
// ============================================================================

public class DtlsHandshakeFragment {
    public let msgType: DtlsHandshakeType
    public let length: UInt32       // total message length (3 bytes in wire)
    public let messageSeq: UInt16   // DTLS-specific
    public let fragmentOffset: UInt32  // 3 bytes
    public let fragmentLength: UInt32   // 3 bytes
    public let body: Array<Byte>

    public init(msgType: DtlsHandshakeType, length: UInt32,
        messageSeq: UInt16, fragmentOffset: UInt32, fragmentLength: UInt32,
        body: Array<Byte>) {
        this.msgType = msgType
        this.length = length
        this.messageSeq = messageSeq
        this.fragmentOffset = fragmentOffset
        this.fragmentLength = fragmentLength
        this.body = body
    }

    public func isComplete(): Bool {
        Int64(fragmentOffset) == 0 && fragmentLength == length
    }

    public func toString(): String {
        "DtlsHandshakeFragment(type=" + msgType.toString() +
        ", len=" + length.toString() +
        ", msgSeq=" + messageSeq.toString() +
        ", fragOff=" + fragmentOffset.toString() +
        ", fragLen=" + fragmentLength.toString() + ")"
    }
}

/// Encode a DTLS handshake fragment header + body.
public func dtlsEncodeHandshakeFragment(frag: DtlsHandshakeFragment): Array<Byte> {
    let out = Array<Byte>(Int64(DTLS_HANDSHAKE_HEADER_LEN) + frag.body.size, repeat: 0)
    out[0] = UInt8(frag.msgType.toUInt8())
    // Length (3 bytes big-endian)
    out[1] = UInt8((frag.length >> 16) & UInt32(0xFF))
    out[2] = UInt8((frag.length >> 8) & UInt32(0xFF))
    out[3] = UInt8(frag.length & UInt32(0xFF))
    // Message sequence (2 bytes big-endian)
    out[4] = UInt8((frag.messageSeq >> 8) & UInt16(0xFF))
    out[5] = UInt8(frag.messageSeq & UInt16(0xFF))
    // Fragment offset (3 bytes big-endian)
    out[6] = UInt8((frag.fragmentOffset >> 16) & UInt32(0xFF))
    out[7] = UInt8((frag.fragmentOffset >> 8) & UInt32(0xFF))
    out[8] = UInt8(frag.fragmentOffset & UInt32(0xFF))
    // Fragment length (3 bytes big-endian)
    out[9] = UInt8((frag.fragmentLength >> 16) & UInt32(0xFF))
    out[10] = UInt8((frag.fragmentLength >> 8) & UInt32(0xFF))
    out[11] = UInt8(frag.fragmentLength & UInt32(0xFF))
    // Body
    for (i in 0..frag.body.size) {
        out[DTLS_HANDSHAKE_HEADER_LEN + i] = frag.body[i]
    }
    out
}

/// Decode a DTLS handshake fragment from data.
public func dtlsDecodeHandshakeFragment(data: Array<Byte>): DtlsHandshakeFragment {
    if (data.size < DTLS_HANDSHAKE_HEADER_LEN) {
        throw CryptoException(CryptoErrorCode.InvalidArgument,
            "DTLS handshake fragment header too short: " + data.size.toString())
    }
    let msgType = DtlsHandshakeType.fromUInt8(UInt8(data[0]))
    let length = (UInt32(data[1]) << 16) | (UInt32(data[2]) << 8) | UInt32(data[3])
    let messageSeq = (UInt16(data[4]) << 8) | UInt16(data[5])
    let fragOffset = (UInt32(data[6]) << 16) | (UInt32(data[7]) << 8) | UInt32(data[8])
    let fragLength = (UInt32(data[9]) << 16) | (UInt32(data[10]) << 8) | UInt32(data[11])

    // bounds checks on declared lengths.
    // 1. Declared total message length must fit the protocol cap.
    if (Int64(length) > DTLS_MAX_HANDSHAKE_MSG_LEN) {
        throw CryptoException(CryptoErrorCode.InvalidArgument,
            "DTLS handshake fragment: declared length " + length.toString() +
            " exceeds max " + DTLS_MAX_HANDSHAKE_MSG_LEN.toString())
    }
    // 2. Declared fragment length must fit the protocol cap.
    if (Int64(fragLength) > DTLS_MAX_HANDSHAKE_MSG_LEN) {
        throw CryptoException(CryptoErrorCode.InvalidArgument,
            "DTLS handshake fragment: declared fragLength " + fragLength.toString() +
            " exceeds max " + DTLS_MAX_HANDSHAKE_MSG_LEN.toString())
    }
    // 3. Fragment range must fit within the declared total length:
    //    fragOffset + fragLength <= length. Guard against UInt32 overflow
    //    by promoting to UInt64 before addition.
    let rangeEnd64 = UInt64(fragOffset) + UInt64(fragLength)
    if (rangeEnd64 > UInt64(length)) {
        throw CryptoException(CryptoErrorCode.InvalidArgument,
            "DTLS handshake fragment: fragment range [" + fragOffset.toString() +
            ", " + rangeEnd64.toString() + ") exceeds declared length " +
            length.toString())
    }
    // 4. Fragment body must be fully present in the buffer.
    let bodyLen = Int64(fragLength)
    if (data.size < DTLS_HANDSHAKE_HEADER_LEN + bodyLen) {
        throw CryptoException(CryptoErrorCode.InvalidArgument,
            "DTLS handshake fragment body truncated: declared " +
            bodyLen.toString() + " bytes but only " +
            (data.size - DTLS_HANDSHAKE_HEADER_LEN).toString() + " available")
    }
    let body = Array<Byte>(bodyLen, repeat: 0)
    for (i in 0..bodyLen) {
        body[i] = data[DTLS_HANDSHAKE_HEADER_LEN + i]
    }
    DtlsHandshakeFragment(msgType, length, messageSeq, fragOffset, fragLength, body)
}

// ============================================================================
// DTLS Handshake Fragment Reassembly
// ============================================================================

public class DtlsFragmentReassembler {
    private var fragments: ArrayList<DtlsHandshakeFragment>
    public let expectedType: DtlsHandshakeType
    public let expectedLength: UInt32
    public let messageSeq: UInt16
    private var receivedBytes: Array<Byte>
    // track covered ranges to detect duplicate / overlapping
    // fragments deterministically. `covered[i] == true` means byte i has
    // been written by a previously accepted fragment; a second write to
    // the same byte is an overlap conflict (RFC 6347 §4.2.2).
    private var covered: Array<Bool>

    public init(expectedType: DtlsHandshakeType, expectedLength: UInt32,
        messageSeq: UInt16) {
        // reject unbounded allocation driven by attacker-controlled
        // declared length.
        if (Int64(expectedLength) > DTLS_MAX_HANDSHAKE_MSG_LEN) {
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "DTLS reassembler: expectedLength " + expectedLength.toString() +
                " exceeds max " + DTLS_MAX_HANDSHAKE_MSG_LEN.toString())
        }
        this.expectedType = expectedType
        this.expectedLength = expectedLength
        this.messageSeq = messageSeq
        this.fragments = ArrayList<DtlsHandshakeFragment>()
        this.receivedBytes = Array<Byte>(Int64(expectedLength), repeat: 0)
        this.covered = Array<Bool>(Int64(expectedLength), repeat: false)
    }

    public func addFragment(frag: DtlsHandshakeFragment): Bool {
        if (frag.msgType != expectedType || frag.messageSeq != messageSeq || frag.length != expectedLength) {
            return false
        }

        // bounds check — fragment range must fit within
        // expectedLength. Promote to UInt64 to avoid UInt32 overflow on
        // `offset + length`.
        let offset64 = UInt64(frag.fragmentOffset)
        let end64 = offset64 + UInt64(frag.fragmentLength)
        if (end64 > UInt64(expectedLength)) {
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "DTLS reassembler: fragment range [" + frag.fragmentOffset.toString() +
                ", " + end64.toString() + ") exceeds expectedLength " +
                expectedLength.toString())
        }
        // body must match declared fragmentLength.
        if (Int64(frag.fragmentLength) != frag.body.size) {
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "DTLS reassembler: fragment body size " + frag.body.size.toString() +
                " != declared fragmentLength " + frag.fragmentLength.toString())
        }

        // RFC 6347 permits identical overlapping retransmissions.
        // Validate every covered byte before changing reassembly state.
        let start = Int64(frag.fragmentOffset)
        let end = start + Int64(frag.fragmentLength)
        for (i in start..end) {
            if (covered[i] && receivedBytes[i] != frag.body[i - start]) {
                throw CryptoException(CryptoErrorCode.InvalidArgument, "conflicting DTLS fragment bytes")
            }
        }
        for (i in 0..frag.body.size) {
            receivedBytes[start + i] = frag.body[i]
            covered[start + i] = true
        }
        isComplete()
    }

    public func isComplete(): Bool {
        // Check if all bytes are covered by received fragments
        var allCovered = true
        for (i in 0..covered.size) {
            if (!covered[i]) {
                allCovered = false
            }
        }
        allCovered
    }

    public func getReassembled(): Array<Byte> {
        if (!isComplete()) {
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "DTLS handshake fragments not complete")
        }
        receivedBytes.clone()
    }
}

// ============================================================================
// DTLS Handshake Flight (RFC 6347 Section 4.2.6)
// ============================================================================

public enum DtlsFlightType <: Equatable<DtlsFlightType> & ToString {
    | Flight0  // ClientHello (no cookie)
    | Flight1  // HelloVerifyRequest
    | Flight2  // ClientHello (with cookie)
    | Flight3  // ServerHello + Certificate + ServerKeyExchange + ServerHelloDone
    | Flight4  // ClientKeyExchange + ChangeCipherSpec + Finished
    | Flight5  // ChangeCipherSpec + Finished
    | Flight6  // ACK (post-handshake)

    public operator func ==(right: DtlsFlightType): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: DtlsFlightType): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case Flight0 => 0
            case Flight1 => 1
            case Flight2 => 2
            case Flight3 => 3
            case Flight4 => 4
            case Flight5 => 5
            case Flight6 => 6
        }
    }

    public func toString(): String {
        match (this) {
            case Flight0 => "Flight0"
            case Flight1 => "Flight1"
            case Flight2 => "Flight2"
            case Flight3 => "Flight3"
            case Flight4 => "Flight4"
            case Flight5 => "Flight5"
            case Flight6 => "Flight6"
        }
    }
}

/// Retransmit timer state for a flight (RFC 6347 Section 4.2.4.1)
public class DtlsFlightTimer {
    public var initialTimeout: Int64 = 1000  // 1 second default
    public var maxTimeout: Int64 = 60000     // 60 seconds max
    public var currentTimeout: Int64 = 1000
    public var retransmitCount: Int64 = 0
    public var maxRetransmits: Int64 = 15

    public init() {
    }

    public func nextTimeout(): Int64 {
        retransmitCount += 1
        if (retransmitCount > maxRetransmits) {
            return -1  // give up
        }
        // Double the timeout (exponential backoff)
        currentTimeout = currentTimeout * 2
        if (currentTimeout > maxTimeout) {
            currentTimeout = maxTimeout
        }
        currentTimeout
    }

    public func reset(): Unit {
        currentTimeout = initialTimeout
        retransmitCount = 0
    }
}

// ============================================================================
// DTLS Epoch and Sequence Management
// ============================================================================

public class DtlsEpochState {
    private var sendExhausted: Bool = false
    public var epoch: UInt16
    public var nextSendSeq: UInt48
    public var nextRecvSeq: UInt48
    public var writeKey: Array<Byte>
    public var writeIv: Array<Byte>
    public var readKey: Array<Byte>
    public var readIv: Array<Byte>

    public init(epoch: UInt16, writeKey: Array<Byte>, writeIv: Array<Byte>,
        readKey: Array<Byte>, readIv: Array<Byte>) {
        this.epoch = epoch
        this.nextSendSeq = UInt48(UInt64(0))
        this.nextRecvSeq = UInt48(UInt64(0))
        this.writeKey = writeKey
        this.writeIv = writeIv
        this.readKey = readKey
        this.readIv = readIv
    }

    public func nextSendSequence(): UInt48 {
        if (sendExhausted) {
            throw CryptoException(CryptoErrorCode.InvalidArgument, "DTLS epoch send sequence exhausted")
        }
        let seq = nextSendSeq
        if (seq.toUInt64() == UInt64(0xffffffffffff)) {
            sendExhausted = true
        } else {
            nextSendSeq = nextSendSeq.next()
        }
        seq
    }

    public func toString(): String {
        "DtlsEpochState(epoch=" + epoch.toString() +
        ", sendSeq=" + nextSendSeq.toString() +
        ", recvSeq=" + nextRecvSeq.toString() + ")"
    }
}

// ============================================================================
// DTLS Session State
// ============================================================================

public enum DtlsConnectionState <: Equatable<DtlsConnectionState> & ToString {
    | Idle
    | ClientHelloSent
    | HelloVerifyReceived
    | ClientHelloWithCookieSent
    | ServerHelloReceived
    | ServerHelloDoneReceived
    | ClientKeyExchangeSent
    | FinishedSent
    | Established
    | Closed
    | Failed

    public operator func ==(right: DtlsConnectionState): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: DtlsConnectionState): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case Idle => 0
            case ClientHelloSent => 1
            case HelloVerifyReceived => 2
            case ClientHelloWithCookieSent => 3
            case ServerHelloReceived => 4
            case ServerHelloDoneReceived => 5
            case ClientKeyExchangeSent => 6
            case FinishedSent => 7
            case Established => 8
            case Closed => 9
            case Failed => 10
        }
    }

    public func toString(): String {
        match (this) {
            case Idle => "Idle"
            case ClientHelloSent => "ClientHelloSent"
            case HelloVerifyReceived => "HelloVerifyReceived"
            case ClientHelloWithCookieSent => "ClientHelloWithCookieSent"
            case ServerHelloReceived => "ServerHelloReceived"
            case ServerHelloDoneReceived => "ServerHelloDoneReceived"
            case ClientKeyExchangeSent => "ClientKeyExchangeSent"
            case FinishedSent => "FinishedSent"
            case Established => "Established"
            case Closed => "Closed"
            case Failed => "Failed"
        }
    }
}

public enum DtlsRole <: Equatable<DtlsRole> & ToString {
    | Client
    | Server

    public operator func ==(right: DtlsRole): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: DtlsRole): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case Client => 0
            case Server => 1
        }
    }

    public func toString(): String {
        match (this) {
            case Client => "Client"
            case Server => "Server"
        }
    }
}

public class DtlsSession {
    public var role: DtlsRole
    public var state: DtlsConnectionState
    public var version: UInt16
    public var currentEpoch: DtlsEpochState
    public var pendingEpoch: ?DtlsEpochState = None
    public var flightTimer: DtlsFlightTimer
    public var currentFlight: DtlsFlightType
    public var messageSeq: UInt16

    public init(role: DtlsRole) {
        this.role = role
        this.state = DtlsConnectionState.Idle
        this.version = DTLS_VERSION_1_2
        this.currentEpoch = DtlsEpochState(UInt16(0),
            Array<Byte>(), Array<Byte>(), Array<Byte>(), Array<Byte>())
        this.flightTimer = DtlsFlightTimer()
        this.currentFlight = DtlsFlightType.Flight0
        this.messageSeq = UInt16(0)
    }

    public func nextMessageSeq(): UInt16 {
        let seq = messageSeq
        messageSeq = messageSeq + UInt16(1)
        seq
    }

    public func transition(newState: DtlsConnectionState): Unit {
        if (!dtlsIsValidStateTransition(role, state, newState)) {
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "illegal DTLS state transition: " + state.toString() +
                " -> " + newState.toString() + " for role " + role.toString())
        }
        state = newState
    }

    public func toString(): String {
        "DtlsSession(role=" + role.toString() +
        ", state=" + state.toString() +
        ", epoch=" + currentEpoch.epoch.toString() +
        ", flight=" + currentFlight.toString() + ")"
    }
}

// ============================================================================
// DTLS-SRTP Protection Profile (RFC 5764)
// ============================================================================

public enum DtlsSrtpProtectionProfile <: Equatable<DtlsSrtpProtectionProfile> & ToString {
    | Aes128CmSha1_80   // SRTP_AES128_CM_HMAC_SHA1_80
    | Aes128CmSha1_32   // SRTP_AES128_CM_HMAC_SHA1_32
    | AeadAes128Gcm     // SRTP_AEAD_AES_128_GCM
    | AeadAes256Gcm     // SRTP_AEAD_AES_256_GCM

    public operator func ==(right: DtlsSrtpProtectionProfile): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: DtlsSrtpProtectionProfile): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case Aes128CmSha1_80 => 0
            case Aes128CmSha1_32 => 1
            case AeadAes128Gcm => 2
            case AeadAes256Gcm => 3
        }
    }

    public func toCode(): UInt16 {
        match (this) {
            case Aes128CmSha1_80 => UInt16(0x0001)
            case Aes128CmSha1_32 => UInt16(0x0002)
            case AeadAes128Gcm => UInt16(0x0007)
            case AeadAes256Gcm => UInt16(0x0008)
        }
    }

    public static func fromCode(code: UInt16): ?DtlsSrtpProtectionProfile {
        if (code == UInt16(0x0001)) { Aes128CmSha1_80 }
        else if (code == UInt16(0x0002)) { Aes128CmSha1_32 }
        else if (code == UInt16(0x0007)) { AeadAes128Gcm }
        else if (code == UInt16(0x0008)) { AeadAes256Gcm }
        else { None }
    }

    public func toString(): String {
        match (this) {
            case Aes128CmSha1_80 => "SRTP_AES128_CM_HMAC_SHA1_80"
            case Aes128CmSha1_32 => "SRTP_AES128_CM_HMAC_SHA1_32"
            case AeadAes128Gcm => "SRTP_AEAD_AES_128_GCM"
            case AeadAes256Gcm => "SRTP_AEAD_AES_256_GCM"
        }
    }

    public func keyLen(): Int64 {
        match (this) {
            case Aes128CmSha1_80 | Aes128CmSha1_32 | AeadAes128Gcm => 16
            case AeadAes256Gcm => 32
        }
    }

    public func saltLen(): Int64 {
        match (this) {
            case Aes128CmSha1_80 | Aes128CmSha1_32 => 14
            case AeadAes128Gcm | AeadAes256Gcm => 12
        }
    }
}

/// DTLS-SRTP keying material extraction (RFC 5764 Section 4.2)
/// Extracts keying material from the DTLS handshake for SRTP.
public func dtlsSrtpExtractKeyingMaterial(masterSecret: Array<Byte>,
    clientRandom: Array<Byte>, serverRandom: Array<Byte>,
    profile: DtlsSrtpProtectionProfile): DtlsSrtpKeyingMaterial {
    // keying material = PRF(master_secret, "EXTRACTOR-dtls_srtp",
    //                       client_random || server_random)
    // For AEAD profiles: 2 * (key_len + salt_len) bytes
    // For non-AEAD: 2 * (key_len + salt_len) bytes
    let totalLen = profile.keyLen() * 2 + profile.saltLen() * 2
    // Simple PRF using HMAC-SHA256 (in real impl, use TLS 1.2 PRF)
    // This is a placeholder that concatenates and hashes
    let label = "EXTRACTOR-dtls_srtp".toArray()
    let seed = Array<Byte>(clientRandom.size + serverRandom.size, repeat: 0)
    for (i in 0..clientRandom.size) { seed[i] = clientRandom[i] }
    for (i in 0..serverRandom.size) { seed[clientRandom.size + i] = serverRandom[i] }

    // P_SHA256 expansion (simplified)
    let material = pSha256(masterSecret, label, seed, totalLen)

    // Split into client/server key and salt
    let keyLen = profile.keyLen()
    let saltLen = profile.saltLen()
    let clientKey = Array<Byte>(keyLen, repeat: 0)
    let serverKey = Array<Byte>(keyLen, repeat: 0)
    let clientSalt = Array<Byte>(saltLen, repeat: 0)
    let serverSalt = Array<Byte>(saltLen, repeat: 0)

    var offset = 0
    for (i in 0..keyLen) { clientKey[i] = material[offset + i] }
    offset += Int64(keyLen)
    for (i in 0..keyLen) { serverKey[i] = material[offset + i] }
    offset += Int64(keyLen)
    for (i in 0..saltLen) { clientSalt[i] = material[offset + i] }
    offset += Int64(saltLen)
    for (i in 0..saltLen) { serverSalt[i] = material[offset + i] }

    DtlsSrtpKeyingMaterial(clientKey, serverKey, clientSalt, serverSalt, profile)
}

public class DtlsSrtpKeyingMaterial {
    public let clientWriteKey: Array<Byte>
    public let serverWriteKey: Array<Byte>
    public let clientWriteSalt: Array<Byte>
    public let serverWriteSalt: Array<Byte>
    public let profile: DtlsSrtpProtectionProfile

    public init(clientWriteKey: Array<Byte>, serverWriteKey: Array<Byte>,
        clientWriteSalt: Array<Byte>, serverWriteSalt: Array<Byte>,
        profile: DtlsSrtpProtectionProfile) {
        this.clientWriteKey = clientWriteKey
        this.serverWriteKey = serverWriteKey
        this.clientWriteSalt = clientWriteSalt
        this.serverWriteSalt = serverWriteSalt
        this.profile = profile
    }

    public func toString(): String {
        "DtlsSrtpKeyingMaterial(profile=" + profile.toString() +
        ", clientKey=" + clientWriteKey.size.toString() + "B" +
        ", serverKey=" + serverWriteKey.size.toString() + "B" +
        ", clientSalt=" + clientWriteSalt.size.toString() + "B" +
        ", serverSalt=" + serverWriteSalt.size.toString() + "B)"
    }
}

// ============================================================================
// P_SHA256 PRF (TLS 1.2 style, simplified for DTLS-SRTP key extraction)
// ============================================================================


// P_SHA256(secret, label || seed, length)
private func pSha256(secret: Array<Byte>, label: Array<Byte>,
    seed: Array<Byte>, length: Int64): Array<Byte> {
    // A(0) = label || seed
    let labelSeed = Array<Byte>(label.size + seed.size, repeat: 0)
    for (i in 0..label.size) { labelSeed[i] = label[i] }
    for (i in 0..seed.size) { labelSeed[label.size + i] = seed[i] }

    // A(1) = HMAC-SHA256(secret, A(0))
    var a = hmac(HashAlgorithm.SHA256, secret, labelSeed)
    let result = ArrayList<Byte>()

    while (result.size < length) {
        // P_hash = HMAC-SHA256(secret, A(i) || label || seed)
        let input = Array<Byte>(a.size + labelSeed.size, repeat: 0)
        for (i in 0..a.size) { input[i] = a[i] }
        for (i in 0..labelSeed.size) { input[a.size + i] = labelSeed[i] }
        let p = hmac(HashAlgorithm.SHA256, secret, input)
        for (b in p) {
            result.add(b)
        }
        // A(i+1) = HMAC-SHA256(secret, A(i))
        a = hmac(HashAlgorithm.SHA256, secret, a)
    }

    // Truncate to length
    let out = Array<Byte>(length, repeat: 0)
    for (i in 0..length) {
        out[i] = result[i]
    }
    out
}

// ============================================================================
// DTLS Alert (RFC 5246 Section 7.2 / RFC 6347)
// ============================================================================

public enum DtlsAlertLevel <: Equatable<DtlsAlertLevel> & ToString {
    | Warning
    | Fatal

    public operator func ==(right: DtlsAlertLevel): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: DtlsAlertLevel): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case Warning => 0
            case Fatal => 1
        }
    }

    public func toUInt8(): UInt8 {
        match (this) {
            case Warning => UInt8(1)
            case Fatal => UInt8(2)
        }
    }

    public static func fromUInt8(b: UInt8): DtlsAlertLevel {
        if (b == UInt8(1)) { Warning }
        else if (b == UInt8(2)) { Fatal }
        else { throw CryptoException(CryptoErrorCode.InvalidArgument, "invalid DTLS alert level: " + b.toString()) }
    }

    public func toString(): String {
        match (this) {
            case Warning => "Warning"
            case Fatal => "Fatal"
        }
    }
}

public enum DtlsAlertDescription <: Equatable<DtlsAlertDescription> & ToString {
    | CloseNotify
    | UnexpectedMessage
    | BadRecordMac
    | HandshakeFailure
    | BadCertificate
    | UnsupportedCertificate
    | CertificateRevoked
    | CertificateExpired
    | CertificateUnknown
    | IllegalParameter
    | UnknownCa
    | AccessDenied
    | DecodeError
    | DecryptError
    | ProtocolVersion
    | InsufficientSecurity
    | InternalError
    | UserCanceled
    | NoRenegotiation
    | UnsupportedExtension

    public operator func ==(right: DtlsAlertDescription): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public operator func !=(right: DtlsAlertDescription): Bool {
        !(this == right)
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case CloseNotify => 0
            case UnexpectedMessage => 1
            case BadRecordMac => 2
            case HandshakeFailure => 3
            case BadCertificate => 4
            case UnsupportedCertificate => 5
            case CertificateRevoked => 6
            case CertificateExpired => 7
            case CertificateUnknown => 8
            case IllegalParameter => 9
            case UnknownCa => 10
            case AccessDenied => 11
            case DecodeError => 12
            case DecryptError => 13
            case ProtocolVersion => 14
            case InsufficientSecurity => 15
            case InternalError => 16
            case UserCanceled => 17
            case NoRenegotiation => 18
            case UnsupportedExtension => 19
        }
    }

    public func toUInt8(): UInt8 {
        match (this) {
            case CloseNotify => UInt8(0)
            case UnexpectedMessage => UInt8(10)
            case BadRecordMac => UInt8(20)
            case HandshakeFailure => UInt8(40)
            case BadCertificate => UInt8(42)
            case UnsupportedCertificate => UInt8(43)
            case CertificateRevoked => UInt8(44)
            case CertificateExpired => UInt8(45)
            case CertificateUnknown => UInt8(46)
            case IllegalParameter => UInt8(47)
            case UnknownCa => UInt8(48)
            case AccessDenied => UInt8(49)
            case DecodeError => UInt8(50)
            case DecryptError => UInt8(51)
            case ProtocolVersion => UInt8(70)
            case InsufficientSecurity => UInt8(71)
            case InternalError => UInt8(80)
            case UserCanceled => UInt8(90)
            case NoRenegotiation => UInt8(100)
            case UnsupportedExtension => UInt8(110)
        }
    }

    public static func fromUInt8(b: UInt8): DtlsAlertDescription {
        if (b == UInt8(0)) { CloseNotify }
        else if (b == UInt8(10)) { UnexpectedMessage }
        else if (b == UInt8(20)) { BadRecordMac }
        else if (b == UInt8(40)) { HandshakeFailure }
        else if (b == UInt8(42)) { BadCertificate }
        else if (b == UInt8(43)) { UnsupportedCertificate }
        else if (b == UInt8(44)) { CertificateRevoked }
        else if (b == UInt8(45)) { CertificateExpired }
        else if (b == UInt8(46)) { CertificateUnknown }
        else if (b == UInt8(47)) { IllegalParameter }
        else if (b == UInt8(48)) { UnknownCa }
        else if (b == UInt8(49)) { AccessDenied }
        else if (b == UInt8(50)) { DecodeError }
        else if (b == UInt8(51)) { DecryptError }
        else if (b == UInt8(70)) { ProtocolVersion }
        else if (b == UInt8(71)) { InsufficientSecurity }
        else if (b == UInt8(80)) { InternalError }
        else if (b == UInt8(90)) { UserCanceled }
        else if (b == UInt8(100)) { NoRenegotiation }
        else if (b == UInt8(110)) { UnsupportedExtension }
        else { throw CryptoException(CryptoErrorCode.InvalidArgument, "invalid DTLS alert description: " + b.toString()) }
    }

    public func toString(): String {
        match (this) {
            case CloseNotify => "close_notify"
            case UnexpectedMessage => "unexpected_message"
            case BadRecordMac => "bad_record_mac"
            case HandshakeFailure => "handshake_failure"
            case BadCertificate => "bad_certificate"
            case UnsupportedCertificate => "unsupported_certificate"
            case CertificateRevoked => "certificate_revoked"
            case CertificateExpired => "certificate_expired"
            case CertificateUnknown => "certificate_unknown"
            case IllegalParameter => "illegal_parameter"
            case UnknownCa => "unknown_ca"
            case AccessDenied => "access_denied"
            case DecodeError => "decode_error"
            case DecryptError => "decrypt_error"
            case ProtocolVersion => "protocol_version"
            case InsufficientSecurity => "insufficient_security"
            case InternalError => "internal_error"
            case UserCanceled => "user_canceled"
            case NoRenegotiation => "no_renegotiation"
            case UnsupportedExtension => "unsupported_extension"
        }
    }
}

public class DtlsAlert {
    public let level: DtlsAlertLevel
    public let description: DtlsAlertDescription

    public init(level: DtlsAlertLevel, description: DtlsAlertDescription) {
        this.level = level
        this.description = description
    }

    public func encode(): Array<Byte> {
        let out = Array<Byte>(2, repeat: 0)
        out[0] = level.toUInt8()
        out[1] = description.toUInt8()
        out
    }

    public static func decode(data: Array<Byte>): DtlsAlert {
        if (data.size < 2) {
            throw CryptoException(CryptoErrorCode.InvalidArgument,
                "DTLS alert too short: " + data.size.toString())
        }
        let level = DtlsAlertLevel.fromUInt8(UInt8(data[0]))
        let desc = DtlsAlertDescription.fromUInt8(UInt8(data[1]))
        DtlsAlert(level, desc)
    }

    public func isFatal(): Bool {
        level == DtlsAlertLevel.Fatal
    }

    public func toString(): String {
        "DtlsAlert(" + level.toString() + ", " + description.toString() + ")"
    }
}

/// Build a fatal alert for a handshake security failure.
public func dtlsFatalAlert(description: DtlsAlertDescription): DtlsAlert {
    DtlsAlert(DtlsAlertLevel.Fatal, description)
}

// ============================================================================
// DTLS State Transition Legality (RFC 6347 / RFC 5246 handshake ordering)
// ============================================================================

/// Check whether a state transition is legal for the given role.
/// Out-of-order transitions are rejected to prevent skipping security gates.
public func dtlsIsValidStateTransition(role: DtlsRole, from: DtlsConnectionState,
    to: DtlsConnectionState): Bool {
    // Closed and Failed are terminal; no exit except explicit reset.
    if (from == DtlsConnectionState.Closed || from == DtlsConnectionState.Failed) {
        return false
    }
    // Any state may transition to Closed or Failed (graceful / error).
    if (to == DtlsConnectionState.Closed || to == DtlsConnectionState.Failed) {
        return true
    }
    // Self-transition is a no-op, allow it.
    if (from == to) {
        return true
    }
    // Role-specific legal forward transitions.
    match (role) {
        case DtlsRole.Client =>
            match (from) {
                case DtlsConnectionState.Idle =>
                    to == DtlsConnectionState.ClientHelloSent
                case DtlsConnectionState.ClientHelloSent =>
                    to == DtlsConnectionState.HelloVerifyReceived ||
                    to == DtlsConnectionState.ServerHelloReceived
                case DtlsConnectionState.HelloVerifyReceived =>
                    to == DtlsConnectionState.ClientHelloWithCookieSent
                case DtlsConnectionState.ClientHelloWithCookieSent =>
                    to == DtlsConnectionState.ServerHelloReceived
                case DtlsConnectionState.ServerHelloReceived =>
                    to == DtlsConnectionState.ServerHelloDoneReceived
                case DtlsConnectionState.ServerHelloDoneReceived =>
                    to == DtlsConnectionState.ClientKeyExchangeSent
                case DtlsConnectionState.ClientKeyExchangeSent =>
                    to == DtlsConnectionState.FinishedSent
                case DtlsConnectionState.FinishedSent =>
                    to == DtlsConnectionState.Established
                case _ => false
            }
        case DtlsRole.Server =>
            match (from) {
                case DtlsConnectionState.Idle =>
                    to == DtlsConnectionState.ServerHelloReceived
                case DtlsConnectionState.ServerHelloReceived =>
                    to == DtlsConnectionState.ServerHelloDoneReceived
                case DtlsConnectionState.ServerHelloDoneReceived =>
                    to == DtlsConnectionState.ClientKeyExchangeSent
                case DtlsConnectionState.ClientKeyExchangeSent =>
                    to == DtlsConnectionState.FinishedSent
                case DtlsConnectionState.FinishedSent =>
                    to == DtlsConnectionState.Established
                case _ => false
            }
    }
}
