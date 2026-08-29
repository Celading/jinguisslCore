package jinguissl_core.crypto.tls

import std.collection.ArrayList
import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}
import jinguissl_core.crypto.utils.secureCopyInto

public let DTLCP_RECORD_HEADER_LEN: Int64 = 13
public let DTLCP_HANDSHAKE_HEADER_LEN: Int64 = 12
public let DTLCP_MAX_SEQUENCE: Int64 = 0xffff_ffff_ffff
public let DTLCP_REPLAY_WINDOW_SIZE: Int64 = 64

public class DtlcpRecordHeader {
    public let contentType: TlsContentType
    public let epoch: Int64
    public let sequence: Int64
    public let length: Int64

    public init(contentType: TlsContentType, epoch: Int64, sequence: Int64, length: Int64) {
        if (epoch < 0 || epoch > 0xffff || sequence < 0 || sequence > DTLCP_MAX_SEQUENCE) {
            throw CryptoException(OutOfBounds, "DTLCP epoch/sequence is out of range")
        }
        if (length < 0 || length > 0xffff) {
            throw CryptoException(OutOfBounds, "DTLCP record length is out of range")
        }
        this.contentType = contentType
        this.epoch = epoch
        this.sequence = sequence
        this.length = length
    }
}

public class DtlcpPlainRecord {
    public let contentType: TlsContentType
    public let epoch: Int64
    public let sequence: Int64
    public let fragment: Array<Byte>

    public init(
        contentType: TlsContentType, epoch: Int64, sequence: Int64, fragment: Array<Byte>
    ) {
        this.contentType = contentType
        this.epoch = epoch
        this.sequence = sequence
        this.fragment = fragment.clone()
    }
}

/** A 64-packet anti-replay window for one DTLCP epoch. */
public class DtlcpReplayWindow {
    var _initialized: Bool = false
    var _highest: Int64 = 0
    var _bitmap: UInt64 = UInt64(0)

    public prop highestSequence: Int64 { get() { if (_initialized) { _highest } else { -1 } } }

    public func reset(): Unit {
        _initialized = false
        _highest = 0
        _bitmap = UInt64(0)
    }

    public func canAccept(sequence: Int64): Bool {
        if (sequence < 0 || sequence > DTLCP_MAX_SEQUENCE) { return false }
        if (!_initialized || sequence > _highest) { return true }
        let distance = _highest - sequence
        if (distance >= DTLCP_REPLAY_WINDOW_SIZE) { return false }
        let bit = UInt64(1) << UInt64(distance)
        (_bitmap & bit) == UInt64(0)
    }

    @OverflowWrapping
    public func markAccepted(sequence: Int64): Unit {
        if (!canAccept(sequence)) {
            throw CryptoException(ParseError, "DTLCP record replay or stale sequence detected")
        }
        if (!_initialized) {
            _initialized = true
            _highest = sequence
            _bitmap = UInt64(1)
            return
        }
        if (sequence > _highest) {
            let delta = sequence - _highest
            _bitmap = if (delta >= DTLCP_REPLAY_WINDOW_SIZE) {
                UInt64(1)
            } else {
                (_bitmap << UInt64(delta)) | UInt64(1)
            }
            _highest = sequence
            return
        }
        let distance = _highest - sequence
        _bitmap |= UInt64(1) << UInt64(distance)
    }
}

/** DTLCP datagram record protection with epoch and out-of-order replay handling. */
public class DtlcpRecordLayer {
    public let cipherSuite: TlcpCipherSuite
    let _writeMacKey: Array<Byte>
    let _readMacKey: Array<Byte>
    let _writeKey: Array<Byte>
    let _readKey: Array<Byte>
    let _writeIv: Array<Byte>
    let _readIv: Array<Byte>
    let _replayWindow = DtlcpReplayWindow()
    var _epoch: Int64 = 0
    var _writeSequence: Int64 = 0

    public init(secrets: TlcpHandshakeSecrets, isClient: Bool, epoch!: Int64 = 0) {
        if (epoch < 0 || epoch > 0xffff) {
            throw CryptoException(OutOfBounds, "DTLCP epoch is out of range")
        }
        this.cipherSuite = secrets.cipherSuite
        this._epoch = epoch
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

    public prop epoch: Int64 { get() { _epoch } }
    public prop writeSequence: Int64 { get() { _writeSequence } }
    public prop highestReadSequence: Int64 { get() { _replayWindow.highestSequence } }

    /** Change epoch after a cipher-state transition; record sequence and replay state restart. */
    public func setEpoch(epoch: Int64): Unit {
        if (epoch < 0 || epoch > 0xffff || epoch < _epoch) {
            throw CryptoException(OutOfBounds, "DTLCP epoch transition is invalid")
        }
        if (epoch == _epoch) { return }
        _epoch = epoch
        _writeSequence = 0
        _replayWindow.reset()
    }

    public func seal(contentType: TlsContentType, plaintext: Array<Byte>): Array<Byte> {
        if (_writeSequence > DTLCP_MAX_SEQUENCE) {
            throw CryptoException(OutOfBounds, "DTLCP write sequence exhausted")
        }
        let sequenceBytes = dtlcpEpochSequenceBytes(_epoch, _writeSequence)
        let protected = tlcpProtectFragment(
            cipherSuite,
            _writeMacKey,
            _writeKey,
            _writeIv,
            sequenceBytes,
            contentType,
            plaintext
        )
        let encoded = dtlcpEncodeRecord(
            DtlcpRecordHeader(contentType, _epoch, _writeSequence, protected.size), protected
        )
        _writeSequence += 1
        encoded
    }

    public func open(encodedRecord: Array<Byte>): DtlcpPlainRecord {
        let (header, protected) = dtlcpDecodeRecord(encodedRecord)
        if (header.epoch != _epoch) {
            throw CryptoException(ParseError, "DTLCP record epoch does not match active epoch")
        }
        if (!_replayWindow.canAccept(header.sequence)) {
            throw CryptoException(ParseError, "DTLCP record replay or stale sequence detected")
        }
        let sequenceBytes = dtlcpEpochSequenceBytes(header.epoch, header.sequence)
        let plaintext = tlcpOpenProtectedFragment(
            cipherSuite,
            _readMacKey,
            _readKey,
            _readIv,
            sequenceBytes,
            header.contentType,
            protected
        )
        _replayWindow.markAccepted(header.sequence)
        DtlcpPlainRecord(header.contentType, header.epoch, header.sequence, plaintext)
    }
}

public func dtlcpCreateClientRecordLayer(
    secrets: TlcpHandshakeSecrets, epoch!: Int64 = 0
): DtlcpRecordLayer {
    DtlcpRecordLayer(secrets, true, epoch: epoch)
}

public func dtlcpCreateServerRecordLayer(
    secrets: TlcpHandshakeSecrets, epoch!: Int64 = 0
): DtlcpRecordLayer {
    DtlcpRecordLayer(secrets, false, epoch: epoch)
}

public func dtlcpEncodeRecord(
    header: DtlcpRecordHeader, protectedFragment: Array<Byte>
): Array<Byte> {
    if (header.length != protectedFragment.size) {
        throw CryptoException(InvalidArgument, "DTLCP record fragment length mismatch")
    }
    let output = Array<Byte>(DTLCP_RECORD_HEADER_LEN + protectedFragment.size, repeat: UInt8(0))
    output[0] = tlcpContentTypeToWire(header.contentType)
    output[1] = UInt8(0x01)
    output[2] = UInt8(0x01)
    output[3] = UInt8((header.epoch >> 8) & 0xff)
    output[4] = UInt8(header.epoch & 0xff)
    var i: Int64 = 0
    while (i < 6) {
        output[5 + i] = UInt8((header.sequence >> ((5 - i) * 8)) & 0xff)
        i += 1
    }
    output[11] = UInt8((header.length >> 8) & 0xff)
    output[12] = UInt8(header.length & 0xff)
    secureCopyInto(protectedFragment, output, dstOffset: DTLCP_RECORD_HEADER_LEN)
    output
}

public func dtlcpDecodeRecord(encoded: Array<Byte>): (DtlcpRecordHeader, Array<Byte>) {
    if (encoded.size < DTLCP_RECORD_HEADER_LEN) {
        throw CryptoException(ParseError, "DTLCP record header is truncated")
    }
    if (UInt8(encoded[1]) != UInt8(0x01) || UInt8(encoded[2]) != UInt8(0x01)) {
        throw CryptoException(ParseError, "DTLCP record version must be 0x0101")
    }
    let epoch = (Int64(UInt8(encoded[3])) << 8) | Int64(UInt8(encoded[4]))
    var sequence: Int64 = 0
    var i: Int64 = 0
    while (i < 6) {
        sequence = (sequence << 8) | Int64(UInt8(encoded[5 + i]))
        i += 1
    }
    let length = (Int64(UInt8(encoded[11])) << 8) | Int64(UInt8(encoded[12]))
    if (encoded.size != DTLCP_RECORD_HEADER_LEN + length) {
        throw CryptoException(ParseError, "DTLCP record length mismatch")
    }
    let header = DtlcpRecordHeader(
        tlcpContentTypeFromWire(UInt8(encoded[0])), epoch, sequence, length
    )
    (header, encoded[DTLCP_RECORD_HEADER_LEN..])
}

/** One DTLS-style handshake fragment carried inside DTLCP handshake records. */
public class DtlcpHandshakeFragment {
    public let messageType: Byte
    public let messageLength: Int64
    public let messageSequence: Int64
    public let fragmentOffset: Int64
    public let fragment: Array<Byte>

    public init(
        messageType: Byte,
        messageLength: Int64,
        messageSequence: Int64,
        fragmentOffset: Int64,
        fragment: Array<Byte>
    ) {
        if (messageLength < 0 || messageLength > TLS_HANDSHAKE_MAX_BODY_LEN) {
            throw CryptoException(OutOfBounds, "DTLCP handshake message length is out of range")
        }
        if (messageSequence < 0 || messageSequence > 0xffff) {
            throw CryptoException(OutOfBounds, "DTLCP handshake message sequence is out of range")
        }
        if (
            fragmentOffset < 0 || fragmentOffset > messageLength ||
            fragment.size > 0xff_ffff || fragmentOffset + fragment.size > messageLength
        ) {
            throw CryptoException(ParseError, "DTLCP handshake fragment bounds are invalid")
        }
        this.messageType = messageType
        this.messageLength = messageLength
        this.messageSequence = messageSequence
        this.fragmentOffset = fragmentOffset
        this.fragment = fragment.clone()
    }
}

public func dtlcpEncodeHandshakeFragment(value: DtlcpHandshakeFragment): Array<Byte> {
    let output = Array<Byte>(DTLCP_HANDSHAKE_HEADER_LEN + value.fragment.size, repeat: UInt8(0))
    output[0] = value.messageType
    dtlcpPutUInt24(value.messageLength, output, 1)
    output[4] = UInt8((value.messageSequence >> 8) & 0xff)
    output[5] = UInt8(value.messageSequence & 0xff)
    dtlcpPutUInt24(value.fragmentOffset, output, 6)
    dtlcpPutUInt24(value.fragment.size, output, 9)
    secureCopyInto(value.fragment, output, dstOffset: DTLCP_HANDSHAKE_HEADER_LEN)
    output
}

public func dtlcpDecodeHandshakeFragment(encoded: Array<Byte>): DtlcpHandshakeFragment {
    if (encoded.size < DTLCP_HANDSHAKE_HEADER_LEN) {
        throw CryptoException(ParseError, "DTLCP handshake fragment header is truncated")
    }
    let messageLength = dtlcpReadUInt24(encoded, 1)
    let messageSequence = (Int64(UInt8(encoded[4])) << 8) | Int64(UInt8(encoded[5]))
    let fragmentOffset = dtlcpReadUInt24(encoded, 6)
    let fragmentLength = dtlcpReadUInt24(encoded, 9)
    if (encoded.size != DTLCP_HANDSHAKE_HEADER_LEN + fragmentLength) {
        throw CryptoException(ParseError, "DTLCP handshake fragment length mismatch")
    }
    DtlcpHandshakeFragment(
        encoded[0], messageLength, messageSequence, fragmentOffset, encoded[DTLCP_HANDSHAKE_HEADER_LEN..]
    )
}

/** Fragment one TLS-shaped TLCP handshake message into DTLCP handshake fragments. */
public func dtlcpFragmentHandshake(
    encodedHandshake: Array<Byte>, messageSequence: Int64, maxFragmentBody: Int64
): Array<Array<Byte>> {
    if (encodedHandshake.size < 4 || maxFragmentBody <= 0 || maxFragmentBody > 0xff_ffff) {
        throw CryptoException(InvalidArgument, "DTLCP handshake fragmentation input is invalid")
    }
    let bodyLength = tlcpDecodeUInt24(encodedHandshake, 1)
    if (encodedHandshake.size != bodyLength + 4) {
        throw CryptoException(ParseError, "TLCP handshake body length mismatch")
    }
    let body = encodedHandshake[4..]
    let fragments = ArrayList<Array<Byte>>()
    if (body.size == 0) {
        fragments.add(dtlcpEncodeHandshakeFragment(
            DtlcpHandshakeFragment(encodedHandshake[0], 0, messageSequence, 0, [])
        ))
        return fragments.toArray()
    }
    var offset: Int64 = 0
    while (offset < body.size) {
        let take = if (body.size - offset < maxFragmentBody) {
            body.size - offset
        } else {
            maxFragmentBody
        }
        fragments.add(dtlcpEncodeHandshakeFragment(DtlcpHandshakeFragment(
            encodedHandshake[0], body.size, messageSequence, offset, body[offset..(offset + take)]
        )))
        offset += take
    }
    fragments.toArray()
}

/** Reassemble one DTLCP handshake message, accepting consistent overlaps out of order. */
public class DtlcpHandshakeReassembler {
    public let messageType: Byte
    public let messageLength: Int64
    public let messageSequence: Int64
    let _body: Array<Byte>
    let _received: Array<Bool>
    var _receivedCount: Int64 = 0

    public init(messageType: Byte, messageLength: Int64, messageSequence: Int64) {
        let probe = DtlcpHandshakeFragment(messageType, messageLength, messageSequence, 0, [])
        this.messageType = probe.messageType
        this.messageLength = probe.messageLength
        this.messageSequence = probe.messageSequence
        this._body = Array<Byte>(messageLength, repeat: UInt8(0))
        this._received = Array<Bool>(messageLength, repeat: false)
    }

    public prop complete: Bool { get() { _receivedCount == messageLength } }

    public func accept(encodedFragment: Array<Byte>): Bool {
        acceptFragment(dtlcpDecodeHandshakeFragment(encodedFragment))
    }

    public func acceptFragment(value: DtlcpHandshakeFragment): Bool {
        if (
            value.messageType != messageType || value.messageLength != messageLength ||
            value.messageSequence != messageSequence
        ) {
            throw CryptoException(ParseError, "DTLCP handshake fragment metadata mismatch")
        }
        var i: Int64 = 0
        while (i < value.fragment.size) {
            let index = value.fragmentOffset + i
            if (_received[index]) {
                if (_body[index] != value.fragment[i]) {
                    throw CryptoException(ParseError, "DTLCP handshake overlap is inconsistent")
                }
            } else {
                _body[index] = value.fragment[i]
                _received[index] = true
                _receivedCount += 1
            }
            i += 1
        }
        complete
    }

    public func encodedHandshake(): Array<Byte> {
        if (!complete) {
            throw CryptoException(InvalidArgument, "DTLCP handshake message is incomplete")
        }
        tlcpEncodeHandshake(messageType, _body)
    }
}

/** Deterministic cached-flight state for the caller's timer/event loop. */
public class DtlcpFlightRetransmitter {
    public let initialTimeoutMillis: Int64
    public let maxTimeoutMillis: Int64
    public let maxAttempts: Int64
    var _flight: Array<Array<Byte>> = []
    var _attempts: Int64 = 0
    var _timeoutMillis: Int64

    public init(
        initialTimeoutMillis!: Int64 = 1000,
        maxTimeoutMillis!: Int64 = 60000,
        maxAttempts!: Int64 = 6
    ) {
        if (
            initialTimeoutMillis <= 0 || maxTimeoutMillis < initialTimeoutMillis || maxAttempts <= 0
        ) {
            throw CryptoException(InvalidArgument, "DTLCP retransmission policy is invalid")
        }
        this.initialTimeoutMillis = initialTimeoutMillis
        this.maxTimeoutMillis = maxTimeoutMillis
        this.maxAttempts = maxAttempts
        this._timeoutMillis = initialTimeoutMillis
    }

    public prop attempts: Int64 { get() { _attempts } }
    public prop timeoutMillis: Int64 { get() { _timeoutMillis } }
    public prop hasPendingFlight: Bool { get() { _flight.size > 0 && _attempts < maxAttempts } }

    public func cacheFlight(datagrams: Array<Array<Byte>>): Unit {
        if (datagrams.size == 0) {
            throw CryptoException(InvalidArgument, "DTLCP flight must not be empty")
        }
        _flight = dtlcpCloneDatagrams(datagrams)
        _attempts = 0
        _timeoutMillis = initialTimeoutMillis
    }

    /** Return the next retransmission without coupling the crypto layer to a clock. */
    public func nextFlight(): Array<Array<Byte>> {
        if (!hasPendingFlight) {
            throw CryptoException(OutOfBounds, "DTLCP retransmission attempts exhausted")
        }
        let current = dtlcpCloneDatagrams(_flight)
        _attempts += 1
        if (_timeoutMillis < maxTimeoutMillis) {
            let doubled = _timeoutMillis * 2
            _timeoutMillis = if (doubled > maxTimeoutMillis) { maxTimeoutMillis } else { doubled }
        }
        current
    }

    public func acknowledgeFlight(): Unit {
        _flight = []
        _attempts = 0
        _timeoutMillis = initialTimeoutMillis
    }
}

func dtlcpEpochSequenceBytes(epoch: Int64, sequence: Int64): Array<Byte> {
    if (epoch < 0 || epoch > 0xffff || sequence < 0 || sequence > DTLCP_MAX_SEQUENCE) {
        throw CryptoException(OutOfBounds, "DTLCP epoch/sequence is out of range")
    }
    let output = Array<Byte>(8, repeat: UInt8(0))
    output[0] = UInt8((epoch >> 8) & 0xff)
    output[1] = UInt8(epoch & 0xff)
    var i: Int64 = 0
    while (i < 6) {
        output[2 + i] = UInt8((sequence >> ((5 - i) * 8)) & 0xff)
        i += 1
    }
    output
}

private func dtlcpPutUInt24(value: Int64, output: Array<Byte>, offset: Int64): Unit {
    if (value < 0 || value > 0xff_ffff || offset < 0 || offset + 3 > output.size) {
        throw CryptoException(OutOfBounds, "DTLCP uint24 value is out of range")
    }
    output[offset] = UInt8((value >> 16) & 0xff)
    output[offset + 1] = UInt8((value >> 8) & 0xff)
    output[offset + 2] = UInt8(value & 0xff)
}

private func dtlcpReadUInt24(input: Array<Byte>, offset: Int64): Int64 {
    if (offset < 0 || offset + 3 > input.size) {
        throw CryptoException(ParseError, "DTLCP uint24 is truncated")
    }
    (Int64(UInt8(input[offset])) << 16) |
        (Int64(UInt8(input[offset + 1])) << 8) |
        Int64(UInt8(input[offset + 2]))
}

private func dtlcpCloneDatagrams(datagrams: Array<Array<Byte>>): Array<Array<Byte>> {
    let output = ArrayList<Array<Byte>>()
    for (datagram in datagrams) { output.add(datagram.clone()) }
    output.toArray()
}
