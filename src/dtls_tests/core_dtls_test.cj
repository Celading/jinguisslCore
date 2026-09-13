package jinguissl_core.dtls_tests

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.ArrayList
import jinguissl_core.crypto.dtls.*

func mkBytes(bytes: Array<Int64>): Array<UInt8> {
    let result = Array<UInt8>(bytes.size, repeat: UInt8(0))
    for (i in 0..bytes.size) {
        result[i] = UInt8(bytes[i])
    }
    result
}

@Test
public class DtlsRecordTestSuite {

    @TestCase
    public func testDtlsRecordHeaderRoundTrip(): Unit {
        let header = DtlsRecordHeader(DtlsContentType.Handshake,
            DTLS_VERSION_1_2, UInt16(0), UInt48(UInt64(42)), UInt16(256))
        let encoded = dtlsEncodeRecordHeader(header)
        @Assert(encoded.size, 13)
        let decoded = dtlsDecodeRecordHeader(encoded)
        @Assert(decoded.contentType, DtlsContentType.Handshake)
        @Assert(decoded.version, DTLS_VERSION_1_2)
        @Assert(decoded.epoch, UInt16(0))
        @Assert(decoded.sequenceNumber.toUInt64(), UInt64(42))
        @Assert(decoded.length, UInt16(256))
    }

    @TestCase
    public func testDtlsRecordEncodeDecode(): Unit {
        let payload = mkBytes([1, 2, 3, 4, 5])
        let encoded = dtlsEncodeRecord(DtlsContentType.ApplicationData,
            DTLS_VERSION_1_2, UInt16(1), UInt48(UInt64(100)), payload)
        @Assert(encoded.size, 13 + 5)
        let (header, fragment) = dtlsDecodeRecord(encoded)
        @Assert(header.contentType, DtlsContentType.ApplicationData)
        @Assert(header.epoch, UInt16(1))
        @Assert(header.sequenceNumber.toUInt64(), UInt64(100))
        @Assert(fragment.size, 5)
        @Assert(fragment[0], UInt8(1))
        @Assert(fragment[4], UInt8(5))
    }

    @TestCase
    public func testDtlsContentTypeFromByte(): Unit {
        @Assert(DtlsContentType.fromUInt8(UInt8(20)), DtlsContentType.ChangeCipherSpec)
        @Assert(DtlsContentType.fromUInt8(UInt8(21)), DtlsContentType.Alert)
        @Assert(DtlsContentType.fromUInt8(UInt8(22)), DtlsContentType.Handshake)
        @Assert(DtlsContentType.fromUInt8(UInt8(23)), DtlsContentType.ApplicationData)
    }

    @TestCase
    public func testUInt48Operations(): Unit {
        let a = UInt48(UInt64(100))
        @Assert(a.toUInt64(), UInt64(100))
        let b = a.next()
        @Assert(b.toUInt64(), UInt64(101))
        let c = UInt48(UInt64(0xFFFF_FFFFFFFF))
        @Assert(c.toUInt64(), UInt64(0xFFFF_FFFFFFFF))
    }
}

@Test
public class DtlsHandshakeFragmentTestSuite {

    @TestCase
    public func testHandshakeFragmentRoundTrip(): Unit {
        let body = mkBytes([0xAA, 0xBB, 0xCC])
        let frag = DtlsHandshakeFragment(DtlsHandshakeType.ClientHello,
            UInt32(3), UInt16(0), UInt32(0), UInt32(3), body)
        let encoded = dtlsEncodeHandshakeFragment(frag)
        @Assert(encoded.size, 12 + 3)
        let decoded = dtlsDecodeHandshakeFragment(encoded)
        @Assert(decoded.msgType, DtlsHandshakeType.ClientHello)
        @Assert(decoded.length, UInt32(3))
        @Assert(decoded.messageSeq, UInt16(0))
        @Assert(decoded.fragmentOffset, UInt32(0))
        @Assert(decoded.fragmentLength, UInt32(3))
        @Assert(decoded.body[0], UInt8(0xAA))
    }

    @TestCase
    public func testHandshakeTypeFromByte(): Unit {
        @Assert(DtlsHandshakeType.fromUInt8(UInt8(1)), DtlsHandshakeType.ClientHello)
        @Assert(DtlsHandshakeType.fromUInt8(UInt8(2)), DtlsHandshakeType.ServerHello)
        @Assert(DtlsHandshakeType.fromUInt8(UInt8(3)), DtlsHandshakeType.HelloVerifyRequest)
        @Assert(DtlsHandshakeType.fromUInt8(UInt8(11)), DtlsHandshakeType.Certificate)
        @Assert(DtlsHandshakeType.fromUInt8(UInt8(20)), DtlsHandshakeType.Finished)
    }

    @TestCase
    public func testFragmentReassembly(): Unit {
        let fullBody = mkBytes([1, 2, 3, 4, 5, 6, 7, 8])
        let reassembler = DtlsFragmentReassembler(DtlsHandshakeType.ClientHello,
            UInt32(8), UInt16(0))

        // Split into two fragments
        let frag1 = DtlsHandshakeFragment(DtlsHandshakeType.ClientHello,
            UInt32(8), UInt16(0), UInt32(0), UInt32(4),
            mkBytes([1, 2, 3, 4]))
        let frag2 = DtlsHandshakeFragment(DtlsHandshakeType.ClientHello,
            UInt32(8), UInt16(0), UInt32(4), UInt32(4),
            mkBytes([5, 6, 7, 8]))

        @Assert(reassembler.addFragment(frag1), false) // not complete yet
        @Assert(reassembler.addFragment(frag2), true)  // now complete
        let reassembled = reassembler.getReassembled()
        @Assert(reassembled.size, 8)
        @Assert(reassembled[0], UInt8(1))
        @Assert(reassembled[7], UInt8(8))
    }
}

@Test
public class DtlsClientHelloTestSuite {

    @TestCase
    public func testClientHelloRoundTrip(): Unit {
        let random = DtlsRandom(UInt32(0x12345678),
            Array<UInt8>(28, repeat: 0))
        let hello = DtlsClientHello(DTLS_VERSION_1_2, random,
            Array<UInt8>(),  // no session id
            Array<UInt8>(),  // no cookie
            [DTLS_CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256],
            [UInt8(0)],  // null compression
            [DtlsSrtpProtectionProfile.AeadAes128Gcm.toCode()])

        let encoded = hello.encode()
        let decoded = DtlsClientHello.decode(encoded)

        @Assert(decoded.version, DTLS_VERSION_1_2)
        @Assert(decoded.sessionId.size, 0)
        @Assert(decoded.cookie.size, 0)
        @Assert(decoded.cipherSuites.size, 1)
        @Assert(decoded.cipherSuites[0], DTLS_CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256)
        @Assert(decoded.srtpProfiles.size, 1)
        @Assert(decoded.srtpProfiles[0], DtlsSrtpProtectionProfile.AeadAes128Gcm.toCode())
    }
}

@Test
public class DtlsServerHelloTestSuite {

    @TestCase
    public func testServerHelloRoundTrip(): Unit {
        let random = DtlsRandom(UInt32(0xABCDEF01),
            Array<UInt8>(28, repeat: 0))
        let hello = DtlsServerHello(DTLS_VERSION_1_2, random,
            Array<UInt8>(),
            DTLS_CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256,
            UInt8(0),
            DtlsSrtpProtectionProfile.AeadAes128Gcm.toCode())

        let encoded = hello.encode()
        let decoded = DtlsServerHello.decode(encoded)

        @Assert(decoded.version, DTLS_VERSION_1_2)
        @Assert(decoded.cipherSuite, DTLS_CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256)
        @Assert(decoded.compressionMethod, UInt8(0))
        match (decoded.srtpProfile) {
            case Some(p) => @Assert(p, DtlsSrtpProtectionProfile.AeadAes128Gcm.toCode())
            case None => @Assert(false, true)
        }
    }
}

@Test
public class DtlsHelloVerifyRequestTestSuite {

    @TestCase
    public func testHelloVerifyRequestRoundTrip(): Unit {
        let cookie = mkBytes([0xDE, 0xAD, 0xBE, 0xEF])
        let hvr = DtlsHelloVerifyRequest(DTLS_VERSION_1_2, cookie)
        let encoded = hvr.encode()
        let decoded = DtlsHelloVerifyRequest.decode(encoded)
        @Assert(decoded.version, DTLS_VERSION_1_2)
        @Assert(decoded.cookie.size, 4)
        @Assert(decoded.cookie[0], UInt8(0xDE))
    }
}

@Test
public class DtlsSessionTestSuite {

    @TestCase
    public func testDtlsSessionInitialState(): Unit {
        let session = DtlsSession(DtlsRole.Client)
        @Assert(session.role, DtlsRole.Client)
        @Assert(session.state, DtlsConnectionState.Idle)
        @Assert(session.version, DTLS_VERSION_1_2)
        @Assert(session.currentEpoch.epoch, UInt16(0))
    }

    @TestCase
    public func testDtlsSessionStateTransition(): Unit {
        let session = DtlsSession(DtlsRole.Client)
        // Drive a legal Client-side forward transition chain; the
        // dtlsIsValidStateTransition gate rejects any skip-ahead.
        session.transition(DtlsConnectionState.ClientHelloSent)
        @Assert(session.state, DtlsConnectionState.ClientHelloSent)
        session.transition(DtlsConnectionState.ServerHelloReceived)
        session.transition(DtlsConnectionState.ServerHelloDoneReceived)
        session.transition(DtlsConnectionState.ClientKeyExchangeSent)
        session.transition(DtlsConnectionState.FinishedSent)
        session.transition(DtlsConnectionState.Established)
        @Assert(session.state, DtlsConnectionState.Established)
    }

    @TestCase
    public func testDtlsMessageSeqIncrement(): Unit {
        let session = DtlsSession(DtlsRole.Server)
        @Assert(session.nextMessageSeq(), UInt16(0))
        @Assert(session.nextMessageSeq(), UInt16(1))
        @Assert(session.nextMessageSeq(), UInt16(2))
    }

    @TestCase
    public func testDtlsFlightTimerBackoff(): Unit {
        let timer = DtlsFlightTimer()
        @Assert(timer.currentTimeout, 1000)
        let t1 = timer.nextTimeout()
        @Assert(t1, 2000)
        let t2 = timer.nextTimeout()
        @Assert(t2, 4000)
    }
}

@Test
public class DtlsSrtpProfileTestSuite {

    @TestCase
    public func testSrtpProfileCodes(): Unit {
        @Assert(DtlsSrtpProtectionProfile.Aes128CmSha1_80.toCode(), UInt16(0x0001))
        @Assert(DtlsSrtpProtectionProfile.AeadAes128Gcm.toCode(), UInt16(0x0007))
        @Assert(DtlsSrtpProtectionProfile.AeadAes256Gcm.toCode(), UInt16(0x0008))
    }

    @TestCase
    public func testSrtpProfileFromCode(): Unit {
        match (DtlsSrtpProtectionProfile.fromCode(UInt16(0x0007))) {
            case Some(p) => @Assert(p, DtlsSrtpProtectionProfile.AeadAes128Gcm)
            case None => @Assert(false, true)
        }
        match (DtlsSrtpProtectionProfile.fromCode(UInt16(0xFFFF))) {
            case Some(_) => @Assert(false, true)
            case None => @Assert(true, true)
        }
    }

    @TestCase
    public func testSrtpProfileKeySaltLen(): Unit {
        @Assert(DtlsSrtpProtectionProfile.AeadAes128Gcm.keyLen(), 16)
        @Assert(DtlsSrtpProtectionProfile.AeadAes128Gcm.saltLen(), 12)
        @Assert(DtlsSrtpProtectionProfile.AeadAes256Gcm.keyLen(), 32)
        @Assert(DtlsSrtpProtectionProfile.Aes128CmSha1_80.saltLen(), 14)
    }

    @TestCase
    public func testSrtpKeyingMaterialExtraction(): Unit {
        let masterSecret = Array<UInt8>(48, repeat: 0xAA)
        let clientRandom = Array<UInt8>(32, repeat: 0xBB)
        let serverRandom = Array<UInt8>(32, repeat: 0xCC)
        let km = dtlsSrtpExtractKeyingMaterial(masterSecret, clientRandom,
            serverRandom, DtlsSrtpProtectionProfile.AeadAes128Gcm)
        @Assert(km.clientWriteKey.size, 16)
        @Assert(km.serverWriteKey.size, 16)
        @Assert(km.clientWriteSalt.size, 12)
        @Assert(km.serverWriteSalt.size, 12)
        // Keys should be different (derived from different material)
        @Assert(km.clientWriteKey != km.serverWriteKey, true)
    }
}
