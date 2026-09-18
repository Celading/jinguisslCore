package jinguissl_core.dtls_tests

import std.unittest.*
import std.unittest.testmacro.*
import jinguissl_core.crypto.dtls.*
import jinguissl_core.crypto.digest.sha256
import jinguissl_core.crypto.error.CryptoException

@Test
public class DtlsIndependentAuditSuite {
    @TestCase
    public func testPublicFlagsCannotAuthorizeExporter(): Unit {
        let context = DtlsHandshakeContext(DtlsRole.Client)
        let peer = DtlsHandshakeContext(DtlsRole.Server)
        context.generateClientRandom()
        context.generateServerRandom()
        context.processPeerKeyExchange(peer.keyExchange.publicKey)
        context.state = DtlsConnectionState.Established
        context.finishedVerified = true
        var rejected = false
        try { _ = context.extractSrtpKeyingMaterial(DtlsSrtpProtectionProfile.AeadAes128Gcm) }
        catch (_: CryptoException) { rejected = true }
        @Assert(rejected)
    }

    @TestCase
    public func testIdenticalOverlapAndSnapshotIsolation(): Unit {
        let r = DtlsFragmentReassembler(DtlsHandshakeType.Certificate, UInt32(5), UInt16(0))
        let first = DtlsHandshakeFragment(DtlsHandshakeType.Certificate, UInt32(5), UInt16(0),
            UInt32(0), UInt32(3), [UInt8(1), UInt8(2), UInt8(3)])
        @Assert(!r.addFragment(first))
        @Assert(!r.addFragment(first))
        @Assert(r.addFragment(DtlsHandshakeFragment(DtlsHandshakeType.Certificate, UInt32(5), UInt16(0),
            UInt32(2), UInt32(3), [UInt8(3), UInt8(4), UInt8(5)])))
        let snapshot = r.getReassembled()
        snapshot[0] = 99
        @Assert(r.getReassembled()[0], UInt8(1))
    }

    @TestCase
    public func testTruncatedHelloVerifyAlwaysUsesCryptoError(): Unit {
        for (bytes in [Array<Byte>(), [UInt8(0xfe)], [UInt8(0xfe), UInt8(0xfd)],
            [UInt8(0xfe), UInt8(0xfd), UInt8(2), UInt8(1)],
            [UInt8(0xfe), UInt8(0xfd), UInt8(0), UInt8(1)]]) {
            var rejected = false
            try { _ = DtlsHelloVerifyRequest.decode(bytes) }
            catch (_: CryptoException) { rejected = true }
            @Assert(rejected)
        }
    }

    @TestCase
    public func testServerHelloExtensionBoundsAndDuplicates(): Unit {
        let base = DtlsServerHello(UInt16(0xfefd), DtlsRandom(UInt32(0), Array<Byte>(28, repeat: 1)),
            [], UInt16(0xc02b), UInt8(0), None).encode()
        for (tail in [[UInt8(0), UInt8(1), UInt8(0)],
            [UInt8(0), UInt8(5), UInt8(0), UInt8(14), UInt8(0), UInt8(1), UInt8(0)],
            [UInt8(0), UInt8(8), UInt8(0), UInt8(23), UInt8(0), UInt8(0),
                UInt8(0), UInt8(23), UInt8(0), UInt8(0)]]) {
            let bytes = Array<Byte>(38 + tail.size, repeat: 0)
            for (i in 0..38) { bytes[i] = base[i] }
            for (i in 0..tail.size) { bytes[38 + i] = tail[i] }
            var rejected = false
            try { _ = DtlsServerHello.decode(bytes) }
            catch (_: CryptoException) { rejected = true }
            @Assert(rejected)
        }
    }

    @TestCase
    public func testRfcAadFieldOrder(): Unit {
        let expected: Array<Byte> = [0, 1, 0, 0, 0, 0, 0, 0x42, 23, 0xfe, 0xfd, 0, 3]
        let actual = dtlsBuildAeadAad(UInt16(1), UInt48(UInt64(0x42)),
            DtlsContentType.ApplicationData, UInt16(0xfefd), 3)
        @Assert(actual, expected)
    }

    @TestCase
    public func testRfcTranscriptIncludesDtlsHeader(): Unit {
        let context = DtlsHandshakeContext(DtlsRole.Client)
        let body: Array<Byte> = [1, 2, 3]
        context.recordHandshakeMessage(DtlsHandshakeType.Certificate, UInt16(7), body)
        let canonical: Array<Byte> = [11, 0, 0, 3, 0, 7, 0, 0, 0, 0, 0, 3, 1, 2, 3]
        @Assert(context.computeTranscriptHash(), sha256(canonical))
    }

    @TestCase
    public func testExportRequiresAuthenticatedHandshake(): Unit {
        let context = DtlsHandshakeContext(DtlsRole.Client)
        let peer = DtlsHandshakeContext(DtlsRole.Server)
        context.generateClientRandom()
        context.generateServerRandom()
        context.processPeerKeyExchange(peer.keyExchange.publicKey)
        @Assert(context.finishedVerified, false)
        var rejected = false
        try {
            let material = context.extractSrtpKeyingMaterial(DtlsSrtpProtectionProfile.AeadAes128Gcm)
            @Assert(material.clientWriteKey.size, 16)
        } catch (_: CryptoException) { rejected = true }
        @Assert(rejected)
    }

    @TestCase
    public func testCookieOverlapStartsAtRotation(): Unit {
        let manager = DtlsCookieManager(32, 300000, 120000)
        let ip: Array<Byte> = [127, 0, 0, 1]
        let random = Array<Byte>(32, repeat: 1)
        let suites: Array<UInt16> = [0xc02b]
        let profiles: Array<UInt16> = [7]
        let cookie = manager.generateCookie(ip, UInt16(4433), UInt16(0xfefd),
            random, suites, profiles, 1000000)
        @Assert(manager.verifyCookie(cookie, ip, UInt16(4433), UInt16(0xfefd),
            random, suites, profiles, 1000000))
        manager.rotate(1000001)
        @Assert(manager.verifyCookie(cookie, ip, UInt16(4433), UInt16(0xfefd),
            random, suites, profiles, 1000002))
    }

    @TestCase
    public func testSequenceMustNotWrap(): Unit {
        let key = Array<Byte>(16, repeat: 1)
        let iv = Array<Byte>(4, repeat: 2)
        let state = DtlsEpochState(UInt16(1), key, iv, key, iv)
        state.nextSendSeq = UInt48(UInt64(0xffffffffffff))
        var rejected = false
        try {
            _ = state.nextSendSequence()
            let wrapped = state.nextSendSequence()
            @Assert(wrapped.toUInt64(), UInt64(0))
        }
        catch (_: CryptoException) { rejected = true }
        @Assert(rejected)
    }
}
