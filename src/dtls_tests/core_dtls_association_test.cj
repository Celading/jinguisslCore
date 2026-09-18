package jinguissl_core.dtls_tests

import std.unittest.*
import std.unittest.testmacro.*
import jinguissl_core.crypto.dtls.*
import jinguissl_core.crypto.error.CryptoException

func associationIdentity(): DtlsIdentity {
    DtlsIdentity.generate("dtls-peer", "260101000000Z", "360101000000Z")
}
func driveAssociation(client: DtlsAssociation, server: DtlsAssociation, reverse: Bool): Unit {
    client.start(0); server.start(0)
    for (i in 1..20) {
        let c = client.takeOutput()
        for (j in 0..c.size) {
            _ = server.receive(c[if (reverse) { c.size - 1 - j } else { j }], i * 100)
        }
        let s = server.takeOutput()
        for (j in 0..s.size) {
            _ = client.receive(s[if (reverse) { s.size - 1 - j } else { j }], i * 100)
        }
        if (client.authenticated && server.authenticated) { return }
    }
    @Fail("DTLS association did not complete")
}

@Test
public class DtlsAssociationTestSuite {
    @TestCase
    public func testMutualAuthenticationApplicationReplayAndExport(): Unit {
        for (reverse in [false, true]) {
            let c = associationIdentity(); let s = associationIdentity()
            let client = DtlsAssociation(DtlsRole.Client, c, s.fingerprintSha256(), [UInt8(1)])
            let server = DtlsAssociation(DtlsRole.Server, s, c.fingerprintSha256(), [UInt8(1)])
            driveAssociation(client, server, reverse)
            @Assert(client.authenticated && server.authenticated)
            @Assert(client.peerCertificateDer(), s.certificateDer())
            @Assert(client.selectedSrtpProfile(), UInt16(7))
            let ck = client.exportSrtp(); let sk = server.exportSrtp()
            @Assert(ck.clientWriteKey, sk.clientWriteKey)
            @Assert(ck.serverWriteSalt, sk.serverWriteSalt)
            @Assert(ck.clientWriteKey != ck.serverWriteKey)
            let packet = client.sealApplicationData("ping".toArray())
            let tampered = packet.clone(); tampered[tampered.size - 1] ^= UInt8(1)
            @Assert(server.receive(tampered, 3000).size, 0)
            @Assert(server.receive(packet, 3001)[0], "ping".toArray())
            @Assert(server.receive(packet, 3002).size, 0)
            @Assert(server.receive([UInt8(22), UInt8(0)], 3002).size, 0)
            @Assert(server.authenticated && !server.isClosed)
            @Assert(client.receive(server.sealApplicationData("pong".toArray()), 3003)[0], "pong".toArray())
            client.close(); server.close(); c.destroy(); s.destroy()
            var rejected = false
            try { _ = client.exportSrtp() } catch (_: CryptoException) { rejected = true }
            @Assert(rejected)
            @Assert(client.isClosed && !client.authenticated)
        }
    }

    @TestCase
    public func testWrongFingerprintIsTerminalAndNoExport(): Unit {
        let c = associationIdentity(); let s = associationIdentity()
        let client = DtlsAssociation(DtlsRole.Client, c, c.fingerprintSha256(), [UInt8(1)])
        let server = DtlsAssociation(DtlsRole.Server, s, c.fingerprintSha256(), [UInt8(1)])
        var rejected = false
        try { driveAssociation(client, server, false) } catch (_: CryptoException) { rejected = true }
        @Assert(rejected)
        @Assert(client.isClosed && !client.authenticated)
        rejected = false
        try { _ = client.exportSrtp() } catch (_: CryptoException) { rejected = true }
        @Assert(rejected)
        server.close(); c.destroy(); s.destroy()
    }

    @TestCase
    public func testLostInitialDatagramRetransmitUsesFreshRecordSequence(): Unit {
        let identity = associationIdentity()
        let client = DtlsAssociation(DtlsRole.Client, identity, identity.fingerprintSha256(), [UInt8(1)])
        client.start(0)
        let first = client.takeOutput()[0]
        client.onTimeout(999)
        @Assert(client.takeOutput().size, 0)
        client.onTimeout(1000)
        let retry = client.takeOutput()[0]
        let (a, plainA) = dtlsDecodeRecord(first)
        let (b, plainB) = dtlsDecodeRecord(retry)
        @Assert(b.sequenceNumber.toUInt64(), a.sequenceNumber.toUInt64() + 1)
        @Assert(plainA, plainB)
        client.close(); identity.destroy()
    }

    @TestCase
    public func testEachHandshakeDatagramCanBeLostOnce(): Unit {
        let a = associationIdentity(); let b = associationIdentity()
        for (lost in 0..17) {
            let client = DtlsAssociation(DtlsRole.Client, a, b.fingerprintSha256(), [UInt8(1)])
            let server = DtlsAssociation(DtlsRole.Server, b, a.fingerprintSha256(), [UInt8(1)])
            client.start(0); server.start(0)
            var packetIndex: Int64 = 0
            for (tick in 1..120) {
                client.onTimeout(tick * 200); server.onTimeout(tick * 200)
                for (wire in client.takeOutput()) {
                    if (packetIndex != lost) { _ = server.receive(wire, tick * 200) }
                    packetIndex += 1
                }
                for (wire in server.takeOutput()) {
                    if (packetIndex != lost) { _ = client.receive(wire, tick * 200) }
                    packetIndex += 1
                }
                if (client.authenticated && server.authenticated) { break }
            }
            if (!client.authenticated || !server.authenticated) {
                @Fail("lost datagram index ${lost}: client=${client.authenticated} server=${server.authenticated} packets=${packetIndex}")
            }
            client.close(); server.close()
        }
        a.destroy(); b.destroy()
    }

    @TestCase
    public func testForgedClientCertificateVerifyCannotAuthenticate(): Unit {
        let a = associationIdentity(); let b = associationIdentity()
        let client = DtlsAssociation(DtlsRole.Client, a, b.fingerprintSha256(), [UInt8(1)])
        let server = DtlsAssociation(DtlsRole.Server, b, a.fingerprintSha256(), [UInt8(1)])
        client.start(0); server.start(0)
        var rejected = false; var modified = false
        try {
            for (tick in 1..10) {
                for (wire in client.takeOutput()) {
                    let header = dtlsDecodeRecordHeader(wire[..13])
                    if (header.epoch == 0 && header.contentType == DtlsContentType.Handshake && wire[13] == 15) {
                        wire[wire.size - 1] ^= UInt8(1); modified = true
                    }
                    _ = server.receive(wire, tick * 100)
                }
                for (wire in server.takeOutput()) { _ = client.receive(wire, tick * 100) }
            }
        } catch (_: CryptoException) { rejected = true }
        @Assert(modified && rejected && server.isClosed && !server.authenticated)
        rejected = false
        try { _ = server.exportSrtp() } catch (_: CryptoException) { rejected = true }
        @Assert(rejected)
        client.close(); server.close(); a.destroy(); b.destroy()
    }

    @TestCase
    public func testCookieVectorsCannotCollideAtFieldBoundaries(): Unit {
        let manager = DtlsCookieManager(32, 300000, 120000)
        let random = Array<Byte>(32, repeat: 1)
        let cookie = manager.generateCookie([UInt8(1)], UInt16(3), DTLS_VERSION_1_2, random,
            [UInt16(0xc02b)], [UInt16(7), UInt16(1)], 0)
        @Assert(!manager.verifyCookie(cookie, [UInt8(1)], UInt16(3), DTLS_VERSION_1_2, random,
            [UInt16(0xc02b), UInt16(7)], [UInt16(1)], 0))
        cookie[1] = 0xff
        @Assert(!manager.verifyCookie(cookie, [UInt8(1)], UInt16(3), DTLS_VERSION_1_2, random,
            [UInt16(0xc02b)], [UInt16(7), UInt16(1)], Int64.Max))
    }

    @TestCase
    public func testApplicationOvertakesServerFinishedWithoutClosingClient(): Unit {
        let a = associationIdentity(); let b = associationIdentity()
        let client = DtlsAssociation(DtlsRole.Client, a, b.fingerprintSha256(), [UInt8(1)])
        let server = DtlsAssociation(DtlsRole.Server, b, a.fingerprintSha256(), [UInt8(1)])
        client.start(0); server.start(0)
        for (tick in 1..10) {
            for (wire in client.takeOutput()) { _ = server.receive(wire, tick * 100) }
            let output = server.takeOutput()
            if (server.authenticated) {
                @Assert(!client.authenticated)
                let earlyApp = server.sealApplicationData("overtook-finished".toArray())
                // Server flight is CCS then Finished. Test application between them.
                @Assert(output.size, 2)
                _ = client.receive(output[0], tick * 100)
                @Assert(client.receive(earlyApp, tick * 100).size, 0)
                @Assert(!client.authenticated && !client.isClosed)
                _ = client.receive(output[1], tick * 100)
                @Assert(client.authenticated)
                @Assert(client.receive(server.sealApplicationData("after-finished".toArray()), tick * 100)[0],
                    "after-finished".toArray())
                client.close(); server.close(); a.destroy(); b.destroy(); return
            }
            for (wire in output) { _ = client.receive(wire, tick * 100) }
        }
        @Fail("server did not finish")
    }

    @TestCase
    public func testServerPointFormatsAreASupportedListNotASingleSelection(): Unit {
        let identity = associationIdentity()
        let cases: Array<Array<Byte>> = [[3, 0, 1, 2], [2, 1, 2], [2, 0], [0], [1, 0, 4]]
        for (i in 0..cases.size) {
            let client = DtlsAssociation(DtlsRole.Client, identity, identity.fingerprintSha256(), [UInt8(1)])
            client.start(0); _ = client.takeOutput()
            let hello = DtlsServerHello(DTLS_VERSION_1_2, DtlsRandom.decode(Array<Byte>(32, repeat: 1)), [],
                UInt16(0xc02b), UInt8(0), UInt16(7), extensions: [DtlsExtension(UInt16(23), []),
                    DtlsExtension(UInt16(11), cases[i])]).encode()
            let fragment = dtlsEncodeHandshakeFragment(DtlsHandshakeFragment(DtlsHandshakeType.ServerHello,
                UInt32(hello.size), UInt16(0), UInt32(0), UInt32(hello.size), hello))
            let record = dtlsEncodeRecord(DtlsContentType.Handshake, DTLS_VERSION_1_2, UInt16(0), UInt48(UInt64(0)), fragment)
            var rejected = false
            try { _ = client.receive(record, 1) } catch (_: CryptoException) { rejected = true }
            @Assert(rejected, i != 0)
            @Assert(client.isClosed, i != 0)
            @Assert(!client.authenticated)
            client.close()
        }
        identity.destroy()
    }
}
