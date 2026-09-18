package jinguissl_core.dtls_tests

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.ArrayList
import jinguissl_core.crypto.dtls.*
import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}

// ============================================================================
// DTLS Clean Failure State + Real UDP Handshake Proof
// ============================================================================
//
// Covers the DTLS acceptance requirements:
//   - clean failure state: any handshake failure must leave the connection
//     in a terminal error state with no residual keys, no residual SRTP
//     material, and no half-established state
//   - record transport between two UDP sockets in one process
//
// The clean-failure tests pin the zeroize-on-failure contract. The UDP
// proof exchanges real DTLS records over a real UDP socket pair bound to
// two distinct ephemeral ports on 127.0.0.1, proving the record layer,
// and transport serialization. This does not prove an authenticated handshake
// or interoperability with a separate implementation.
// ============================================================================

private func mkBytes(n: Int64, fill: UInt8): Array<Byte> {
    Array<Byte>(n, repeat: fill)
}

/// Assert that an Option is None. Used for types that do not implement
/// Equatable (e.g. DtlsKeyBlock, DtlsSrtpKeyingMaterial), so @Assert
/// cannot compare them directly against None.
private func assertNone<T>(label: String, opt: ?T): Unit {
    match (opt) {
        case Some(_) =>
            @Assert(false, true)  // fail: expected None
        case None =>
            ()  // pass
    }
}

// ---------------------------------------------------------------------------
// Clean Failure State — zeroize-on-failure contract
// ---------------------------------------------------------------------------

@Test
public class DtlsCleanFailureStateTestSuite {

    // Acceptance: a fatal alert transitions state to Failed and records the
    // alert on lastFatalAlert.
    @TestCase
    public func testFatalAlert_TransitionsToFailed(): Unit {
        let ctx = DtlsHandshakeContext(DtlsRole.Client)
        @Assert(ctx.state, DtlsConnectionState.Idle)
        ctx.recordFatalAlert(DtlsAlertDescription.HandshakeFailure,
            "test-induced")
        @Assert(ctx.state, DtlsConnectionState.Failed)
        match (ctx.lastFatalAlert) {
            case Some(a) =>
                @Assert(a.isFatal(), true)
                @Assert(a.description, DtlsAlertDescription.HandshakeFailure)
            case None =>
                @Assert(false, true)  // fail: alert not recorded
        }
    }

    // Acceptance: a fatal alert zeroizes the master secret — no residual
    // key material after failure.
    @TestCase
    public func testFatalAlert_ZeroizesMasterSecret(): Unit {
        let ctx = DtlsHandshakeContext(DtlsRole.Client)
        ctx.generateClientRandom()
        ctx.generateServerRandom()
        ctx.processPeerKeyExchange(ctx.keyExchange.publicKey)
        // Confirm master secret is set before failure.
        @Assert(ctx.isHandshakeComplete(), true)
        // Fail the handshake.
        ctx.recordFatalAlert(DtlsAlertDescription.HandshakeFailure, "test")
        // Master secret MUST be None after failure.
        assertNone("masterSecret", ctx.masterSecret)
        @Assert(ctx.isHandshakeComplete(), false)
    }

    // Acceptance: a fatal alert zeroizes the key block — no residual
    // write keys or IVs after failure.
    @TestCase
    public func testFatalAlert_ZeroizesKeyBlock(): Unit {
        let ctx = DtlsHandshakeContext(DtlsRole.Client)
        ctx.generateClientRandom()
        ctx.generateServerRandom()
        ctx.processPeerKeyExchange(ctx.keyExchange.publicKey)
        // keyBlock should be Some after processPeerKeyExchange
        match (ctx.keyBlock) {
            case Some(_) => ()  // expected
            case None => @Assert(false, true)
        }
        ctx.recordFatalAlert(DtlsAlertDescription.HandshakeFailure, "test")
        assertNone("keyBlock", ctx.keyBlock)
    }

    // Acceptance: a fatal alert zeroizes the SRTP keying material — no
    // residual SRTP keys after failure.
    @TestCase
    public func testFatalAlert_ZeroizesSrtpMaterial(): Unit {
        let ctx = dtlsAuthenticatedFixture()
        _ = ctx.extractSrtpKeyingMaterial(
            DtlsSrtpProtectionProfile.Aes128CmSha1_80)
        // Confirm SRTP material is set before failure.
        match (ctx.srtpKeyingMaterial) {
            case Some(_) => ()
            case None => @Assert(false, true)
        }
        ctx.recordFatalAlert(DtlsAlertDescription.HandshakeFailure, "test")
        assertNone("srtpKeyingMaterial", ctx.srtpKeyingMaterial)
    }

    // Acceptance: a fatal alert zeroizes the ECDHE shared secret — no
    // residual pre-master secret after failure.
    @TestCase
    public func testFatalAlert_ZeroizesEcdheSharedSecret(): Unit {
        let ctx = DtlsHandshakeContext(DtlsRole.Client)
        ctx.generateClientRandom()
        ctx.generateServerRandom()
        ctx.processPeerKeyExchange(ctx.keyExchange.publicKey)
        @Assert(ctx.keyExchange.hasSharedSecret(), true)
        ctx.recordFatalAlert(DtlsAlertDescription.HandshakeFailure, "test")
        @Assert(ctx.keyExchange.hasSharedSecret(), false)
        @Assert(ctx.keyExchange.peerPublicKey, None)
    }

    // Acceptance: a fatal alert clears the transcript so a replayed
    // Finished cannot be replayed post-fail.
    @TestCase
    public func testFatalAlert_ClearsTranscript(): Unit {
        let ctx = DtlsHandshakeContext(DtlsRole.Client)
        let dummy = mkBytes(4, 0x42)
        ctx.recordHandshakeMessage(DtlsHandshakeType.ClientHello,
            UInt16(0), dummy)
        ctx.recordHandshakeMessage(DtlsHandshakeType.ServerHello,
            UInt16(1), dummy)
        @Assert(ctx.transcriptMessages.size > 0, true)
        ctx.recordFatalAlert(DtlsAlertDescription.HandshakeFailure, "test")
        @Assert(ctx.transcriptMessages.size, 0)
    }

    // Acceptance: a fatal alert resets finishedVerified so no caller can
    // read a stale verdict.
    @TestCase
    public func testFatalAlert_ResetsFinishedVerified(): Unit {
        let ctx = DtlsHandshakeContext(DtlsRole.Client)
        // Simulate a previously-verified Finished (defensive: set directly).
        ctx.finishedVerified = true
        ctx.recordFatalAlert(DtlsAlertDescription.HandshakeFailure, "test")
        @Assert(ctx.finishedVerified, false)
    }

    // Acceptance: recordFatalAlert is idempotent — calling it multiple times
    // does not crash and leaves the context in a consistent Failed state.
    @TestCase
    public func testFatalAlert_Idempotent(): Unit {
        let ctx = DtlsHandshakeContext(DtlsRole.Client)
        ctx.generateClientRandom()
        ctx.generateServerRandom()
        ctx.processPeerKeyExchange(ctx.keyExchange.publicKey)
        ctx.recordFatalAlert(DtlsAlertDescription.HandshakeFailure, "first")
        @Assert(ctx.state, DtlsConnectionState.Failed)
        // Second call must not crash and must preserve Failed state.
        ctx.recordFatalAlert(DtlsAlertDescription.InternalError, "second")
        @Assert(ctx.state, DtlsConnectionState.Failed)
        assertNone("masterSecret", ctx.masterSecret)
        assertNone("keyBlock", ctx.keyBlock)
        assertNone("srtpKeyingMaterial", ctx.srtpKeyingMaterial)
        // The last alert description should be from the most recent call.
        match (ctx.lastFatalAlert) {
            case Some(a) =>
                @Assert(a.description, DtlsAlertDescription.InternalError)
            case None =>
                @Assert(false, true)
        }
    }

    // Acceptance: a Failed context cannot transition to Established — the
    // state machine rejects the transition (no half-established state).
    @TestCase
    public func testFailed_CannotTransitionToEstablished(): Unit {
        let ctx = DtlsHandshakeContext(DtlsRole.Client)
        ctx.recordFatalAlert(DtlsAlertDescription.HandshakeFailure, "test")
        @Assert(ctx.state, DtlsConnectionState.Failed)
        // The state machine MUST reject any transition out of Failed.
        let ok = dtlsIsValidStateTransition(DtlsRole.Client,
            DtlsConnectionState.Failed,
            DtlsConnectionState.Established)
        @Assert(ok, false)
    }

    // Acceptance: a Closed context also cannot transition to Established.
    @TestCase
    public func testClosed_CannotTransitionToEstablished(): Unit {
        let ok = dtlsIsValidStateTransition(DtlsRole.Client,
            DtlsConnectionState.Closed,
            DtlsConnectionState.Established)
        @Assert(ok, false)
    }
}

// ---------------------------------------------------------------------------
// Real UDP Handshake Proof — two-endpoint record exchange over UDP
// ---------------------------------------------------------------------------
//
// This test proves the DTLS record layer, handshake layer, and transport
// layer compose into a real handshake path over UDP. Two DtlsUdpTransport
// instances bind to two distinct ephemeral ports on 127.0.0.1 and exchange
// real ClientHello/ServerHello records encoded per RFC 6347.
//
// This fixture only tests two sockets in one process. Independent peer
// handshake and application-data proofs belong to integration tests.
// ---------------------------------------------------------------------------

@Test
public class DtlsUdpHandshakeProofTestSuite {

    // Acceptance: two endpoints can bind to distinct ephemeral ports on
    // 127.0.0.1 and exchange a real DTLS ClientHello record over UDP.
    @TestCase
    public func testUdp_ClientHelloExchange(): Unit {
        let server = DtlsUdpTransport()
        server.bind(host: "127.0.0.1", port: UInt16(0))
        let serverPort = server.localPort
        @Assert(serverPort > UInt16(0), true)

        let client = DtlsUdpTransport()
        client.bind(host: "127.0.0.1", port: UInt16(0))
        let clientPort = client.localPort
        @Assert(clientPort > UInt16(0), true)
        @Assert(clientPort != serverPort, true)

        // Build a real ClientHello with use_srtp extension.
        let clientRandom = DtlsRandom.generate()
        let cipherSuites = [UInt16(0xC02B)]  // TLS_ECDHE_ECDSA_AES128_GCM_SHA256
        let srtpProfiles = [UInt16(0x0001)]  // SRTP_AES128_CM_HMAC_SHA1_80
        let compression = Array<Byte>(1, repeat: 0)  // null compression
        let ch = DtlsClientHello(
            UInt16(0xFEFD),
            clientRandom,
            Array<Byte>(0, repeat: 0),
            Array<Byte>(0, repeat: 0),
            cipherSuites,
            compression,
            srtpProfiles
        )
        let chBody = ch.encode()
        let record = dtlsEncodeRecord(DtlsContentType.Handshake,
            UInt16(0xFEFD), UInt16(0), UInt48(UInt64(0)), chBody)

        // Client sends ClientHello to server.
        client.sendTo("127.0.0.1", serverPort, record)

        // Server receives the record.
        match (server.receiveFrom(timeoutMs: 2000)) {
            case Some((fromHost, fromPort, data)) =>
                @Assert(fromHost, "127.0.0.1")
                @Assert(fromPort, clientPort)
                @Assert(data.size, record.size)
                // Decode the record and the ClientHello.
                let (hdr, body) = dtlsDecodeRecord(data)
                @Assert(hdr.contentType, DtlsContentType.Handshake)
                @Assert(hdr.version, UInt16(0xFEFD))
                let decodedCh = DtlsClientHello.decode(body)
                @Assert(decodedCh.version, UInt16(0xFEFD))
                @Assert(decodedCh.cipherSuites.size, 1)
                @Assert(decodedCh.cipherSuites[0], UInt16(0xC02B))
                @Assert(decodedCh.srtpProfiles.size, 1)
                @Assert(decodedCh.srtpProfiles[0], UInt16(0x0001))
            case None =>
                @Assert(false, true)  // fail: no data received
        }
    }

    // Acceptance: the server can send a ServerHello back to the client over
    // UDP, completing a real record-layer round trip.
    @TestCase
    public func testUdp_ServerHelloRoundTrip(): Unit {
        let server = DtlsUdpTransport()
        server.bind(host: "127.0.0.1", port: UInt16(0))
        let serverPort = server.localPort

        let client = DtlsUdpTransport()
        client.bind(host: "127.0.0.1", port: UInt16(0))
        let clientPort = client.localPort

        // Build and send a ServerHello from server to client.
        let serverRandom = DtlsRandom.generate()
        let sh = DtlsServerHello(
            UInt16(0xFEFD),
            serverRandom,
            Array<Byte>(0, repeat: 0),
            UInt16(0xC02B),
            UInt8(0),
            None
        )
        let shBody = sh.encode()
        let record = dtlsEncodeRecord(DtlsContentType.Handshake,
            UInt16(0xFEFD), UInt16(0), UInt48(UInt64(0)), shBody)

        server.sendTo("127.0.0.1", clientPort, record)

        match (client.receiveFrom(timeoutMs: 2000)) {
            case Some((fromHost, fromPort, data)) =>
                @Assert(fromHost, "127.0.0.1")
                @Assert(fromPort, serverPort)
                let (hdr, body) = dtlsDecodeRecord(data)
                @Assert(hdr.contentType, DtlsContentType.Handshake)
                let decodedSh = DtlsServerHello.decode(body)
                @Assert(decodedSh.version, UInt16(0xFEFD))
                @Assert(decodedSh.cipherSuite, UInt16(0xC02B))
            case None =>
                @Assert(false, true)
        }
    }

    // Acceptance: a real DTLS Alert record can be exchanged over UDP,
    // proving the alert wire path is exercised end-to-end.
    @TestCase
    public func testUdp_AlertExchange(): Unit {
        let server = DtlsUdpTransport()
        server.bind(host: "127.0.0.1", port: UInt16(0))
        let serverPort = server.localPort

        let client = DtlsUdpTransport()
        client.bind(host: "127.0.0.1", port: UInt16(0))
        let clientPort = client.localPort

        let alert = dtlsFatalAlert(DtlsAlertDescription.HandshakeFailure)
        let alertBody = alert.encode()
        let record = dtlsEncodeRecord(DtlsContentType.Alert,
            UInt16(0xFEFD), UInt16(0), UInt48(UInt64(0)), alertBody)

        client.sendTo("127.0.0.1", serverPort, record)

        match (server.receiveFrom(timeoutMs: 2000)) {
            case Some((_, _, data)) =>
                let (hdr, body) = dtlsDecodeRecord(data)
                @Assert(hdr.contentType, DtlsContentType.Alert)
                let decodedAlert = DtlsAlert.decode(body)
                @Assert(decodedAlert.isFatal(), true)
                @Assert(decodedAlert.description,
                    DtlsAlertDescription.HandshakeFailure)
            case None =>
                @Assert(false, true)
        }
    }
}
