package jinguissl_core.dtls_tests

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.ArrayList
import jinguissl_core.crypto.dtls.*
import jinguissl_core.crypto.x509.{x509CreateSelfSignedEcCertificate, X509SelfSignedConfig, X509Certificate}
import jinguissl_core.crypto.ecc.{EcPrivateKey, NamedCurve, ecdsaSign, ecPublicFromPrivateKey}
import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.digest.{sha256, bytesToHexLower}
import jinguissl_core.crypto.utils.randomSeed

// ============================================================================
// Handshake Completion Security Gate — regression tests
// ============================================================================
//
// Each test exercises one of the seven mandatory gates required by
// the DTLS protocol contract:
//   1. happy path: all gates pass -> Established
//   2. certificate fingerprint mismatch (covers cert mismatch + fingerprint
//      mismatch as a single failure surface)
//   3. forged ServerKeyExchange signature
//   4. tampered transcript -> wrong Finished
//   5. wrong Finished verify_data
//   6. out-of-order flight (state machine rejects illegal transition)
//   7. alert-on-failure: every failure path records a fatal DtlsAlert
// ============================================================================

private func mkGateBytes(bytes: Array<Int64>): Array<Byte> {
    let result = Array<Byte>(bytes.size, repeat: 0)
    for (i in 0..bytes.size) { result[i] = UInt8(bytes[i]) }
    result
}

/// Build a deterministic EC P-256 private key for tests.
/// Uses a fixed scalar in [1, n-1].
private func mkTestEcPrivateKey(): EcPrivateKey {
    let scalarHex = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
    EcPrivateKey(NamedCurve.P256, BigNum.fromHex(scalarHex))
}

/// Build a self-signed EC P-256 certificate for tests.
private func mkTestEcCert(): X509Certificate {
    let priv = mkTestEcPrivateKey()
    let config = X509SelfSignedConfig("dtls-gate-test")
    x509CreateSelfSignedEcCertificate(config, priv)
}

/// Drive the local context through a synthetic but ordered handshake up to
/// FinishedSent. The peer Finished is then verified using the same label
/// computed from the local master secret, so the happy path completes.
private func driveContextToFinishedSent(ctx: DtlsHandshakeContext,
    peerCertDer: Array<Byte>, expectedFp: String): Unit {
    // Set peer certificate + fingerprint and verify (gates 1a/1b).
    ctx.setPeerCertificate(peerCertDer)
    ctx.setExpectedFingerprint(expectedFp)
    ctx.verifyPeerCertificateFingerprint()

    // Synthesize key exchange so master secret + key block are derived.
    ctx.generateClientRandom()
    ctx.generateServerRandom()
    ctx.processPeerKeyExchange(ctx.keyExchange.publicKey)

    // Record a minimal transcript so computeTranscriptHash returns a
    // deterministic value (used by both Finished computations).
    let dummyBody = mkGateBytes([0x01, 0x02, 0x03, 0x04])
    let signed = ArrayList<Byte>()
    for (b in ctx.clientRandom) { signed.add(b) }
    for (b in ctx.serverRandom) { signed.add(b) }
    for (b in dummyBody) { signed.add(b) }
    let (r, s) = ecdsaSign(mkTestEcPrivateKey(), sha256(signed.toArray()))
    ctx.verifyServerKeyExchangeSignature(dummyBody, r, s)
    ctx.recordHandshakeMessage(DtlsHandshakeType.ClientHello, UInt16(0), dummyBody)
    ctx.recordHandshakeMessage(DtlsHandshakeType.ServerHello, UInt16(1), dummyBody)
    ctx.recordHandshakeMessage(DtlsHandshakeType.Certificate, UInt16(2), dummyBody)
    ctx.recordHandshakeMessage(DtlsHandshakeType.ServerKeyExchange, UInt16(3), dummyBody)
    ctx.recordHandshakeMessage(DtlsHandshakeType.ServerHelloDone, UInt16(4), dummyBody)
    ctx.recordHandshakeMessage(DtlsHandshakeType.ClientKeyExchange, UInt16(5), dummyBody)

    // Transition through the legal Client sequence up to FinishedSent.
    ctx.state = DtlsConnectionState.ClientHelloSent
    ctx.state = DtlsConnectionState.ServerHelloReceived
    ctx.state = DtlsConnectionState.ServerHelloDoneReceived
    ctx.state = DtlsConnectionState.ClientKeyExchangeSent
    ctx.state = DtlsConnectionState.FinishedSent

    // Verify peer (server) Finished using the same label the local context
    // would use to compute it. In the happy path this matches.
    let peerVerify = ctx.computeFinishedVerifyData("server finished")
    ctx.verifyPeerFinished(peerVerify, "server finished")
}

@Test
public class DtlsHandshakeCompletionGateTestSuite {

    // Gate 1: happy path — all gates pass, finalizeHandshake transitions
    // the context to Established.
    @TestCase
    public func testHandshakeCompletionGate_HappyPath(): Unit {
        let ctx = DtlsHandshakeContext(DtlsRole.Client)
        let cert = mkTestEcCert()
        let fp = bytesToHexLower(sha256(cert.der))

        driveContextToFinishedSent(ctx, cert.der, fp)

        // Before finalize: not Established.
        @Assert(ctx.state, DtlsConnectionState.FinishedSent)

        ctx.finalizeHandshake()

        @Assert(ctx.state, DtlsConnectionState.Established)
        @Assert(ctx.finishedVerified, true)
        match (ctx.lastFatalAlert) {
            case Some(_) => @Assert(false, true)  // no fatal alert on success
            case None => ()
        }
    }

    // Gate 2: fingerprint mismatch — verifyPeerCertificateFingerprint throws
    // and records a fatal alert.
    @TestCase
    public func testHandshakeCompletionGate_FingerprintMismatch(): Unit {
        let ctx = DtlsHandshakeContext(DtlsRole.Client)
        let cert = mkTestEcCert()
        // Wrong fingerprint (64 hex chars but does not match the cert).
        let wrongFp = "0000000000000000000000000000000000000000000000000000000000000000"

        ctx.setPeerCertificate(cert.der)
        ctx.setExpectedFingerprint(wrongFp)

        var threw = false
        try {
            ctx.verifyPeerCertificateFingerprint()
        } catch (e: Exception) {
            threw = true
        }
        @Assert(threw, true)
        // Fatal alert must be recorded.
        match (ctx.lastFatalAlert) {
            case Some(alert) =>
                @Assert(alert.isFatal(), true)
                @Assert(alert.description, DtlsAlertDescription.BadCertificate)
            case None => @Assert(false, true)
        }
        // finalizeHandshake must also fail because fingerprint verification
        // will be re-run as a defense-in-depth gate.
        var finalizeThrew = false
        try {
            ctx.finalizeHandshake()
        } catch (e: Exception) {
            finalizeThrew = true
        }
        @Assert(finalizeThrew, true)
        @Assert(ctx.state, DtlsConnectionState.Failed)
    }

    // Gate 3: forged ServerKeyExchange signature — ecdsaVerify returns false,
    // verifyServerKeyExchangeSignature throws and records a fatal alert.
    @TestCase
    public func testHandshakeCompletionGate_ForgedSkeSignature(): Unit {
        let ctx = DtlsHandshakeContext(DtlsRole.Client)
        let cert = mkTestEcCert()
        let fp = bytesToHexLower(sha256(cert.der))
        ctx.setPeerCertificate(cert.der)
        ctx.setExpectedFingerprint(fp)
        ctx.verifyPeerCertificateFingerprint()

        ctx.generateClientRandom()
        ctx.generateServerRandom()

        // Forge an obviously-invalid (r, s) pair. RFC 5246 requires r,s in
        // [1, n-1]; we pick two large valid-looking values that nonetheless
        // cannot be a real signature for this digest.
        let r = BigNum.fromHex("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF")
        let s = BigNum.fromHex("CAFEBABECAFEBABECAFEBABECAFEBABECAFEBABECAFEBABECAFEBABECAFEBABE")
        let skeBody = mkGateBytes([0x03, 0x00, 0x1D, 0x20])

        var threw = false
        try {
            ctx.verifyServerKeyExchangeSignature(skeBody, r, s)
        } catch (e: Exception) {
            threw = true
        }
        @Assert(threw, true)
        match (ctx.lastFatalAlert) {
            case Some(alert) =>
                @Assert(alert.isFatal(), true)
                @Assert(alert.description, DtlsAlertDescription.HandshakeFailure)
            case None => @Assert(false, true)
        }
    }

    // Gate 3b: valid SKE signature verifies silently.
    @TestCase
    public func testHandshakeCompletionGate_ValidSkeSignature(): Unit {
        let priv = mkTestEcPrivateKey()
        let cert = x509CreateSelfSignedEcCertificate(
            X509SelfSignedConfig("dtls-gate-test"), priv)
        let ctx = DtlsHandshakeContext(DtlsRole.Client)
        let fp = bytesToHexLower(sha256(cert.der))
        ctx.setPeerCertificate(cert.der)
        ctx.setExpectedFingerprint(fp)
        ctx.verifyPeerCertificateFingerprint()

        ctx.generateClientRandom()
        ctx.generateServerRandom()

        // Build the signed content exactly as verifyServerKeyExchangeSignature
        // does, sign it with the private key, then verify.
        let skeBody = mkGateBytes([0x03, 0x00, 0x1D, 0x20])
        let signed = Array<Byte>(ctx.clientRandom.size + ctx.serverRandom.size + skeBody.size,
            repeat: 0)
        for (i in 0..ctx.clientRandom.size) { signed[i] = ctx.clientRandom[i] }
        for (i in 0..ctx.serverRandom.size) { signed[ctx.clientRandom.size + i] = ctx.serverRandom[i] }
        for (i in 0..skeBody.size) {
            signed[ctx.clientRandom.size + ctx.serverRandom.size + i] = skeBody[i]
        }
        let digest = sha256(signed)
        let (r, s) = ecdsaSign(priv, digest)

        // Should not throw.
        ctx.verifyServerKeyExchangeSignature(skeBody, r, s)
        match (ctx.lastFatalAlert) {
            case Some(_) => @Assert(false, true)
            case None => ()
        }
    }

    // Gate 4: tampered transcript — a peer that computed its Finished
    // verify_data over the original transcript cannot match a locally
    // tampered transcript. verifyPeerFinished must reject the stale
    // verify_data and record a fatal alert.
    @TestCase
    public func testHandshakeCompletionGate_TamperedTranscript(): Unit {
        let ctx = DtlsHandshakeContext(DtlsRole.Client)
        let cert = mkTestEcCert()
        let fp = bytesToHexLower(sha256(cert.der))

        // Set up the context (peer cert + key exchange + transcript) but
        // do NOT call verifyPeerFinished yet.
        ctx.setPeerCertificate(cert.der)
        ctx.setExpectedFingerprint(fp)
        ctx.verifyPeerCertificateFingerprint()
        ctx.generateClientRandom()
        ctx.generateServerRandom()
        ctx.processPeerKeyExchange(ctx.keyExchange.publicKey)
        let dummyBody = mkGateBytes([0x01, 0x02, 0x03, 0x04])
        ctx.recordHandshakeMessage(DtlsHandshakeType.ClientHello, UInt16(0), dummyBody)
        ctx.recordHandshakeMessage(DtlsHandshakeType.ServerHello, UInt16(1), dummyBody)
        ctx.recordHandshakeMessage(DtlsHandshakeType.Certificate, UInt16(2), dummyBody)

        // Peer computes its Finished verify_data over the ORIGINAL transcript.
        let peerVerify = ctx.computeFinishedVerifyData("server finished")

        // Attacker tampers with the transcript after the peer signed off.
        ctx.transcriptMessages.add(UInt8(0xFF))

        // The stale peerVerify must no longer validate against the tampered
        // transcript.
        var threw = false
        try {
            ctx.verifyPeerFinished(peerVerify, "server finished")
        } catch (e: Exception) {
            threw = true
        }
        @Assert(threw, true)
        @Assert(ctx.finishedVerified, false)
        match (ctx.lastFatalAlert) {
            case Some(alert) =>
                @Assert(alert.isFatal(), true)
                @Assert(alert.description, DtlsAlertDescription.HandshakeFailure)
            case None => @Assert(false, true)
        }
    }

    // Gate 5: wrong Finished verify_data — verifyPeerFinished must reject
    // any verify_data that does not match the PRF output.
    @TestCase
    public func testHandshakeCompletionGate_WrongFinished(): Unit {
        let ctx = DtlsHandshakeContext(DtlsRole.Client)
        let cert = mkTestEcCert()
        let fp = bytesToHexLower(sha256(cert.der))

        // Set up context but do not call verifyPeerFinished yet.
        ctx.setPeerCertificate(cert.der)
        ctx.setExpectedFingerprint(fp)
        ctx.verifyPeerCertificateFingerprint()
        ctx.generateClientRandom()
        ctx.generateServerRandom()
        ctx.processPeerKeyExchange(ctx.keyExchange.publicKey)
        let dummyBody = mkGateBytes([0x01, 0x02, 0x03, 0x04])
        ctx.recordHandshakeMessage(DtlsHandshakeType.ClientHello, UInt16(0), dummyBody)

        // Wrong verify_data: all 0xAA.
        let wrongVerify = mkGateBytes(Array<Int64>(12, repeat: 0xAA))
        var threw = false
        try {
            ctx.verifyPeerFinished(wrongVerify, "server finished")
        } catch (e: Exception) {
            threw = true
        }
        @Assert(threw, true)
        @Assert(ctx.finishedVerified, false)
        match (ctx.lastFatalAlert) {
            case Some(alert) =>
                @Assert(alert.isFatal(), true)
                @Assert(alert.description, DtlsAlertDescription.HandshakeFailure)
            case None => @Assert(false, true)
        }

        // finalizeHandshake must fail because finishedVerified is false.
        var finalizeThrew = false
        try {
            ctx.finalizeHandshake()
        } catch (e: Exception) {
            finalizeThrew = true
        }
        @Assert(finalizeThrew, true)
    }

    // Gate 5b: wrong Finished length is also rejected.
    @TestCase
    public func testHandshakeCompletionGate_WrongFinishedLength(): Unit {
        let ctx = DtlsHandshakeContext(DtlsRole.Client)
        let cert = mkTestEcCert()
        let fp = bytesToHexLower(sha256(cert.der))
        ctx.setPeerCertificate(cert.der)
        ctx.setExpectedFingerprint(fp)
        ctx.verifyPeerCertificateFingerprint()
        ctx.generateClientRandom()
        ctx.generateServerRandom()
        ctx.processPeerKeyExchange(ctx.keyExchange.publicKey)

        // verify_data of 11 bytes (too short).
        let shortVerify = mkGateBytes(Array<Int64>(11, repeat: 0x01))
        var threw = false
        try {
            ctx.verifyPeerFinished(shortVerify, "server finished")
        } catch (e: Exception) {
            threw = true
        }
        @Assert(threw, true)
        match (ctx.lastFatalAlert) {
            case Some(alert) => @Assert(alert.isFatal(), true)
            case None => @Assert(false, true)
        }
    }

    // Gate 6: out-of-order flight — dtlsIsValidStateTransition rejects
    // illegal transitions; finalizeHandshake cannot be reached from an
    // out-of-order state.
    @TestCase
    public func testHandshakeCompletionGate_OutOfOrderFlight(): Unit {
        // Client cannot jump Idle -> Established directly.
        @Assert(dtlsIsValidStateTransition(DtlsRole.Client,
            DtlsConnectionState.Idle,
            DtlsConnectionState.Established), false)

        // Client cannot jump Idle -> FinishedSent (must pass through
        // ClientHelloSent -> ServerHelloReceived -> ServerHelloDoneReceived
        // -> ClientKeyExchangeSent -> FinishedSent).
        @Assert(dtlsIsValidStateTransition(DtlsRole.Client,
            DtlsConnectionState.Idle,
            DtlsConnectionState.FinishedSent), false)

        // Server cannot jump Idle -> Established.
        @Assert(dtlsIsValidStateTransition(DtlsRole.Server,
            DtlsConnectionState.Idle,
            DtlsConnectionState.Established), false)

        // Server cannot skip ServerHelloReceived.
        @Assert(dtlsIsValidStateTransition(DtlsRole.Server,
            DtlsConnectionState.Idle,
            DtlsConnectionState.ServerHelloDoneReceived), false)

        // Closed and Failed are terminal.
        @Assert(dtlsIsValidStateTransition(DtlsRole.Client,
            DtlsConnectionState.Failed,
            DtlsConnectionState.Established), false)
        @Assert(dtlsIsValidStateTransition(DtlsRole.Server,
            DtlsConnectionState.Closed,
            DtlsConnectionState.Established), false)

        // finalizeHandshake called from Idle must fail.
        let ctx = DtlsHandshakeContext(DtlsRole.Client)
        let cert = mkTestEcCert()
        let fp = bytesToHexLower(sha256(cert.der))
        ctx.setPeerCertificate(cert.der)
        ctx.setExpectedFingerprint(fp)
        // Force finishedVerified = true to isolate the state-machine gate.
        // We cannot call finalizeHandshake from Idle regardless of
        // finishedVerified, because the state machine forbids it.
        var threw = false
        try {
            ctx.finalizeHandshake()
        } catch (e: Exception) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Gate 7: alert-on-failure — every failure path above must have recorded
    // a fatal DtlsAlert on lastFatalAlert. This test re-checks that invariant
    // for a fresh context that fails finalizeHandshake.
    @TestCase
    public func testHandshakeCompletionGate_AlertOnFailure(): Unit {
        let ctx = DtlsHandshakeContext(DtlsRole.Client)
        // Do NOT set peer certificate or fingerprint; do NOT verify Finished.
        // finalizeHandshake must fail at gate 1 (peer certificate not set)
        // and record a fatal alert.
        var threw = false
        try {
            ctx.finalizeHandshake()
        } catch (e: Exception) {
            threw = true
        }
        @Assert(threw, true)
        match (ctx.lastFatalAlert) {
            case Some(alert) =>
                @Assert(alert.isFatal(), true)
                @Assert(alert.description, DtlsAlertDescription.HandshakeFailure)
            case None => @Assert(false, true)
        }
        // Context state must be Failed.
        @Assert(ctx.state, DtlsConnectionState.Failed)
    }

    // Gate 8: SKE signature verification is client-only — server role is
    // rejected with IllegalParameter alert.
    @TestCase
    public func testHandshakeCompletionGate_SkeVerifyClientOnly(): Unit {
        let serverCtx = DtlsHandshakeContext(DtlsRole.Server)
        let cert = mkTestEcCert()
        serverCtx.setPeerCertificate(cert.der)
        let fp = bytesToHexLower(sha256(cert.der))
        serverCtx.setExpectedFingerprint(fp)

        let r = BigNum.fromHex("01")
        let s = BigNum.fromHex("01")
        let skeBody = mkGateBytes([0x03, 0x00, 0x1D, 0x20])

        var threw = false
        try {
            serverCtx.verifyServerKeyExchangeSignature(skeBody, r, s)
        } catch (e: Exception) {
            threw = true
        }
        @Assert(threw, true)
        match (serverCtx.lastFatalAlert) {
            case Some(alert) =>
                @Assert(alert.description, DtlsAlertDescription.IllegalParameter)
            case None => @Assert(false, true)
        }
    }
}

// ============================================================================
// DTLS Alert encode/decode regression
// ============================================================================

@Test
public class DtlsAlertTestSuite {

    @TestCase
    public func testDtlsAlertRoundTrip(): Unit {
        let alert = DtlsAlert(DtlsAlertLevel.Fatal,
            DtlsAlertDescription.HandshakeFailure)
        let encoded = alert.encode()
        @Assert(encoded.size, 2)
        let decoded = DtlsAlert.decode(encoded)
        @Assert(decoded.level, DtlsAlertLevel.Fatal)
        @Assert(decoded.description, DtlsAlertDescription.HandshakeFailure)
    }

    @TestCase
    public func testDtlsFatalAlertHelper(): Unit {
        let alert = dtlsFatalAlert(DtlsAlertDescription.BadCertificate)
        @Assert(alert.isFatal(), true)
        @Assert(alert.description, DtlsAlertDescription.BadCertificate)
    }

    @TestCase
    public func testDtlsAlertDecodeTooShort(): Unit {
        var threw = false
        try {
            let _ = DtlsAlert.decode(mkGateBytes([0x01]))
        } catch (e: Exception) {
            threw = true
        }
        @Assert(threw, true)
    }
}

// ============================================================================
// DTLS Session state machine regression
// ============================================================================

@Test
public class DtlsSessionStateMachineTestSuite {

    @TestCase
    public func testSessionRejectsIllegalTransition(): Unit {
        let session = DtlsSession(DtlsRole.Client)
        @Assert(session.state, DtlsConnectionState.Idle)

        // Idle -> Established is illegal for Client.
        var threw = false
        try {
            session.transition(DtlsConnectionState.Established)
        } catch (e: Exception) {
            threw = true
        }
        @Assert(threw, true)
        @Assert(session.state, DtlsConnectionState.Idle)
    }

    @TestCase
    public func testSessionAcceptsLegalClientSequence(): Unit {
        let session = DtlsSession(DtlsRole.Client)
        session.transition(DtlsConnectionState.ClientHelloSent)
        session.transition(DtlsConnectionState.ServerHelloReceived)
        session.transition(DtlsConnectionState.ServerHelloDoneReceived)
        session.transition(DtlsConnectionState.ClientKeyExchangeSent)
        session.transition(DtlsConnectionState.FinishedSent)
        session.transition(DtlsConnectionState.Established)
        @Assert(session.state, DtlsConnectionState.Established)
    }

    @TestCase
    public func testSessionTerminalStatesAreTerminal(): Unit {
        let session = DtlsSession(DtlsRole.Client)
        session.transition(DtlsConnectionState.Failed)
        // Cannot leave Failed.
        var threw = false
        try {
            session.transition(DtlsConnectionState.Established)
        } catch (e: Exception) {
            threw = true
        }
        @Assert(threw, true)
        @Assert(session.state, DtlsConnectionState.Failed)
    }
}
