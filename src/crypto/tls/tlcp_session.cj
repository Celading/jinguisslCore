package jinguissl_core.crypto.tls

import std.collection.ArrayList
import std.sync.Mutex
import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.digest.{hash, HashAlgorithm}
import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.sm2.{Sm2PrivateKey, Sm2PublicKey, sm2GeneratePrivateKey,
    sm2PublicKey, sm2Sign, sm2Verify}
import jinguissl_core.crypto.utils.randomSeed
import jinguissl_core.crypto.x509.{X509VerificationPolicy, x509ParsePemChain, x509ExtractSm2PublicKey}

public enum TlcpRole <: Equatable<TlcpRole> {
    | Client | Server
    public operator func ==(right: TlcpRole): Bool {
        let client = match (this) { case Client => true; case Server => false }
        let otherClient = match (right) { case Client => true; case Server => false }
        client == otherClient
    }
    public operator func !=(right: TlcpRole): Bool { !(this == right) }
}

/** Experimental, transport-independent full TLCP handshake. Caller owns a
 * reliable byte stream and monotonic clock, and drains takeOutput after every
 * event. No ALPN, resumption, renegotiation, early data or transport downgrade.
 * handshakeComplete is key confirmation; peerAuthenticated additionally means
 * a verified peer certificate. Static-ECC servers may not authenticate clients.
 * All methods are serialized. Destruction is best-effort for owned byte buffers,
 * not managed arithmetic temporaries or caller copies. */
public class TlcpSession {
    private let mutex = Mutex()
    private let state: TlcpSessionState
    public init(role: TlcpRole, trustAnchorsPem: String, validationTime: String,
        expectedPeerDnsName!: String = "", identity!: ?TlcpIdentity = None,
        policy!: TlcpProviderPolicy = TlcpProviderPolicy()) {
        state = TlcpSessionState(role, trustAnchorsPem, validationTime, expectedPeerDnsName, identity, policy)
    }
    public prop handshakeComplete: Bool { get() { synchronized(mutex) { state.ready && !state.closed } } }
    public prop peerAuthenticated: Bool { get() { synchronized(mutex) { state.ready && !state.closed && state.peerVerified } } }
    public prop isClosed: Bool { get() { synchronized(mutex) { state.closed } } }
    public func start(nowMs: Int64): Unit {
        synchronized(mutex) {
            try { state.start(nowMs) }
            catch (e: CryptoException) { state.fail("internal-error", e.message, 80) }
        }
    }
    public func receive(bytes: Array<Byte>, nowMs: Int64): Array<Array<Byte>> {
        synchronized(mutex) { state.receive(bytes, nowMs) }
    }
    public func takeOutput(): Array<Array<Byte>> { synchronized(mutex) { state.takeOutput() } }
    public func onTimeout(nowMs: Int64): Unit { synchronized(mutex) { state.clock(nowMs) } }
    public func sealApplicationData(bytes: Array<Byte>): Array<Byte> {
        synchronized(mutex) { state.sealApplicationData(bytes) }
    }
    public func selectedCipherSuite(): TlcpCipherSuite {
        synchronized(mutex) { state.requireReady(); state.suite }
    }
    public func peerCertificateHandshake(): Array<Byte> {
        synchronized(mutex) { state.requireReady(); state.peerMessage.clone() }
    }
    public func closeNotify(): Unit { synchronized(mutex) { state.closeNotify() } }
    public func endOfInput(): Unit { synchronized(mutex) { state.endOfInput() } }
    public func close(): Unit { synchronized(mutex) { state.close() } }
}

class TlcpSessionState {
    let role: TlcpRole
    let trust: X509VerificationPolicy
    let policy: TlcpProviderPolicy
    let identity: ?TlcpIdentity
    var phase: Int64 = 0
    var ready = false
    var closed = false
    var peerVerified = false
    var sawClose = false
    var sawCcs = false
    var writeProtected = false
    var requestedCertificate = false
    var secureRenegotiation = false
    var clientRandom: Array<Byte> = []
    var serverRandom: Array<Byte> = []
    var peerMessage: Array<Byte> = []
    var peerBundle: ?TlcpCertificateBundle = None
    var peerEphemeral: ?Sm2PublicKey = None
    var ephemeral: Array<Byte> = []
    var suite: TlcpCipherSuite = ECC_SM4_GCM_SM3
    var secrets: ?TlcpHandshakeSecrets = None
    var records: ?TlcpRecordLayer = None
    var input: Array<Byte> = []
    var handshakeInput: Array<Byte> = []
    var transcript: Array<Byte> = []
    var output = ArrayList<Array<Byte>>()
    var outputBytes: Int64 = 0
    var lastClock: Int64 = 0
    var deadline: Int64 = 0
    var contextReason = "invalid-message"
    var contextAlert: Int64 = 50

    init(role: TlcpRole, anchors: String, validationTime: String, dns: String,
        identity: ?TlcpIdentity, policy: TlcpProviderPolicy) {
        if (validationTime.size == 0 || (role == TlcpRole.Client && dns.trimAscii().size == 0)) {
            throw TlcpProviderException("invalid-policy", "TLCP requires validation time and client-side peer DNS name")
        }
        if (role == TlcpRole.Server && identity.isNone()) {
            throw TlcpProviderException("missing-identity", "TLCP server requires a dual-certificate identity")
        }
        if (role == TlcpRole.Client && identity.isNone()) {
            for (s in policy.cipherSuites()) {
                if (s.usesEcdhe()) { throw TlcpProviderException("missing-identity", "TLCP ECDHE requires client dual identity") }
            }
        }
        this.role = role; this.policy = policy
        this.trust = X509VerificationPolicy(x509ParsePemChain(anchors), validationTime: validationTime,
            requiredLeafDnsName: dns)
        this.identity = if (let Some(id) <- identity) { Some(id.copyOwned()) } else { None }
    }
    func requireOpen(): Unit {
        if (closed) { throw TlcpProviderException("closed", "TLCP session closed") }
    }
    func requireReady(): Unit {
        requireOpen()
        if (!ready) { throw TlcpProviderException("not-authenticated", "TLCP Finished is not verified") }
    }
    func clock(now: Int64): Unit {
        requireOpen()
        if (now < lastClock || now < 0 || now > Int64.Max - 120000) {
            fail("invalid-clock", "TLCP requires a monotonic millisecond clock", 80)
        }
        lastClock = now
        if (phase != 0 && !ready && now >= deadline) { fail("timeout", "TLCP handshake deadline expired", 40) }
    }
    func start(now: Int64): Unit {
        requireOpen()
        if (phase != 0) { fail("invalid-state", "TLCP session already started", 10) }
        clock(now); deadline = now + policy.handshakeTimeoutMs
        if (role == TlcpRole.Client) {
            clientRandom = randomSeed(size: 32)
            sendHandshake(tlcpEncodeClientHello(TlcpClientHello(clientRandom, policy.cipherSuites(), secureRenegotiation: true)))
            phase = 1
        } else { phase = 10 }
    }
    func queue(bytes: Array<Byte>): Unit {
        if (outputBytes + bytes.size > 262144) { fail("budget-exceeded", "Drain TLCP output before more input", 80) }
        output.add(bytes); outputBytes += bytes.size
    }
    func takeOutput(): Array<Array<Byte>> {
        let result = output.toArray(); output.clear(); outputBytes = 0; result
    }
    func remember(message: Array<Byte>): Unit {
        if (transcript.size + message.size > 1048576) { fail("budget-exceeded", "TLCP transcript budget exceeded", 80) }
        transcript = tlcpConcat(transcript, message)
    }
    func sendHandshake(message: Array<Byte>): Unit {
        remember(message)
        var offset: Int64 = 0
        while (offset < message.size) {
            let end = min(offset + 16384, message.size)
            let fragment = message[offset..end]
            queue(if (writeProtected) { layer().seal(Handshake, fragment) } else { tlcpEncodeRecord(Handshake, fragment) })
            offset = end
        }
    }
    func receive(bytes: Array<Byte>, now: Int64): Array<Array<Byte>> {
        clock(now)
        if (phase == 0) { fail("invalid-state", "Start TLCP session before input", 10) }
        if (bytes.size > 65536 || input.size + bytes.size > 83973) { fail("budget-exceeded", "TLCP input budget exceeded", 22) }
        let application = ArrayList<Array<Byte>>()
        try {
            input = tlcpConcat(input, bytes)
            while (input.size >= 5 && !closed) {
                let length = tlcpDecodeUInt16(input, 3)
                if (length > 18432) { fail("budget-exceeded", "TLCP record too large", 22) }
                if (input.size < length + 5) { break }
                let encoded = input[..(length + 5)]; input = input[(length + 5)..]
                contextReason = if (sawCcs) { "bad-record-mac" } else { "invalid-message" }
                contextAlert = if (sawCcs) { Int64(20) } else { Int64(50) }
                let plain = if (sawCcs) { layer().open(encoded) } else {
                    let (kind, fragment) = tlcpDecodeRecord(encoded); TlcpPlainRecord(kind, fragment)
                }
                handleRecord(plain, application)
            }
            application.toArray()
        } catch (e: CryptoException) { fail(contextReason, e.message, contextAlert); [] }
          catch (e: TlcpProviderException) { close(); throw e }
    }
    func handleRecord(record: TlcpPlainRecord, application: ArrayList<Array<Byte>>): Unit {
        match (record.contentType) {
            case Handshake =>
                if (ready) { fail("unsupported-renegotiation", "TLCP renegotiation is disabled", 10) }
                handshakeInput = tlcpConcat(handshakeInput, record.fragment)
                if (handshakeInput.size > 262144) { fail("budget-exceeded", "TLCP handshake message too large", 50) }
                while (handshakeInput.size >= 4) {
                    let size = tlcpDecodeUInt24(handshakeInput, 1) + 4
                    if (size > 262144) { fail("budget-exceeded", "TLCP handshake message too large", 50) }
                    if (handshakeInput.size < size) { break }
                    let message = handshakeInput[..size]; handshakeInput = handshakeInput[size..]
                    handleHandshake(message)
                }
            case ChangeCipherSpec =>
                if (sawCcs || handshakeInput.size != 0 || !(phase == 6 || phase == 15) ||
                    record.fragment.size != 1 || record.fragment[0] != UInt8(1)) {
                    fail("invalid-state", "Unexpected TLCP ChangeCipherSpec", 10)
                }
                sawCcs = true
            case ApplicationData =>
                if (!ready) { fail("not-authenticated", "Application data before TLCP Finished", 10) }
                application.add(record.fragment.clone())
            case Alert =>
                if (record.fragment.size != 2) { fail("invalid-message", "Invalid TLCP alert", 50) }
                if (record.fragment[1] == UInt8(0) && ready && record.fragment[0] == UInt8(1)) {
                    sawClose = true; closeNotify()
                } else { fail("peer-alert", "TLCP peer alert ${record.fragment[1]}", Int64(record.fragment[1])) }
        }
    }
    func handleHandshake(message: Array<Byte>): Unit {
        contextReason = "invalid-message"; contextAlert = 50
        let kind = message[0]
        if (sawCcs) {
            if (!(phase == 6 || phase == 15) || kind != UInt8(20)) { fail("invalid-state", "Expected TLCP Finished", 10) }
            contextReason = "finished-verification-failed"; contextAlert = 51
            tlcpVerifyFinishedHandshake(message, schedule().masterSecret, transcript, role == TlcpRole.Server)
            remember(message)
            if (role == TlcpRole.Server) { sendFinished() }
            ready = true; phase = 20
            retireHandshakeKeys()
            return
        }
        if (role == TlcpRole.Client) { clientHandshake(kind, message) }
        else { serverHandshake(kind, message) }
    }
    func verifyPeer(message: Array<Byte>): Unit {
        contextReason = "certificate-verification-failed"; contextAlert = 42
        let bundle = tlcpParseDualCertificateHandshake(message)
        _ = tlcpVerifyDualCertificateBundle(bundle, trust)
        peerBundle = Some(bundle); peerMessage = message.clone()
    }
    func clientHandshake(kind: Byte, message: Array<Byte>): Unit {
        if (phase == 1 && kind == UInt8(2)) {
            let hello = tlcpDecodeServerHello(message)
            var offered = false
            for (s in policy.cipherSuites()) { if (s == hello.cipherSuite) { offered = true } }
            // A newly allocated server session id is valid in a full handshake.
            // It is not retained or offered for resumption by this engine.
            if (!offered) {
                fail("unsupported-negotiation", "Unexpected TLCP suite or extension", 47)
            }
            for (ext in hello.extensions) {
                if (ext.extType != 0xff01 || ext.data.size != 1 || ext.data[0] != UInt8(0) || secureRenegotiation) {
                    fail("unsupported-negotiation", "Unsupported or duplicate TLCP ServerHello extension", 47)
                }
                secureRenegotiation = true
            }
            suite = hello.cipherSuite; serverRandom = hello.random.clone(); phase = 2
        } else if (phase == 2 && kind == UInt8(11)) {
            verifyPeer(message); phase = 3
        } else if (phase == 3 && kind == UInt8(12)) {
            contextReason = "signature-verification-failed"; contextAlert = 51
            let peer = bundle()
            if (suite.usesEcdhe()) {
                peerEphemeral = Some(tlcpParseAndVerifyEcdheServerKeyExchange(message,
                    peer.signingCertificate, clientRandom, serverRandom))
            } else {
                tlcpVerifyEccServerKeyExchange(message, peer.signingCertificate,
                    peer.encryptionCertificate, clientRandom, serverRandom)
            }
            peerVerified = true; phase = 4
        } else if (phase == 4 && kind == UInt8(13)) {
            verifyCertificateRequest(message); requestedCertificate = true; phase = 5
        } else if ((phase == 4 || phase == 5) && kind == UInt8(14) && message.size == 4) {
            remember(message); sendClientFlight(); phase = 6; return
        } else { fail("invalid-state", "Unexpected TLCP server handshake message", 10) }
        remember(message)
    }
    func serverHandshake(kind: Byte, message: Array<Byte>): Unit {
        if (phase == 10 && kind == UInt8(1)) {
            let hello = tlcpDecodeClientHello(message)
            secureRenegotiation = hello.secureRenegotiation
            var sawRenegotiationExtension = false
            for (ext in hello.extensions) {
                if (ext.extType == 0xff01) {
                    if (sawRenegotiationExtension || ext.data.size != 1 || ext.data[0] != UInt8(0)) {
                        fail("unsupported-renegotiation", "Only an initial empty renegotiation_info is accepted", 40)
                    }
                    secureRenegotiation = true; sawRenegotiationExtension = true
                }
            }
            clientRandom = hello.random.clone(); serverRandom = randomSeed(size: 32)
            // A session id is never echoed: this provider always performs a full handshake.
            suite = tlcpSelectCipherSuite(hello.cipherSuites, policy.cipherSuites())
            remember(message); sendServerFlight(); phase = if (requestedCertificate) { Int64(11) } else { Int64(12) }; return
        } else if (phase == 11 && kind == UInt8(11)) {
            verifyPeer(message); phase = 12
        } else if (phase == 12 && kind == UInt8(16)) {
            if (suite.usesEcdhe()) {
                installSecrets(tlcpDeriveEcdheServerSecrets(own().encryptionKey(), ephemeralKey(),
                    x509ExtractSm2PublicKey(bundle().encryptionCertificate), tlcpParseEcdheClientKeyExchange(message),
                    clientRandom, serverRandom, suite))
            } else {
                let preMaster = tlcpProcessEccClientKeyExchange(own().encryptionKey(), message)
                try { installSecrets(tlcpDeriveSecretsFromPreMaster(preMaster, clientRandom, serverRandom, suite)) }
                finally { tlcpWipe(preMaster) }
            }
            phase = if (requestedCertificate) { Int64(13) } else { Int64(15) }
        } else if (phase == 13 && kind == UInt8(15)) {
            contextReason = "signature-verification-failed"; contextAlert = 51
            let body = tlcpDecodeHandshake(message, 15, "TLCP CertificateVerify")
            if (body.size < 2 || tlcpDecodeUInt16(body, 0) != body.size - 2) { fail("invalid-message", "Invalid CertificateVerify length", 50) }
            let (r, s) = tlcpDecodeSm2SignatureDer(body[2..])
            if (!sm2Verify(x509ExtractSm2PublicKey(bundle().signingCertificate),
                TLCP_DEFAULT_SM2_IDENTITY.toArray(), hash(HashAlgorithm.SM3, transcript), r, s)) {
                fail("signature-verification-failed", "TLCP client CertificateVerify failed", 51)
            }
            peerVerified = true; phase = 15
        } else { fail("invalid-state", "Unexpected TLCP client handshake message", 10) }
        remember(message)
    }
    func sendServerFlight(): Unit {
        let extensions: Array<TlsExtension> = if (secureRenegotiation) { [TlsExtension(0xff01, [UInt8(0)])] } else { [] }
        sendHandshake(tlcpEncodeServerHello(TlcpServerHello(serverRandom, suite, extensions: extensions)))
        sendHandshake(own().certificateHandshake())
        if (suite.usesEcdhe()) {
            ephemeral = sm2GeneratePrivateKey().scalar.toBytesBE(paddedLen: 32)
            sendHandshake(tlcpBuildEcdheServerKeyExchange(sm2PublicKey(ephemeralKey()), own().signingKey(), clientRandom, serverRandom))
        } else {
            let local = tlcpParseDualCertificateHandshake(own().certificateHandshake())
            sendHandshake(tlcpBuildEccServerKeyExchange(own().signingKey(), local.encryptionCertificate, clientRandom, serverRandom))
        }
        requestedCertificate = policy.requireClientCertificate || suite.usesEcdhe()
        if (requestedCertificate) { sendHandshake(tlcpEncodeHandshake(13, [UInt8(1), 64, 0, 0])) }
        sendHandshake(tlcpEncodeHandshake(14, []))
    }
    func verifyCertificateRequest(message: Array<Byte>): Unit {
        let body = tlcpDecodeHandshake(message, 13, "TLCP CertificateRequest")
        if (body.size < 4 || Int64(body[0]) + 3 > body.size) { fail("invalid-message", "Truncated CertificateRequest", 50) }
        let end = Int64(body[0]) + 1
        var supported = false
        for (kind in body[1..end]) { if (kind == UInt8(64)) { supported = true } }
        if (!supported || identity.isNone()) { fail("missing-identity", "No acceptable TLCP client identity", 40) }
        if (tlcpDecodeUInt16(body, end) != body.size - end - 2) { fail("invalid-message", "Invalid certificate authority vector", 50) }
        var offset = end + 2
        while (offset < body.size) {
            let length = tlcpDecodeUInt16(body, offset); offset += 2
            if (length == 0 || offset + length > body.size) { fail("invalid-message", "Invalid certificate authority name", 50) }
            offset += length
        }
    }
    func sendClientFlight(): Unit {
        if (suite.usesEcdhe() && !requestedCertificate) { fail("missing-identity", "TLCP ECDHE requires CertificateRequest", 40) }
        if (requestedCertificate) { sendHandshake(own().certificateHandshake()) }
        if (suite.usesEcdhe()) {
            ephemeral = sm2GeneratePrivateKey().scalar.toBytesBE(paddedLen: 32)
            sendHandshake(tlcpBuildEcdheClientKeyExchange(sm2PublicKey(ephemeralKey())))
            let peer = match (peerEphemeral) { case Some(value) => value; case None => throw TlcpProviderException("invalid-state", "Missing peer ephemeral key") }
            installSecrets(tlcpDeriveEcdheClientSecrets(own().encryptionKey(), ephemeralKey(),
                x509ExtractSm2PublicKey(bundle().encryptionCertificate), peer, clientRandom, serverRandom, suite))
        } else {
            let (message, preMaster) = tlcpBuildEccClientKeyExchange(x509ExtractSm2PublicKey(bundle().encryptionCertificate))
            try {
                sendHandshake(message)
                installSecrets(tlcpDeriveSecretsFromPreMaster(preMaster, clientRandom, serverRandom, suite))
            } finally { tlcpWipe(preMaster) }
        }
        if (requestedCertificate) {
            let (r, s) = sm2Sign(own().signingKey(), TLCP_DEFAULT_SM2_IDENTITY.toArray(), hash(HashAlgorithm.SM3, transcript))
            let signature = tlcpEncodeSm2SignatureDer(r, s)
            sendHandshake(tlcpEncodeHandshake(15, tlcpConcat(tlcpEncodeUInt16(signature.size), signature)))
        }
        sendFinished()
    }
    func installSecrets(value: TlcpHandshakeSecrets): Unit {
        secrets = Some(value); records = Some(TlcpRecordLayer(value, role == TlcpRole.Client))
    }
    func sendFinished(): Unit {
        queue(tlcpEncodeRecord(ChangeCipherSpec, [UInt8(1)])); writeProtected = true
        sendHandshake(tlcpBuildFinishedHandshake(schedule().masterSecret, transcript, role == TlcpRole.Client))
    }
    func own(): TlcpIdentity { match (identity) { case Some(value) => value; case None => throw TlcpProviderException("missing-identity", "Missing TLCP identity") } }
    func bundle(): TlcpCertificateBundle { match (peerBundle) { case Some(value) => value; case None => throw TlcpProviderException("invalid-state", "Missing TLCP peer certificate") } }
    func ephemeralKey(): Sm2PrivateKey { Sm2PrivateKey(BigNum.fromBytesBE(ephemeral)) }
    func schedule(): TlcpHandshakeSecrets { match (secrets) { case Some(value) => value; case None => throw TlcpProviderException("invalid-state", "Missing TLCP key schedule") } }
    func layer(): TlcpRecordLayer { match (records) { case Some(value) => value; case None => throw TlcpProviderException("invalid-state", "Missing TLCP record keys") } }
    func sealApplicationData(bytes: Array<Byte>): Array<Byte> {
        requireReady()
        if (output.size != 0) { throw TlcpProviderException("output-pending", "Drain TLCP handshake output before application data") }
        try { layer().seal(ApplicationData, bytes) }
        catch (e: CryptoException) { fail("record-failure", e.message, 80); [] }
    }
    func retireHandshakeKeys(): Unit {
        if (let Some(value) <- secrets) { value.destroy() }; secrets = None
        if (let Some(value) <- identity) { value.destroy() }
        tlcpWipe(ephemeral); ephemeral = []; transcript = []
    }
    func close(): Unit {
        closed = true; ready = false; retireHandshakeKeys()
        if (let Some(value) <- records) { value.destroy() }; records = None
        input = []; handshakeInput = []
    }
    func closeNotify(): Unit {
        if (closed) { return }
        try { if (ready) { queue(layer().seal(Alert, [UInt8(1), 0])) } }
        catch (e: CryptoException) { fail("record-failure", e.message, 80) }
        finally { close() }
    }
    func endOfInput(): Unit {
        if (!sawClose) { fail("truncated-stream", "Transport ended without authenticated close_notify", 50) }
    }
    func fail(reason: String, message: String, alert: Int64): Unit {
        output.clear(); outputBytes = 0
        if (!closed) {
            try {
                let bytes = [UInt8(2), UInt8(alert)]
                output.add(if (writeProtected && records.isSome()) { layer().seal(Alert, bytes) } else { tlcpEncodeRecord(Alert, bytes) })
            } catch (_: CryptoException) { output.clear() }
        }
        close()
        throw TlcpProviderException(reason, message, alertDescription: alert)
    }
}
