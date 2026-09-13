package jinguissl_core.crypto.dtls

import std.collection.{ArrayList, HashMap}
import std.sync.Mutex
import jinguissl_core.crypto.digest.sha256
import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.x509.{x509ParseDer, x509ExtractEcPublicKey}
import jinguissl_core.crypto.ecc.NamedCurve

/** Transport-independent, fingerprint-authenticated DTLS 1.2 association.
 * Supports X25519/ECDSA-P256/AES128-GCM-SHA256 with mandatory extended master
 * secret. The server requires client certificate proof; the client supplies it
 * when requested. No PSK, resumption, renegotiation or CID.
 * Caller owns UDP demultiplexing and a monotonic millisecond clock; call start,
 * receive, onTimeout and drain output. Fingerprints must come from trusted signaling.
 * Packet loss is tolerated by bounded flight retransmission. */
public class DtlsAssociation {
    private let mutex = Mutex()
    private let state: DtlsAssociationState
    public init(role: DtlsRole, identity: DtlsIdentity, expectedFingerprint: String,
        peerBinding: Array<Byte>, profiles!: Array<UInt16> = [UInt16(7), UInt16(1)]) {
        this.state = DtlsAssociationState(role, identity, expectedFingerprint, peerBinding, profiles)
    }
    public prop authenticated: Bool { get() { synchronized(mutex) { state.authenticated } } }
    public prop isClosed: Bool { get() { synchronized(mutex) { state.closed } } }
    public func start(nowMs: Int64): Unit { synchronized(mutex) { state.start(nowMs) } }
    public func receive(datagram: Array<Byte>, nowMs: Int64): Array<Array<Byte>> {
        synchronized(mutex) { state.receive(datagram, nowMs) }
    }
    public func takeOutput(): Array<Array<Byte>> { synchronized(mutex) { state.takeOutput() } }
    public func onTimeout(nowMs: Int64): Unit { synchronized(mutex) { state.onTimeout(nowMs) } }
    public func sealApplicationData(bytes: Array<Byte>): Array<Byte> {
        synchronized(mutex) { state.sealApplicationData(bytes) }
    }
    public func exportSrtp(): DtlsSrtpKeyingMaterial { synchronized(mutex) { state.exportSrtp() } }
    public func selectedSrtpProfile(): UInt16 { synchronized(mutex) { state.selectedSrtpProfile() } }
    public func peerCertificateDer(): Array<Byte> { synchronized(mutex) { state.peerCertificateDer() } }
    /** Queue an authenticated close_notify after pending output, then retire secrets.
     * takeOutput() remains drainable after closure; UDP delivery is not guaranteed. */
    public func closeNotify(): Unit { synchronized(mutex) { state.closeNotify() } }
    public func close(): Unit { synchronized(mutex) { state.close() } }
}

class DtlsFlightRecord {
    let kind: DtlsContentType
    let epoch: UInt16
    let bytes: Array<Byte>
    init(kind: DtlsContentType, epoch: UInt16, bytes: Array<Byte>) {
        this.kind = kind; this.epoch = epoch; this.bytes = bytes.clone()
    }
}

class DtlsAssociationState {
    let role: DtlsRole
    let identity: DtlsIdentity
    let context: DtlsHandshakeContext
    let binding: Array<Byte>
    let profiles: Array<UInt16>
    let cookieManager = DtlsCookieManager(32, 300000, 120000)
    let reassembly = HashMap<UInt16, DtlsFragmentReassembler>()
    let replay = DtlsReplayWindow(UInt16(1), 64)
    var output = ArrayList<Array<Byte>>()
    var flight = ArrayList<DtlsFlightRecord>()
    var earlyProtected = ArrayList<Array<Byte>>()
    var epochState: ?DtlsEpochState = None
    var sendPlain: UInt64 = 0
    var sendMessage: UInt16 = 0
    var receiveMessage: UInt16 = 0
    var phase: Int64 = 0
    var closed: Bool = false
    var established: Bool = false
    var started: Bool = false
    var seenCcs: Bool = false
    var requestedCertificate: Bool = false
    var selectedProfile: UInt16 = 0
    var peerKey: Array<Byte> = []
    var lastClock: Int64 = 0
    var lastFlightAt: Int64 = 0
    var deadline: Int64 = 0
    var timeout: Int64 = 1000
    var retries: Int64 = 0
    var cookieChallenges: Int64 = 0

    init(role: DtlsRole, identity: DtlsIdentity, expectedFingerprint: String,
        binding: Array<Byte>, profiles: Array<UInt16>) {
        dtlsRequire(binding.size > 0 && binding.size <= 64, "DTLS needs bounded peer endpoint binding")
        dtlsRequire(profiles.size > 0 && profiles.size <= 8, "DTLS needs bounded SRTP profile list")
        for (p in profiles) { dtlsRequire(DtlsSrtpProtectionProfile.fromCode(p).isSome(), "unknown SRTP profile") }
        this.role = role
        this.context = DtlsHandshakeContext(role)
        this.context.setExpectedFingerprint(expectedFingerprint)
        this.identity = identity.copyOwned()
        this.binding = binding.clone(); this.profiles = profiles.clone()
    }
    prop authenticated: Bool { get() { established && !closed } }
    func requireOpen(): Unit { dtlsRequire(!closed, "DTLS association is closed") }
    func clock(now: Int64): Unit {
        dtlsRequire(now >= lastClock && now <= Int64.Max - 120000, "invalid DTLS monotonic clock")
        lastClock = now
    }
    func start(now: Int64): Unit {
        requireOpen(); dtlsRequire(!started, "DTLS association already started"); clock(now)
        started = true
        if (role == DtlsRole.Client) {
            context.generateClientRandom()
            beginFlight()
            sendClientHello([])
            flushFlight(now)
            phase = 1
        }
    }
    func beginFlight(): Unit { flight.clear(); retries = 0; timeout = 1000 }
    func queueRecord(kind: DtlsContentType, epoch: UInt16, bytes: Array<Byte>): Unit {
        dtlsRequire(flight.size < 128, "DTLS flight record budget exceeded")
        flight.add(DtlsFlightRecord(kind, epoch, bytes))
    }
    func queueHandshake(kind: DtlsHandshakeType, body: Array<Byte>, protectedRecord: Bool, hash: Bool): Unit {
        dtlsRequire(body.size <= 65536 && sendMessage < UInt16.Max, "DTLS handshake budget exceeded")
        if (hash) { context.recordHandshakeMessage(kind, sendMessage, body) }
        var offset: Int64 = 0
        while (offset < body.size || (offset == 0 && body.size == 0)) {
            let size = min(1100, body.size - offset)
            let fragment = dtlsEncodeHandshakeFragment(DtlsHandshakeFragment(kind, UInt32(body.size),
                sendMessage, UInt32(offset), UInt32(size), body[offset..(offset + size)]))
            queueRecord(DtlsContentType.Handshake, if (protectedRecord) { UInt16(1) } else { UInt16(0) }, fragment)
            offset += size
            if (size == 0) { break }
        }
        sendMessage += 1
    }
    func encodeRecord(kind: DtlsContentType, epoch: UInt16, bytes: Array<Byte>): Array<Byte> {
        if (epoch == 0) {
            dtlsRequire(sendPlain <= UInt64(0xffffffffffff), "DTLS plaintext sequence exhausted")
            let seq = UInt48(sendPlain)
            sendPlain += 1
            dtlsEncodeRecord(kind, DTLS_VERSION_1_2, epoch, seq, bytes)
        } else {
            let keys = requireEpoch()
            let seq = keys.nextSendSequence()
            let payload = dtlsAeadEncrypt(keys.writeKey, keys.writeIv, epoch, seq, kind, DTLS_VERSION_1_2, bytes)
            dtlsEncodeRecord(kind, DTLS_VERSION_1_2, epoch, seq, payload)
        }
    }
    func flushFlight(now: Int64): Unit {
        dtlsRequire(output.size + flight.size <= 256, "drain DTLS output before more input")
        for (record in flight) { output.add(encodeRecord(record.kind, record.epoch, record.bytes)) }
        lastFlightAt = now; deadline = now + timeout
    }
    func takeOutput(): Array<Array<Byte>> {
        let result = output.toArray()
        output.clear()
        result
    }
    func onTimeout(now: Int64): Unit {
        requireOpen(); clock(now)
        if (flight.size == 0 || now < deadline) { return }
        retries += 1
        if (retries > 7) {
            if (established) { flight.clear(); return }
            close()
            dtlsRequire(false, "DTLS handshake retransmission budget exhausted")
        }
        timeout = min(timeout * 2, 60000)
        try { flushFlight(now) } catch (e: CryptoException) { close(); throw e }
    }
    func repeatFlight(now: Int64): Unit {
        if (flight.size > 0 && now >= lastFlightAt + 200 && retries < 7) {
            retries += 1
            flushFlight(now)
        }
    }
    func receive(datagram: Array<Byte>, now: Int64): Array<Array<Byte>> {
        requireOpen(); dtlsRequire(started, "start DTLS association first"); clock(now)
        // Unauthenticated UDP framing errors must not retire an established peer.
        if (datagram.size > 65535) { return [] }
        let records = ArrayList<Array<Byte>>()
        try {
            let r = DtlsReader(datagram)
            while (r.remaining > 0) {
                dtlsRequire(records.size < 64, "DTLS datagram record budget exceeded")
                let head = r.take(13)
                let header = dtlsDecodeRecordHeader(head)
                dtlsRequire(header.length <= 18432 && (header.epoch != 0 || header.length <= 16384),
                    "DTLS record exceeds protocol bound")
                records.add(dtlsJoin([head, r.take(Int64(header.length))]))
            }
        } catch (_: CryptoException) { return [] }
        let data = ArrayList<Array<Byte>>()
        try {
            for (record in records) {
                if (closed) { break }
                processRecord(record, now, data)
            }
            drainEarly(now, data)
            data.toArray()
        } catch (e: CryptoException) {
            close()
            throw e
        }
    }
    func processRecord(record: Array<Byte>, now: Int64, data: ArrayList<Array<Byte>>): Unit {
        let (header, payload) = dtlsDecodeRecord(record)
        if (header.epoch == 0 && established) { return }
        if (header.version != DTLS_VERSION_1_2 &&
            !(header.epoch == 0 && header.version == DTLS_VERSION_1_0)) { return }
        if (header.epoch > 1) { return }
        if (header.epoch == 1 && (epochState.isNone() || !seenCcs)) {
            if (!established && earlyProtected.size < 8 && record.size <= 16421) {
                earlyProtected.add(record.clone())
            }
            return
        }
        var plain = payload
        if (header.epoch == 1) {
            let keys = requireEpoch()
            try {
                plain = dtlsAeadDecrypt(keys.readKey, keys.readIv, header.epoch, header.sequenceNumber,
                    header.contentType, header.version, payload)
            } catch (_: CryptoException) { return } // DTLS silently discards invalid MACs.
            if (replay.contains(header.sequenceNumber)) { repeatFlight(now); return }
            try { replay.checkAndRecord(header.sequenceNumber) } catch (_: CryptoException) { return }
        } else if (established) { return }
        if (header.contentType == DtlsContentType.ChangeCipherSpec) {
            dtlsRequire(header.epoch == 0 && plain == [UInt8(1)], "invalid DTLS ChangeCipherSpec")
            seenCcs = true
        } else if (header.contentType == DtlsContentType.Handshake) {
            let r = DtlsReader(plain)
            while (r.remaining > 0) {
                let head = r.take(12)
                let size = (Int64(head[9]) << 16) | (Int64(head[10]) << 8) | Int64(head[11])
                let fragment = dtlsDecodeHandshakeFragment(dtlsJoin([head, r.take(size)]))
                dtlsRequire((fragment.msgType == DtlsHandshakeType.Finished) == (header.epoch == 1),
                    "DTLS handshake message at wrong protection epoch")
                acceptFragment(fragment, now)
            }
        } else if (header.contentType == DtlsContentType.ApplicationData) {
            dtlsRequire(authenticated && header.epoch == 1, "DTLS application data before authentication")
            data.add(plain.clone()); flight.clear()
        } else if (header.contentType == DtlsContentType.Alert) {
            if (header.epoch == 0 && epochState.isSome()) { return }
            dtlsRequire(plain.size == 2, "invalid DTLS alert")
            if (authenticated && header.epoch == 1 && plain == [UInt8(1), UInt8(0)]) { closeNotify() }
            else { close() }
        }
    }
    func drainEarly(now: Int64, data: ArrayList<Array<Byte>>): Unit {
        if (epochState.isNone() || !seenCcs || closed) { return }
        let pending = earlyProtected.toArray()
        earlyProtected.clear()
        for (record in pending) { if (!closed) { processRecord(record, now, data) } }
    }
    func acceptFragment(fragment: DtlsHandshakeFragment, now: Int64): Unit {
        if (role == DtlsRole.Server && phase == 0 && receiveMessage == 0 && fragment.msgType == DtlsHandshakeType.ClientHello &&
            fragment.messageSeq <= 1 && reassembly.size == 0) { receiveMessage = fragment.messageSeq }
        if (fragment.messageSeq < receiveMessage) { repeatFlight(now); return }
        dtlsRequire(Int64(fragment.messageSeq) - Int64(receiveMessage) <= 8 &&
            fragment.length <= 65536, "DTLS reassembly window exceeded")
        let assembler = match (reassembly.get(fragment.messageSeq)) {
            case Some(value) => value
            case None =>
                // The five-message server flight must fit even in reverse order.
                // Eight buffered messages plus the expected message, each <=64 KiB.
                dtlsRequire(reassembly.size < 9, "DTLS reassembly allocation budget exceeded")
                let value = DtlsFragmentReassembler(fragment.msgType, fragment.length, fragment.messageSeq)
                reassembly[fragment.messageSeq] = value
                value
        }
        dtlsRequire(assembler.expectedType == fragment.msgType && assembler.expectedLength == fragment.length,
            "DTLS fragment identity mismatch")
        _ = assembler.addFragment(fragment)
        while (true) {
            let next = match (reassembly.get(receiveMessage)) {
                case Some(value) => value
                case None => break
            }
            if (!next.isComplete()) { break }
            _ = reassembly.remove(receiveMessage)
            let seq = receiveMessage
            dtlsRequire(receiveMessage < UInt16.Max, "DTLS handshake sequence exhausted")
            receiveMessage += 1
            handshakeMessage(next.expectedType, seq, next.getReassembled(), now)
        }
    }
    func sendClientHello(cookie: Array<Byte>): Unit {
        let hello = DtlsClientHello(DTLS_VERSION_1_2, DtlsRandom.decode(context.clientRandom), [], cookie,
            [UInt16(0xc02b)], [UInt8(0)], profiles, extensions: [
                DtlsExtension(UInt16(10), [UInt8(0), UInt8(4), UInt8(0), UInt8(29), UInt8(0), UInt8(23)]),
                DtlsExtension(UInt16(13), [UInt8(0), UInt8(2), UInt8(4), UInt8(3)]),
                DtlsExtension(UInt16(11), [UInt8(1), UInt8(0)]),
                DtlsExtension(UInt16(23), []), DtlsExtension(UInt16(0xff01), [UInt8(0)])])
        queueHandshake(DtlsHandshakeType.ClientHello, hello.encode(), false, true)
    }
    func handshakeMessage(kind: DtlsHandshakeType, seq: UInt16, body: Array<Byte>, now: Int64): Unit {
        dtlsRequire(!closed, "DTLS handshake after close")
        if (role == DtlsRole.Client) { clientMessage(kind, seq, body, now) }
        else { serverMessage(kind, seq, body, now) }
    }
    func append(kind: DtlsHandshakeType, seq: UInt16, body: Array<Byte>): Unit {
        dtlsRequire(context.transcriptMessages.size + body.size + 12 <= 262144, "DTLS transcript budget exceeded")
        context.recordHandshakeMessage(kind, seq, body)
    }
    func certificateBody(): Array<Byte> {
        let der = identity.certificateDer()
        let list = dtlsJoin([dtlsU24(der.size), der])
        dtlsJoin([dtlsU24(list.size), list])
    }
    func peerCertificate(body: Array<Byte>): Unit {
        let r = DtlsReader(body)
        let list = DtlsReader(r.take(r.u24())); r.end()
        dtlsRequire(list.remaining > 0, "DTLS requires a peer certificate")
        let der = list.take(list.u24())
        var count: Int64 = 1
        while (list.remaining > 0) { _ = list.take(list.u24()); count += 1 }
        dtlsRequire(count <= 8, "DTLS certificate chain exceeds budget")
        dtlsRequire(x509ExtractEcPublicKey(x509ParseDer(der)).curve == NamedCurve.P256,
            "DTLS peer identity must use P-256")
        context.setPeerCertificate(der)
        context.verifyPeerCertificateFingerprint()
    }
    func signature(body: Array<Byte>): Array<Byte> {
        let r = DtlsReader(body)
        dtlsRequire(r.u16() == 0x0403, "DTLS requires ECDSA SHA-256 signature")
        let sig = r.take(r.u16()); r.end(); sig
    }
    func signedBody(digest: Array<Byte>): Array<Byte> {
        let sig = identity.sign(digest)
        dtlsJoin([[UInt8(4), UInt8(3)], dtlsU16(sig.size), sig])
    }
    func deriveKeys(): Unit {
        context.processPeerKeyExchange(peerKey, sessionHash: context.computeTranscriptHash())
        let kb = match (context.keyBlock) { case Some(value) => value; case None => throwMissingKeys() }
        epochState = if (role == DtlsRole.Client) {
            Some(DtlsEpochState(UInt16(1), kb.clientWriteKey, kb.clientWriteIv, kb.serverWriteKey, kb.serverWriteIv))
        } else { Some(DtlsEpochState(UInt16(1), kb.serverWriteKey, kb.serverWriteIv, kb.clientWriteKey, kb.clientWriteIv)) }
    }
    func requireEpoch(): DtlsEpochState {
        match (epochState) {
            case Some(value) => value
            case None => dtlsRequire(false, "DTLS traffic keys unavailable"); DtlsEpochState(UInt16(1), [], [], [], [])
        }
    }
    func throwMissingKeys(): DtlsKeyBlock {
        dtlsRequire(false, "DTLS key block unavailable"); DtlsKeyBlock([], [], [], [])
    }
    func clientMessage(kind: DtlsHandshakeType, seq: UInt16, body: Array<Byte>, now: Int64): Unit {
        if (phase == 1 && kind == DtlsHandshakeType.HelloVerifyRequest) {
            cookieChallenges += 1; dtlsRequire(cookieChallenges <= 3, "too many DTLS cookie challenges")
            let challenge = DtlsHelloVerifyRequest.decode(body)
            dtlsRequire(challenge.cookie.size > 0 && (challenge.version == DTLS_VERSION_1_0 ||
                challenge.version == DTLS_VERSION_1_2), "invalid DTLS cookie challenge")
            context.transcriptMessages.clear(); beginFlight()
            sendClientHello(challenge.cookie); flushFlight(now); return
        }
        if (phase == 1 && kind == DtlsHandshakeType.ServerHello) {
            let hello = DtlsServerHello.decode(body)
            dtlsRequire(hello.version == DTLS_VERSION_1_2 && hello.cipherSuite == 0xc02b &&
                hello.compressionMethod == 0 && hello.sessionId.size <= 32, "unsupported DTLS server selection")
            selectedProfile = match (hello.srtpProfile) { case Some(p) => p; case None => UInt16(0) }
            dtlsRequire(profiles.contains(selectedProfile), "DTLS server selected unoffered SRTP profile")
            var ems = false
            for (ext in hello.extensions) {
                if (ext.kind == 23) { dtlsRequire(ext.data.size == 0, "invalid EMS extension"); ems = true }
                else if (ext.kind == 11) { dtlsRequire(ext.data == [UInt8(1), UInt8(0)], "unsupported EC point format") }
                else if (ext.kind == 0xff01) { dtlsRequire(ext.data == [UInt8(0)], "renegotiation is unsupported") }
                else { dtlsRequire(false, "unsolicited DTLS server extension") }
            }
            dtlsRequire(ems, "DTLS extended master secret is required")
            context.serverRandom = hello.random.encode(); flight.clear(); phase = 2
        } else if (phase == 2 && kind == DtlsHandshakeType.Certificate) {
            peerCertificate(body); phase = 3
        } else if (phase == 3 && kind == DtlsHandshakeType.ServerKeyExchange) {
            dtlsRequire(body.size >= 40 && body[0] == 3 && body[1] == 0 && body[2] == 29 && body[3] == 32,
                "DTLS requires X25519 ServerKeyExchange")
            peerKey = body[4..36].clone()
            let (r, s) = dtlsReadSignature(signature(body[36..]))
            context.verifyServerKeyExchangeSignature(body[..36], r, s); phase = 4
        } else if (phase == 4 && kind == DtlsHandshakeType.CertificateRequest) {
            dtlsRequire(!requestedCertificate, "duplicate DTLS CertificateRequest")
            let r = DtlsReader(body)
            let types = r.take(r.u8()); let schemes = DtlsReader(r.take(r.u16()))
            var supported = false
            while (schemes.remaining > 0) { if (schemes.u16() == 0x0403) { supported = true } }
            _ = r.take(r.u16()); r.end()
            dtlsRequire(types.contains(UInt8(64)) && supported, "DTLS peer does not accept ECDSA identity")
            requestedCertificate = true
        } else if (phase == 4 && kind == DtlsHandshakeType.ServerHelloDone) {
            dtlsRequire(body.size == 0, "invalid ServerHelloDone")
            append(kind, seq, body); beginFlight()
            if (requestedCertificate) { queueHandshake(DtlsHandshakeType.Certificate, certificateBody(), false, true) }
            queueHandshake(DtlsHandshakeType.ClientKeyExchange,
                dtlsBuildClientKeyExchangeEcdhe(context.keyExchange.publicKey), false, true)
            deriveKeys()
            if (requestedCertificate) {
                queueHandshake(DtlsHandshakeType.CertificateVerify, signedBody(context.computeTranscriptHash()), false, true)
            }
            queueRecord(DtlsContentType.ChangeCipherSpec, UInt16(0), [UInt8(1)])
            queueHandshake(DtlsHandshakeType.Finished, context.computeFinishedVerifyData("client finished"), true, true)
            context.state = DtlsConnectionState.FinishedSent
            phase = 5; flushFlight(now); return
        } else if (phase == 5 && kind == DtlsHandshakeType.Finished) {
            context.verifyPeerFinished(body, "server finished")
            context.finalizeHandshake(); established = true; phase = 6; flight.clear()
        } else { dtlsRequire(false, "unexpected DTLS server handshake message") }
        append(kind, seq, body)
    }
    func serverMessage(kind: DtlsHandshakeType, seq: UInt16, body: Array<Byte>, now: Int64): Unit {
        if (phase == 0 && kind == DtlsHandshakeType.ClientHello) {
            let hello = DtlsClientHello.decode(body)
            dtlsRequire(hello.version == DTLS_VERSION_1_2 && hello.cipherSuites.contains(UInt16(0xc02b)) &&
                hello.compressionMethods.contains(UInt8(0)), "unsupported DTLS ClientHello")
            let random = hello.random.encode()
            if (!cookieManager.verifyCookie(hello.cookie, binding, UInt16(0), hello.version, random,
                hello.cipherSuites, hello.srtpProfiles, now)) {
                let cookie = cookieManager.generateCookie(binding, UInt16(0), hello.version, random,
                    hello.cipherSuites, hello.srtpProfiles, now)
                beginFlight()
                queueHandshake(DtlsHandshakeType.HelloVerifyRequest,
                    DtlsHelloVerifyRequest(DTLS_VERSION_1_0, cookie).encode(), false, false)
                flushFlight(now); return
            }
            var ems = false; var group = false; var signature = false
            var secureRenegotiation = hello.cipherSuites.contains(UInt16(0xff))
            for (ext in hello.extensions) {
                if (ext.kind == 23) { dtlsRequire(ext.data.size == 0, "invalid EMS extension"); ems = true }
                if (ext.kind == 0xff01) {
                    dtlsRequire(ext.data == [UInt8(0)], "DTLS renegotiation is unsupported")
                    secureRenegotiation = true
                }
                if (ext.kind == 10 || ext.kind == 13) {
                    let r = DtlsReader(ext.data); let list = DtlsReader(r.take(r.u16())); r.end()
                    while (list.remaining > 0) {
                        let value = list.u16()
                        if (ext.kind == 10 && value == 29) { group = true }
                        if (ext.kind == 13 && value == 0x0403) { signature = true }
                    }
                }
            }
            dtlsRequire(ems && group && signature, "DTLS requires EMS, X25519 and ECDSA SHA-256")
            for (p in profiles) { if (hello.srtpProfiles.contains(p)) { selectedProfile = p; break } }
            dtlsRequire(selectedProfile != 0, "no shared DTLS SRTP protection profile")
            context.clientRandom = random; context.generateServerRandom(); append(kind, seq, body)
            beginFlight()
            let extensions = ArrayList<DtlsExtension>()
            extensions.add(DtlsExtension(UInt16(23), []))
            if (secureRenegotiation) { extensions.add(DtlsExtension(UInt16(0xff01), [UInt8(0)])) }
            let sh = DtlsServerHello(DTLS_VERSION_1_2, DtlsRandom.decode(context.serverRandom), [],
                UInt16(0xc02b), UInt8(0), selectedProfile, extensions: extensions.toArray())
            queueHandshake(DtlsHandshakeType.ServerHello, sh.encode(), false, true)
            queueHandshake(DtlsHandshakeType.Certificate, certificateBody(), false, true)
            let params = dtlsBuildServerKeyExchangeEcdhe(context.keyExchange.publicKey)
            queueHandshake(DtlsHandshakeType.ServerKeyExchange, dtlsJoin([params,
                signedBody(sha256(dtlsJoin([context.clientRandom, context.serverRandom, params])))]), false, true)
            queueHandshake(DtlsHandshakeType.CertificateRequest,
                [UInt8(1), UInt8(64), UInt8(0), UInt8(2), UInt8(4), UInt8(3), UInt8(0), UInt8(0)], false, true)
            queueHandshake(DtlsHandshakeType.ServerHelloDone, [], false, true)
            phase = 1; flushFlight(now); return
        }
        if (phase == 1 && kind == DtlsHandshakeType.Certificate) {
            peerCertificate(body); flight.clear(); phase = 2
        } else if (phase == 2 && kind == DtlsHandshakeType.ClientKeyExchange) {
            dtlsRequire(body.size == 33 && body[0] == 32, "invalid X25519 ClientKeyExchange")
            peerKey = body[1..].clone(); append(kind, seq, body); deriveKeys(); phase = 3; return
        } else if (phase == 3 && kind == DtlsHandshakeType.CertificateVerify) {
            let (r, s) = dtlsReadSignature(signature(body))
            context.verifyClientCertificateSignature(r, s); phase = 4
        } else if (phase == 4 && kind == DtlsHandshakeType.Finished) {
            context.verifyPeerFinished(body, "client finished"); append(kind, seq, body)
            beginFlight(); queueRecord(DtlsContentType.ChangeCipherSpec, UInt16(0), [UInt8(1)])
            queueHandshake(DtlsHandshakeType.Finished, context.computeFinishedVerifyData("server finished"), true, true)
            context.state = DtlsConnectionState.FinishedSent
            context.finalizeHandshake(); established = true; phase = 5; flushFlight(now); return
        } else { dtlsRequire(false, "unexpected DTLS client handshake message") }
        append(kind, seq, body)
    }
    func sealApplicationData(bytes: Array<Byte>): Array<Byte> {
        requireOpen(); dtlsRequire(authenticated && output.size == 0, "authenticate and drain DTLS handshake first")
        dtlsRequire(bytes.size <= 16384, "DTLS application message exceeds 16 KiB")
        try { encodeRecord(DtlsContentType.ApplicationData, UInt16(1), bytes) }
        catch (e: CryptoException) { close(); throw e }
    }
    func exportSrtp(): DtlsSrtpKeyingMaterial {
        requireOpen(); dtlsRequire(authenticated, "DTLS authentication is incomplete")
        let profile = match (DtlsSrtpProtectionProfile.fromCode(selectedProfile)) {
            case Some(value) => value
            case None => dtlsRequire(false, "unknown negotiated SRTP profile"); DtlsSrtpProtectionProfile.AeadAes128Gcm
        }
        let km = context.extractSrtpKeyingMaterial(profile)
        DtlsSrtpKeyingMaterial(km.clientWriteKey.clone(), km.serverWriteKey.clone(),
            km.clientWriteSalt.clone(), km.serverWriteSalt.clone(), km.profile)
    }
    func selectedSrtpProfile(): UInt16 { dtlsRequire(authenticated, "DTLS authentication is incomplete"); selectedProfile }
    func peerCertificateDer(): Array<Byte> {
        dtlsRequire(authenticated, "DTLS authentication is incomplete")
        match (context.peerCertDer) { case Some(value) => value.clone(); case None => Array<Byte>() }
    }
    func closeNotify(): Unit {
        requireOpen(); dtlsRequire(authenticated, "authenticate DTLS before close_notify")
        try {
            let alert = encodeRecord(DtlsContentType.Alert, UInt16(1), [UInt8(1), UInt8(0)])
            let pending = output.toArray()
            close()
            for (record in pending) { output.add(record) }
            output.add(alert)
        } catch (e: CryptoException) { close(); throw e }
    }
    func close(): Unit {
        if (closed) { return }
        closed = true; established = false
        context.recordFatalAlert(DtlsAlertDescription.UserCanceled, "association retired")
        context.state = DtlsConnectionState.Closed
        epochState = None; identity.destroy(); reassembly.clear(); flight.clear(); earlyProtected.clear(); output.clear()
    }
}
