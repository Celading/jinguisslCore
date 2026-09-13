package jinguissl_core.dtls_tests

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.ArrayList
import jinguissl_core.crypto.dtls.*
import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}

// ============================================================================
// DTLS Malformed Packet Corpus + Retransmit Timer Proof
// ============================================================================
//
// Covers the DTLS acceptance requirements:
//   - malformed packet corpus tests covering record layer, handshake layer,
//     and DTLS-SRTP extension
//   - timeout and retransmit proof per RFC 6347 §4.2.4 (DTLS handshake
//     retransmission timer with exponential backoff)
//
// Every malformed-input test asserts a deterministic rejection so a future
// regression that silently accepts a malformed packet will turn the test
// red. The retransmit tests pin the exact RFC 6347 §4.2.4 backoff schedule.
// ============================================================================

private func mkBytes(n: Int64, fill: UInt8): Array<Byte> {
    Array<Byte>(n, repeat: fill)
}

private func mkByteList(items: Array<UInt8>): Array<Byte> {
    let out = Array<Byte>(items.size, repeat: 0)
    for (i in 0..items.size) { out[i] = items[i] }
    out
}

// ---------------------------------------------------------------------------
// Malformed corpus — DTLS record layer (RFC 6347 §4.1)
// ---------------------------------------------------------------------------

@Test
public class DtlsRecordLayerCorpusTestSuite {

    // Acceptance: a record header shorter than 13 bytes is rejected.
    @TestCase
    public func testDecodeRecordHeader_Truncated_Rejected(): Unit {
        let cases = [0, 1, 5, 10, 12]
        for (n in cases) {
            var threw = false
            try {
                _ = dtlsDecodeRecordHeader(mkBytes(Int64(n), 0x00))
            } catch (e: CryptoException) {
                threw = true
            }
            @Assert(threw, true)
        }
    }

    // Acceptance: an illegal content type byte is rejected.
    @TestCase
    public func testDecodeRecordHeader_IllegalContentType_Rejected(): Unit {
        // 13 bytes, content type = 0xFF (illegal)
        let bad = mkByteList([UInt8(0xFF), UInt8(0xFE), UInt8(0xFD),
            UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0),
            UInt8(0), UInt8(0), UInt8(0), UInt8(0)])
        var threw = false
        try {
            _ = dtlsDecodeRecordHeader(bad)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: a record whose declared length exceeds the buffer is
    // rejected (truncation guard).
    @TestCase
    public func testDecodeRecord_DeclaredLengthExceedsBuffer_Rejected(): Unit {
        // 13-byte header + 4-byte fragment, but header declares length=100.
        let buf = mkByteList([
            UInt8(0x16),  // Handshake
            UInt8(0xFE), UInt8(0xFD),  // DTLS 1.2
            UInt8(0), UInt8(0),  // epoch 0
            UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(1),  // seq 1
            UInt8(0), UInt8(100)  // length 100 (exceeds 4-byte body)
        ])
        // Append 4 bytes of fragment body.
        let full = Array<Byte>(buf.size + 4, repeat: 0)
        for (i in 0..buf.size) { full[i] = buf[i] }
        var threw = false
        try {
            _ = dtlsDecodeRecord(full)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: a well-formed record decodes cleanly (happy path pin).
    @TestCase
    public func testDecodeRecord_HappyPath(): Unit {
        let frag = mkBytes(8, 0x42)
        let rec = dtlsEncodeRecord(DtlsContentType.Handshake,
            UInt16(0xFEFD), UInt16(0), UInt48(UInt64(1)), frag)
        let (hdr, body) = dtlsDecodeRecord(rec)
        @Assert(hdr.contentType, DtlsContentType.Handshake)
        @Assert(hdr.length, UInt16(8))
        @Assert(body.size, 8)
        @Assert(body[0], UInt8(0x42))
    }
}

// ---------------------------------------------------------------------------
// Malformed corpus — DTLS handshake layer (RFC 6347 §4.2.2)
// ---------------------------------------------------------------------------

@Test
public class DtlsHandshakeLayerCorpusTestSuite {

    // Acceptance: a ClientHello shorter than version+random (34 bytes) is
    // rejected.
    @TestCase
    public func testDecodeClientHello_Truncated_Rejected(): Unit {
        let cases = [0, 2, 10, 33]
        for (n in cases) {
            var threw = false
            try {
                _ = DtlsClientHello.decode(mkBytes(Int64(n), 0x00))
            } catch (e: CryptoException) {
                threw = true
            }
            @Assert(threw, true)
        }
    }

    // Acceptance: a ClientHello with a sessionId length exceeding 32 is
    // rejected (RFC 5246 §7.4.1.2 cap).
    @TestCase
    public func testDecodeClientHello_SessionIdTooLong_Rejected(): Unit {
        // version(2) + random(32) + sessionIdLen=33
        let buf = Array<Byte>(2 + 32 + 1, repeat: 0)
        buf[0] = UInt8(0xFE)
        buf[1] = UInt8(0xFD)
        // random is all zero
        buf[34] = UInt8(33)  // sessionId length = 33 (exceeds max 32)
        var threw = false
        try {
            _ = DtlsClientHello.decode(buf)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: a ClientHello with an odd cipher_suites length is rejected
    // (each suite is 2 bytes).
    @TestCase
    public func testDecodeClientHello_OddCipherSuitesLen_Rejected(): Unit {
        // version(2) + random(32) + sessionIdLen=0 + cookieLen=0 +
        // cipherSuitesLen=3 (odd)
        let buf = Array<Byte>(2 + 32 + 1 + 1 + 2, repeat: 0)
        buf[0] = UInt8(0xFE)
        buf[1] = UInt8(0xFD)
        // sessionIdLen = 0 at offset 34
        // cookieLen = 0 at offset 35
        buf[36] = UInt8(0)  // cipherSuitesLen high byte
        buf[37] = UInt8(3)  // cipherSuitesLen low byte = 3 (odd)
        var threw = false
        try {
            _ = DtlsClientHello.decode(buf)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: a ClientHello whose cipher_suites body is truncated is
    // rejected.
    @TestCase
    public func testDecodeClientHello_CipherSuitesTruncated_Rejected(): Unit {
        // version(2) + random(32) + sessionIdLen=0 + cookieLen=0 +
        // cipherSuitesLen=4 but only 2 bytes of body
        let buf = Array<Byte>(2 + 32 + 1 + 1 + 2 + 2, repeat: 0)
        buf[0] = UInt8(0xFE)
        buf[1] = UInt8(0xFD)
        buf[36] = UInt8(0)
        buf[37] = UInt8(4)  // cipherSuitesLen = 4
        // only 2 bytes of cipher suite body follow
        var threw = false
        try {
            _ = DtlsClientHello.decode(buf)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }
}

// ---------------------------------------------------------------------------
// Malformed corpus — DTLS-SRTP extension (RFC 5764 §4.1)
// ---------------------------------------------------------------------------

@Test
public class DtlsSrtpExtensionCorpusTestSuite {

    // Acceptance: a use_srtp extension with an odd profile list length is
    // rejected (each profile is 2 bytes).
    @TestCase
    public func testDecodeClientHello_SrtpProfileListOddLen_Rejected(): Unit {
        // Build a minimal ClientHello with a use_srtp extension whose
        // profile list length is 3 (odd).
        // version(2) + random(32) + sessionIdLen=0 + cookieLen=0 +
        // cipherSuitesLen=2 + one cipher suite + compressionLen=1 + one
        // compression method + extensionsTotalLen + use_srtp ext
        let csLen = 2
        let compLen = 1
        let extBodyLen = 2 + 3 + 1  // profileListLen=3 (odd) + mkiLen=0
        let extTotalLen = 4 + extBodyLen  // ext type(2) + ext len(2) + body
        let totalLen = 2 + 32 + 1 + 1 + 2 + csLen + 1 + compLen + 2 + extTotalLen
        let buf = Array<Byte>(totalLen, repeat: 0)
        var pos = 0
        buf[pos] = UInt8(0xFE); buf[pos + 1] = UInt8(0xFD); pos += 2
        // random 32 bytes (zero)
        pos += 32
        buf[pos] = UInt8(0); pos += 1  // sessionIdLen
        buf[pos] = UInt8(0); pos += 1  // cookieLen
        buf[pos] = UInt8(0); buf[pos + 1] = UInt8(csLen); pos += 2
        buf[pos] = UInt8(0xC0); buf[pos + 1] = UInt8(0x2B); pos += 2
        buf[pos] = UInt8(compLen); pos += 1
        buf[pos] = UInt8(0); pos += 1  // null compression
        buf[pos] = UInt8(0); buf[pos + 1] = UInt8(extTotalLen); pos += 2
        // use_srtp extension
        buf[pos] = UInt8(0); buf[pos + 1] = UInt8(0x0E); pos += 2  // ext type
        buf[pos] = UInt8(0); buf[pos + 1] = UInt8(extBodyLen); pos += 2
        buf[pos] = UInt8(0); buf[pos + 1] = UInt8(3); pos += 2  // profileListLen=3 (odd)
        // 3 bytes of profile body
        buf[pos] = UInt8(0); buf[pos + 1] = UInt8(1); buf[pos + 2] = UInt8(2); pos += 3
        buf[pos] = UInt8(0); pos += 1  // mkiLen=0

        var threw = false
        try {
            _ = DtlsClientHello.decode(buf)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: a use_srtp extension truncated at the profile list length
    // field is rejected.
    @TestCase
    public func testDecodeClientHello_SrtpProfileListTruncated_Rejected(): Unit {
        // Build a ClientHello where the use_srtp extension declares more
        // profile bytes than the extension body contains.
        let csLen = 2
        let compLen = 1
        // ext body: profileListLen=4 (claims 4 bytes) + only 2 bytes present + mkiLen
        let extBodyLen = 2 + 2 + 1  // less than declared
        let extTotalLen = 4 + extBodyLen
        let totalLen = 2 + 32 + 1 + 1 + 2 + csLen + 1 + compLen + 2 + extTotalLen
        let buf = Array<Byte>(totalLen, repeat: 0)
        var pos = 0
        buf[pos] = UInt8(0xFE); buf[pos + 1] = UInt8(0xFD); pos += 2
        pos += 32
        buf[pos] = UInt8(0); pos += 1
        buf[pos] = UInt8(0); pos += 1
        buf[pos] = UInt8(0); buf[pos + 1] = UInt8(csLen); pos += 2
        buf[pos] = UInt8(0xC0); buf[pos + 1] = UInt8(0x2B); pos += 2
        buf[pos] = UInt8(compLen); pos += 1
        buf[pos] = UInt8(0); pos += 1
        buf[pos] = UInt8(0); buf[pos + 1] = UInt8(extTotalLen); pos += 2
        buf[pos] = UInt8(0); buf[pos + 1] = UInt8(0x0E); pos += 2
        buf[pos] = UInt8(0); buf[pos + 1] = UInt8(extBodyLen); pos += 2
        buf[pos] = UInt8(0); buf[pos + 1] = UInt8(4); pos += 2  // claims 4 bytes
        buf[pos] = UInt8(0); buf[pos + 1] = UInt8(1); pos += 2  // only 2 bytes
        buf[pos] = UInt8(0); pos += 1  // mkiLen

        var threw = false
        try {
            _ = DtlsClientHello.decode(buf)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: a use_srtp extension with a well-formed profile list
    // decodes cleanly (happy path pin).
    @TestCase
    public func testDecodeClientHello_SrtpHappyPath(): Unit {
        let csLen = 2
        let compLen = 1
        let extBodyLen = 2 + 2 + 1  // profileListLen=2 + one profile + mkiLen=0
        let extTotalLen = 4 + extBodyLen
        let totalLen = 2 + 32 + 1 + 1 + 2 + csLen + 1 + compLen + 2 + extTotalLen
        let buf = Array<Byte>(totalLen, repeat: 0)
        var pos = 0
        buf[pos] = UInt8(0xFE); buf[pos + 1] = UInt8(0xFD); pos += 2
        pos += 32
        buf[pos] = UInt8(0); pos += 1
        buf[pos] = UInt8(0); pos += 1
        buf[pos] = UInt8(0); buf[pos + 1] = UInt8(csLen); pos += 2
        buf[pos] = UInt8(0xC0); buf[pos + 1] = UInt8(0x2B); pos += 2
        buf[pos] = UInt8(compLen); pos += 1
        buf[pos] = UInt8(0); pos += 1
        buf[pos] = UInt8(0); buf[pos + 1] = UInt8(extTotalLen); pos += 2
        buf[pos] = UInt8(0); buf[pos + 1] = UInt8(0x0E); pos += 2
        buf[pos] = UInt8(0); buf[pos + 1] = UInt8(extBodyLen); pos += 2
        buf[pos] = UInt8(0); buf[pos + 1] = UInt8(2); pos += 2  // profileListLen=2
        buf[pos] = UInt8(0); buf[pos + 1] = UInt8(1); pos += 2  // SRTP_AES128_CM_HMAC_SHA1_80
        buf[pos] = UInt8(0); pos += 1  // mkiLen=0

        let ch = DtlsClientHello.decode(buf)
        @Assert(ch.srtpProfiles.size, 1)
        @Assert(ch.srtpProfiles[0], UInt16(0x0001))
    }
}

// ---------------------------------------------------------------------------
// RFC 6347 §4.2.4 Retransmission Timer — exponential backoff proof
// ---------------------------------------------------------------------------

@Test
public class DtlsFlightTimerBackoffTestSuite {

    // Acceptance: initial timer state matches RFC 6347 §4.2.4 defaults.
    @TestCase
    public func testInitial_State(): Unit {
        let t = DtlsFlightTimer()
        @Assert(t.initialTimeout, 1000)   // 1 second
        @Assert(t.maxTimeout, 60000)      // 60 seconds
        @Assert(t.currentTimeout, 1000)
        @Assert(t.retransmitCount, 0)
        @Assert(t.maxRetransmits, 15)
    }

    // Acceptance: exponential backoff doubles the timeout on each retransmit
    // up to the 60-second cap. This pins the exact RFC 6347 §4.2.4 schedule.
    @TestCase
    public func testBackoff_DoublesUntilCap(): Unit {
        let t = DtlsFlightTimer()
        // Retransmit 1: 1000 -> 2000
        var to = t.nextTimeout()
        @Assert(to, 2000)
        @Assert(t.retransmitCount, 1)
        // Retransmit 2: 2000 -> 4000
        to = t.nextTimeout()
        @Assert(to, 4000)
        // Retransmit 3: 4000 -> 8000
        to = t.nextTimeout()
        @Assert(to, 8000)
        // Retransmit 4: 8000 -> 16000
        to = t.nextTimeout()
        @Assert(to, 16000)
        // Retransmit 5: 16000 -> 32000
        to = t.nextTimeout()
        @Assert(to, 32000)
        // Retransmit 6: 32000 -> 60000 (capped)
        to = t.nextTimeout()
        @Assert(to, 60000)
        @Assert(t.currentTimeout, 60000)
        // Retransmit 7: stays at 60000 (cap)
        to = t.nextTimeout()
        @Assert(to, 60000)
    }

    // Acceptance: after maxRetransmits (15) retransmits, nextTimeout returns
    // -1 (give up). This proves the timer terminates a stuck handshake
    // rather than retransmitting forever.
    @TestCase
    public func testBackoff_GiveUp_AfterMaxRetransmits(): Unit {
        let t = DtlsFlightTimer()
        var lastTo = Int64(0)
        // Perform 15 successful retransmits.
        for (_ in 0..15) {
            lastTo = t.nextTimeout()
            @Assert(lastTo > Int64(0), true)
        }
        @Assert(t.retransmitCount, 15)
        // The 16th call MUST return -1 (give up).
        lastTo = t.nextTimeout()
        @Assert(lastTo, Int64(-1))
        @Assert(t.retransmitCount, 16)
    }

    // Acceptance: reset() restores the timer to initial state so a new
    // flight can start fresh.
    @TestCase
    public func testReset_RestoresInitialState(): Unit {
        let t = DtlsFlightTimer()
        _ = t.nextTimeout()
        _ = t.nextTimeout()
        _ = t.nextTimeout()
        @Assert(t.retransmitCount, 3)
        @Assert(t.currentTimeout, 8000)
        t.reset()
        @Assert(t.retransmitCount, 0)
        @Assert(t.currentTimeout, 1000)
        // After reset, the next retransmit resumes the backoff schedule.
        let to = t.nextTimeout()
        @Assert(to, 2000)
    }

    // Acceptance: the backoff schedule is deterministic — two timers with
    // the same initial state produce the identical sequence of timeouts.
    // This pins the reproducibility required for replayable proof.
    @TestCase
    public func testBackoff_DeterministicSchedule(): Unit {
        let t1 = DtlsFlightTimer()
        let t2 = DtlsFlightTimer()
        for (_ in 0..10) {
            @Assert(t1.nextTimeout(), t2.nextTimeout())
        }
        @Assert(t1.retransmitCount, t2.retransmitCount)
        @Assert(t1.currentTimeout, t2.currentTimeout)
    }
}
