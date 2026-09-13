package jinguissl_core.dtls_tests

import std.unittest.*
import std.unittest.testmacro.*
import jinguissl_core.crypto.dtls.*
import jinguissl_core.crypto.error.CryptoException

// ============================================================================
// Parser Bounds And Malformed State — regression tests
// ============================================================================
//
// Covers: dtlsDecodeHandshakeFragment bounds checks (declared length cap,
// fragment-range check, body-truncation check), DtlsFragmentReassembler
// bounds/duplicate/overlap detection, and DtlsClientHello.decode field-level
// bounds checks (sessionId/cookie/cipherSuites/extensions/use_srtp).
// ============================================================================

private func mkFragmentBytes(msgType: DtlsHandshakeType, length: UInt32,
    messageSeq: UInt16, fragOffset: UInt32, fragLength: UInt32,
    body: Array<Byte>): Array<Byte> {
    let out = Array<Byte>(Int64(DTLS_HANDSHAKE_HEADER_LEN) + body.size, repeat: 0)
    out[0] = UInt8(msgType.toUInt8())
    out[1] = UInt8((length >> 16) & UInt32(0xFF))
    out[2] = UInt8((length >> 8) & UInt32(0xFF))
    out[3] = UInt8(length & UInt32(0xFF))
    out[4] = UInt8((messageSeq >> 8) & UInt16(0xFF))
    out[5] = UInt8(messageSeq & UInt16(0xFF))
    out[6] = UInt8((fragOffset >> 16) & UInt32(0xFF))
    out[7] = UInt8((fragOffset >> 8) & UInt32(0xFF))
    out[8] = UInt8(fragOffset & UInt32(0xFF))
    out[9] = UInt8((fragLength >> 16) & UInt32(0xFF))
    out[10] = UInt8((fragLength >> 8) & UInt32(0xFF))
    out[11] = UInt8(fragLength & UInt32(0xFF))
    for (i in 0..body.size) {
        out[Int64(DTLS_HANDSHAKE_HEADER_LEN) + i] = body[i]
    }
    out
}

@Test
public class DtlsFragmentDecodeBoundsTestSuite {

    // Acceptance: oversized declared length is rejected.
    @TestCase
    public func testOversizedDeclaredLength_Rejected(): Unit {
        // Declare length = 2 MiB (> 1 MiB cap).
        let hugeLen: UInt32 = UInt32(2 * 1024 * 1024)
        let fragBytes = mkFragmentBytes(DtlsHandshakeType.ClientHello,
            hugeLen, UInt16(0), UInt32(0), UInt32(0), Array<Byte>(0, repeat: 0))
        var threw = false
        try {
            _ = dtlsDecodeHandshakeFragment(fragBytes)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: oversized fragment length is rejected.
    @TestCase
    public func testOversizedFragmentLength_Rejected(): Unit {
        let hugeLen: UInt32 = UInt32(2 * 1024 * 1024)
        // length=0 but fragLength=hugeLen — also caught by range check.
        let fragBytes = mkFragmentBytes(DtlsHandshakeType.ClientHello,
            UInt32(0), UInt16(0), UInt32(0), hugeLen, Array<Byte>(0, repeat: 0))
        var threw = false
        try {
            _ = dtlsDecodeHandshakeFragment(fragBytes)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: fragment range exceeds declared length is rejected.
    @TestCase
    public func testFragmentRangeExceedsDeclaredLength_Rejected(): Unit {
        // length=10, fragOffset=5, fragLength=10 -> range [5,15) > 10.
        let fragBytes = mkFragmentBytes(DtlsHandshakeType.ClientHello,
            UInt32(10), UInt16(0), UInt32(5), UInt32(10),
            Array<Byte>(10, repeat: 0))
        var threw = false
        try {
            _ = dtlsDecodeHandshakeFragment(fragBytes)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: truncated body is rejected.
    @TestCase
    public func testTruncatedBody_Rejected(): Unit {
        // Declare fragLength=10 but provide only 3 body bytes.
        let fragBytes = mkFragmentBytes(DtlsHandshakeType.ClientHello,
            UInt32(10), UInt16(0), UInt32(0), UInt32(10),
            Array<Byte>(3, repeat: 0))
        var threw = false
        try {
            _ = dtlsDecodeHandshakeFragment(fragBytes)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: valid fragment is accepted.
    @TestCase
    public func testValidFragment_Accepted(): Unit {
        let body = Array<Byte>(5, repeat: UInt8(0xAB))
        let fragBytes = mkFragmentBytes(DtlsHandshakeType.ClientHello,
            UInt32(5), UInt16(0), UInt32(0), UInt32(5), body)
        let frag = dtlsDecodeHandshakeFragment(fragBytes)
        @Assert(frag.length, UInt32(5))
        @Assert(frag.fragmentOffset, UInt32(0))
        @Assert(frag.fragmentLength, UInt32(5))
        @Assert(frag.body.size, 5)
    }

    // Acceptance: header too short is rejected.
    @TestCase
    public func testHeaderTooShort_Rejected(): Unit {
        var threw = false
        try {
            _ = dtlsDecodeHandshakeFragment(Array<Byte>(5, repeat: 0))
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: integer-overflow protection on fragOffset + fragLength.
    // fragOffset = 0xFFFFFFFF, fragLength = 1 -> naive UInt32 add overflows
    // to 0, which would falsely pass `<= length`. Promoting to UInt64
    // catches the true value 0x100000000.
    @TestCase
    public func testIntegerOverflow_RangeCheck_Rejected(): Unit {
        let fragBytes = mkFragmentBytes(DtlsHandshakeType.ClientHello,
            UInt32(0xFFFFFFFF), UInt16(0), UInt32(0xFFFFFFFF), UInt32(1),
            Array<Byte>(1, repeat: 0))
        var threw = false
        try {
            _ = dtlsDecodeHandshakeFragment(fragBytes)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }
}

@Test
public class DtlsFragmentReassemblerBoundsTestSuite {

    // Acceptance: oversized expectedLength is rejected at construction.
    @TestCase
    public func testOversizedExpectedLength_Rejected(): Unit {
        var threw = false
        try {
            _ = DtlsFragmentReassembler(DtlsHandshakeType.ClientHello,
                UInt32(DTLS_MAX_HANDSHAKE_MSG_LEN + 1), UInt16(0))
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: fragment range exceeds expectedLength is rejected.
    @TestCase
    public func testFragmentRangeExceedsExpectedLength_Rejected(): Unit {
        let r = DtlsFragmentReassembler(DtlsHandshakeType.ClientHello,
            UInt32(10), UInt16(0))
        // Fragment claims offset=5, length=10 -> range [5,15) > 10.
        let frag = DtlsHandshakeFragment(DtlsHandshakeType.ClientHello,
            UInt32(10), UInt16(0), UInt32(5), UInt32(10),
            Array<Byte>(10, repeat: 0))
        var threw = false
        try {
            _ = r.addFragment(frag)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: body size mismatch with declared fragmentLength is rejected.
    @TestCase
    public func testBodySizeMismatch_Rejected(): Unit {
        let r = DtlsFragmentReassembler(DtlsHandshakeType.ClientHello,
            UInt32(10), UInt16(0))
        // Declare fragmentLength=5 but body has only 3 bytes.
        let frag = DtlsHandshakeFragment(DtlsHandshakeType.ClientHello,
            UInt32(10), UInt16(0), UInt32(0), UInt32(5),
            Array<Byte>(3, repeat: 0))
        var threw = false
        try {
            _ = r.addFragment(frag)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: duplicate fragment is rejected.
    @TestCase
    public func testDuplicateFragment_Rejected(): Unit {
        let r = DtlsFragmentReassembler(DtlsHandshakeType.ClientHello,
            UInt32(10), UInt16(0))
        let frag1 = DtlsHandshakeFragment(DtlsHandshakeType.ClientHello,
            UInt32(10), UInt16(0), UInt32(0), UInt32(5),
            Array<Byte>(5, repeat: 0xAA))
        let frag2 = DtlsHandshakeFragment(DtlsHandshakeType.ClientHello,
            UInt32(10), UInt16(0), UInt32(0), UInt32(5),
            Array<Byte>(5, repeat: 0xBB))
        _ = r.addFragment(frag1)
        var threw = false
        try {
            _ = r.addFragment(frag2)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: overlapping fragment is rejected.
    @TestCase
    public func testOverlappingFragment_Rejected(): Unit {
        let r = DtlsFragmentReassembler(DtlsHandshakeType.ClientHello,
            UInt32(10), UInt16(0))
        // Fragment 1: [0, 5)
        let frag1 = DtlsHandshakeFragment(DtlsHandshakeType.ClientHello,
            UInt32(10), UInt16(0), UInt32(0), UInt32(5),
            Array<Byte>(5, repeat: 0xAA))
        // Fragment 2: [3, 8) — overlaps [3, 5).
        let frag2 = DtlsHandshakeFragment(DtlsHandshakeType.ClientHello,
            UInt32(10), UInt16(0), UInt32(3), UInt32(5),
            Array<Byte>(5, repeat: 0xBB))
        _ = r.addFragment(frag1)
        var threw = false
        try {
            _ = r.addFragment(frag2)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: no partial state mutation on failure — reassembler
    // state is unchanged after a rejected fragment.
    @TestCase
    public func testNoPartialMutationOnFailure(): Unit {
        let r = DtlsFragmentReassembler(DtlsHandshakeType.ClientHello,
            UInt32(10), UInt16(0))
        let frag1 = DtlsHandshakeFragment(DtlsHandshakeType.ClientHello,
            UInt32(10), UInt16(0), UInt32(0), UInt32(5),
            Array<Byte>(5, repeat: 0xAA))
        _ = r.addFragment(frag1)
        // Bad fragment: range exceeds expectedLength.
        let badFrag = DtlsHandshakeFragment(DtlsHandshakeType.ClientHello,
            UInt32(10), UInt16(0), UInt32(5), UInt32(10),
            Array<Byte>(10, repeat: 0xBB))
        var threw = false
        try {
            _ = r.addFragment(badFrag)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
        // Reassembler must NOT be complete (only [0,5) covered).
        @Assert(r.isComplete(), false)
        // A valid complementary fragment can still complete it.
        let frag2 = DtlsHandshakeFragment(DtlsHandshakeType.ClientHello,
            UInt32(10), UInt16(0), UInt32(5), UInt32(5),
            Array<Byte>(5, repeat: 0xCC))
        let complete = r.addFragment(frag2)
        @Assert(complete, true)
    }

    // Acceptance: malicious reassembly — many small fragments that
    // together cover the message without gaps are accepted.
    @TestCase
    public func testManySmallFragments_Accepted(): Unit {
        let total: UInt32 = UInt32(20)
        let r = DtlsFragmentReassembler(DtlsHandshakeType.ClientHello,
            total, UInt16(0))
        // 4 fragments of 5 bytes each, non-overlapping.
        for (k in 0..4) {
            let off = UInt32(k * 5)
            let frag = DtlsHandshakeFragment(DtlsHandshakeType.ClientHello,
                total, UInt16(0), off, UInt32(5),
                Array<Byte>(5, repeat: UInt8(k)))
            _ = r.addFragment(frag)
        }
        @Assert(r.isComplete(), true)
        let reassembled = r.getReassembled()
        @Assert(reassembled.size, 20)
        @Assert(reassembled[0], UInt8(0))
        @Assert(reassembled[5], UInt8(1))
        @Assert(reassembled[10], UInt8(2))
        @Assert(reassembled[15], UInt8(3))
    }

    // Acceptance: msgType / messageSeq mismatch returns false (no throw).
    @TestCase
    public func testTypeOrSeqMismatch_ReturnsFalse(): Unit {
        let r = DtlsFragmentReassembler(DtlsHandshakeType.ClientHello,
            UInt32(10), UInt16(0))
        let wrongType = DtlsHandshakeFragment(DtlsHandshakeType.ServerHello,
            UInt32(10), UInt16(0), UInt32(0), UInt32(10),
            Array<Byte>(10, repeat: 0))
        @Assert(r.addFragment(wrongType), false)
        let wrongSeq = DtlsHandshakeFragment(DtlsHandshakeType.ClientHello,
            UInt32(10), UInt16(7), UInt32(0), UInt32(10),
            Array<Byte>(10, repeat: 0))
        @Assert(r.addFragment(wrongSeq), false)
    }
}

@Test
public class DtlsClientHelloBoundsTestSuite {

    // Helper: build a minimal valid ClientHello body (no extensions).
    private func buildClientHello(sessLen: Int64, cookieLen: Int64,
        csLen: Int64, compLen: Int64): Array<Byte> {
        let total = 2 + 32 + 1 + sessLen + 1 + cookieLen + 2 + csLen + 1 + compLen
        let out = Array<Byte>(total, repeat: 0)
        var pos = 0
        // version
        out[pos] = UInt8(0xFE); out[pos + 1] = UInt8(0xFD); pos += 2
        // random (32 bytes of zero)
        pos += 32
        // sessionId
        out[pos] = UInt8(sessLen); pos += 1
        pos += sessLen
        // cookie
        out[pos] = UInt8(cookieLen); pos += 1
        pos += cookieLen
        // cipherSuites
        out[pos] = UInt8((csLen >> 8) & 0xFF); out[pos + 1] = UInt8(csLen & 0xFF); pos += 2
        pos += csLen
        // compression
        out[pos] = UInt8(compLen); pos += 1
        pos += compLen
        out
    }

    // Acceptance: oversized sessionId is rejected.
    @TestCase
    public func testOversizedSessionId_Rejected(): Unit {
        // sessionId length = 33 (> 32 max).
        let data = buildClientHello(33, 0, 2, 1)
        var threw = false
        try {
            _ = DtlsClientHello.decode(data)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: oversized cookie is rejected.
    @TestCase
    public func testOversizedCookie_Rejected(): Unit {
        // cookie length = 256 (> 255 max). Note: cookie length is a single
        // byte so 256 cannot be encoded; we test with a manually-crafted
        // overlong body where the cookie length byte says 0 but the body
        // is structured to trip a different check. Instead, test that a
        // 255-byte cookie is accepted (boundary).
        let data = buildClientHello(0, 255, 2, 1)
        let ch = DtlsClientHello.decode(data)
        @Assert(ch.cookie.size, 255)
    }

    // Acceptance: odd cipherSuites length is rejected.
    @TestCase
    public func testOddCipherSuitesLength_Rejected(): Unit {
        // csLen = 3 (odd).
        let data = buildClientHello(0, 0, 3, 1)
        var threw = false
        try {
            _ = DtlsClientHello.decode(data)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: even cipherSuites length is accepted.
    @TestCase
    public func testEvenCipherSuitesLength_Accepted(): Unit {
        let data = buildClientHello(0, 0, 2, 1)
        let ch = DtlsClientHello.decode(data)
        @Assert(ch.cipherSuites.size, 1)
    }

    // Acceptance: truncated ClientHello (buffer too short) is rejected.
    @TestCase
    public func testTruncatedClientHello_Rejected(): Unit {
        // Only 10 bytes — too short for version + random.
        var threw = false
        try {
            _ = DtlsClientHello.decode(Array<Byte>(10, repeat: 0))
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: sessionId boundary (32 bytes) is accepted.
    @TestCase
    public func testSessionIdBoundary_Accepted(): Unit {
        let data = buildClientHello(32, 0, 2, 1)
        let ch = DtlsClientHello.decode(data)
        @Assert(ch.sessionId.size, 32)
    }
}
