package jinguissl_core.dtls_tests

import std.unittest.*
import std.unittest.testmacro.*
import jinguissl_core.crypto.dtls.*
import jinguissl_core.crypto.error.CryptoException

// ============================================================================
// Explicit Nonce Ciphertext Boundary — regression tests
// ============================================================================
//
// Proves exact boundary acceptance/rejection for the DTLS 1.2 AES-GCM
// AEAD ciphertext layout:
//   explicit_nonce (8 bytes) || encrypted_plaintext || auth tag (16 bytes)
//
// Boundary invariants:
//   DTLS_MAX_PLAINTEXT_LEN            = 16384
//   DTLS_EXPLICIT_NONCE_LEN           = 8
//   DTLS_AEAD_TAG_LEN                 = 16
//   DTLS_MIN_AEAD_CIPHERTEXT_LEN      = 8 + 16 = 24  (zero-length plaintext)
//   DTLS_MAX_CIPHERTEXT_LEN           = 16384 + 8 + 16 = 16408
//
// Test matrix required by the DTLS protocol contract:
//   - boundary-maximum acceptance
//   - boundary-plus-one rejection
//   - explicit-nonce length mismatch
//   - AEAD tag length mismatch
//   - zero-length plaintext boundary
//   - no partial state mutation on rejection
// ============================================================================

private func mkKey(): Array<Byte> {
    let k = Array<Byte>(16, repeat: 0)
    for (i in 0..16) {
        k[i] = UInt8((i + 1) % 256)
    }
    k
}

private func mkIv(): Array<Byte> {
    let iv = Array<Byte>(4, repeat: 0)
    iv[0] = UInt8(0x11)
    iv[1] = UInt8(0x22)
    iv[2] = UInt8(0x33)
    iv[3] = UInt8(0x44)
    iv
}

private func mkPlaintext(n: Int64): Array<Byte> {
    let p = Array<Byte>(n, repeat: 0)
    var i = 0
    while (i < n) {
        p[i] = UInt8(i % 256)
        i += 1
    }
    p
}

private let DTLS_VER: UInt16 = UInt16(0xFEFD)

@Test
public class DtlsAeadBoundaryTestSuite {

    // Acceptance: boundary-maximum — plaintext at exactly
    // DTLS_MAX_PLAINTEXT_LEN (16384) encrypts to a blob of exactly
    // DTLS_MAX_CIPHERTEXT_LEN (16408) and decrypts back cleanly.
    @TestCase
    public func testBoundaryMaximum_Accepted(): Unit {
        let key = mkKey()
        let iv = mkIv()
        let pt = mkPlaintext(DTLS_MAX_PLAINTEXT_LEN)
        let blob = dtlsAeadEncrypt(key, iv, UInt16(0x0001),
            UInt48(UInt64(0x01)), DtlsContentType.ApplicationData, DTLS_VER, pt)
        @Assert(blob.size, DTLS_MAX_CIPHERTEXT_LEN)
        // Explicit nonce is the first 8 bytes.
        @Assert(blob.size, 16408)
        let recovered = dtlsAeadDecrypt(key, iv, UInt16(0x0001),
            UInt48(UInt64(0x01)), DtlsContentType.ApplicationData, DTLS_VER, blob)
        @Assert(recovered.size, DTLS_MAX_PLAINTEXT_LEN)
        // Spot-check first and last plaintext bytes.
        @Assert(recovered[0], UInt8(0))
        @Assert(recovered[DTLS_MAX_PLAINTEXT_LEN - 1], UInt8(255))
    }

    // Acceptance: boundary-plus-one — plaintext one byte over the max
    // (16385) is rejected before any allocation.
    @TestCase
    public func testBoundaryPlusOne_Plaintext_Rejected(): Unit {
        let key = mkKey()
        let iv = mkIv()
        let pt = mkPlaintext(DTLS_MAX_PLAINTEXT_LEN + 1)
        var threw = false
        try {
            _ = dtlsAeadEncrypt(key, iv, UInt16(0x0001),
                UInt48(UInt64(0x01)), DtlsContentType.ApplicationData,
                DTLS_VER, pt)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: ciphertext upper bound — a blob one byte over
    // DTLS_MAX_CIPHERTEXT_LEN (16409) is rejected on decrypt.
    @TestCase
    public func testCiphertextUpperBoundPlusOne_Rejected(): Unit {
        let key = mkKey()
        let iv = mkIv()
        // Build a blob of size 16409 by encrypting a max-size plaintext
        // and appending one extra byte.
        let pt = mkPlaintext(DTLS_MAX_PLAINTEXT_LEN)
        let blob = dtlsAeadEncrypt(key, iv, UInt16(0x0001),
            UInt48(UInt64(0x01)), DtlsContentType.ApplicationData, DTLS_VER, pt)
        let oversized = Array<Byte>(blob.size + 1, repeat: 0)
        for (i in 0..blob.size) {
            oversized[i] = blob[i]
        }
        oversized[blob.size] = UInt8(0x00)
        @Assert(oversized.size, DTLS_MAX_CIPHERTEXT_LEN + 1)
        var threw = false
        try {
            _ = dtlsAeadDecrypt(key, iv, UInt16(0x0001),
                UInt48(UInt64(0x01)), DtlsContentType.ApplicationData,
                DTLS_VER, oversized)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: ciphertext lower bound — a blob shorter than
    // DTLS_MIN_AEAD_CIPHERTEXT_LEN (24) is rejected. This covers both
    // explicit-nonce truncation (size < 8) and AEAD tag truncation
    // (8 <= size < 24).
    @TestCase
    public func testCiphertextLowerBound_TooShort_Rejected(): Unit {
        let key = mkKey()
        let iv = mkIv()
        // size = 7: explicit nonce field itself truncated.
        var threw1 = false
        try {
            _ = dtlsAeadDecrypt(key, iv, UInt16(0x0001),
                UInt48(UInt64(0x01)), DtlsContentType.ApplicationData,
                DTLS_VER, Array<Byte>(7, repeat: 0))
        } catch (e: CryptoException) {
            threw1 = true
        }
        @Assert(threw1, true)

        // size = 20: explicit nonce present (8) but tag field truncated
        // (only 12 bytes left, need 16).
        var threw2 = false
        try {
            _ = dtlsAeadDecrypt(key, iv, UInt16(0x0001),
                UInt48(UInt64(0x01)), DtlsContentType.ApplicationData,
                DTLS_VER, Array<Byte>(20, repeat: 0))
        } catch (e: CryptoException) {
            threw2 = true
        }
        @Assert(threw2, true)

        // size = 23: one byte short of the minimum (24).
        var threw3 = false
        try {
            _ = dtlsAeadDecrypt(key, iv, UInt16(0x0001),
                UInt48(UInt64(0x01)), DtlsContentType.ApplicationData,
                DTLS_VER, Array<Byte>(23, repeat: 0))
        } catch (e: CryptoException) {
            threw3 = true
        }
        @Assert(threw3, true)
    }

    // Acceptance: zero-length plaintext boundary — plaintext of size 0
    // produces a blob of exactly DTLS_MIN_AEAD_CIPHERTEXT_LEN (24) and
    // decrypts back to an empty plaintext.
    @TestCase
    public func testZeroLengthPlaintext_Accepted(): Unit {
        let key = mkKey()
        let iv = mkIv()
        let pt = Array<Byte>(0, repeat: 0)
        let blob = dtlsAeadEncrypt(key, iv, UInt16(0x0001),
            UInt48(UInt64(0x01)), DtlsContentType.Alert, DTLS_VER, pt)
        @Assert(blob.size, DTLS_MIN_AEAD_CIPHERTEXT_LEN)
        @Assert(blob.size, 24)
        let recovered = dtlsAeadDecrypt(key, iv, UInt16(0x0001),
            UInt48(UInt64(0x01)), DtlsContentType.Alert, DTLS_VER, blob)
        @Assert(recovered.size, 0)
    }

    // Acceptance: explicit-nonce length mismatch — a blob whose first
    // 8 bytes do not match epoch || seq_num is rejected. (The explicit
    // nonce is fixed-layout 8 bytes, so "length mismatch" manifests as
    // a content mismatch against the authenticated header.)
    @TestCase
    public func testExplicitNonceMismatch_Rejected(): Unit {
        let key = mkKey()
        let iv = mkIv()
        let pt = mkPlaintext(64)
        let blob = dtlsAeadEncrypt(key, iv, UInt16(0x0001),
            UInt48(UInt64(0x01)), DtlsContentType.ApplicationData, DTLS_VER, pt)
        // Flip the first explicit-nonce byte (epoch high byte).
        let tampered = Array<Byte>(blob.size, repeat: 0)
        for (i in 0..blob.size) {
            tampered[i] = blob[i]
        }
        tampered[0] = tampered[0] ^ UInt8(0xFF)
        var threw = false
        try {
            _ = dtlsAeadDecrypt(key, iv, UInt16(0x0001),
                UInt48(UInt64(0x01)), DtlsContentType.ApplicationData,
                DTLS_VER, tampered)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: AEAD tag length mismatch — a blob whose trailing 16
    // bytes are not a valid tag is rejected by AES-GCM verification.
    // (Tag length is fixed at 16 by the layout; a "length mismatch" is
    // realized as a content mismatch that fails GCM auth.)
    @TestCase
    public func testAeadTagMismatch_Rejected(): Unit {
        let key = mkKey()
        let iv = mkIv()
        let pt = mkPlaintext(64)
        let blob = dtlsAeadEncrypt(key, iv, UInt16(0x0001),
            UInt48(UInt64(0x01)), DtlsContentType.ApplicationData, DTLS_VER, pt)
        // Flip the last tag byte.
        let tampered = Array<Byte>(blob.size, repeat: 0)
        for (i in 0..blob.size) {
            tampered[i] = blob[i]
        }
        tampered[blob.size - 1] = tampered[blob.size - 1] ^ UInt8(0xFF)
        var threw = false
        try {
            _ = dtlsAeadDecrypt(key, iv, UInt16(0x0001),
                UInt48(UInt64(0x01)), DtlsContentType.ApplicationData,
                DTLS_VER, tampered)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: no partial state mutation on rejection — after a
    // rejected decrypt, a subsequent valid decrypt still succeeds and
    // returns the correct plaintext. The decrypt function is pure
    // (no shared mutable state), so this is a defensive check.
    @TestCase
    public func testNoPartialMutationOnRejection(): Unit {
        let key = mkKey()
        let iv = mkIv()
        let pt = mkPlaintext(128)
        let blob = dtlsAeadEncrypt(key, iv, UInt16(0x0002),
            UInt48(UInt64(0x05)), DtlsContentType.ApplicationData, DTLS_VER, pt)
        // First, a rejected call (oversized blob).
        let oversized = Array<Byte>(DTLS_MAX_CIPHERTEXT_LEN + 1, repeat: 0)
        var threw = false
        try {
            _ = dtlsAeadDecrypt(key, iv, UInt16(0x0002),
                UInt48(UInt64(0x05)), DtlsContentType.ApplicationData,
                DTLS_VER, oversized)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
        // Then a valid call on the same key/iv/epoch/seq still works.
        let recovered = dtlsAeadDecrypt(key, iv, UInt16(0x0002),
            UInt48(UInt64(0x05)), DtlsContentType.ApplicationData, DTLS_VER, blob)
        @Assert(recovered.size, 128)
        @Assert(recovered[0], UInt8(0))
        @Assert(recovered[127], UInt8(127))
    }

    // Acceptance: encrypt-then-decrypt round trip at a mid-range size
    // confirms the boundary checks did not break the happy path.
    @TestCase
    public func testRoundTrip_MidRange(): Unit {
        let key = mkKey()
        let iv = mkIv()
        let pt = mkPlaintext(1024)
        let blob = dtlsAeadEncrypt(key, iv, UInt16(0x0003),
            UInt48(UInt64(0x10)), DtlsContentType.Handshake, DTLS_VER, pt)
        @Assert(blob.size, 1024 + 8 + 16)
        let recovered = dtlsAeadDecrypt(key, iv, UInt16(0x0003),
            UInt48(UInt64(0x10)), DtlsContentType.Handshake, DTLS_VER, blob)
        @Assert(recovered.size, 1024)
        @Assert(recovered[0], UInt8(0))
        @Assert(recovered[1023], UInt8(255))
    }
}

@Test
public class DtlsAeadBoundaryConstantTestSuite {

    // Acceptance: the boundary constants are exactly the values
    // mandated by RFC 6347 §4.1.1 / §4.1.2.1. This pins the boundary
    // arithmetic so a future regression cannot silently relax it.
    @TestCase
    public func testBoundaryConstants_Exact(): Unit {
        @Assert(DTLS_MAX_PLAINTEXT_LEN, 16384)
        @Assert(DTLS_EXPLICIT_NONCE_LEN, 8)
        @Assert(DTLS_AEAD_TAG_LEN, 16)
        @Assert(DTLS_MIN_AEAD_CIPHERTEXT_LEN, 24)
        @Assert(DTLS_MAX_CIPHERTEXT_LEN, 16408)
        // Prove the boundary arithmetic is internally consistent.
        @Assert(DTLS_MAX_CIPHERTEXT_LEN,
            DTLS_MAX_PLAINTEXT_LEN + DTLS_EXPLICIT_NONCE_LEN + DTLS_AEAD_TAG_LEN)
        @Assert(DTLS_MIN_AEAD_CIPHERTEXT_LEN,
            DTLS_EXPLICIT_NONCE_LEN + DTLS_AEAD_TAG_LEN)
    }
}
