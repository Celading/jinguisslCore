package jinguissl_core.dtls_tests

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.ArrayList
import jinguissl_core.crypto.dtls.*
import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}

// ============================================================================
// DTLS RFC 6347 / RFC 5764 Negative Vectors — regression tests
// ============================================================================
//
// Covers the DTLS acceptance requirement:
//   - RFC 6347 aligned negative vectors covering all defined alert types
//     and failure paths
//   - RFC 5764 aligned DTLS-SRTP negative vectors covering SRTP master key
//     derivation, SRTP protection profile negotiation, and key extraction
//
// Every test asserts a deterministic failure (throw or rejection) so the
// negative surface is pinned: a future regression that silently accepts a
// malformed alert or an invalid SRTP profile will turn the test red.
// ============================================================================

private func mkBytes(n: Int64, fill: UInt8): Array<Byte> {
    Array<Byte>(n, repeat: fill)
}

// ---------------------------------------------------------------------------
// RFC 6347 §7.2 Alert Protocol — negative vectors
// ---------------------------------------------------------------------------

@Test
public class DtlsAlertLevelNegativeTestSuite {

    // Acceptance: every defined alert level round-trips through toUInt8 /
    // fromUInt8. Pins the wire values so a future regression cannot silently
    // renumber them.
    @TestCase
    public func testLevel_RoundTrip(): Unit {
        @Assert(DtlsAlertLevel.Warning.toUInt8(), UInt8(1))
        @Assert(DtlsAlertLevel.Fatal.toUInt8(), UInt8(2))
        @Assert(DtlsAlertLevel.fromUInt8(UInt8(1)), DtlsAlertLevel.Warning)
        @Assert(DtlsAlertLevel.fromUInt8(UInt8(2)), DtlsAlertLevel.Fatal)
    }

    // Acceptance: illegal alert level bytes are rejected.
    @TestCase
    public func testLevel_IllegalBytes_Rejected(): Unit {
        let bads = [UInt8(0), UInt8(3), UInt8(5), UInt8(128), UInt8(255)]
        for (b in bads) {
            var threw = false
            try {
                _ = DtlsAlertLevel.fromUInt8(b)
            } catch (e: CryptoException) {
                threw = true
            }
            @Assert(threw, true)
        }
    }
}

@Test
public class DtlsAlertDescriptionNegativeTestSuite {

    // Acceptance: every defined alert description round-trips through the
    // exact RFC 5246 §7.2.2 wire value. This is the negative-vector pin: a
    // future regression that renumbers an alert description will break the
    // round-trip and turn the test red.
    @TestCase
    public func testDescription_RoundTrip_AllDefined(): Unit {
        let cases = [
            (DtlsAlertDescription.CloseNotify, UInt8(0)),
            (DtlsAlertDescription.UnexpectedMessage, UInt8(10)),
            (DtlsAlertDescription.BadRecordMac, UInt8(20)),
            (DtlsAlertDescription.HandshakeFailure, UInt8(40)),
            (DtlsAlertDescription.BadCertificate, UInt8(42)),
            (DtlsAlertDescription.UnsupportedCertificate, UInt8(43)),
            (DtlsAlertDescription.CertificateRevoked, UInt8(44)),
            (DtlsAlertDescription.CertificateExpired, UInt8(45)),
            (DtlsAlertDescription.CertificateUnknown, UInt8(46)),
            (DtlsAlertDescription.IllegalParameter, UInt8(47)),
            (DtlsAlertDescription.UnknownCa, UInt8(48)),
            (DtlsAlertDescription.AccessDenied, UInt8(49)),
            (DtlsAlertDescription.DecodeError, UInt8(50)),
            (DtlsAlertDescription.DecryptError, UInt8(51)),
            (DtlsAlertDescription.ProtocolVersion, UInt8(70)),
            (DtlsAlertDescription.InsufficientSecurity, UInt8(71)),
            (DtlsAlertDescription.InternalError, UInt8(80)),
            (DtlsAlertDescription.UserCanceled, UInt8(90)),
            (DtlsAlertDescription.NoRenegotiation, UInt8(100)),
            (DtlsAlertDescription.UnsupportedExtension, UInt8(110))
        ]
        for ((desc, wire) in cases) {
            @Assert(desc.toUInt8(), wire)
            @Assert(DtlsAlertDescription.fromUInt8(wire), desc)
        }
    }

    // Acceptance: illegal alert description bytes are rejected. These are
    // the negative vectors — values that are not assigned by RFC 5246.
    @TestCase
    public func testDescription_IllegalBytes_Rejected(): Unit {
        let bads = [UInt8(1), UInt8(2), UInt8(5), UInt8(41), UInt8(60),
                    UInt8(69), UInt8(72), UInt8(91), UInt8(105), UInt8(200),
                    UInt8(255)]
        for (b in bads) {
            var threw = false
            try {
                _ = DtlsAlertDescription.fromUInt8(b)
            } catch (e: CryptoException) {
                threw = true
            }
            @Assert(threw, true)
        }
    }
}

@Test
public class DtlsAlertEncodeDecodeNegativeTestSuite {

    // Acceptance: a truncated alert (0 bytes or 1 byte) is rejected.
    @TestCase
    public func testDecode_Truncated_Rejected(): Unit {
        var threw0 = false
        try {
            _ = DtlsAlert.decode(Array<Byte>(0, repeat: 0))
        } catch (e: CryptoException) {
            threw0 = true
        }
        @Assert(threw0, true)

        var threw1 = false
        try {
            _ = DtlsAlert.decode(mkBytes(1, 0x00))
        } catch (e: CryptoException) {
            threw1 = true
        }
        @Assert(threw1, true)
    }

    // Acceptance: an alert with a legal level but illegal description is
    // rejected. This pins the fail-closed behavior: the decoder does not
    // accept partial validity.
    @TestCase
    public func testDecode_LegalLevelIllegalDescription_Rejected(): Unit {
        let bad = [UInt8(2), UInt8(99)]  // Fatal + illegal description
        var threw = false
        try {
            _ = DtlsAlert.decode(bad)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: an alert with an illegal level but legal description is
    // rejected.
    @TestCase
    public func testDecode_IllegalLevelLegalDescription_Rejected(): Unit {
        let bad = [UInt8(9), UInt8(40)]  // illegal level + HandshakeFailure
        var threw = false
        try {
            _ = DtlsAlert.decode(bad)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: isFatal() returns true only for Fatal-level alerts.
    @TestCase
    public func testIsFatal_OnlyFatalLevel(): Unit {
        let fatal = dtlsFatalAlert(DtlsAlertDescription.HandshakeFailure)
        @Assert(fatal.isFatal(), true)
        let warning = DtlsAlert(DtlsAlertLevel.Warning,
            DtlsAlertDescription.CloseNotify)
        @Assert(warning.isFatal(), false)
    }

    // Acceptance: every alert description can be carried by a fatal alert.
    // This proves the alert emit path is total over the description enum.
    @TestCase
    public func testFatalAlert_AllDescriptions(): Unit {
        let descs = [
            DtlsAlertDescription.CloseNotify,
            DtlsAlertDescription.UnexpectedMessage,
            DtlsAlertDescription.BadRecordMac,
            DtlsAlertDescription.HandshakeFailure,
            DtlsAlertDescription.BadCertificate,
            DtlsAlertDescription.UnsupportedCertificate,
            DtlsAlertDescription.CertificateRevoked,
            DtlsAlertDescription.CertificateExpired,
            DtlsAlertDescription.CertificateUnknown,
            DtlsAlertDescription.IllegalParameter,
            DtlsAlertDescription.UnknownCa,
            DtlsAlertDescription.AccessDenied,
            DtlsAlertDescription.DecodeError,
            DtlsAlertDescription.DecryptError,
            DtlsAlertDescription.ProtocolVersion,
            DtlsAlertDescription.InsufficientSecurity,
            DtlsAlertDescription.InternalError,
            DtlsAlertDescription.UserCanceled,
            DtlsAlertDescription.NoRenegotiation,
            DtlsAlertDescription.UnsupportedExtension
        ]
        for (d in descs) {
            let a = dtlsFatalAlert(d)
            @Assert(a.isFatal(), true)
            @Assert(a.description, d)
            // Round-trip through encode/decode.
            let decoded = DtlsAlert.decode(a.encode())
            @Assert(decoded.level, a.level)
            @Assert(decoded.description, a.description)
        }
    }
}

// ---------------------------------------------------------------------------
// RFC 5764 DTLS-SRTP — negative vectors
// ---------------------------------------------------------------------------

@Test
public class DtlsSrtpProfileNegativeTestSuite {

    // Acceptance: every defined SRTP protection profile round-trips through
    // the exact RFC 5764 §4.1.2 wire code.
    @TestCase
    public func testProfile_RoundTrip_AllDefined(): Unit {
        @Assert(DtlsSrtpProtectionProfile.Aes128CmSha1_80.toCode(), UInt16(0x0001))
        @Assert(DtlsSrtpProtectionProfile.Aes128CmSha1_32.toCode(), UInt16(0x0002))
        @Assert(DtlsSrtpProtectionProfile.AeadAes128Gcm.toCode(), UInt16(0x0007))
        @Assert(DtlsSrtpProtectionProfile.AeadAes256Gcm.toCode(), UInt16(0x0008))

        @Assert(DtlsSrtpProtectionProfile.fromCode(UInt16(0x0001)),
            DtlsSrtpProtectionProfile.Aes128CmSha1_80)
        @Assert(DtlsSrtpProtectionProfile.fromCode(UInt16(0x0002)),
            DtlsSrtpProtectionProfile.Aes128CmSha1_32)
        @Assert(DtlsSrtpProtectionProfile.fromCode(UInt16(0x0007)),
            DtlsSrtpProtectionProfile.AeadAes128Gcm)
        @Assert(DtlsSrtpProtectionProfile.fromCode(UInt16(0x0008)),
            DtlsSrtpProtectionProfile.AeadAes256Gcm)
    }

    // Acceptance: illegal SRTP profile codes return None (negotiation
    // rejection). These are the negative vectors — codes not assigned by
    // RFC 5764 §4.1.2.
    @TestCase
    public func testProfile_IllegalCodes_ReturnNone(): Unit {
        let bads = [UInt16(0x0000), UInt16(0x0003), UInt16(0x0004),
                    UInt16(0x0005), UInt16(0x0006), UInt16(0x0009),
                    UInt16(0x00FF), UInt16(0xFFFF)]
        for (c in bads) {
            match (DtlsSrtpProtectionProfile.fromCode(c)) {
                case Some(_) =>
                    @Assert(false, true)  // fail: illegal code accepted
                case None =>
                    ()  // pass: illegal code rejected
            }
        }
    }

    // Acceptance: keyLen / saltLen match RFC 5764 §4.2.2 for every profile.
    @TestCase
    public func testProfile_KeySaltLens_RFC5764(): Unit {
        // SRTP_AES128_CM_HMAC_SHA1_80: key=16, salt=14
        @Assert(DtlsSrtpProtectionProfile.Aes128CmSha1_80.keyLen(), 16)
        @Assert(DtlsSrtpProtectionProfile.Aes128CmSha1_80.saltLen(), 14)
        // SRTP_AES128_CM_HMAC_SHA1_32: key=16, salt=14
        @Assert(DtlsSrtpProtectionProfile.Aes128CmSha1_32.keyLen(), 16)
        @Assert(DtlsSrtpProtectionProfile.Aes128CmSha1_32.saltLen(), 14)
        // SRTP_AEAD_AES_128_GCM: key=16, salt=12
        @Assert(DtlsSrtpProtectionProfile.AeadAes128Gcm.keyLen(), 16)
        @Assert(DtlsSrtpProtectionProfile.AeadAes128Gcm.saltLen(), 12)
        // SRTP_AEAD_AES_256_GCM: key=32, salt=12
        @Assert(DtlsSrtpProtectionProfile.AeadAes256Gcm.keyLen(), 32)
        @Assert(DtlsSrtpProtectionProfile.AeadAes256Gcm.saltLen(), 12)
    }
}

@Test
public class DtlsSrtpKeyExtractionNegativeTestSuite {

    // Acceptance: SRTP keying material extraction is deterministic — the
    // same master secret + randoms + profile MUST produce identical keying
    // material. This pins the PRF contract.
    @TestCase
    public func testKeyExtraction_Deterministic(): Unit {
        let ms = mkBytes(48, 0xAB)
        let cr = mkBytes(32, 0x11)
        let sr = mkBytes(32, 0x22)
        let km1 = dtlsSrtpExtractKeyingMaterialProper(ms, cr, sr,
            DtlsSrtpProtectionProfile.Aes128CmSha1_80)
        let km2 = dtlsSrtpExtractKeyingMaterialProper(ms, cr, sr,
            DtlsSrtpProtectionProfile.Aes128CmSha1_80)
        @Assert(km1.clientWriteKey, km2.clientWriteKey)
        @Assert(km1.serverWriteKey, km2.serverWriteKey)
        @Assert(km1.clientWriteSalt, km2.clientWriteSalt)
        @Assert(km1.serverWriteSalt, km2.serverWriteSalt)
    }

    // Acceptance: different master secrets produce different keying material.
    @TestCase
    public func testKeyExtraction_DifferentSecret_DifferentMaterial(): Unit {
        let cr = mkBytes(32, 0x11)
        let sr = mkBytes(32, 0x22)
        let ms1 = mkBytes(48, 0xAB)
        let ms2 = mkBytes(48, 0xCD)
        let km1 = dtlsSrtpExtractKeyingMaterialProper(ms1, cr, sr,
            DtlsSrtpProtectionProfile.Aes128CmSha1_80)
        let km2 = dtlsSrtpExtractKeyingMaterialProper(ms2, cr, sr,
            DtlsSrtpProtectionProfile.Aes128CmSha1_80)
        @Assert(km1.clientWriteKey != km2.clientWriteKey, true)
        @Assert(km1.serverWriteKey != km2.serverWriteKey, true)
    }

    // Acceptance: different randoms produce different keying material.
    @TestCase
    public func testKeyExtraction_DifferentRandom_DifferentMaterial(): Unit {
        let ms = mkBytes(48, 0xAB)
        let cr1 = mkBytes(32, 0x11)
        let sr1 = mkBytes(32, 0x22)
        let cr2 = mkBytes(32, 0x33)
        let sr2 = mkBytes(32, 0x44)
        let km1 = dtlsSrtpExtractKeyingMaterialProper(ms, cr1, sr1,
            DtlsSrtpProtectionProfile.Aes128CmSha1_80)
        let km2 = dtlsSrtpExtractKeyingMaterialProper(ms, cr2, sr2,
            DtlsSrtpProtectionProfile.Aes128CmSha1_80)
        @Assert(km1.clientWriteKey != km2.clientWriteKey, true)
    }

    // Acceptance: different profiles produce different-length keying material
    // (key+salt lengths differ). AES-256-GCM has a 32-byte key.
    @TestCase
    public func testKeyExtraction_ProfileAffectsLength(): Unit {
        let ms = mkBytes(48, 0xAB)
        let cr = mkBytes(32, 0x11)
        let sr = mkBytes(32, 0x22)
        let km128 = dtlsSrtpExtractKeyingMaterialProper(ms, cr, sr,
            DtlsSrtpProtectionProfile.AeadAes128Gcm)
        let km256 = dtlsSrtpExtractKeyingMaterialProper(ms, cr, sr,
            DtlsSrtpProtectionProfile.AeadAes256Gcm)
        @Assert(km128.clientWriteKey.size, 16)
        @Assert(km256.clientWriteKey.size, 32)
        @Assert(km128.clientWriteSalt.size, 12)
        @Assert(km256.clientWriteSalt.size, 12)
    }

    // Acceptance: client and server keys MUST differ (derivation offset
    // differs). This is the RFC 5764 §4.2 anti-symmetry pin.
    @TestCase
    public func testKeyExtraction_ClientServerKeysDiffer(): Unit {
        let ms = mkBytes(48, 0xAB)
        let cr = mkBytes(32, 0x11)
        let sr = mkBytes(32, 0x22)
        let km = dtlsSrtpExtractKeyingMaterialProper(ms, cr, sr,
            DtlsSrtpProtectionProfile.Aes128CmSha1_80)
        @Assert(km.clientWriteKey != km.serverWriteKey, true)
        @Assert(km.clientWriteSalt != km.serverWriteSalt, true)
    }

    // Acceptance: extracting SRTP keying material from a context with no
    // master secret is rejected. This is the gate: no SRTP
    // export before handshake completion.
    @TestCase
    public func testContext_ExtractSrtp_NoMasterSecret_Rejected(): Unit {
        let ctx = DtlsHandshakeContext(DtlsRole.Client)
        var threw = false
        try {
            _ = ctx.extractSrtpKeyingMaterial(
                DtlsSrtpProtectionProfile.Aes128CmSha1_80)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: extracting SRTP keying material after a fatal alert is
    // rejected — the master secret has been zeroized. This is the DTLS
    // clean-failure requirement: no residual SRTP material after failure.
    @TestCase
    public func testContext_ExtractSrtp_AfterFatalAlert_Rejected(): Unit {
        let ctx = dtlsAuthenticatedFixture()
        // Confirm we can extract before failure.
        let km = ctx.extractSrtpKeyingMaterial(
            DtlsSrtpProtectionProfile.Aes128CmSha1_80)
        @Assert(km.clientWriteKey.size, 16)
        // Now fail the handshake.
        ctx.recordFatalAlert(DtlsAlertDescription.HandshakeFailure,
            "test-induced failure")
        // SRTP extraction MUST now fail — master secret zeroized.
        var threw = false
        try {
            _ = ctx.extractSrtpKeyingMaterial(
                DtlsSrtpProtectionProfile.Aes128CmSha1_80)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }
}
