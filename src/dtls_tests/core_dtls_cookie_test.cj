package jinguissl_core.dtls_tests

import std.unittest.*
import std.unittest.testmacro.*
import jinguissl_core.crypto.dtls.*
import jinguissl_core.crypto.error.CryptoException

// ============================================================================
// Cookie Secret Rotation And Binding — regression tests
// ============================================================================

private func mkIp(a: UInt8, b: UInt8, c: UInt8, d: UInt8): Array<Byte> {
    let arr = Array<Byte>(4, repeat: 0)
    arr[0] = a
    arr[1] = b
    arr[2] = c
    arr[3] = d
    arr
}

private func mkRandom(seed: UInt8): Array<Byte> {
    let r = Array<Byte>(32, repeat: 0)
    for (i in 0..32) {
        r[i] = seed + UInt8(i)
    }
    r
}

private func mkCipherSuites(): Array<UInt16> {
    let arr = Array<UInt16>(3, repeat: UInt16(0))
    arr[0] = UInt16(0x009C)
    arr[1] = UInt16(0x009D)
    arr[2] = UInt16(0xCCAB)
    arr
}

private func mkSrtpProfiles(): Array<UInt16> {
    let arr = Array<UInt16>(1, repeat: UInt16(0))
    arr[0] = UInt16(0x0001)
    arr
}

@Test
public class DtlsCookieManagerBasicTestSuite {

    // Acceptance: a freshly generated cookie verifies successfully.
    @TestCase
    public func testFreshCookie_Verifies(): Unit {
        let mgr = DtlsCookieManager(32, 300_000, 120_000)
        let cookie = mgr.generateCookie(mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000)
        @Assert(cookie.size, 41)  // 1 + 8 + 32
        let ok = mgr.verifyCookie(cookie, mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000)
        @Assert(ok, true)
    }

    // Acceptance: cookie forgery — wrong HMAC — is rejected.
    @TestCase
    public func testCookieForgery_Rejected(): Unit {
        let mgr = DtlsCookieManager(32, 300_000, 120_000)
        let cookie = mgr.generateCookie(mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000)
        // Tamper with the HMAC byte.
        let tampered = Array<Byte>(cookie.size, repeat: 0)
        for (i in 0..cookie.size) { tampered[i] = cookie[i] }
        tampered[9] = tampered[9] ^ UInt8(0xFF)
        let ok = mgr.verifyCookie(tampered, mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000)
        @Assert(ok, false)
    }

    // Acceptance: IP rebinding — same cookie from a different client IP —
    // is rejected.
    @TestCase
    public func testIpRebinding_Rejected(): Unit {
        let mgr = DtlsCookieManager(32, 300_000, 120_000)
        let cookie = mgr.generateCookie(mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000)
        let ok = mgr.verifyCookie(cookie, mkIp(10, 0, 0, 1), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000)
        @Assert(ok, false)
    }

    // Acceptance: port rebinding is rejected.
    @TestCase
    public func testPortRebinding_Rejected(): Unit {
        let mgr = DtlsCookieManager(32, 300_000, 120_000)
        let cookie = mgr.generateCookie(mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000)
        let ok = mgr.verifyCookie(cookie, mkIp(192, 168, 1, 10), UInt16(6000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000)
        @Assert(ok, false)
    }

    // Acceptance: version mismatch is rejected.
    @TestCase
    public func testVersionMismatch_Rejected(): Unit {
        let mgr = DtlsCookieManager(32, 300_000, 120_000)
        let cookie = mgr.generateCookie(mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000)
        let ok = mgr.verifyCookie(cookie, mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_0, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000)
        @Assert(ok, false)
    }

    // Acceptance: client random tampering is rejected.
    @TestCase
    public func testClientRandomTampering_Rejected(): Unit {
        let mgr = DtlsCookieManager(32, 300_000, 120_000)
        let cookie = mgr.generateCookie(mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000)
        let tamperedRandom = Array<Byte>(32, repeat: 0)
        for (i in 0..32) { tamperedRandom[i] = mkRandom(0x01)[i] }
        tamperedRandom[0] = tamperedRandom[0] ^ UInt8(0xFF)
        let ok = mgr.verifyCookie(cookie, mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, tamperedRandom, mkCipherSuites(), mkSrtpProfiles(),
            1_000_000)
        @Assert(ok, false)
    }

    // Acceptance: cipher suites tampering is rejected.
    @TestCase
    public func testCipherSuitesTampering_Rejected(): Unit {
        let mgr = DtlsCookieManager(32, 300_000, 120_000)
        let cookie = mgr.generateCookie(mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000)
        let tamperedCs = Array<UInt16>(2, repeat: UInt16(0))
        tamperedCs[0] = UInt16(0x009C)
        tamperedCs[1] = UInt16(0x009D)
        let ok = mgr.verifyCookie(cookie, mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), tamperedCs, mkSrtpProfiles(),
            1_000_000)
        @Assert(ok, false)
    }

    // Acceptance: srtp profiles tampering is rejected.
    @TestCase
    public func testSrtpProfilesTampering_Rejected(): Unit {
        let mgr = DtlsCookieManager(32, 300_000, 120_000)
        let cookie = mgr.generateCookie(mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000)
        let tamperedSrtp = Array<UInt16>(1, repeat: UInt16(0))
        tamperedSrtp[0] = UInt16(0x0002)
        let ok = mgr.verifyCookie(cookie, mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), tamperedSrtp,
            1_000_000)
        @Assert(ok, false)
    }

    // Acceptance: expired cookie is rejected.
    @TestCase
    public func testExpiredCookie_Rejected(): Unit {
        let ttl: Int64 = 60_000  // 60 seconds
        let mgr = DtlsCookieManager(32, ttl, 120_000)
        // Cookie issued at t=1_000_000.
        let cookie = mgr.generateCookie(mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000)
        // Verify at t=1_000_000 + ttl + 1 -> expired.
        let ok = mgr.verifyCookie(cookie, mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000 + ttl + 1)
        @Assert(ok, false)
    }

    // Acceptance: cookie at exactly ttl boundary is still accepted.
    @TestCase
    public func testCookieAtTtlBoundary_Accepted(): Unit {
        let ttl: Int64 = 60_000
        let mgr = DtlsCookieManager(32, ttl, 120_000)
        let cookie = mgr.generateCookie(mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000)
        let ok = mgr.verifyCookie(cookie, mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000 + ttl)
        @Assert(ok, true)
    }

    // Acceptance: malformed cookie (wrong size) is rejected.
    @TestCase
    public func testMalformedCookie_Rejected(): Unit {
        let mgr = DtlsCookieManager(32, 300_000, 120_000)
        let ok = mgr.verifyCookie(Array<Byte>(10, repeat: 0),
            mkIp(192, 168, 1, 10), UInt16(5000), DTLS_VERSION_1_2,
            mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(), 1_000_000)
        @Assert(ok, false)
    }

    // Acceptance: invalid secretId (e.g. 0xFF) is rejected.
    @TestCase
    public func testInvalidSecretId_Rejected(): Unit {
        let mgr = DtlsCookieManager(32, 300_000, 120_000)
        let cookie = mgr.generateCookie(mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000)
        // Override secretId to 0xFF.
        let bad = Array<Byte>(cookie.size, repeat: 0)
        for (i in 0..cookie.size) { bad[i] = cookie[i] }
        bad[0] = UInt8(0xFF)
        let ok = mgr.verifyCookie(bad, mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000)
        @Assert(ok, false)
    }
}

@Test
public class DtlsCookieManagerRotationTestSuite {

    // Acceptance: rotation overlap window — cookies issued under the
    // previous secret are still accepted during the overlap window.
    @TestCase
    public func testRotationOverlapWindow_PreviousCookieAccepted(): Unit {
        let mgr = DtlsCookieManager(32, 300_000, 120_000)
        // Issue a cookie at t=1000 under the initial secret.
        let cookie = mgr.generateCookie(mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000)
        // Rotate at t=2000. Previous secret retained for overlapMs=120_000.
        mgr.rotate(2_000)
        @Assert(mgr.hasPrevious, true)
        // Cookie issued at t=1000 under previous secret; verify at t=2000.
        // Cookie age = 1000 < ttl=300_000, and nowMs - prev.createdAtMs = 0
        // <= overlap=120_000 -> accept.
        let ok = mgr.verifyCookie(cookie, mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            2_000)
        @Assert(ok, true)
    }

    // Acceptance: after the rotation overlap window expires, cookies
    // bearing the previous secretId are rejected.
    @TestCase
    public func testPostRotation_OldCookieRejected_AfterOverlap(): Unit {
        let mgr = DtlsCookieManager(32, 300_000, 120_000)
        let cookie = mgr.generateCookie(mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000)
        mgr.rotate(2_000)
        // Verify at t = 2_000 + overlap + 1 = 122_001. The cookie itself
        // is still within its ttl (age = 121_001 < 300_000), but the
        // previous secret is now beyond its overlap window.
        let ok = mgr.verifyCookie(cookie, mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            2_000 + 120_000 + 1)
        @Assert(ok, false)
    }

    // Acceptance: after rotation, new cookies are issued under the new
    // current secret and verify cleanly.
    @TestCase
    public func testPostRotation_NewCookieVerifies(): Unit {
        let mgr = DtlsCookieManager(32, 300_000, 120_000)
        mgr.rotate(2_000)
        let cookie = mgr.generateCookie(mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            3_000)
        let ok = mgr.verifyCookie(cookie, mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            3_000)
        @Assert(ok, true)
    }

    // Acceptance: retirePrevious drops the previous secret; cookies
    // bearing secretId=1 are then rejected.
    @TestCase
    public func testRetirePrevious_DropsOldSecret(): Unit {
        let mgr = DtlsCookieManager(32, 300_000, 120_000)
        let cookie = mgr.generateCookie(mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000)
        mgr.rotate(2_000)
        @Assert(mgr.hasPrevious, true)
        mgr.retirePrevious()
        @Assert(mgr.hasPrevious, false)
        let ok = mgr.verifyCookie(cookie, mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            2_000)
        @Assert(ok, false)
    }

    // Acceptance: two managers with independent secrets do not accept
    // each other's cookies (cross-instance forgery).
    @TestCase
    public func testCrossInstanceForgery_Rejected(): Unit {
        let mgr1 = DtlsCookieManager(32, 300_000, 120_000)
        let mgr2 = DtlsCookieManager(32, 300_000, 120_000)
        let cookie = mgr1.generateCookie(mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000)
        let ok = mgr2.verifyCookie(cookie, mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000)
        @Assert(ok, false)
    }
}

@Test
public class DtlsCookieManagerConstructionTestSuite {

    // Acceptance: secret size < 16 is rejected.
    @TestCase
    public func testSecretSizeTooSmall_Rejected(): Unit {
        var threw = false
        try {
            _ = DtlsCookieManager(8, 300_000, 120_000)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: ttlMs <= 0 is rejected.
    @TestCase
    public func testTtlNonPositive_Rejected(): Unit {
        var threw = false
        try {
            _ = DtlsCookieManager(32, 0, 120_000)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: rotationOverlapMs < 0 is rejected.
    @TestCase
    public func testRotationOverlapNegative_Rejected(): Unit {
        var threw = false
        try {
            _ = DtlsCookieManager(32, 300_000, -1)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance: future-timestamp cookie beyond ttl is rejected
    // (clock-skew forgery defense).
    @TestCase
    public func testFutureTimestampBeyondTtl_Rejected(): Unit {
        let mgr = DtlsCookieManager(32, 60_000, 120_000)
        // Cookie issued at t=1_000_000 + 61_000 (61s in the future).
        let cookie = mgr.generateCookie(mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_061_000)
        let ok = mgr.verifyCookie(cookie, mkIp(192, 168, 1, 10), UInt16(5000),
            DTLS_VERSION_1_2, mkRandom(0x01), mkCipherSuites(), mkSrtpProfiles(),
            1_000_000)
        @Assert(ok, false)
    }
}
