package jinguissl_core.dtls_tests

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.ArrayList
import jinguissl_core.crypto.dtls.*
import jinguissl_core.crypto.error.CryptoException

// ============================================================================
// Random Constructor Mismatch — regression tests
// ============================================================================
//
// Covers RFC 6347 §4.1.2 ClientHello/ServerHello random field layout:
//   32 bytes = 4-byte GMT unix time + 28-byte random
//
// Test matrix required by the DTLS protocol contract:
//   1. zero random (all-zero 28-byte body) round trips
//   2. full-entropy random (non-zero 28-byte body) round trips
//   3. GMT time edge values (0x00000000, 0xFFFFFFFF, 0x80000000)
//   4. parser overflow (buffer larger than 32 bytes — only first 32 read)
//   5. truncated input (< 32 bytes — rejected, no partial state)
//   6. mismatched length (constructor rejects 27/29/32-byte randomBytes)
//   7. builder round trip via DtlsHandshakeContext.generateClientRandom
//      + dtlsBuildClientHelloWithEcdhe (the original 32-vs-28 mismatch site)
//   8. ClientHello/ServerHello random field round trip through encode/decode
//   9. deterministic failure on malformed input without partial state mutation
// ============================================================================

private func mkBytes(n: Int64, fill: UInt8): Array<Byte> {
    Array<Byte>(n, repeat: fill)
}

@Test
public class DtlsRandomConstructorTestSuite {

    // Acceptance 6: constructor rejects mismatched lengths.
    @TestCase
    public func testDtlsRandomConstructor_Rejects27Bytes(): Unit {
        var threw = false
        try {
            _ = DtlsRandom(UInt32(0), mkBytes(27, 0x01))
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    @TestCase
    public func testDtlsRandomConstructor_Rejects29Bytes(): Unit {
        var threw = false
        try {
            _ = DtlsRandom(UInt32(0), mkBytes(29, 0x01))
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // This is the exact regression for the original 32-vs-28 mismatch:
    // the constructor MUST reject a 32-byte buffer passed as randomBytes,
    // because randomBytes is the 28-byte tail, not the full 32-byte field.
    @TestCase
    public func testDtlsRandomConstructor_Rejects32Bytes(): Unit {
        var threw = false
        try {
            _ = DtlsRandom(UInt32(0), mkBytes(32, 0x01))
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    @TestCase
    public func testDtlsRandomConstructor_Accepts28Bytes(): Unit {
        let r = DtlsRandom(UInt32(0), mkBytes(28, 0x01))
        @Assert(r.randomBytes.size, 28)
        @Assert(r.gmtUnixTime, UInt32(0))
    }
}

@Test
public class DtlsRandomRoundTripTestSuite {

    // Acceptance 1: zero random round trips.
    @TestCase
    public func testDtlsRandom_ZeroRandom(): Unit {
        let r = DtlsRandom(UInt32(0), mkBytes(28, 0x00))
        let enc = r.encode()
        @Assert(enc.size, 32)
        let dec = DtlsRandom.decode(enc)
        @Assert(dec.gmtUnixTime, UInt32(0))
        @Assert(dec.randomBytes, mkBytes(28, 0x00))
    }

    // Acceptance 2: full-entropy random round trips.
    @TestCase
    public func testDtlsRandom_FullEntropy(): Unit {
        let body = Array<Byte>(28, repeat: 0)
        for (i in 0..28) {
            body[i] = UInt8((i * 7 + 1) % 256)
        }
        let r = DtlsRandom(UInt32(0x12345678), body)
        let enc = r.encode()
        let dec = DtlsRandom.decode(enc)
        @Assert(dec.gmtUnixTime, UInt32(0x12345678))
        @Assert(dec.randomBytes, body)
    }

    // Acceptance 3: GMT time edge values.
    @TestCase
    public func testDtlsRandom_GmtEdge_Zero(): Unit {
        let r = DtlsRandom(UInt32(0x00000000), mkBytes(28, 0xAB))
        let dec = DtlsRandom.decode(r.encode())
        @Assert(dec.gmtUnixTime, UInt32(0x00000000))
    }

    @TestCase
    public func testDtlsRandom_GmtEdge_Max(): Unit {
        let r = DtlsRandom(UInt32(0xFFFFFFFF), mkBytes(28, 0xAB))
        let dec = DtlsRandom.decode(r.encode())
        @Assert(dec.gmtUnixTime, UInt32(0xFFFFFFFF))
    }

    @TestCase
    public func testDtlsRandom_GmtEdge_SignedBoundary(): Unit {
        let r = DtlsRandom(UInt32(0x80000000), mkBytes(28, 0xAB))
        let dec = DtlsRandom.decode(r.encode())
        @Assert(dec.gmtUnixTime, UInt32(0x80000000))
    }

    // Acceptance 4: parser overflow — buffer larger than 32 bytes; only the
    // first 32 bytes are consumed, the rest is ignored by decode (caller
    // is responsible for slicing the exact field out of a larger buffer).
    @TestCase
    public func testDtlsRandom_ParserOverflow(): Unit {
        let r = DtlsRandom(UInt32(0xCAFEBABE), mkBytes(28, 0x42))
        let enc = r.encode()
        // Append 8 trailing garbage bytes; decode must still return the
        // original 32-byte field and ignore the tail.
        let padded = Array<Byte>(40, repeat: 0)
        for (i in 0..32) { padded[i] = enc[i] }
        for (i in 32..40) { padded[i] = UInt8(0xFF) }
        let dec = DtlsRandom.decode(padded)
        @Assert(dec.gmtUnixTime, UInt32(0xCAFEBABE))
        @Assert(dec.randomBytes, mkBytes(28, 0x42))
    }

    // Acceptance 5: truncated input is rejected.
    @TestCase
    public func testDtlsRandom_TruncatedInput(): Unit {
        var threw = false
        try {
            _ = DtlsRandom.decode(mkBytes(31, 0x01))
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    @TestCase
    public func testDtlsRandom_EmptyInput(): Unit {
        var threw = false
        try {
            _ = DtlsRandom.decode(Array<Byte>())
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Acceptance 9: deterministic failure without partial state mutation.
    // DtlsRandom is immutable; on failure the constructor throws and no
    // DtlsRandom instance escapes. Verified here by asserting the throw
    // and that no decode result is observable.
    @TestCase
    public func testDtlsRandom_DeterministicFailureNoPartialState(): Unit {
        let bad = mkBytes(27, 0x01)
        var escaped: ?DtlsRandom = None
        try {
            escaped = Some(DtlsRandom(UInt32(0), bad))
        } catch (e: CryptoException) {
            // expected
        }
        match (escaped) {
            case Some(_) => @Assert(false, true)  // no instance must escape
            case None => ()
        }
    }

    // decodeFrom bounds checks.
    @TestCase
    public func testDtlsRandomDecodeFrom_InBounds(): Unit {
        let r = DtlsRandom(UInt32(0x11223344), mkBytes(28, 0x77))
        let buf = r.encode()
        let dec = DtlsRandom.decodeFrom(buf, 0)
        @Assert(dec.gmtUnixTime, UInt32(0x11223344))
    }

    @TestCase
    public func testDtlsRandomDecodeFrom_OutOfBounds(): Unit {
        let buf = mkBytes(40, 0x00)
        var threw = false
        try {
            _ = DtlsRandom.decodeFrom(buf, 9)  // 9 + 32 = 41 > 40
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    @TestCase
    public func testDtlsRandomDecodeFrom_NegativeOffset(): Unit {
        let buf = mkBytes(40, 0x00)
        var threw = false
        try {
            _ = DtlsRandom.decodeFrom(buf, -1)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }
}

@Test
public class DtlsRandomGenerateTestSuite {

    // DtlsRandom.generate produces a valid 32-byte field with GMT=0 and a
    // 28-byte random body.
    @TestCase
    public func testDtlsRandomGenerate_ProducesValidField(): Unit {
        let r = DtlsRandom.generate()
        @Assert(r.gmtUnixTime, UInt32(0))
        @Assert(r.randomBytes.size, 28)
        let enc = r.encode()
        @Assert(enc.size, 32)
        // First 4 bytes are GMT = 0.
        @Assert(enc[0], UInt8(0))
        @Assert(enc[1], UInt8(0))
        @Assert(enc[2], UInt8(0))
        @Assert(enc[3], UInt8(0))
        // decode round trips.
        let dec = DtlsRandom.decode(enc)
        @Assert(dec.gmtUnixTime, UInt32(0))
        @Assert(dec.randomBytes, r.randomBytes)
    }

    // Two consecutive generate() calls should (probabilistically) produce
    // different random bodies. We assert inequality to catch a broken RNG
    // that always returns the same buffer.
    @TestCase
    public func testDtlsRandomGenerate_DistinctAcrossCalls(): Unit {
        let a = DtlsRandom.generate()
        let b = DtlsRandom.generate()
        var same = true
        for (i in 0..28) {
            if (a.randomBytes[i] != b.randomBytes[i]) {
                same = false
            }
        }
        @Assert(same, false)
    }
}

// ============================================================================
// Builder round trip: the original 32-vs-28 mismatch site.
// dtlsBuildClientHelloWithEcdhe used to call DtlsRandom(UInt32(0),
// context.clientRandom) with a 32-byte buffer, which threw. Now it uses
// DtlsRandom.decode(context.clientRandom).
// ============================================================================

@Test
public class DtlsBuilderRandomRoundTripTestSuite {

    // Acceptance 7: builder round trip via DtlsHandshakeContext.
    @TestCase
    public func testBuilder_ClientHelloRandomRoundTrip(): Unit {
        let ctx = DtlsHandshakeContext(DtlsRole.Client)
        let hello = dtlsBuildClientHelloWithEcdhe(ctx,
            [DtlsSrtpProtectionProfile.AeadAes128Gcm.toCode()])

        // The builder must have populated ctx.clientRandom with a 32-byte
        // encoded random field, and hello.random must decode back to the
        // same GMT + body.
        @Assert(ctx.clientRandom.size, 32)
        let enc = hello.random.encode()
        @Assert(enc, ctx.clientRandom)

        let encoded = hello.encode()
        let decoded = DtlsClientHello.decode(encoded)
        @Assert(decoded.random.encode(), ctx.clientRandom)
        @Assert(decoded.random.gmtUnixTime, hello.random.gmtUnixTime)
        @Assert(decoded.random.randomBytes, hello.random.randomBytes)
    }

    @TestCase
    public func testBuilder_ServerHelloRandomRoundTrip(): Unit {
        let ctx = DtlsHandshakeContext(DtlsRole.Server)
        let hello = dtlsBuildServerHelloWithEcdhe(ctx,
            DtlsSrtpProtectionProfile.AeadAes128Gcm.toCode())

        @Assert(ctx.serverRandom.size, 32)
        let enc = hello.random.encode()
        @Assert(enc, ctx.serverRandom)

        let encoded = hello.encode()
        let decoded = DtlsServerHello.decode(encoded)
        @Assert(decoded.random.encode(), ctx.serverRandom)
        @Assert(decoded.random.gmtUnixTime, hello.random.gmtUnixTime)
        @Assert(decoded.random.randomBytes, hello.random.randomBytes)
    }

    // Acceptance 8: ClientHello random field round trip through
    // encode/decode with a non-zero GMT.
    @TestCase
    public func testClientHello_RandomFieldRoundTrip(): Unit {
        let body = Array<Byte>(28, repeat: 0)
        for (i in 0..28) {
            body[i] = UInt8((i + 1) % 256)
        }
        let random = DtlsRandom(UInt32(0xDEADBEEF), body)
        let hello = DtlsClientHello(DTLS_VERSION_1_2, random,
            Array<Byte>(), Array<Byte>(),
            [DTLS_CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256],
            [UInt8(0)],
            [DtlsSrtpProtectionProfile.AeadAes128Gcm.toCode()])

        let encoded = hello.encode()
        let decoded = DtlsClientHello.decode(encoded)
        @Assert(decoded.random.gmtUnixTime, UInt32(0xDEADBEEF))
        @Assert(decoded.random.randomBytes, body)
        @Assert(decoded.random.encode(), random.encode())
    }

    @TestCase
    public func testServerHello_RandomFieldRoundTrip(): Unit {
        let body = Array<Byte>(28, repeat: 0)
        for (i in 0..28) {
            body[i] = UInt8((28 - i) % 256)
        }
        let random = DtlsRandom(UInt32(0x01020304), body)
        let hello = DtlsServerHello(DTLS_VERSION_1_2, random,
            Array<Byte>(),
            DTLS_CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256,
            UInt8(0),
            DtlsSrtpProtectionProfile.AeadAes128Gcm.toCode())

        let encoded = hello.encode()
        let decoded = DtlsServerHello.decode(encoded)
        @Assert(decoded.random.gmtUnixTime, UInt32(0x01020304))
        @Assert(decoded.random.randomBytes, body)
        @Assert(decoded.random.encode(), random.encode())
    }
}

// ============================================================================
// Truncated ClientHello/ServerHello parser rejection.
// ============================================================================

@Test
public class DtlsHelloTruncationTestSuite {

    @TestCase
    public func testClientHelloDecode_RejectsTruncatedBeforeRandom(): Unit {
        // Only 2 bytes (version) — not enough for the 32-byte random.
        let truncated = Array<Byte>(2, repeat: 0)
        var threw = false
        try {
            _ = DtlsClientHello.decode(truncated)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    @TestCase
    public func testClientHelloDecode_RejectsTruncatedInsideRandom(): Unit {
        // 2 + 10 bytes — inside the random field.
        let truncated = Array<Byte>(12, repeat: 0)
        var threw = false
        try {
            _ = DtlsClientHello.decode(truncated)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    @TestCase
    public func testServerHelloDecode_RejectsTruncatedBeforeRandom(): Unit {
        let truncated = Array<Byte>(2, repeat: 0)
        var threw = false
        try {
            _ = DtlsServerHello.decode(truncated)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    @TestCase
    public func testServerHelloDecode_RejectsTruncatedInsideRandom(): Unit {
        let truncated = Array<Byte>(20, repeat: 0)
        var threw = false
        try {
            _ = DtlsServerHello.decode(truncated)
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    // Empty buffer is rejected.
    @TestCase
    public func testClientHelloDecode_RejectsEmpty(): Unit {
        var threw = false
        try {
            _ = DtlsClientHello.decode(Array<Byte>())
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }

    @TestCase
    public func testServerHelloDecode_RejectsEmpty(): Unit {
        var threw = false
        try {
            _ = DtlsServerHello.decode(Array<Byte>())
        } catch (e: CryptoException) {
            threw = true
        }
        @Assert(threw, true)
    }
}
