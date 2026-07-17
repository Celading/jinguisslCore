 package jinguissl_core.tests

 import jinguissl_core.crypto.aes.{AesGcmContext, aesGcmEncryptWithContext, aesGcmDecryptWithContext, aesNewGcmContext}
 import jinguissl_core.crypto.quic.{quicAeadEncrypt, quicAeadDecrypt, quicAeadAesGcmEncrypt, quicAeadAesGcmDecrypt}
 import jinguissl_core.crypto.digest.bytesToHexLower
 import jinguissl_core.crypto.error.CryptoException

 private let TEST_KEY: Array<Byte> = [
     UInt8(0x1f), UInt8(0x36), UInt8(0x96), UInt8(0x13),
     UInt8(0xdd), UInt8(0x76), UInt8(0xd5), UInt8(0x46),
     UInt8(0x77), UInt8(0x30), UInt8(0xef), UInt8(0xcb),
     UInt8(0xe3), UInt8(0xb1), UInt8(0xa2), UInt8(0x2d)
 ]
 private let TEST_IV: Array<Byte> = [
     UInt8(0xfa), UInt8(0x04), UInt8(0x4b), UInt8(0x2f),
     UInt8(0x42), UInt8(0xa3), UInt8(0xfd), UInt8(0x3b),
     UInt8(0x46), UInt8(0xfb), UInt8(0x25), UInt8(0x5c)
 ]

 @Test
 public class QuicAeadTestSuite {

     @TestCase
     public func testAeadRoundTrip(): Unit {
         let ctx = aesNewGcmContext(TEST_KEY)
        let pt = "hello quic".toArray()
        let aad = "aad".toArray()

         let sealed = quicAeadAesGcmEncrypt(ctx, TEST_IV, 42, pt, aad)

         // sealed = ct || tag, total = pt.size + 16
         @Assert(sealed.size, pt.size + 16)

         let recovered = quicAeadAesGcmDecrypt(ctx, TEST_IV, 42, sealed, aad)
         @Assert(recovered, pt)

         // Wrong packet number must fail
         try {
             _ = quicAeadAesGcmDecrypt(ctx, TEST_IV, 99, sealed, aad)
             @Fail("AEAD should fail with wrong packet number")
         } catch (_: CryptoException) {
             @Assert(true)
         }
     }

     @TestCase
     public func testAeadConveniencePath(): Unit {
        let pt = "hello quic".toArray()
        let aad = "aad".toArray()

         let sealed = quicAeadEncrypt(TEST_KEY, TEST_IV, 7, pt, aad)
         @Assert(sealed.size, pt.size + 16)

         let recovered = quicAeadDecrypt(TEST_KEY, TEST_IV, 7, sealed, aad)
         @Assert(recovered, pt)

         // Wrong key must fail
         let badKey = Array<Byte>(16, repeat: 0xab)
         try {
             _ = quicAeadDecrypt(badKey, TEST_IV, 7, sealed, aad)
             @Fail("AEAD should fail with wrong key")
         } catch (_: CryptoException) {
             @Assert(true)
         }
     }

     @TestCase
     public func testAeadEmptyPlaintext(): Unit {
         let ctx = aesNewGcmContext(TEST_KEY)
        let aad = "aad".toArray()

         let sealed = quicAeadAesGcmEncrypt(ctx, TEST_IV, 0, [], aad)
         @Assert(sealed.size, 16) // only tag

         let recovered = quicAeadAesGcmDecrypt(ctx, TEST_IV, 0, sealed, aad)
         @Assert(recovered, [])
     }

     @TestCase
     public func testAeadShortCiphertextRejected(): Unit {
         let ctx = aesNewGcmContext(TEST_KEY)
         try {
             _ = quicAeadAesGcmDecrypt(ctx, TEST_IV, 0, hexToBytes("00"), hexToBytes(""))
             @Fail("short ciphertext should be rejected")
         } catch (_: CryptoException) {
             @Assert(true)
         }
     }

     @TestCase
     public func testAeadDifferentPnChangesCiphertext(): Unit {
         let ctx = aesNewGcmContext(TEST_KEY)
        let pt = "hello quic".toArray()
        let aad = "aad".toArray()

         let s1 = quicAeadAesGcmEncrypt(ctx, TEST_IV, 1, pt, aad)
         let s2 = quicAeadAesGcmEncrypt(ctx, TEST_IV, 2, pt, aad)
         @Assert(s1 != s2, true)
     }
 }

 /// ── hex helpers (same pattern as core_aes_test.cj) ──────────────

 private func hexToBytes(hex: String): Array<Byte> {
     let clean = hex.trimAscii().replace(" ", "").replace("\n", "").replace("\t", "")
     if ((clean.size % 2) != 0) {
         throw Exception("invalid hex length")
     }
     let out = Array<Byte>(clean.size / 2, repeat: 0)
     var i = 0
     while (i < clean.size) {
         let hi = hexNibble(clean[i])
         let lo = hexNibble(clean[i + 1])
         out[i / 2] = UInt8((hi << 4) | lo)
         i += 2
     }
     out
 }

 private func hexNibble(ch: Byte): UInt8 {
     if (ch >= b'0' && ch <= b'9') { return UInt8(ch - b'0') }
     let lower = if (ch >= b'A' && ch <= b'F') { ch + 32 } else { ch }
     if (lower >= b'a' && lower <= b'f') { return UInt8(lower - b'a' + 10) }
     throw Exception("invalid hex char")
 }

 private func assertHex(actual: Array<Byte>, expectedHex: String): Unit {
     @Assert(bytesToHexLower(actual), expectedHex.toAsciiLower())
 }
