 package jinguissl_core.tests

 import jinguissl_core.crypto.aes.{AesGcmContext, aesGcmEncryptWithContext, aesGcmDecryptWithContext, aesNewGcmContext}
 import jinguissl_core.crypto.chacha20.{Chacha20Poly1305Context, chacha20Poly1305EncryptWithContext, chacha20Poly1305DecryptWithContext, chacha20Poly1305NewContext}
 import jinguissl_core.crypto.quic.{quicAeadEncrypt, quicAeadDecrypt, quicAeadAesGcmEncrypt, quicAeadAesGcmDecrypt, quicAeadChaCha20Encrypt, quicAeadChaCha20Decrypt, QuicAeadAlgorithm}
 import jinguissl_core.crypto.digest.bytesToHexLower
 import jinguissl_core.crypto.error.CryptoException

 // ── Test keys ─────────────────────────────────────────────────────

 private let TEST_KEY_128: Array<Byte> = [
     UInt8(0x1f), UInt8(0x36), UInt8(0x96), UInt8(0x13),
     UInt8(0xdd), UInt8(0x76), UInt8(0xd5), UInt8(0x46),
     UInt8(0x77), UInt8(0x30), UInt8(0xef), UInt8(0xcb),
     UInt8(0xe3), UInt8(0xb1), UInt8(0xa2), UInt8(0x2d)
 ]

 private let TEST_KEY_256: Array<Byte> = [
     UInt8(0x00), UInt8(0x01), UInt8(0x02), UInt8(0x03),
     UInt8(0x04), UInt8(0x05), UInt8(0x06), UInt8(0x07),
     UInt8(0x08), UInt8(0x09), UInt8(0x0a), UInt8(0x0b),
     UInt8(0x0c), UInt8(0x0d), UInt8(0x0e), UInt8(0x0f),
     UInt8(0x10), UInt8(0x11), UInt8(0x12), UInt8(0x13),
     UInt8(0x14), UInt8(0x15), UInt8(0x16), UInt8(0x17),
     UInt8(0x18), UInt8(0x19), UInt8(0x1a), UInt8(0x1b),
     UInt8(0x1c), UInt8(0x1d), UInt8(0x1e), UInt8(0x1f)
 ]

 private let TEST_KEY_CHACHA: Array<Byte> = [
     UInt8(0x80), UInt8(0x81), UInt8(0x82), UInt8(0x83),
     UInt8(0x84), UInt8(0x85), UInt8(0x86), UInt8(0x87),
     UInt8(0x88), UInt8(0x89), UInt8(0x8a), UInt8(0x8b),
     UInt8(0x8c), UInt8(0x8d), UInt8(0x8e), UInt8(0x8f),
     UInt8(0x90), UInt8(0x91), UInt8(0x92), UInt8(0x93),
     UInt8(0x94), UInt8(0x95), UInt8(0x96), UInt8(0x97),
     UInt8(0x98), UInt8(0x99), UInt8(0x9a), UInt8(0x9b),
     UInt8(0x9c), UInt8(0x9d), UInt8(0x9e), UInt8(0x9f)
 ]

 private let TEST_IV: Array<Byte> = [
     UInt8(0xfa), UInt8(0x04), UInt8(0x4b), UInt8(0x2f),
     UInt8(0x42), UInt8(0xa3), UInt8(0xfd), UInt8(0x3b),
     UInt8(0x46), UInt8(0xfb), UInt8(0x25), UInt8(0x5c)
 ]

 @Test
 public class QuicAeadTestSuite {

     // ── AES-128-GCM ──────────────────────────────────────────────

     @TestCase
     public func testAead128GcmRoundTrip(): Unit {
         let ctx = aesNewGcmContext(TEST_KEY_128)
         let pt = "hello quic".toArray()
         let aad = "aad".toArray()

         let sealed = quicAeadAesGcmEncrypt(ctx, TEST_IV, 42, pt, aad)
         @Assert(sealed.size, pt.size + 16)

         let recovered = quicAeadAesGcmDecrypt(ctx, TEST_IV, 42, sealed, aad)
         @Assert(recovered, pt)
     }

     @TestCase
     public func testAead128GcmWrongPnFails(): Unit {
         let ctx = aesNewGcmContext(TEST_KEY_128)
         let pt = "hello quic".toArray()
         let aad = "aad".toArray()
         let sealed = quicAeadAesGcmEncrypt(ctx, TEST_IV, 42, pt, aad)

         try {
             _ = quicAeadAesGcmDecrypt(ctx, TEST_IV, 99, sealed, aad)
             @Fail("AEAD should fail with wrong packet number")
         } catch (_: CryptoException) {
             @Assert(true)
         }
     }

     @TestCase
     public func testAead128GcmConveniencePath(): Unit {
         let pt = "hello quic".toArray()
         let aad = "aad".toArray()

         let sealed = quicAeadEncrypt(TEST_KEY_128, TEST_IV, 7, pt, aad, QuicAeadAlgorithm.Aes128Gcm)
         @Assert(sealed.size, pt.size + 16)

         let recovered = quicAeadDecrypt(TEST_KEY_128, TEST_IV, 7, sealed, aad, QuicAeadAlgorithm.Aes128Gcm)
         @Assert(recovered, pt)
     }

     @TestCase
     public func testAead128GcmWrongKeyFails(): Unit {
         let pt = "hello quic".toArray()
         let aad = "aad".toArray()
         let sealed = quicAeadEncrypt(TEST_KEY_128, TEST_IV, 7, pt, aad, QuicAeadAlgorithm.Aes128Gcm)

         let badKey = Array<Byte>(16, repeat: 0xab)
         try {
             _ = quicAeadDecrypt(badKey, TEST_IV, 7, sealed, aad, QuicAeadAlgorithm.Aes128Gcm)
             @Fail("AEAD should fail with wrong key")
         } catch (_: CryptoException) {
             @Assert(true)
         }
     }

     @TestCase
     public func testAead128GcmEmptyPlaintext(): Unit {
         let ctx = aesNewGcmContext(TEST_KEY_128)
         let aad = "aad".toArray()

         let sealed = quicAeadAesGcmEncrypt(ctx, TEST_IV, 0, [], aad)
         @Assert(sealed.size, 16)

         let recovered = quicAeadAesGcmDecrypt(ctx, TEST_IV, 0, sealed, aad)
         @Assert(recovered, [])
     }

     @TestCase
     public func testAead128GcmShortCiphertextRejected(): Unit {
         let ctx = aesNewGcmContext(TEST_KEY_128)
         try {
             _ = quicAeadAesGcmDecrypt(ctx, TEST_IV, 0, hexToBytes("00"), hexToBytes(""))
             @Fail("short ciphertext should be rejected")
         } catch (_: CryptoException) {
             @Assert(true)
         }
     }

     @TestCase
     public func testAead128GcmDifferentPnChangesCiphertext(): Unit {
         let ctx = aesNewGcmContext(TEST_KEY_128)
         let pt = "hello quic".toArray()
         let aad = "aad".toArray()

         let s1 = quicAeadAesGcmEncrypt(ctx, TEST_IV, 1, pt, aad)
         let s2 = quicAeadAesGcmEncrypt(ctx, TEST_IV, 2, pt, aad)
         @Assert(s1 != s2, true)
     }

     // ── AES-256-GCM ──────────────────────────────────────────────

     @TestCase
     public func testAead256GcmRoundTrip(): Unit {
         let ctx = aesNewGcmContext(TEST_KEY_256)
         let pt = "hello quic aes256".toArray()
         let aad = "aad256".toArray()

         let sealed = quicAeadAesGcmEncrypt(ctx, TEST_IV, 13, pt, aad)
         @Assert(sealed.size, pt.size + 16)

         let recovered = quicAeadAesGcmDecrypt(ctx, TEST_IV, 13, sealed, aad)
         @Assert(recovered, pt)
     }

     @TestCase
     public func testAead256GcmConveniencePath(): Unit {
         let pt = "hello quic aes256".toArray()
         let aad = "aad256".toArray()

         let sealed = quicAeadEncrypt(TEST_KEY_256, TEST_IV, 7, pt, aad, QuicAeadAlgorithm.Aes256Gcm)
         @Assert(sealed.size, pt.size + 16)

         let recovered = quicAeadDecrypt(TEST_KEY_256, TEST_IV, 7, sealed, aad, QuicAeadAlgorithm.Aes256Gcm)
         @Assert(recovered, pt)
     }

     @TestCase
     public func testAead256GcmWrongKeyFails(): Unit {
         let pt = "hello quic aes256".toArray()
         let aad = "aad256".toArray()
         let sealed = quicAeadEncrypt(TEST_KEY_256, TEST_IV, 7, pt, aad, QuicAeadAlgorithm.Aes256Gcm)

         let badKey = Array<Byte>(32, repeat: 0xcc)
         try {
             _ = quicAeadDecrypt(badKey, TEST_IV, 7, sealed, aad, QuicAeadAlgorithm.Aes256Gcm)
             @Fail("AES-256 AEAD should fail with wrong key")
         } catch (_: CryptoException) {
             @Assert(true)
         }
     }

     @TestCase
     public func testAead256GcmEmptyPlaintext(): Unit {
         let ctx = aesNewGcmContext(TEST_KEY_256)
         let aad = "aad256".toArray()

         let sealed = quicAeadAesGcmEncrypt(ctx, TEST_IV, 0, [], aad)
         @Assert(sealed.size, 16)

         let recovered = quicAeadAesGcmDecrypt(ctx, TEST_IV, 0, sealed, aad)
         @Assert(recovered, [])
     }

     // ── ChaCha20-Poly1305 ────────────────────────────────────────

     @TestCase
     public func testAeadChaCha20Poly1305ContextRoundTrip(): Unit {
         let ctx = chacha20Poly1305NewContext(TEST_KEY_CHACHA)
         let pt = "hello quic chacha".toArray()
         let aad = "aad_chacha".toArray()

         let sealed = quicAeadChaCha20Encrypt(ctx, TEST_IV, 42, pt, aad)
         @Assert(sealed.size, pt.size + 16)

         let recovered = quicAeadChaCha20Decrypt(ctx, TEST_IV, 42, sealed, aad)
         @Assert(recovered, pt)
     }

     @TestCase
     public func testAeadChaCha20Poly1305ConveniencePath(): Unit {
         let pt = "hello quic chacha".toArray()
         let aad = "aad_chacha".toArray()

         let sealed = quicAeadEncrypt(TEST_KEY_CHACHA, TEST_IV, 7, pt, aad, QuicAeadAlgorithm.ChaCha20Poly1305)
         @Assert(sealed.size, pt.size + 16)

         let recovered = quicAeadDecrypt(TEST_KEY_CHACHA, TEST_IV, 7, sealed, aad, QuicAeadAlgorithm.ChaCha20Poly1305)
         @Assert(recovered, pt)
     }

     @TestCase
     public func testAeadChaCha20Poly1305WrongPnFails(): Unit {
         let ctx = chacha20Poly1305NewContext(TEST_KEY_CHACHA)
         let pt = "hello quic chacha".toArray()
         let aad = "aad_chacha".toArray()
         let sealed = quicAeadChaCha20Encrypt(ctx, TEST_IV, 42, pt, aad)

         try {
             _ = quicAeadChaCha20Decrypt(ctx, TEST_IV, 99, sealed, aad)
             @Fail("ChaCha20 AEAD should fail with wrong packet number")
         } catch (_: CryptoException) {
             @Assert(true)
         }
     }

     @TestCase
     public func testAeadChaCha20Poly1305EmptyPlaintext(): Unit {
         let ctx = chacha20Poly1305NewContext(TEST_KEY_CHACHA)
         let aad = "aad_chacha".toArray()

         let sealed = quicAeadChaCha20Encrypt(ctx, TEST_IV, 0, [], aad)
         @Assert(sealed.size, 16)

         let recovered = quicAeadChaCha20Decrypt(ctx, TEST_IV, 0, sealed, aad)
         @Assert(recovered, [])
     }

     @TestCase
     public func testAeadChaCha20Poly1305ShortCiphertextRejected(): Unit {
         let ctx = chacha20Poly1305NewContext(TEST_KEY_CHACHA)
         try {
             _ = quicAeadChaCha20Decrypt(ctx, TEST_IV, 0, hexToBytes("00"), hexToBytes(""))
             @Fail("short ciphertext should be rejected")
         } catch (_: CryptoException) {
             @Assert(true)
         }
     }

     // ── Cross-algorithm ──────────────────────────────────────────

     @TestCase
     public func testAeadDifferentAlgorithmsProduceDifferently(): Unit {
         let pt = "hello quic".toArray()
         let aad = "aad".toArray()

         let s128 = quicAeadEncrypt(TEST_KEY_128, TEST_IV, 7, pt, aad, QuicAeadAlgorithm.Aes128Gcm)
         let s256 = quicAeadEncrypt(TEST_KEY_256, TEST_IV, 7, pt, aad, QuicAeadAlgorithm.Aes256Gcm)
         let sChacha = quicAeadEncrypt(TEST_KEY_CHACHA, TEST_IV, 7, pt, aad, QuicAeadAlgorithm.ChaCha20Poly1305)

         @Assert(s128 != s256, true)
         @Assert(s128 != sChacha, true)
         @Assert(s256 != sChacha, true)
     }

     @TestCase
     public func testAeadAlgorithmCrossDecryptFails(): Unit {
         let pt = "hello quic".toArray()
         let aad = "aad".toArray()

         let sealed = quicAeadEncrypt(TEST_KEY_128, TEST_IV, 7, pt, aad, QuicAeadAlgorithm.Aes128Gcm)
         try {
             _ = quicAeadDecrypt(TEST_KEY_CHACHA, TEST_IV, 7, sealed, aad, QuicAeadAlgorithm.ChaCha20Poly1305)
             @Fail("cross-algorithm decryption should fail")
         } catch (_: CryptoException) {
             @Assert(true)
         }
     }

     @TestCase
     public func testAeadEnumToString(): Unit {
         @Assert(QuicAeadAlgorithm.Aes128Gcm.toString(), "AES-128-GCM")
         @Assert(QuicAeadAlgorithm.Aes256Gcm.toString(), "AES-256-GCM")
         @Assert(QuicAeadAlgorithm.ChaCha20Poly1305.toString(), "ChaCha20-Poly1305")
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
