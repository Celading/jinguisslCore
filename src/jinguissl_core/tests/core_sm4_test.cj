package jinguissl_core.tests

import jinguissl_core.crypto.sm4.*

@Test
public class CoreSm4TestSuite {
    /* SM4 known test vectors from GM/T 0002-2012 */

    @TestCase
    public func testSm4EncryptDecryptSingleBlock(): Unit {
        /* Test vector from GB/T 32907-2016 / GM/T 0002-2012 */
        let key: Array<Byte> = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
        ]
        let plaintext: Array<Byte> = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
        ]
        let expectedCiphertext: Array<Byte> = [
            0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E,
            0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46
        ]
        let ciphertext = sm4Encrypt(key, plaintext)
        @Assert(arrToHex(ciphertext), arrToHex(expectedCiphertext))

        let decrypted = sm4Decrypt(key, ciphertext)
        @Assert(arrToHex(decrypted), arrToHex(plaintext))
    }

    @TestCase
    public func testSm4EncryptDecryptMultiBlock(): Unit {
        let key: Array<Byte> = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
        ]
        /* Two blocks (32 bytes) */
        var plaintext = Array<Byte>(32, repeat: UInt8(0))
        var i = 0
        while (i < 16) {
            plaintext[i] = UInt8(i)
            plaintext[i + 16] = UInt8(16 + i)
            i += 1
        }
        let ciphertext = sm4Encrypt(key, plaintext)
        @Assert(ciphertext.size, 32)

        let decrypted = sm4Decrypt(key, ciphertext)
        @Assert(arrToHex(decrypted), arrToHex(plaintext))
    }

    @TestCase
    public func testSm4DecryptSingleBlock(): Unit {
        /* Decrypt the known ciphertext back to plaintext */
        let key: Array<Byte> = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
        ]
        let ciphertext: Array<Byte> = [
            0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E,
            0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46
        ]
        let expectedPlaintext: Array<Byte> = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
        ]
        let decrypted = sm4Decrypt(key, ciphertext)
        @Assert(arrToHex(decrypted), arrToHex(expectedPlaintext))
    }

    @TestCase
    public func testSm4RoundTripZeroKey(): Unit {
        /* All-zero key and all-zero plaintext */
        var key = Array<Byte>(16, repeat: UInt8(0))
        var plaintext = Array<Byte>(16, repeat: UInt8(0))
        let ciphertext = sm4Encrypt(key, plaintext)
        @Assert(ciphertext.size, 16)
        let decrypted = sm4Decrypt(key, ciphertext)
        @Assert(arrToHex(decrypted), arrToHex(plaintext))
    }

    @TestCase
    public func testSm4Deterministic(): Unit {
        let key: Array<Byte> = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
        ]
        let plaintext: Array<Byte> = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
        ]
        let r1 = sm4Encrypt(key, plaintext)
        let r2 = sm4Encrypt(key, plaintext)
        @Assert(arrToHex(r1), arrToHex(r2))
    }

    @TestCase
    public func testSm4InvalidKeySize(): Unit {
        let key = Array<Byte>(15, repeat: UInt8(0xAB))
        let data = Array<Byte>(16, repeat: UInt8(0))
        try {
            sm4Encrypt(key, data)
            @Assert(false, true)  /* Should not reach here */
        } catch (e: Exception) {
            @Assert(true, true)  /* Expected exception */
        }
    }

    @TestCase
    public func testSm4InvalidDataSize(): Unit {
        let key = Array<Byte>(16, repeat: UInt8(0xAB))
        let data = Array<Byte>(15, repeat: UInt8(0))
        try {
            sm4Encrypt(key, data)
            @Assert(false, true)  /* Should not reach here */
        } catch (e: Exception) {
            @Assert(true, true)  /* Expected exception */
        }
    }

    @TestCase
    public func testSm4CbcAndCtrPublishedVectors(): Unit {
        let key = hexToBytes("2b7e151628aed2a6abf7158809cf4f3c")
        let plaintext = hexToBytes(
            "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411e5fbc1191a0a52ef" +
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        let cbcIv = hexToBytes("000102030405060708090a0b0c0d0e0f")
        let cbcExpected =
            "ac529af989a62fce9cddc5ffb84125ca" +
            "b168dd69db3c0eea1ab16de6aea43c59" +
            "2c15567bff8f707486c202c7be59101f" +
            "74a629b350cd7e11be99998af5206d6c"
        let cbc = sm4CbcEncrypt(key, cbcIv, plaintext)
        @Assert(arrToHex(cbc), cbcExpected)
        @Assert(arrToHex(sm4CbcDecrypt(key, cbcIv, cbc)), arrToHex(plaintext))

        let counter = hexToBytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        let ctrExpected =
            "14ae4a72b97a93ce1216ccd998e371c1" +
            "60f7ef8b6344bd6da1992505e5fc219b" +
            "0bf057f86c5d75103c0f46519c7fb2e7" +
            "292805035adb9a90ecef145359d7cf0e"
        let ctr = sm4CtrCrypt(key, counter, plaintext)
        @Assert(arrToHex(ctr), ctrExpected)
        @Assert(arrToHex(sm4CtrCrypt(key, counter, ctr)), arrToHex(plaintext))
    }

    @TestCase
    public func testSm4EcbAndCbcPkcs7StrictRoundTrip(): Unit {
        let key = hexToBytes("0123456789abcdeffedcba9876543210")
        let iv = hexToBytes("000102030405060708090a0b0c0d0e0f")
        let plaintext = hexToBytes("00112233445566778899aabbcc")
        let ecb = sm4EcbEncrypt(key, plaintext, pkcs7: true)
        @Assert(arrToHex(sm4EcbDecrypt(key, ecb, pkcs7: true)), arrToHex(plaintext))
        let cbc = sm4CbcEncrypt(key, iv, plaintext, pkcs7: true)
        @Assert(arrToHex(sm4CbcDecrypt(key, iv, cbc, pkcs7: true)), arrToHex(plaintext))

        cbc[cbc.size - 1] ^= UInt8(1)
        var rejected = false
        try {
            sm4CbcDecrypt(key, iv, cbc, pkcs7: true)
        } catch (e: Exception) {
            rejected = true
        }
        @Assert(rejected, true)
    }

    @TestCase
    public func testSm4GcmRfc8998VectorAndTamperRejection(): Unit {
        let key = hexToBytes("0123456789abcdeffedcba9876543210")
        let iv = hexToBytes("00001234567800000000abcd")
        let aad = hexToBytes("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        let plaintext = hexToBytes(
            "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb" +
            "ccccccccccccccccdddddddddddddddd" +
            "eeeeeeeeeeeeeeeeffffffffffffffff" +
            "eeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa"
        )
        let expectedCiphertext =
            "17f399f08c67d5ee19d0dc9969c4bb7d" +
            "5fd46fd3756489069157b282bb200735" +
            "d82710ca5c22f0ccfa7cbf93d496ac15" +
            "a56834cbcf98c397b4024a2691233b8d"
        let expectedTag = "83de3541e4c2b58177e065a9bf7b62ec"
        let (ciphertext, tag) = sm4GcmEncrypt(key, iv, plaintext, aad: aad)
        @Assert(arrToHex(ciphertext), expectedCiphertext)
        @Assert(arrToHex(tag), expectedTag)
        @Assert(arrToHex(sm4GcmDecrypt(key, iv, ciphertext, tag, aad: aad)), arrToHex(plaintext))

        tag[0] ^= UInt8(1)
        var rejected = false
        try {
            sm4GcmDecrypt(key, iv, ciphertext, tag, aad: aad)
        } catch (e: Exception) {
            rejected = true
        }
        @Assert(rejected, true)
    }

    @TestCase
    public func testSm4CcmRfc8998VectorAndTamperRejection(): Unit {
        let key = hexToBytes("0123456789abcdeffedcba9876543210")
        let nonce = hexToBytes("00001234567800000000abcd")
        let aad = hexToBytes("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        let plaintext = hexToBytes(
            "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb" +
            "ccccccccccccccccdddddddddddddddd" +
            "eeeeeeeeeeeeeeeeffffffffffffffff" +
            "eeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa"
        )
        let expectedCiphertext =
            "48af93501fa62adbcd414cce6034d895" +
            "dda1bf8f132f042098661572e7483094" +
            "fd12e518ce062c98acee28d95df4416b" +
            "ed31a2f04476c18bb40c84a74b97dc5b"
        let expectedTag = "16842d4fa186f56ab33256971fa110f4"
        let (ciphertext, tag) = sm4CcmEncrypt(key, nonce, plaintext, aad: aad)
        @Assert(arrToHex(ciphertext), expectedCiphertext)
        @Assert(arrToHex(tag), expectedTag)
        @Assert(arrToHex(sm4CcmDecrypt(key, nonce, ciphertext, tag, aad: aad)), arrToHex(plaintext))

        tag[tag.size - 1] ^= UInt8(1)
        var rejected = false
        try {
            sm4CcmDecrypt(key, nonce, ciphertext, tag, aad: aad)
        } catch (e: Exception) {
            rejected = true
        }
        @Assert(rejected, true)
    }

    private func arrToHex(bytes: Array<Byte>): String {
        let hexChars: Array<String> = [
            "0", "1", "2", "3", "4", "5", "6", "7",
            "8", "9", "a", "b", "c", "d", "e", "f"
        ]
        var result = ""
        var i = 0
        while (i < bytes.size) {
            let b = Int64(bytes[i])
            result = result + hexChars[(b >> 4) & 0xF] + hexChars[b & 0xF]
            i += 1
        }
        result
    }

    private func hexToBytes(hex: String): Array<Byte> {
        let chars = hex.toArray()
        let output = Array<Byte>(chars.size / 2, repeat: UInt8(0))
        var i: Int64 = 0
        while (i < output.size) {
            output[i] = UInt8(hexNibble(chars[i * 2]) * 16 + hexNibble(chars[i * 2 + 1]))
            i += 1
        }
        output
    }

    private func hexNibble(value: Byte): Int64 {
        if (value >= UInt8(0x30) && value <= UInt8(0x39)) {
            return Int64(value - UInt8(0x30))
        }
        if (value >= UInt8(0x61) && value <= UInt8(0x66)) {
            return Int64(value - UInt8(0x61)) + 10
        }
        Int64(value - UInt8(0x41)) + 10
    }
}
