package jinguissl_core.tests

import jinguissl_core.crypto.sm4.*

@Test
public class CoreSm4ExtendedTestSuite {
    @TestCase
    public func testCfb128AndOfbCompatibilityVectors(): Unit {
        let key = extHex("2b7e151628aed2a6abf7158809cf4f3c")
        let iv = extHex("000102030405060708090a0b0c0d0e0f")
        let oneBlock = extHex("6bc1bee22e409f96e93d7e117393172a")
        let cfb = sm4CfbEncrypt(key, iv, oneBlock)
        @Assert(extHexOf(cfb), "bc710d762d070b26361da82b54565e46")
        @Assert(extHexOf(sm4CfbDecrypt(key, iv, cfb)), extHexOf(oneBlock))

        let message = extHex(
            "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411e5fbc1191a0a52ef" +
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        let expected =
            "bc710d762d070b26361da82b54565e46" +
            "07a0c62834740ad3240d239125e11621" +
            "d476b21cc9f04951f0741d2ef9e09498" +
            "1584fc142bf13aa626b82f9d7d076cce"
        let ofb = sm4OfbCrypt(key, iv, message)
        @Assert(extHexOf(ofb), expected)
        @Assert(extHexOf(sm4OfbCrypt(key, iv, ofb)), extHexOf(message))
    }

    @TestCase
    public func testXtsFullAndCiphertextStealingVector(): Unit {
        let key = extHex(
            "2b7e151628aed2a6abf7158809cf4f3c" +
            "000102030405060708090a0b0c0d0e0f"
        )
        let tweak = extHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        let plaintext = extHex(
            "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411e5fbc1191a0a52ef" +
            "f69f2445df4f9b17"
        )
        let expected =
            "e9538251c71d7b80bbe4483fef497bd1" +
            "2c5c581bd6242fc51e08964fb4f60fdb" +
            "0ba42f63499279213d318d2c11f6886e" +
            "903be7f93a1b3479"
        let encrypted = sm4XtsEncrypt(key, tweak, plaintext)
        @Assert(extHexOf(encrypted), expected)
        @Assert(extHexOf(sm4XtsDecrypt(key, tweak, encrypted)), extHexOf(plaintext))
    }

    @TestCase
    public func testHctrCompatibilityVectorAndRoundTrip(): Unit {
        let key = extHex(
            "2b7e151628aed2a6abf7158809cf4f3c" +
            "000102030405060708090a0b0c0d0e0f"
        )
        let tweak = extHex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        let plaintext = extHex(
            "6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411e5fbc1191a0a52ef" +
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        let expected =
            "9cd7481d3b7ca904b14b4084d9d4c83e" +
            "d39eac8e16747895fc2ae1eecd220276" +
            "af3d0d2f21cb3807561347c81ad13811" +
            "7dd85c652afe16a47dc68eb884068ae3"
        let encrypted = sm4HctrEncrypt(key, tweak, plaintext)
        @Assert(extHexOf(encrypted), expected)
        @Assert(extHexOf(sm4HctrDecrypt(key, tweak, encrypted)), extHexOf(plaintext))
    }

    @TestCase
    public func testCmacAndZeroPaddedCbcMacVectors(): Unit {
        let cmacKey = extHex("0a00000000000000d71d5e0000000000")
        let allOnes = extHex("ffffffffffffffffffffffffffffffff")
        @Assert(extHexOf(sm4Cmac(cmacKey, allOnes)), "ce837ff991368d769a3beff3260f32e6")

        let cbcKey = extHex("00000000000000000000000000000000")
        let cbcMessage = extHex("60437d010000000064fafee5787f0000")
        @Assert(extHexOf(sm4CbcMac(cbcKey, cbcMessage)), "dbbe98446572391ff7fc5a2a7c82dacc")
        @Assert(sm4Cmac(cmacKey, allOnes, tagLen: 8).size, 8)
    }

    @TestCase
    public func testExtendedModeBoundaryRejections(): Unit {
        var rejected = false
        try {
            sm4XtsEncrypt(
                Array<Byte>(32, repeat: UInt8(0)),
                Array<Byte>(16, repeat: UInt8(0)),
                Array<Byte>(16, repeat: UInt8(0))
            )
        } catch (e: Exception) {
            rejected = true
        }
        @Assert(rejected, true)

        rejected = false
        try {
            sm4HctrEncrypt(
                Array<Byte>(32, repeat: UInt8(1)),
                Array<Byte>(16, repeat: UInt8(2)),
                Array<Byte>(15, repeat: UInt8(3))
            )
        } catch (e: Exception) {
            rejected = true
        }
        @Assert(rejected, true)
    }

    private func extHexOf(bytes: Array<Byte>): String {
        let alphabet: Array<String> = [
            "0", "1", "2", "3", "4", "5", "6", "7",
            "8", "9", "a", "b", "c", "d", "e", "f"
        ]
        var output = ""
        var i: Int64 = 0
        while (i < bytes.size) {
            output += alphabet[Int64(bytes[i] >> UInt8(4))]
            output += alphabet[Int64(bytes[i] & UInt8(0x0F))]
            i += 1
        }
        output
    }

    private func extHex(value: String): Array<Byte> {
        let chars = value.toArray()
        let output = Array<Byte>(chars.size / 2, repeat: UInt8(0))
        var i: Int64 = 0
        while (i < output.size) {
            output[i] = UInt8(extNibble(chars[i * 2]) * 16 + extNibble(chars[i * 2 + 1]))
            i += 1
        }
        output
    }

    private func extNibble(value: Byte): Int64 {
        if (value >= UInt8(0x30) && value <= UInt8(0x39)) {
            return Int64(value - UInt8(0x30))
        }
        if (value >= UInt8(0x61) && value <= UInt8(0x66)) {
            return Int64(value - UInt8(0x61)) + 10
        }
        if (value >= UInt8(0x41) && value <= UInt8(0x46)) {
            return Int64(value - UInt8(0x41)) + 10
        }
        throw Exception("invalid hexadecimal digit")
    }
}
