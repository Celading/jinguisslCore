package jinguissl_core.tests

import jinguissl_core.crypto.drbg.{Sm3HashDrbg, Sm4CtrDrbg}

@Test
public class CoreGmDrbgTestSuite {
    @TestCase
    public func testSm3HashDrbgCompatibilityVector(): Unit {
        let entropy = Array<Byte>(1000, repeat: UInt8(0xFF))
        let nonce = Array<Byte>(20, repeat: UInt8(0xFF))
        let personalization: Array<Byte> = [0, 1, 2, 3, 4, 5]
        let drbg = Sm3HashDrbg(entropy, nonce, personalization: personalization)
        @Assert(
            gmDrbgHex(drbg.generate(32)),
            "9caa4b0a7905006e0307c522fa8b83b8efb1e801b89c2040ce2cb9779385a210"
        )
    }

    @TestCase
    public func testSm4CtrDrbgCompatibilityVector(): Unit {
        let entropy = Array<Byte>(1000, repeat: UInt8(0xFF))
        let nonce = Array<Byte>(20, repeat: UInt8(0xFF))
        let personalization: Array<Byte> = [0, 1, 2, 3, 4, 5]
        let drbg = Sm4CtrDrbg(entropy, nonce, personalization: personalization)
        @Assert(
            gmDrbgHex(drbg.generateBytes(32)),
            "f23fa0ea91e9688afa388fe7a48026f8e6c98dd3d250cfef6456ebaf1de3eae8"
        )
    }

    @TestCase
    public func testDeterministicStateAdditionalInputAndReseed(): Unit {
        let entropy = Array<Byte>(32, repeat: UInt8(0x41))
        let nonce = Array<Byte>(16, repeat: UInt8(0x42))
        let first = Sm3HashDrbg(entropy, nonce)
        let second = Sm3HashDrbg(entropy, nonce)
        @Assert(gmDrbgHex(first.generate(16)), gmDrbgHex(second.generate(16)))
        @Assert(first.reseedCounter(), UInt64(2))

        let beforeReseed = first.generate(16, additionalInput: [UInt8(7)])
        first.reseed(Array<Byte>(32, repeat: UInt8(0x43)), additionalInput: [UInt8(8)])
        @Assert(first.reseedCounter(), UInt64(1))
        let afterReseed = first.generate(16)
        @Assert(gmDrbgHex(beforeReseed) == gmDrbgHex(afterReseed), false)
    }

    @TestCase
    public func testRequestLimitsAndUninstantiateFailClosed(): Unit {
        let entropy = Array<Byte>(32, repeat: UInt8(1))
        let nonce = Array<Byte>(16, repeat: UInt8(2))
        let ctr = Sm4CtrDrbg(entropy, nonce)
        var rejected = false
        try {
            ctr.generate(17)
        } catch (e: Exception) {
            rejected = true
        }
        @Assert(rejected, true)
        @Assert(ctr.generateBytes(48).size, 48)

        ctr.uninstantiate()
        rejected = false
        try {
            ctr.generate(16)
        } catch (e: Exception) {
            rejected = true
        }
        @Assert(rejected, true)
    }

    @TestCase
    public func testReseedRemainsAvailableAfterInterval(): Unit {
        let entropy = Array<Byte>(32, repeat: UInt8(3))
        let nonce = Array<Byte>(16, repeat: UInt8(4))
        let ctr = Sm4CtrDrbg(entropy, nonce)
        var i: Int64 = 0
        while (i < 1024) {
            ctr.generate(1)
            i += 1
        }

        var rejected = false
        try {
            ctr.generate(1)
        } catch (e: Exception) {
            rejected = true
        }
        @Assert(rejected, true)

        ctr.reseed(Array<Byte>(32, repeat: UInt8(5)))
        @Assert(ctr.reseedCounter(), UInt64(1))
        @Assert(ctr.generate(1).size, 1)
    }

    private func gmDrbgHex(bytes: Array<Byte>): String {
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
}
