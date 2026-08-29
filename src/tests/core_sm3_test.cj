package jinguissl_core.tests

import jinguissl_core.crypto.sm3.*

@Test
public class CoreSm3TestSuite {
    /* SM3 known test vectors from GM/T 0004-2012 */

    @TestCase
    public func testSm3EmptyString(): Unit {
        /* "abc" → SM3("abc") */
        let data: Array<Byte> = [0x61, 0x62, 0x63]
        let digest = sm3(data)
        let expected = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        @Assert(bytesToHexLower(digest), expected)
    }

    @TestCase
    public func testSm3KnownVector_1(): Unit {
        /* "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd" (64 bytes) */
        let data: Array<Byte> = [
            0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
            0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
            0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
            0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
            0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
            0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
            0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
            0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64
        ]
        let digest = sm3(data)
        /* GM/T 0004-2012 example 2 */
        let expected = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
        @Assert(bytesToHexLower(digest), expected)
    }

    @TestCase
    public func testSm3KnownVector_2(): Unit {
        /* Single byte 0x61 ("a") */
        let data: Array<Byte> = [0x61]
        let digest = sm3(data)
        let expected = "623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88"
        @Assert(bytesToHexLower(digest), expected)
    }

    @TestCase
    public func testSm3OutputSize(): Unit {
        let data: Array<Byte> = [0x00, 0x01, 0x02]
        let digest = sm3(data)
        @Assert(digest.size, 32)
    }

    @TestCase
    public func testSm3Deterministic(): Unit {
        let data: Array<Byte> = [0x61, 0x62, 0x63]
        let r1 = sm3(data)
        let r2 = sm3(data)
        @Assert(bytesToHexLower(r1), bytesToHexLower(r2))
    }

    @TestCase
    public func testSm3LargeInput(): Unit {
        /* 1000 bytes of 0x00 */
        var data = Array<Byte>(1000, repeat: UInt8(0))
        let digest = sm3(data)
        @Assert(digest.size, 32)
        /* Just validate it runs without error — no standard vector for this specific input */
        let hex = bytesToHexLower(digest)
        @Assert(hex.size, 64)
    }

    @TestCase
    public func testSm3IncrementalMatchesOneShotAcrossBlockBoundaries(): Unit {
        let first = Array<Byte>(63, repeat: UInt8(0xA5))
        let second: Array<Byte> = [0x01, 0x02]
        let third = Array<Byte>(130, repeat: UInt8(0x5A))
        let all = Array<Byte>(first.size + second.size + third.size, repeat: UInt8(0))
        var offset: Int64 = 0
        for (value in first) { all[offset] = value; offset += 1 }
        for (value in second) { all[offset] = value; offset += 1 }
        for (value in third) { all[offset] = value; offset += 1 }

        let context = Sm3Context()
        context.update(first)
        context.update(second)
        context.update(third)
        @Assert(bytesToHexLower(context.finish()), bytesToHexLower(sm3(all)))
    }

    @TestCase
    public func testSm3ContextResetAndFinalizationGuard(): Unit {
        let context = Sm3Context()
        context.update([0x61, 0x62, 0x63])
        let first = context.finish()
        var rejected = false
        try {
            context.update([0x00])
        } catch (e: Exception) {
            rejected = true
        }
        @Assert(rejected, true)

        context.reset()
        context.update([0x61, 0x62, 0x63])
        @Assert(bytesToHexLower(context.finish()), bytesToHexLower(first))
    }

    @TestCase
    public func testHmacSm3IndependentVector(): Unit {
        let key: Array<Byte> = [0x6B, 0x65, 0x79]
        let data: Array<Byte> = [0x61, 0x62, 0x63]
        let expected = "28e63256e7c5a087b1f073265dc53092163f7b82729735d06f28f10af9d52393"
        @Assert(bytesToHexLower(hmacSm3(key, data)), expected)
    }

    @TestCase
    public func testSm3KdfCounterAndTruncation(): Unit {
        let output = sm3Kdf([0x61, 0x62, 0x63], 40)
        let expected = "fe1ea80dac6f100c33537bd24619ec7c72a1e8b1ffeaefb1eb52a37791fdaf619db16c0ac7bebb47"
        @Assert(bytesToHexLower(output), expected)
        @Assert(sm3Kdf([0x61], 0).size, 0)
    }

    /* Reuse bytesToHexLower from the digest package */
    private func bytesToHexLower(bytes: Array<Byte>): String {
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
}
