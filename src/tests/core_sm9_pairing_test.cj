package jinguissl_core.tests

import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.sm9.{Sm9G2Point, sm9GeneratorG1, sm9GeneratorG2, sm9G1PointToBytes, sm9G2PointToBytes, sm9Pairing}

@Test
public class CoreSm9PairingTestSuite {
    @TestCase
    public func testStandardGeneratorsEncodeCanonically(): Unit {
        @Assert(
            sm9Hex(sm9G1PointToBytes(sm9GeneratorG1())),
            "93de051d62bf718ff5ed0704487d01d6e1e4086909dc3280e8c4e4817c66dddd" +
            "21fe8dda4f21e607631065125c395bbc1c1c00cbfa6024350c464cd70a3ea616"
        )
        @Assert(
            sm9Hex(sm9G2PointToBytes(sm9GeneratorG2())),
            "85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141" +
            "3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65b" +
            "17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96" +
            "a7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7"
        )
    }

    @TestCase
    public func testRatePairingPublishedVector(): Unit {
        let signingMasterPublic = Sm9G2Point(
            BigNum.fromHex("29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32"),
            BigNum.fromHex("9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408"),
            BigNum.fromHex("41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D"),
            BigNum.fromHex("69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25")
        )
        let expected =
            "4e378fb5561cd0668f906b731ac58fee25738edf09cadc7a29c0abc0177aea6d" +
            "28b3404a61908f5d6198815c99af1990c8af38655930058c28c21bb539ce0000" +
            "38bffe40a22d529a0c66124b2c308dac9229912656f62b4facfced408e02380f" +
            "a01f2c8bee81769609462c69c96aa923fd863e209d3ce26dd889b55e2e3873db" +
            "67e0e0c2eed7a6993dce28fe9aa2ef56834307860839677f96685f2b44d0911f" +
            "5a1ae172102efd95df7338dbc577c66d8d6c15e0a0158c7507228efb078f42a6" +
            "1604a3fcfa9783e667ce9fcb1062c2a5c6685c316dda62de0548baa6ba30038b" +
            "93634f44fa13af76169f3cc8fbea880adaff8475d5fd28a75deb83c44362b439" +
            "b3129a75d31d17194675a1bc56947920898fbf390a5bf5d931ce6cbb3340f66d" +
            "4c744e69c4a2e1c8ed72f796d151a17ce2325b943260fc460b9f73cb57c9014b" +
            "84b87422330d7936eaba1109fa5a7a7181ee16f2438b0aeb2f38fd5f7554e57a" +
            "aab9f06a4eeba4323a7833db202e4e35639d93fa3305af73f0f071d7d284fcfb"
        @Assert(sm9Hex(sm9Pairing(sm9GeneratorG1(), signingMasterPublic).toBytes()), expected)
    }

    private func sm9Hex(bytes: Array<Byte>): String {
        let alphabet: Array<String> = [
            "0", "1", "2", "3", "4", "5", "6", "7",
            "8", "9", "a", "b", "c", "d", "e", "f"
        ]
        var output = ""
        for (value in bytes) {
            output += alphabet[Int64(value >> UInt8(4))]
            output += alphabet[Int64(value & UInt8(0x0F))]
        }
        output
    }
}
