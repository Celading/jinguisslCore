package jinguissl_core.tests

import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.sm2.*

@Test
public class CoreSm2TestSuite {
    @TestCase
    public func testSm2GbSignatureVectorAndIdentityBinding(): Unit {
        let publicKey = sm2PublicKeyFromUncompressed(hexToBytes(
            "0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020" +
            "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13"
        ))
        let identity = hexToBytes("31323334353637383132333435363738")
        let message = hexToBytes("6d65737361676520646967657374")
        let r = BigNum.fromHex("f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3")
        let s = BigNum.fromHex("b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa")

        @Assert(sm2Verify(publicKey, identity, message, r, s), true)
        let wrongIdentity = identity.clone()
        wrongIdentity[0] ^= UInt8(1)
        @Assert(sm2Verify(publicKey, wrongIdentity, message, r, s), false)
        @Assert(
            bytesToHex(sm2ComputeZa(identity, publicKey)),
            "b2e14c5c79c6df5b85f4fe7ed8db7a262b9da7e07ccb0ea9f4747b8ccda8a4f3"
        )
    }

    @TestCase
    public func testSm2PublicDerivationAndRandomizedSignRoundTrip(): Unit {
        let privateKey = Sm2PrivateKey(BigNum.fromHex(
            "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"
        ))
        let publicKey = sm2PublicKey(privateKey)
        @Assert(
            bytesToHex(sm2PublicKeyToUncompressed(publicKey)),
            "0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020" +
            "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13"
        )
        let identity = hexToBytes("31323334353637383132333435363738")
        let message = hexToBytes("6d65737361676520646967657374")
        let (r, s) = sm2Sign(privateKey, identity, message)
        @Assert(sm2Verify(publicKey, identity, message, r, s), true)
        message[0] ^= UInt8(1)
        @Assert(sm2Verify(publicKey, identity, message, r, s), false)
    }

    @TestCase
    public func testSm2C1C3C2RoundTripAndTamperRejection(): Unit {
        let privateKey = Sm2PrivateKey(BigNum.fromHex(
            "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"
        ))
        let publicKey = sm2PublicKey(privateKey)
        let plaintext = hexToBytes("656e6372797074696f6e207374616e64617264")
        let publishedCiphertext = hexToBytes(
            "0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73" +
            "e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0" +
            "59983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd8766" +
            "21886ca989ca9c7d58087307ca93092d651efa"
        )
        @Assert(bytesToHex(sm2Decrypt(privateKey, publishedCiphertext)), bytesToHex(plaintext))

        let ciphertext = sm2Encrypt(publicKey, plaintext)
        @Assert(ciphertext[0], UInt8(0x04))
        @Assert(bytesToHex(sm2Decrypt(privateKey, ciphertext)), bytesToHex(plaintext))

        ciphertext[65] ^= UInt8(1)
        var rejected = false
        try {
            sm2Decrypt(privateKey, ciphertext)
        } catch (e: Exception) {
            rejected = true
        }
        @Assert(rejected, true)
    }

    @TestCase
    public func testSm2SharedPointSymmetry(): Unit {
        let first = Sm2PrivateKey(BigNum.fromHex(
            "81eb26e941bb5af16df116495f90695272ae2cd63d6c4ae1678418be48230029"
        ))
        let second = Sm2PrivateKey(BigNum.fromHex(
            "785129917d45a9ea5437a59356b82338eaadda6ceb199088f14ae10defa229b5"
        ))
        @Assert(
            bytesToHex(sm2SharedPoint(first, sm2PublicKey(second))),
            bytesToHex(sm2SharedPoint(second, sm2PublicKey(first)))
        )
    }

    @TestCase
    public func testSm2GbKeyExchangeVectorAndConfirmations(): Unit {
        let id = hexToBytes("31323334353637383132333435363738")
        let aStatic = Sm2PrivateKey(BigNum.fromHex(
            "81eb26e941bb5af16df116495f90695272ae2cd63d6c4ae1678418be48230029"
        ))
        let aEphemeral = Sm2PrivateKey(BigNum.fromHex(
            "d4de15474db74d06491c440d305e012400990f3e390c7e87153c12db2ea60bb3"
        ))
        let bStatic = Sm2PrivateKey(BigNum.fromHex(
            "785129917d45a9ea5437a59356b82338eaadda6ceb199088f14ae10defa229b5"
        ))
        let bEphemeral = Sm2PrivateKey(BigNum.fromHex(
            "7e07124814b309489125eaed101113164ebf0f3458c5bd88335c1f9d596243d6"
        ))
        let a = sm2InitiatorKeyExchange(
            aStatic,
            aEphemeral,
            sm2PublicKey(bStatic),
            sm2PublicKey(bEphemeral),
            id,
            id,
            16
        )
        let b = sm2ResponderKeyExchange(
            bStatic,
            bEphemeral,
            sm2PublicKey(aStatic),
            sm2PublicKey(aEphemeral),
            id,
            id,
            16
        )
        @Assert(bytesToHex(a.key), "6c89347354de2484c60b4ab1fde4c6e5")
        @Assert(bytesToHex(b.key), bytesToHex(a.key))
        @Assert(bytesToHex(a.expectedPeerConfirmation), "d3a0fe15dee185ceae907a6b595cc32a266ed7b3367e9983a896dc32fa20f8eb")
        @Assert(bytesToHex(a.sendConfirmation), "18c7894b3816df16cf07b05c5ec0bef5d655d58f779cc1b400a4f3884644db88")
        @Assert(bytesToHex(a.expectedPeerConfirmation), bytesToHex(b.sendConfirmation))
        @Assert(bytesToHex(a.sendConfirmation), bytesToHex(b.expectedPeerConfirmation))
        @Assert(sm2VerifyConfirmation(a.expectedPeerConfirmation, b.sendConfirmation), true)
        b.sendConfirmation[0] ^= UInt8(1)
        @Assert(sm2VerifyConfirmation(a.expectedPeerConfirmation, b.sendConfirmation), false)
    }

    @TestCase
    public func testSm2RejectsInvalidKeysAndEncodings(): Unit {
        var rejected = false
        try {
            Sm2PrivateKey(BigNum.zero())
        } catch (e: Exception) {
            rejected = true
        }
        @Assert(rejected, true)

        rejected = false
        try {
            sm2Sign(
                Sm2PrivateKey(BigNum.fromHex(
                    "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54122"
                )),
                [],
                [UInt8(1)]
            )
        } catch (e: Exception) {
            rejected = true
        }
        @Assert(rejected, true)

        rejected = false
        try {
            sm2PublicKeyFromUncompressed(Array<Byte>(65, repeat: UInt8(0)))
        } catch (e: Exception) {
            rejected = true
        }
        @Assert(rejected, true)
    }

    private func bytesToHex(bytes: Array<Byte>): String {
        let digits: Array<String> = [
            "0", "1", "2", "3", "4", "5", "6", "7",
            "8", "9", "a", "b", "c", "d", "e", "f"
        ]
        var output = ""
        for (value in bytes) {
            output += digits[Int64(value >> UInt8(4))]
            output += digits[Int64(value & UInt8(0x0F))]
        }
        output
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
