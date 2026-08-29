package jinguissl_core.tests

import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.sm9.{
    Sm9EncryptionMasterPrivateKey,
    Sm9SignMasterPrivateKey,
    sm9BeginKeyExchangeWithNonce,
    sm9CompleteKeyExchange,
    sm9Decrypt,
    sm9EncryptWithNonce,
    sm9EncryptionMasterPublicKey,
    sm9ExtractEncryptionUserPrivateKey,
    sm9ExtractSignUserPrivateKey,
    sm9G1PointToBytes,
    sm9G2PointToBytes,
    sm9HashH1,
    sm9SignWithNonce,
    sm9Verify,
    sm9VerifyKeyExchangeConfirmation
}

@Test
public class CoreSm9SchemesTestSuite {
    @TestCase
    public func testH1AndPublishedSignatureVector(): Unit {
        @Assert(
            sm9SchemeHex(sm9HashH1(sm9SchemeHexBytes("416c69636501")).toBytesBE(paddedLen: 32)),
            "2acc468c3926b0bdb2767e99ff26e084de9ced8dbc7d5fbf418027b667862fab"
        )

        let master = Sm9SignMasterPrivateKey(
            BigNum.fromHex("0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4")
        )
        let alice = "Alice".toArray()
        let userKey = sm9ExtractSignUserPrivateKey(master, alice)
        @Assert(
            sm9SchemeHex(sm9G1PointToBytes(userKey.point)),
            "a5702f05cf1315305e2d6eb64b0deb923db1a0bcf0caff90523ac8754aa69820" +
            "78559a844411f9825c109f5ee3f52d720dd01785392a727bb1556952b2b013d3"
        )

        let message = "Chinese IBS standard".toArray()
        let signature = sm9SignWithNonce(
            userKey,
            message,
            BigNum.fromHex("033C8616B06704813203DFD00965022ED15975C662337AED648835DC4B1CBE")
        )
        @Assert(
            sm9SchemeHex(signature.toBytes()),
            "823c4b21e4bd2dfe1ed92c606653e996668563152fc33f55d7bfbb9bd9705adb" +
            "73bf96923ce58b6ad0e13e9643a406d8eb98417c50ef1b29cef9adb48b6d598c" +
            "856712f1c2e0968ab7769f42a99586aed139d5b8b3e15891827cc2aced9baa05"
        )
        @Assert(sm9Verify(userKey.masterPublicKey, alice, message, signature), true)
        @Assert(sm9Verify(userKey.masterPublicKey, alice, "Chinese IBS standarD".toArray(), signature), false)
    }

    @TestCase
    public func testPublishedEncryptionVectorAndTamperRejection(): Unit {
        let master = Sm9EncryptionMasterPrivateKey(
            BigNum.fromHex("0001EDEE3778F441F8DEA3D9FA0ACC4E07EE36C93F9A08618AF4AD85CEDE1C22")
        )
        let publicKey = sm9EncryptionMasterPublicKey(master)
        @Assert(
            sm9SchemeHex(sm9G1PointToBytes(publicKey.point)),
            "787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a892f" +
            "f769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f644c57a7b1"
        )
        let bob = "Bob".toArray()
        let userKey = sm9ExtractEncryptionUserPrivateKey(master, bob)
        @Assert(
            sm9SchemeHex(sm9G2PointToBytes(userKey.point)),
            "94736acd2c8c8796cc4785e938301a139a059d3537b6414140b2d31eecf41683" +
            "115bae85f5d8bc6c3dbd9e5342979acccf3c2f4f28420b1cb4f8c0b59a19b15" +
            "87aa5e47570da7600cd760a0cf7beaf71c447f3844753fe74fa7ba92ca7d3b55" +
            "f27538a62e7f7bfb51dce08704796d94c9d56734f119ea44732b50e31cdeb75c1"
        )
        let plaintext = "Chinese IBE standard".toArray()
        let ciphertext = sm9EncryptWithNonce(
            publicKey,
            bob,
            plaintext,
            BigNum.fromHex("AAC0541779C8FC45E3E2CB25C12B5D2576B2129AE8BB5EE2CBE5EC9E785C")
        )
        @Assert(
            sm9SchemeHex(ciphertext),
            "2445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff" +
            "42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac0" +
            "ba672387bcd6de5016a158a52bb2e7fc429197bcab70b25afee37a2b9db9f367" +
            "1b5f5b0e951489682f3e64e1378cdd5da9513b1c"
        )
        @Assert(sm9Decrypt(userKey, bob, ciphertext), plaintext)

        let tampered = ciphertext.clone()
        tampered[tampered.size - 1] ^= UInt8(0x01)
        var rejected = false
        try {
            _ = sm9Decrypt(userKey, bob, tampered)
        } catch (_: CryptoException) {
            rejected = true
        }
        @Assert(rejected, true)
    }

    @TestCase
    public func testPublishedAuthenticatedKeyExchangeVector(): Unit {
        let master = Sm9EncryptionMasterPrivateKey(
            BigNum.fromHex("0002E65B0762D042F51F0D23542B13ED8CFA2E9A0E7206361E013A283905E31F")
        )
        let aliceIdentity = "Alice".toArray()
        let bobIdentity = "Bob".toArray()
        let aliceKey = sm9ExtractEncryptionUserPrivateKey(master, aliceIdentity, hierarchy: UInt8(0x02))
        let bobKey = sm9ExtractEncryptionUserPrivateKey(master, bobIdentity, hierarchy: UInt8(0x02))
        let aliceState = sm9BeginKeyExchangeWithNonce(
            aliceKey,
            aliceIdentity,
            bobIdentity,
            BigNum.fromHex("5879DD1D51E175946F23B1B41E93BA31C584AE59A426EC1046A4D03B06C8"),
            hierarchy: UInt8(0x02)
        )
        @Assert(
            sm9SchemeHex(sm9G1PointToBytes(aliceState.ephemeralPublic)),
            "7cba5b19069ee66aa79d490413d11846b9ba76dd22567f809cf23b6d964bb265" +
            "a9760c99cb6f706343fed05637085864958d6c90902aba7d405fbedf7b781599"
        )
        let bobState = sm9BeginKeyExchangeWithNonce(
            bobKey,
            bobIdentity,
            aliceIdentity,
            BigNum.fromHex("018B98C44BEF9F8537FB7D071B2C928B3BC65BD3D69E1EEE213564905634FE"),
            hierarchy: UInt8(0x02)
        )
        let aliceResult = sm9CompleteKeyExchange(
            aliceState, bobState.ephemeralPublic, true, 16
        )
        let bobResult = sm9CompleteKeyExchange(
            bobState, aliceState.ephemeralPublic, false, 16
        )
        @Assert(sm9SchemeHex(aliceResult.key), "c5c13a8f59a97cdeae64f16a2272a9e7")
        @Assert(bobResult.key, aliceResult.key)
        @Assert(
            sm9SchemeHex(bobResult.sendConfirmation),
            "3bb4bcee8139c960b4d6566db1e0d5f0b2767680e5e1bf934103e6c66e40ffee"
        )
        @Assert(
            sm9SchemeHex(aliceResult.sendConfirmation),
            "195d1b7256ba7e0e67c71202a25f8c94ff8241702c2f55d613ae1c6b98215172"
        )
        @Assert(
            sm9VerifyKeyExchangeConfirmation(
                aliceResult.expectedPeerConfirmation, bobResult.sendConfirmation
            ),
            true
        )
        @Assert(
            sm9VerifyKeyExchangeConfirmation(
                bobResult.expectedPeerConfirmation, aliceResult.sendConfirmation
            ),
            true
        )
    }
}

private func sm9SchemeHex(bytes: Array<Byte>): String {
    let digits: Array<String> = [
        "0", "1", "2", "3", "4", "5", "6", "7",
        "8", "9", "a", "b", "c", "d", "e", "f"
    ]
    var result = ""
    for (byte in bytes) {
        let value = UInt8(byte)
        result += digits[Int64(value >> UInt8(4))]
        result += digits[Int64(value & UInt8(0x0F))]
    }
    result
}

private func sm9SchemeHexBytes(value: String): Array<Byte> {
    BigNum.fromHex(value).toBytesBE(paddedLen: value.size / 2)
}
