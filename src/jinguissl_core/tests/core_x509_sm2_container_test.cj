package jinguissl_core.tests

import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.sm2.{Sm2PrivateKey, sm2PublicKey, sm2PublicKeyToUncompressed}
import jinguissl_core.crypto.x509.*

@Test
public class X509Sm2ContainerTestSuite {
    @TestCase
    public func testOpenHitlsSm2ContainerFixtures(): Unit {
        // Apache-2.0 openHiTLS fixture set, pinned at 26f152c627b6b429a73973f762c8b71bb582fa23:
        // testcode/testdata/cert/asn1/sm2_pkcs8/{sm2_pkcs8,sm2_pkcs1,sm2pub_pkcs1}.der
        let pkcs8 = gmHexToBytes(
            "308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420" +
            "c5983f142e49d2e2f2c55e216ac7a32803df0a0c5eb5134238e16204579cbea0a14403" +
            "420004a6a52df225c7064b5daf8defb3902e24e80a090abd1f74d60556f924bef62cd80" +
            "83d73107eae27bed467ed642c2781643ad0f557d089930503cbd1ab36584371"
        )
        let sec1 = gmHexToBytes(
            "30770201010420c5983f142e49d2e2f2c55e216ac7a32803df0a0c5eb5134238e16204" +
            "579cbea0a00a06082a811ccf5501822da14403420004a6a52df225c7064b5daf8defb39" +
            "02e24e80a090abd1f74d60556f924bef62cd8083d73107eae27bed467ed642c2781643a" +
            "d0f557d089930503cbd1ab36584371"
        )
        let spki = gmHexToBytes(
            "3059301306072a8648ce3d020106082a811ccf5501822d03420004a6a52df225c7064b5" +
            "daf8defb3902e24e80a090abd1f74d60556f924bef62cd8083d73107eae27bed467ed64" +
            "2c2781643ad0f557d089930503cbd1ab36584371"
        )
        let expectedScalar = "c5983f142e49d2e2f2c55e216ac7a32803df0a0c5eb5134238e16204579cbea0"
        let expectedPublic = gmHexToBytes(
            "04a6a52df225c7064b5daf8defb3902e24e80a090abd1f74d60556f924bef62cd8" +
            "083d73107eae27bed467ed642c2781643ad0f557d089930503cbd1ab36584371"
        )

        @Assert(x509ParseSm2PrivateKeyPkcs8Der(pkcs8).scalar.toHex(), expectedScalar)
        @Assert(x509ParseSm2PrivateKeySec1Der(sec1).scalar.toHex(), expectedScalar)
        @Assert(sm2PublicKeyToUncompressed(x509ParseSm2PublicKeyDer(spki)), expectedPublic)
    }

    @TestCase
    public func testSm2PublicSec1AndPkcs8RoundTrips(): Unit {
        let privateKey = gmTestPrivateKey()
        let expectedPublic = sm2PublicKeyToUncompressed(sm2PublicKey(privateKey))

        let publicDer = x509EncodeSm2PublicKeyDer(sm2PublicKey(privateKey))
        @Assert(
            sm2PublicKeyToUncompressed(x509ParseSm2PublicKeyDer(publicDer)),
            expectedPublic
        )
        @Assert(
            sm2PublicKeyToUncompressed(x509ParseSm2PublicKeyPem(
                x509EncodeSm2PublicKeyPem(sm2PublicKey(privateKey))
            )),
            expectedPublic
        )

        let sec1Der = x509EncodeSm2PrivateKeySec1Der(privateKey)
        @Assert(
            x509ParseSm2PrivateKeySec1Der(sec1Der).scalar.toHex(),
            privateKey.scalar.toHex()
        )
        @Assert(
            x509ParseSm2PrivateKeySec1Pem(
                x509EncodeSm2PrivateKeySec1Pem(privateKey)
            ).scalar.toHex(),
            privateKey.scalar.toHex()
        )

        let pkcs8Der = x509EncodeSm2PrivateKeyPkcs8Der(privateKey)
        @Assert(
            x509ParseSm2PrivateKeyPkcs8Der(pkcs8Der).scalar.toHex(),
            privateKey.scalar.toHex()
        )
        @Assert(
            x509ParseSm2PrivateKeyPkcs8Pem(
                x509EncodeSm2PrivateKeyPkcs8Pem(privateKey)
            ).scalar.toHex(),
            privateKey.scalar.toHex()
        )
    }

    @TestCase
    public func testSm2PrivateContainersRejectMismatchedEmbeddedPublicKey(): Unit {
        let privateKey = gmTestPrivateKey()
        let sec1Der = x509EncodeSm2PrivateKeySec1Der(privateKey)
        sec1Der[sec1Der.size - 1] ^= UInt8(1)
        var sec1Rejected = false
        try {
            _ = x509ParseSm2PrivateKeySec1Der(sec1Der)
        } catch (_: CryptoException) {
            sec1Rejected = true
        }
        @Assert(sec1Rejected, true)

        let pkcs8Der = x509EncodeSm2PrivateKeyPkcs8Der(privateKey)
        pkcs8Der[pkcs8Der.size - 1] ^= UInt8(1)
        var pkcs8Rejected = false
        try {
            _ = x509ParseSm2PrivateKeyPkcs8Der(pkcs8Der)
        } catch (_: CryptoException) {
            pkcs8Rejected = true
        }
        @Assert(pkcs8Rejected, true)
    }

    @TestCase
    public func testSm2CertificateRequestRoundTripAndIdentityBinding(): Unit {
        let request = x509CreateSm2CertificateRequest("gm-client.example", gmTestPrivateKey())
        @Assert(request.subject.commonName(), "gm-client.example")
        x509VerifySm2CertificateRequest(request)

        let fromDer = x509ParseSm2CertificateRequestDer(request.der)
        let fromPem = x509ParseSm2CertificateRequestPem(request.toPem())
        @Assert(fromDer.der, request.der)
        @Assert(fromPem.der, request.der)

        var wrongIdentityRejected = false
        try {
            x509VerifySm2CertificateRequest(request, signerIdentity: "wrong-sm2-id".toArray())
        } catch (_: CryptoException) {
            wrongIdentityRejected = true
        }
        @Assert(wrongIdentityRejected, true)

        let tamperedDer = request.der.clone()
        tamperedDer[tamperedDer.size - 1] ^= UInt8(1)
        var tamperRejected = false
        try {
            let tampered = x509ParseSm2CertificateRequestDer(tamperedDer)
            x509VerifySm2CertificateRequest(tampered)
        } catch (_: CryptoException) {
            tamperRejected = true
        }
        @Assert(tamperRejected, true)
    }

    @TestCase
    public func testSm2IssuerCertificateAndCrlLifecycle(): Unit {
        let rootPrivate = gmTestPrivateKey()
        let root = x509CreateSelfSignedSm2Certificate(
            X509SelfSignedConfig(
                "GM Test Root",
                serialNumber: [UInt8(0x10)],
                notBefore: "260101000000Z",
                notAfter: "360101000000Z",
                keyUsageMask: X509_KEY_USAGE_DIGITAL_SIGNATURE |
                    X509_KEY_USAGE_KEY_CERT_SIGN |
                    X509_KEY_USAGE_CRL_SIGN
            ),
            rootPrivate
        )
        let leafPrivate = Sm2PrivateKey(BigNum.fromHex(
            "59276e27d506861a16680f3ad9c02dcca6c3f21bdf45a6cdbf1a5c27b4062cc8"
        ))
        let leaf = x509CreateSm2Certificate(
            X509Sm2CertificateConfig(
                "gm-leaf.example",
                serialNumber: [UInt8(0x20), UInt8(0x01)],
                notBefore: "260101000000Z",
                notAfter: "300101000000Z",
                keyUsageMask: X509_KEY_USAGE_DIGITAL_SIGNATURE
            ),
            sm2PublicKey(leafPrivate),
            root,
            rootPrivate
        )
        @Assert(leaf.isSelfIssued(), false)
        @Assert(leaf.issuer.commonName(), "GM Test Root")
        x509VerifySignatureWithIssuer(leaf, root)
        x509VerifySm2SignatureWithIssuerIdentity(
            leaf, root, X509_SM2_DEFAULT_SIGNER_IDENTITY.toArray()
        )

        let validPolicy = X509VerificationPolicy(
            [root],
            validationTime: "270101000000Z"
        )
        @Assert(x509VerifyCertificateChain(leaf, validPolicy).chain.size, 2)

        let crl = x509CreateSm2Crl(
            X509Sm2CrlConfig(
                "270101000000Z",
                nextUpdate: "280101000000Z",
                revokedCertificates: [X509Sm2RevokedCertificate(
                    leaf.serialNumber,
                    "270101000000Z"
                )]
            ),
            root,
            rootPrivate
        )
        @Assert(crl.signatureAlgorithmOid, X509_OID_SM3_WITH_SM2)
        @Assert(crl.revokedSerialHexLower, [leaf.serialHexLower()])
        let parsedCrl = x509ParseCrlPem(x509CrlToPem(crl))
        x509VerifyCrlSignatureWithIssuer(parsedCrl, root)

        var revokedRejected = false
        try {
            _ = x509VerifyCertificateChain(
                leaf,
                X509VerificationPolicy(
                    [root],
                    crls: [parsedCrl],
                    requireCrlForAllIssuers: true,
                    validationTime: "270201000000Z"
                )
            )
        } catch (_: CryptoException) {
            revokedRejected = true
        }
        @Assert(revokedRejected, true)
    }

    @TestCase
    public func testSm2IssuanceAndCrlRejectWrongAuthorityOrIdentity(): Unit {
        let rootPrivate = gmTestPrivateKey()
        let root = x509CreateSelfSignedSm2Certificate(
            X509SelfSignedConfig(
                "GM Authority",
                keyUsageMask: X509_KEY_USAGE_KEY_CERT_SIGN | X509_KEY_USAGE_CRL_SIGN
            ),
            rootPrivate
        )
        let otherPrivate = Sm2PrivateKey(BigNum.one())
        var wrongKeyRejected = false
        try {
            _ = x509CreateSm2Certificate(
                X509Sm2CertificateConfig("wrong-authority.example"),
                sm2PublicKey(otherPrivate),
                root,
                otherPrivate
            )
        } catch (_: CryptoException) {
            wrongKeyRejected = true
        }
        @Assert(wrongKeyRejected, true)

        let crl = x509CreateSm2Crl(
            X509Sm2CrlConfig("270101000000Z"),
            root,
            rootPrivate
        )
        var wrongIdentityRejected = false
        try {
            x509VerifySm2CrlSignatureWithIssuerIdentity(
                crl, root, "wrong-sm2-id".toArray()
            )
        } catch (_: CryptoException) {
            wrongIdentityRejected = true
        }
        @Assert(wrongIdentityRejected, true)

        let tamperedDer = crl.der.clone()
        tamperedDer[tamperedDer.size - 1] ^= UInt8(1)
        var tamperRejected = false
        try {
            x509VerifyCrlSignatureWithIssuer(x509ParseCrlDer(tamperedDer), root)
        } catch (_: CryptoException) {
            tamperRejected = true
        }
        @Assert(tamperRejected, true)
    }
}

private func gmTestPrivateKey(): Sm2PrivateKey {
    Sm2PrivateKey(BigNum.fromHex(
        "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"
    ))
}

private func gmHexToBytes(hex: String): Array<Byte> {
    let chars = hex.toArray()
    let output = Array<Byte>(chars.size / 2, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < output.size) {
        output[i] = UInt8(gmHexNibble(chars[i * 2]) * 16 + gmHexNibble(chars[i * 2 + 1]))
        i += 1
    }
    output
}

private func gmHexNibble(value: Byte): Int64 {
    if (value >= UInt8(0x30) && value <= UInt8(0x39)) {
        return Int64(value - UInt8(0x30))
    }
    if (value >= UInt8(0x61) && value <= UInt8(0x66)) {
        return Int64(value - UInt8(0x61)) + 10
    }
    Int64(value - UInt8(0x41)) + 10
}
