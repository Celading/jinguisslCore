package jinguissl_core.tests

import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.digest.HashAlgorithm
import jinguissl_core.crypto.sm2.*
import jinguissl_core.crypto.sm3.sm3
import jinguissl_core.crypto.tls.*
import jinguissl_core.crypto.x509.*

@Test
public class Tls13SmProfileTestSuite {
    @TestCase
    public func testRfc8998RegistryMappings(): Unit {
        @Assert(TLS13_CIPHER_SUITE_SM4_GCM_SM3, 0x00c6)
        @Assert(TLS13_CIPHER_SUITE_SM4_CCM_SM3, 0x00c7)
        @Assert(TLS13_SIG_SCHEME_SM2_SM3, 0x0708)
        @Assert(TLS13_GROUP_CURVE_SM2, 41)
        @Assert(tls13CipherSuiteAeadAlgorithm(TLS13_CIPHER_SUITE_SM4_GCM_SM3), SM4_GCM)
        @Assert(tls13CipherSuiteAeadAlgorithm(TLS13_CIPHER_SUITE_SM4_CCM_SM3), SM4_CCM)
        @Assert(tls13CipherSuiteHashAlgorithm(TLS13_CIPHER_SUITE_SM4_GCM_SM3), HashAlgorithm.SM3)
        @Assert(tls13CipherSuiteKeyLen(TLS13_CIPHER_SUITE_SM4_CCM_SM3), 16)
        @Assert(tls13CipherSuiteIvLen(TLS13_CIPHER_SUITE_SM4_GCM_SM3), 12)
    }

    @TestCase
    public func testRfc8998HelloAndCurveSm2KeyShares(): Unit {
        let clientPrivate = testSm2PrivateA()
        let serverPrivate = testSm2PrivateB()
        let clientPublic = sm2PublicKey(clientPrivate)
        let serverPublic = sm2PublicKey(serverPrivate)

        let clientHello = tls13BuildClientHelloSm2(clientPublic)
        let extractedClient = tls13ExtractClientSm2KeyShare(clientHello)
        @Assert(sm2PublicKeyToUncompressed(extractedClient), sm2PublicKeyToUncompressed(clientPublic))

        let serverHello = tls13BuildServerHelloForSm2(clientHello, serverPublic)
        let extractedServer = tls13ExtractServerSm2KeyShare(serverHello)
        @Assert(sm2PublicKeyToUncompressed(extractedServer), sm2PublicKeyToUncompressed(serverPublic))
        @Assert(tlsDecodeServerHelloHandshake(serverHello).cipherSuite, TLS13_CIPHER_SUITE_SM4_GCM_SM3)
    }

    @TestCase
    public func testRfc8998Sm3ScheduleAndSm4RecordRoundTrip(): Unit {
        let clientPrivate = testSm2PrivateA()
        let serverPrivate = testSm2PrivateB()
        let clientPublic = sm2PublicKey(clientPrivate)
        let serverPublic = sm2PublicKey(serverPrivate)
        let clientHello = tls13BuildClientHelloSm2(clientPublic)
        let serverHello = tls13BuildServerHelloForSm2(clientHello, serverPublic)
        let transcriptHash = sm3(concatSmTestBytes(clientHello, serverHello))

        for (suite in [TLS13_CIPHER_SUITE_SM4_GCM_SM3, TLS13_CIPHER_SUITE_SM4_CCM_SM3]) {
            let clientSecrets = tls13DeriveSecretsFromSm2ForCipherSuite(
                clientPrivate,
                serverPublic,
                transcriptHash,
                suite
            )
            let serverSecrets = tls13DeriveSecretsFromSm2ForCipherSuite(
                serverPrivate,
                clientPublic,
                transcriptHash,
                suite
            )
            @Assert(clientSecrets.hashAlgorithm, HashAlgorithm.SM3)
            @Assert(clientSecrets.clientWriteKey, serverSecrets.clientWriteKey)
            @Assert(clientSecrets.serverWriteKey, serverSecrets.serverWriteKey)

            let clientLayer = tls13CreateClientRecordLayerHandle(clientSecrets, suite)
            let serverLayer = tls13CreateServerRecordLayerHandle(serverSecrets, suite)
            let plaintext = "RFC8998-Cangjie-record".toArray()
            let encoded = clientLayer.seal(ApplicationData, plaintext)
            let opened = serverLayer.open(encoded)
            @Assert(opened.contentType, ApplicationData)
            @Assert(opened.fragment, plaintext)
        }
    }

    @TestCase
    public func testRfc8998Sm2CertificateVerifyIdentityBinding(): Unit {
        let privateKey = testSm2PrivateA()
        let publicKey = sm2PublicKey(privateKey)
        let transcriptHash = sm3("RFC8998 transcript".toArray())
        let encoded = tls13BuildServerCertificateVerifySm2(privateKey, transcriptHash)
        @Assert(tls13VerifyServerCertificateVerifySm2(encoded, publicKey, transcriptHash), true)
        transcriptHash[0] ^= UInt8(1)
        @Assert(tls13VerifyServerCertificateVerifySm2(encoded, publicKey, transcriptHash), false)
        @Assert(TLS13_SM2_SIGNATURE_IDENTITY, "TLSv1.3+GM+Cipher+Suite")
    }

    @TestCase
    public func testRfc8998Sm2X509MinimumPath(): Unit {
        let privateKey = testSm2PrivateA()
        let certificate = x509CreateSelfSignedSm2Certificate(
            X509SelfSignedConfig(
                "rfc8998.local",
                keyUsageMask: X509_KEY_USAGE_DIGITAL_SIGNATURE
            ),
            privateKey
        )
        @Assert(certificate.signatureAlgorithmOid, X509_OID_SM3_WITH_SM2)
        @Assert(
            sm2PublicKeyToUncompressed(x509ExtractSm2PublicKey(certificate)),
            sm2PublicKeyToUncompressed(sm2PublicKey(privateKey))
        )
        x509VerifySignatureWithIssuer(certificate, certificate)

        let transcriptHash = sm3("RFC8998 certificate transcript".toArray())
        let certificateVerify = tls13BuildServerCertificateVerifySm2(privateKey, transcriptHash)
        @Assert(
            tls13VerifyServerCertificateVerify(certificateVerify, certificate, transcriptHash),
            true
        )
    }
}

private func testSm2PrivateA(): Sm2PrivateKey {
    Sm2PrivateKey(BigNum.fromHex(
        "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"
    ))
}

private func testSm2PrivateB(): Sm2PrivateKey {
    Sm2PrivateKey(BigNum.fromHex(
        "81eb26e941bb5af16df116495f90695272ae2cd63d6c4ae1678418be48230029"
    ))
}

private func concatSmTestBytes(left: Array<Byte>, right: Array<Byte>): Array<Byte> {
    let output = Array<Byte>(left.size + right.size, repeat: UInt8(0))
    var i = 0
    while (i < left.size) {
        output[i] = left[i]
        i += 1
    }
    i = 0
    while (i < right.size) {
        output[left.size + i] = right[i]
        i += 1
    }
    output
}
