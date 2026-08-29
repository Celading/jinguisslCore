package jinguissl_core.tests

import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.sm2.{Sm2PrivateKey, sm2PublicKey, sm2PublicKeyToUncompressed}
import jinguissl_core.crypto.tls.*
import jinguissl_core.crypto.x509.*

@Test
public class CoreTlcpTestSuite {
    @TestCase
    public func testOpenHitlsTlcpSurfaceConstantsAndHelloNegotiation(): Unit {
        @Assert(TLCP_VERSION, 0x0101)
        @Assert(TLCP_SM2_NAMED_GROUP, 41)
        let suites = tlcpDefaultCipherSuites()
        @Assert(suites.size, 4)
        @Assert(suites[0].wireValue(), 0xe011)
        @Assert(suites[1].wireValue(), 0xe013)
        @Assert(suites[2].wireValue(), 0xe051)
        @Assert(suites[3].wireValue(), 0xe053)

        let clientRandom = tlcpTestBytes(32, UInt8(0x10))
        let client = TlcpClientHello(
            clientRandom,
            [ECC_SM4_GCM_SM3, ECDHE_SM4_CBC_SM3],
            sessionId: [UInt8(1), UInt8(2)]
        )
        let encodedClient = tlcpEncodeClientHello(client)
        let decodedClient = tlcpDecodeClientHello(encodedClient)
        @Assert(decodedClient.random, clientRandom)
        @Assert(decodedClient.sessionId, [UInt8(1), UInt8(2)])
        @Assert(decodedClient.cipherSuites.size, 2)

        let encodedServer = tlcpBuildServerHello(
            encodedClient,
            supportedSuites: [ECDHE_SM4_CBC_SM3, ECC_SM4_GCM_SM3]
        )
        let server = tlcpDecodeServerHello(encodedServer)
        @Assert(server.cipherSuite, ECDHE_SM4_CBC_SM3)

        let badVersion = encodedClient.clone()
        badVersion[4] = UInt8(0x03)
        tlcpAssertRejected({ => _ = tlcpDecodeClientHello(badVersion) })
    }

    @TestCase
    public func testTlcpDualCertificateRolesAndStaticEccHandshake(): Unit {
        let credentials = tlcpTestCredentials()
        let encodedCertificates = tlcpBuildDualCertificateHandshake(
            credentials.signingCertificate.der,
            credentials.encryptionCertificate.der
        )
        let bundle = tlcpParseDualCertificateHandshake(encodedCertificates)
        let verified = tlcpVerifyDualCertificateBundle(
            bundle,
            X509VerificationPolicy(
                [credentials.rootCertificate],
                requiredLeafKeyUsageMask: X509_KEY_USAGE_DIGITAL_SIGNATURE,
                validationTime: "270101000000Z"
            )
        )
        @Assert(verified.signingResult.chain.size, 2)
        @Assert(verified.encryptionResult.chain.size, 2)

        let swapped = TlcpCertificateBundle(
            credentials.encryptionCertificate, credentials.signingCertificate
        )
        tlcpAssertRejected({ =>
            _ = tlcpVerifyDualCertificateBundle(
                swapped,
                X509VerificationPolicy(
                    [credentials.rootCertificate], validationTime: "270101000000Z"
                )
            )
        })

        let clientRandom = tlcpTestBytes(32, UInt8(0x21))
        let serverRandom = tlcpTestBytes(32, UInt8(0x81))
        let serverKeyExchange = tlcpBuildEccServerKeyExchange(
            credentials.signingPrivateKey,
            credentials.encryptionCertificate,
            clientRandom,
            serverRandom
        )
        tlcpVerifyEccServerKeyExchange(
            serverKeyExchange,
            credentials.signingCertificate,
            credentials.encryptionCertificate,
            clientRandom,
            serverRandom
        )

        let (clientKeyExchange, clientPreMaster) = tlcpBuildEccClientKeyExchange(
            sm2PublicKey(credentials.encryptionPrivateKey)
        )
        let serverPreMaster = tlcpProcessEccClientKeyExchange(
            credentials.encryptionPrivateKey, clientKeyExchange
        )
        @Assert(serverPreMaster, clientPreMaster)

        for (suite in [ECC_SM4_CBC_SM3, ECC_SM4_GCM_SM3]) {
            let clientSecrets = tlcpDeriveSecretsFromPreMaster(
                clientPreMaster, clientRandom, serverRandom, suite
            )
            let serverSecrets = tlcpDeriveSecretsFromPreMaster(
                serverPreMaster, clientRandom, serverRandom, suite
            )
            tlcpAssertSecretsEqual(clientSecrets, serverSecrets)
            tlcpAssertBidirectionalRecordRoundTrip(clientSecrets)

            let transcript = tlcpConcatForTest(
                tlcpConcatForTest(encodedCertificates, serverKeyExchange), clientKeyExchange
            )
            let clientFinished = tlcpBuildFinishedHandshake(
                clientSecrets.masterSecret, transcript, true
            )
            tlcpVerifyFinishedHandshake(
                clientFinished, serverSecrets.masterSecret, transcript, true
            )
            let tampered = clientFinished.clone()
            tampered[tampered.size - 1] ^= UInt8(1)
            tlcpAssertRejected({ =>
                tlcpVerifyFinishedHandshake(
                    tampered, serverSecrets.masterSecret, transcript, true
                )
            })
        }
    }

    @TestCase
    public func testTlcpEcdheHandshakeAndIdentityBinding(): Unit {
        let credentials = tlcpTestCredentials()
        let clientStatic = tlcpPrivateKey(
            "81eb26e941bb5af16df116495f90695272ae2cd63d6c4ae1678418be48230029"
        )
        let clientEphemeral = tlcpPrivateKey(
            "d4de15474db74d06491c440d305e012400990f3e390c7e87153c12db2ea60bb3"
        )
        let serverEphemeral = tlcpPrivateKey(
            "7e07124814b309489125eaed101113164ebf0f3458c5bd88335c1f9d596243d6"
        )
        let clientRandom = tlcpTestBytes(32, UInt8(0x31))
        let serverRandom = tlcpTestBytes(32, UInt8(0x91))

        let serverKeyExchange = tlcpBuildEcdheServerKeyExchange(
            sm2PublicKey(serverEphemeral),
            credentials.signingPrivateKey,
            clientRandom,
            serverRandom
        )
        let parsedServerEphemeral = tlcpParseAndVerifyEcdheServerKeyExchange(
            serverKeyExchange,
            credentials.signingCertificate,
            clientRandom,
            serverRandom
        )
        @Assert(
            sm2PublicKeyToUncompressed(parsedServerEphemeral),
            sm2PublicKeyToUncompressed(sm2PublicKey(serverEphemeral))
        )
        tlcpAssertRejected({ =>
            _ = tlcpParseAndVerifyEcdheServerKeyExchange(
                serverKeyExchange,
                credentials.signingCertificate,
                clientRandom,
                serverRandom,
                signerIdentity: "wrong-tlcp-id".toArray()
            )
        })

        let clientKeyExchange = tlcpBuildEcdheClientKeyExchange(sm2PublicKey(clientEphemeral))
        let parsedClientEphemeral = tlcpParseEcdheClientKeyExchange(clientKeyExchange)
        for (suite in [ECDHE_SM4_CBC_SM3, ECDHE_SM4_GCM_SM3]) {
            let clientSecrets = tlcpDeriveEcdheClientSecrets(
                clientStatic,
                clientEphemeral,
                sm2PublicKey(credentials.encryptionPrivateKey),
                parsedServerEphemeral,
                clientRandom,
                serverRandom,
                suite
            )
            let serverSecrets = tlcpDeriveEcdheServerSecrets(
                credentials.encryptionPrivateKey,
                serverEphemeral,
                sm2PublicKey(clientStatic),
                parsedClientEphemeral,
                clientRandom,
                serverRandom,
                suite
            )
            tlcpAssertSecretsEqual(clientSecrets, serverSecrets)
            tlcpAssertBidirectionalRecordRoundTrip(clientSecrets)
        }
    }

    @TestCase
    public func testTlcpStaticEccConcealsInvalidCiphertext(): Unit {
        let credentials = tlcpTestCredentials()
        let (encoded, expected) = tlcpBuildEccClientKeyExchange(
            sm2PublicKey(credentials.encryptionPrivateKey)
        )
        let tampered = encoded.clone()
        tampered[tampered.size - 1] ^= UInt8(1)
        let fallback = tlcpProcessEccClientKeyExchange(
            credentials.encryptionPrivateKey, tampered
        )
        @Assert(fallback.size, TLCP_PREMASTER_SECRET_LEN)
        @Assert(fallback[0], UInt8(0x01))
        @Assert(fallback[1], UInt8(0x01))
        @Assert(fallback == expected, false)
    }

    @TestCase
    public func testTlcpRecordRejectsTamperWithoutConsumingSequence(): Unit {
        let preMaster = tlcpTestBytes(48, UInt8(0x40))
        let clientRandom = tlcpTestBytes(32, UInt8(0x01))
        let serverRandom = tlcpTestBytes(32, UInt8(0x61))
        for (suite in [ECC_SM4_CBC_SM3, ECC_SM4_GCM_SM3]) {
            let secrets = tlcpDeriveSecretsFromPreMaster(
                preMaster, clientRandom, serverRandom, suite
            )
            let sender = tlcpCreateClientRecordLayer(secrets)
            let receiver = tlcpCreateServerRecordLayer(secrets)
            let encoded = sender.seal(ApplicationData, "authenticated TLCP".toArray())
            let tampered = encoded.clone()
            tampered[tampered.size - 1] ^= UInt8(1)
            tlcpAssertRejected({ => _ = receiver.open(tampered) })
            @Assert(receiver.readSequence, 0)
            @Assert(receiver.open(encoded).fragment, "authenticated TLCP".toArray())
            @Assert(receiver.readSequence, 1)
        }
    }
}

private class TlcpTestCredentials {
    let rootCertificate: X509Certificate
    let signingCertificate: X509Certificate
    let encryptionCertificate: X509Certificate
    let signingPrivateKey: Sm2PrivateKey
    let encryptionPrivateKey: Sm2PrivateKey

    init(
        rootCertificate: X509Certificate,
        signingCertificate: X509Certificate,
        encryptionCertificate: X509Certificate,
        signingPrivateKey: Sm2PrivateKey,
        encryptionPrivateKey: Sm2PrivateKey
    ) {
        this.rootCertificate = rootCertificate
        this.signingCertificate = signingCertificate
        this.encryptionCertificate = encryptionCertificate
        this.signingPrivateKey = signingPrivateKey
        this.encryptionPrivateKey = encryptionPrivateKey
    }
}

private func tlcpTestCredentials(): TlcpTestCredentials {
    let rootPrivateKey = tlcpPrivateKey(
        "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"
    )
    let signingPrivateKey = tlcpPrivateKey(
        "59276e27d506861a16680f3ad9c02dcca6c3f21bdf45a6cdbf1a5c27b4062cc8"
    )
    let encryptionPrivateKey = tlcpPrivateKey(
        "785129917d45a9ea5437a59356b82338eaadda6ceb199088f14ae10defa229b5"
    )
    let rootCertificate = x509CreateSelfSignedSm2Certificate(
        X509SelfSignedConfig(
            "TLCP Test Root",
            serialNumber: [UInt8(0x41)],
            keyUsageMask: X509_KEY_USAGE_KEY_CERT_SIGN | X509_KEY_USAGE_CRL_SIGN
        ),
        rootPrivateKey
    )
    let signingCertificate = x509CreateSm2Certificate(
        X509Sm2CertificateConfig(
            "tlcp-sign.example",
            serialNumber: [UInt8(0x42)],
            keyUsageMask: X509_KEY_USAGE_DIGITAL_SIGNATURE |
                X509_KEY_USAGE_CONTENT_COMMITMENT
        ),
        sm2PublicKey(signingPrivateKey),
        rootCertificate,
        rootPrivateKey
    )
    let encryptionCertificate = x509CreateSm2Certificate(
        X509Sm2CertificateConfig(
            "tlcp-enc.example",
            serialNumber: [UInt8(0x43)],
            keyUsageMask: X509_KEY_USAGE_KEY_ENCIPHERMENT |
                X509_KEY_USAGE_DATA_ENCIPHERMENT |
                X509_KEY_USAGE_KEY_AGREEMENT
        ),
        sm2PublicKey(encryptionPrivateKey),
        rootCertificate,
        rootPrivateKey
    )
    TlcpTestCredentials(
        rootCertificate,
        signingCertificate,
        encryptionCertificate,
        signingPrivateKey,
        encryptionPrivateKey
    )
}

private func tlcpPrivateKey(scalarHex: String): Sm2PrivateKey {
    Sm2PrivateKey(BigNum.fromHex(scalarHex))
}

private func tlcpAssertSecretsEqual(
    first: TlcpHandshakeSecrets, second: TlcpHandshakeSecrets
): Unit {
    @Assert(first.masterSecret, second.masterSecret)
    @Assert(first.clientMacKey, second.clientMacKey)
    @Assert(first.serverMacKey, second.serverMacKey)
    @Assert(first.clientWriteKey, second.clientWriteKey)
    @Assert(first.serverWriteKey, second.serverWriteKey)
    @Assert(first.clientWriteIv, second.clientWriteIv)
    @Assert(first.serverWriteIv, second.serverWriteIv)
}

private func tlcpAssertBidirectionalRecordRoundTrip(secrets: TlcpHandshakeSecrets): Unit {
    let client = tlcpCreateClientRecordLayer(secrets)
    let server = tlcpCreateServerRecordLayer(secrets)
    let request = "client TLCP request".toArray()
    let response = "server TLCP response".toArray()
    let openedRequest = server.open(client.seal(ApplicationData, request))
    @Assert(openedRequest.contentType, ApplicationData)
    @Assert(openedRequest.fragment, request)
    let openedResponse = client.open(server.seal(Handshake, response))
    @Assert(openedResponse.contentType, Handshake)
    @Assert(openedResponse.fragment, response)
}

private func tlcpTestBytes(size: Int64, start: Byte): Array<Byte> {
    let output = Array<Byte>(size, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < size) {
        output[i] = UInt8((Int64(start) + i) & 0xff)
        i += 1
    }
    output
}

private func tlcpConcatForTest(left: Array<Byte>, right: Array<Byte>): Array<Byte> {
    let output = Array<Byte>(left.size + right.size, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < left.size) { output[i] = left[i]; i += 1 }
    var j: Int64 = 0
    while (j < right.size) { output[left.size + j] = right[j]; j += 1 }
    output
}

private func tlcpAssertRejected(action: () -> Unit): Unit {
    var rejected = false
    try {
        action()
    } catch (_: CryptoException) {
        rejected = true
    }
    @Assert(rejected, true)
}
