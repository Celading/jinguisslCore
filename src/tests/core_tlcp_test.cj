package jinguissl_core.tests

import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.sm2.{Sm2PrivateKey, sm2PublicKey, sm2PublicKeyToUncompressed}
import jinguissl_core.crypto.tls.*
import jinguissl_core.crypto.x509.*

@Test
public class CoreTlcpTestSuite {
    @TestCase
    public func testOwnedSessionRejectsValidMacWithIncorrectFinished(): Unit {
        let c = tlcpTestCredentials(sharedPeerName: true)
        let identity = TlcpIdentity(c.signingPrivateKey.scalar.toBytesBE(paddedLen: 32),
            c.encryptionPrivateKey.scalar.toBytesBE(paddedLen: 32), c.signingCertificate.der, c.encryptionCertificate.der)
        let server = TlcpSession(TlcpRole.Server, c.rootCertificate.toPem(), "270101000000Z",
            identity: Some(identity), policy: TlcpProviderPolicy(cipherSuites: [ECC_SM4_GCM_SM3]))
        identity.destroy(); server.start(0)
        let ch = tlcpBuildClientHello(cipherSuites: [ECC_SM4_GCM_SM3])
        _ = server.receive(tlcpEncodeRecord(Handshake, ch), 0)
        let flight = server.takeOutput()
        let (_, sh) = tlcpDecodeRecord(flight[0])
        let (cke, preMaster) = tlcpBuildEccClientKeyExchange(sm2PublicKey(c.encryptionPrivateKey))
        let secrets = tlcpDeriveSecretsFromPreMaster(preMaster, tlcpDecodeClientHello(ch).random,
            tlcpDecodeServerHello(sh).random, ECC_SM4_GCM_SM3)
        let layer = tlcpCreateClientRecordLayer(secrets)
        secrets.destroy()
        for (i in 0..preMaster.size) { preMaster[i] = 0 }
        _ = server.receive(tlcpEncodeRecord(Handshake, cke), 0)
        _ = server.receive(tlcpEncodeRecord(ChangeCipherSpec, [UInt8(1)]), 0)
        let invalidFinished = Array<Byte>(16, repeat: 0); invalidFinished[0] = 20; invalidFinished[3] = 12
        tlcpAssertPolicyRefused("finished-verification-failed", { =>
            _ = server.receive(layer.seal(Handshake, invalidFinished), 0)
        })
        @Assert(server.handshakeComplete, false); @Assert(server.isClosed, true)
        layer.destroy()
    }

    @TestCase
    public func testClientHelloScsvAndFreshServerSessionId(): Unit {
        let c = tlcpTestCredentials(sharedPeerName: true)
        let (client, server) = tlcpSessionPair(c, ECC_SM4_GCM_SM3)
        let (_, hello) = tlcpDecodeRecord(client.takeOutput()[0])
        @Assert(tlcpDecodeClientHello(hello).secureRenegotiation, true)
        let sh = tlcpEncodeServerHello(TlcpServerHello(tlcpTestBytes(32, 1), ECC_SM4_GCM_SM3,
            sessionId: [UInt8(1), 2], extensions: [TlsExtension(0xff01, [UInt8(0)])]))
        _ = client.receive(tlcpEncodeRecord(Handshake, sh), 0)
        @Assert(client.handshakeComplete, false); @Assert(client.isClosed, false)
        tlcpAssertPolicyRefused("invalid-clock", { => client.onTimeout(-1) })
        server.close()
    }

    @TestCase
    public func testOwnedSessionsAuthenticateAllFourSuitesAndClose(): Unit {
        let c = tlcpTestCredentials(sharedPeerName: true)
        for (suite in tlcpDefaultCipherSuites()) {
            let (client, server) = tlcpSessionPair(c, suite)
            @Assert(client.handshakeComplete, false)
            tlcpAssertPolicyRefused("not-authenticated", { => _ = client.sealApplicationData([]) })
            tlcpPump(client, server)
            @Assert(client.handshakeComplete, true); @Assert(server.handshakeComplete, true)
            @Assert(client.peerAuthenticated, true)
            @Assert(server.peerAuthenticated, suite.usesEcdhe())
            @Assert(client.selectedCipherSuite(), suite)
            let received = server.receive(client.sealApplicationData("hello".toArray()), 5)
            @Assert(received.size, 1); @Assert(received[0], "hello".toArray())
            @Assert(client.receive(server.sealApplicationData("world".toArray()), 6)[0], "world".toArray())
            client.closeNotify()
            for (bytes in client.takeOutput()) { _ = server.receive(bytes, 7) }
            @Assert(client.isClosed, true); @Assert(server.isClosed, true)
            server.endOfInput()
            tlcpAssertPolicyRefused("closed", { => _ = client.sealApplicationData([]) })
        }
    }

    @TestCase
    public func testOwnedSessionRejectsHostnameStateTimeoutAndRecordTampering(): Unit {
        let c = tlcpTestCredentials(sharedPeerName: true)
        let (client, server) = tlcpSessionPair(c, ECC_SM4_GCM_SM3)
        tlcpAssertPolicyRefused("not-authenticated", { => _ = server.receive(tlcpEncodeRecord(ApplicationData, [UInt8(1)]), 0) })
        @Assert(server.isClosed, true); client.close()
        let (timed, unused) = tlcpSessionPair(c, ECC_SM4_GCM_SM3)
        tlcpAssertPolicyRefused("timeout", { => timed.onTimeout(30000) })
        @Assert(timed.isClosed, true); unused.close()
        let (badHost, hostServer) = tlcpSessionPair(c, ECC_SM4_GCM_SM3, dns: "wrong.example")
        for (b in badHost.takeOutput()) { _ = hostServer.receive(b, 0) }
        tlcpAssertPolicyRefused("certificate-verification-failed", { =>
            for (b in hostServer.takeOutput()) { _ = badHost.receive(b, 0) }
        })
        @Assert(badHost.isClosed, true); hostServer.close()
        let (a, b) = tlcpSessionPair(c, ECC_SM4_GCM_SM3)
        tlcpPump(a, b)
        let wire = a.sealApplicationData([UInt8(1)]); wire[wire.size - 1] ^= UInt8(1)
        tlcpAssertPolicyRefused("bad-record-mac", { => _ = b.receive(wire, 6) })
        @Assert(b.isClosed, true); a.close()
        let (truncated, other) = tlcpSessionPair(c, ECC_SM4_GCM_SM3)
        tlcpAssertPolicyRefused("truncated-stream", { => truncated.endOfInput() })
        other.close()
    }

    @TestCase
    public func testOwnedSessionRejectsSignatureFinishedAndCcsSplicing(): Unit {
        let c = tlcpTestCredentials(sharedPeerName: true)
        for (badKind in [Int64(12), 20, 99]) {
            let (client, server) = tlcpSessionPair(c, ECC_SM4_GCM_SM3)
            for (wire in client.takeOutput()) { _ = server.receive(wire, 0) }
            if (badKind == 12) {
                tlcpAssertPolicyRefused("signature-verification-failed", { =>
                    for (wire in server.takeOutput()) {
                        if (wire[5] == UInt8(12)) { wire[wire.size - 1] ^= UInt8(1) }
                        _ = client.receive(wire, 0)
                    }
                })
            } else if (badKind == 99) {
                tlcpAssertPolicyRefused("invalid-state", { => _ = client.receive(tlcpEncodeRecord(ChangeCipherSpec, [UInt8(1)]), 0) })
            } else {
                for (wire in server.takeOutput()) { _ = client.receive(wire, 0) }
                let flight = client.takeOutput()
                tlcpAssertPolicyRefused("bad-record-mac", { =>
                    for (i in 0..flight.size) {
                        if (i == flight.size - 1) { flight[i][flight[i].size - 1] ^= UInt8(1) }
                        _ = server.receive(flight[i], 0)
                    }
                })
                @Assert(server.handshakeComplete, false)
            }
            client.close(); server.close()
        }
    }

    @TestCase
    public func testOwnedIdentitySnapshotsMismatchAndDestruction(): Unit {
        let c = tlcpTestCredentials()
        let signing = c.signingPrivateKey.scalar.toBytesBE(paddedLen: 32)
        let encryption = c.encryptionPrivateKey.scalar.toBytesBE(paddedLen: 32)
        let identity = TlcpIdentity(signing, encryption,
            c.signingCertificate.der, c.encryptionCertificate.der)
        let expected = identity.certificateHandshake()
        let changed = identity.certificateHandshake()
        changed[0] = 0
        @Assert(identity.certificateHandshake(), expected)
        @Assert(identity.isDestroyed, false)
        identity.destroy(); identity.destroy()
        @Assert(identity.isDestroyed, true)
        @Assert(signing, c.signingPrivateKey.scalar.toBytesBE(paddedLen: 32))
        tlcpAssertRejected({ => _ = TlcpIdentity(encryption, signing,
            c.signingCertificate.der, c.encryptionCertificate.der) })
        tlcpAssertRejected({ => _ = TlcpIdentity(encryption, signing,
            c.encryptionCertificate.der, c.signingCertificate.der) })
        tlcpAssertRejected({ => _ = TlcpIdentity([], encryption,
            c.signingCertificate.der, c.encryptionCertificate.der) })
    }

    @TestCase
    public func testDestroyedSecretsAndRecordLayersRejectReuse(): Unit {
        for (suite in tlcpDefaultCipherSuites()) {
            let secrets = tlcpDeriveSecretsFromPreMaster(tlcpTestBytes(48, 1),
                tlcpTestBytes(32, 2), tlcpTestBytes(32, 3), suite)
            let layer = tlcpCreateClientRecordLayer(secrets)
            secrets.destroy(); secrets.destroy()
            @Assert(secrets.isDestroyed, true)
            @Assert(secrets.masterSecret, Array<Byte>(48, repeat: 0))
            tlcpAssertRejected({ => _ = tlcpCreateServerRecordLayer(secrets) })
            tlcpAssertRejected({ => _ = dtlcpCreateClientRecordLayer(secrets) })
            // Existing record layers own independent keys until explicitly retired.
            _ = layer.seal(ApplicationData, [UInt8(1)])
            layer.destroy(); layer.destroy()
            @Assert(layer.isDestroyed, true)
            tlcpAssertRejected({ => _ = layer.seal(ApplicationData, []) })
            tlcpAssertRejected({ => _ = layer.open([]) })
        }
    }

    @TestCase
    public func testProviderPolicyRefusesUnsupportedRequestsAndClonesSuites(): Unit {
        let suites = [TlcpCipherSuite.ECC_SM4_GCM_SM3]
        let policy = TlcpProviderPolicy(cipherSuites: suites, handshakeTimeoutMs: 1)
        suites[0] = ECDHE_SM4_CBC_SM3
        let copy = policy.cipherSuites(); copy[0] = ECDHE_SM4_GCM_SM3
        @Assert(policy.cipherSuites()[0], ECC_SM4_GCM_SM3)
        tlcpAssertPolicyRefused("unsupported-alpn", { => _ = TlcpProviderPolicy(alpnProtocols: ["http/1.1"]) })
        tlcpAssertPolicyRefused("unsupported-http2", { => _ = TlcpProviderPolicy(requireHttp2: true) })
        tlcpAssertPolicyRefused("unsupported-resumption", { => _ = TlcpProviderPolicy(requestResumption: true) })
        tlcpAssertPolicyRefused("unsupported-certification", { => _ = TlcpProviderPolicy(requireCertifiedImplementation: true) })
        tlcpAssertPolicyRefused("invalid-policy", { => _ = TlcpProviderPolicy(cipherSuites: []) })
        tlcpAssertPolicyRefused("invalid-policy", { => _ = TlcpProviderPolicy(cipherSuites: [ECC_SM4_CBC_SM3, ECC_SM4_CBC_SM3]) })
        tlcpAssertPolicyRefused("invalid-policy", { => _ = TlcpProviderPolicy(handshakeTimeoutMs: 0) })
        tlcpAssertPolicyRefused("invalid-policy", { => _ = TlcpProviderPolicy(handshakeTimeoutMs: 120001) })
    }

    @TestCase
    public func testEcdheClientKeyExchangeNamedCurveWireVector(): Unit {
        let publicKey = sm2PublicKey(tlcpPrivateKey("01"))
        let encoded = tlcpBuildEcdheClientKeyExchange(publicKey)
        @Assert(encoded[..8], [UInt8(16), 0, 0, 69, 3, 0, 41, 65])
        @Assert(encoded[8..], sm2PublicKeyToUncompressed(publicKey))
        @Assert(sm2PublicKeyToUncompressed(tlcpParseEcdheClientKeyExchange(encoded)), encoded[8..])
        let wrongCurve = encoded.clone(); wrongCurve[6] = 23
        tlcpAssertRejected({ => _ = tlcpParseEcdheClientKeyExchange(wrongCurve) })
        let legacy = Array<Byte>(70, repeat: 0)
        legacy[0] = 16; legacy[3] = 66; legacy[4] = 65
        tlcpAssertRejected({ => _ = tlcpParseEcdheClientKeyExchange(legacy) })
    }

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

private func tlcpAssertPolicyRefused(reason: String, action: () -> Unit): Unit {
    var actual = ""
    try { action() } catch (e: TlcpProviderException) { actual = e.reason }
    @Assert(actual, reason)
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

private func tlcpTestCredentials(sharedPeerName!: Bool = false): TlcpTestCredentials {
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
            if (sharedPeerName) { "tlcp-sign.example" } else { "tlcp-enc.example" },
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

private func tlcpSessionPair(c: TlcpTestCredentials, suite: TlcpCipherSuite,
    dns!: String = "tlcp-sign.example"): (TlcpSession, TlcpSession) {
    let identity = TlcpIdentity(c.signingPrivateKey.scalar.toBytesBE(paddedLen: 32),
        c.encryptionPrivateKey.scalar.toBytesBE(paddedLen: 32), c.signingCertificate.der, c.encryptionCertificate.der)
    let policy = TlcpProviderPolicy(cipherSuites: [suite])
    let client = TlcpSession(TlcpRole.Client, c.rootCertificate.toPem(), "270101000000Z",
        expectedPeerDnsName: dns, identity: Some(identity), policy: policy)
    let server = TlcpSession(TlcpRole.Server, c.rootCertificate.toPem(), "270101000000Z",
        identity: Some(identity), policy: policy)
    identity.destroy()
    client.start(0); server.start(0)
    (client, server)
}

private func tlcpPump(client: TlcpSession, server: TlcpSession): Unit {
    for (_ in 0..4) {
        // Split even record headers; join all handshake records in the opposite direction.
        for (wire in client.takeOutput()) {
            for (i in 0..wire.size) { _ = server.receive(wire[i..(i + 1)], 0) }
        }
        var flight: Array<Byte> = []
        for (wire in server.takeOutput()) { flight = tlcpConcatForTest(flight, wire) }
        if (flight.size > 0) { _ = client.receive(flight, 0) }
    }
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
