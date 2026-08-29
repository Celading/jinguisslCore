package jinguissl_core.tests

import std.fs.*
import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.digest.sha256
import jinguissl_core.crypto.ecc.*
import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.tls.*
import jinguissl_core.crypto.x509.{
    X509SelfSignedConfig,
    X509VerificationPolicy,
    x509CreateSelfSignedEcCertificate,
    x509ParseEcPrivateKeyPkcs8Pem,
    x509ParsePem
}

@Test
public class Tls13ClientAuthSecurityTestSuite {
    @TestCase
    public func testRequiredClientAuthRejectsUntrustedAndTamperedProofs(): Unit {
        let leaf = x509ParsePem(readText("testdata/x509/policy_leaf.pem"))
        let intermediate = x509ParsePem(readText("testdata/x509/policy_intermediate.pem"))
        let root = x509ParsePem(readText("testdata/x509/policy_root.pem"))
        let privateKey = x509ParseEcPrivateKeyPkcs8Pem(
            readText("testdata/x509/policy_leaf_key_pkcs8.pem")
        )
        let transcriptHash = sha256("c198-required-client-auth-transcript".toArray())
        let clientHsTrafficSecret = sha256("c198-required-client-auth-secret".toArray())
        let encodedRequest = tls13BuildCertificateRequestHandshake(
            requestContext: [UInt8(0xc1), UInt8(0x98)],
            signatureSchemes: [TLS13_SIG_SCHEME_ECDSA_SECP256R1_SHA256],
            certificateAuthorities: [intermediate.subject.der]
        )
        let flight = tls13BuildClientAuthFlightForCertificateRequest(
            [leaf.der, intermediate.der],
            encodedRequest,
            transcriptHash,
            clientHsTrafficSecret,
            certificatePrivateKeyEcdsa: privateKey
        )
        let policy = X509VerificationPolicy([root], validationTime: "230101000000Z")
        let verified = tls13VerifyClientAuthFlightForCertificateRequest(
            flight,
            encodedRequest,
            policy,
            transcriptHash,
            clientHsTrafficSecret
        )
        @Assert(verified.chain.size, 3)

        let unrelatedRoot = x509CreateSelfSignedEcCertificate(
            X509SelfSignedConfig("c198-unrelated-client-auth-root"),
            EcPrivateKey(P256, BigNum.fromHex("03"))
        )
        let unrelatedPolicy = X509VerificationPolicy(
            [unrelatedRoot],
            validationTime: "230101000000Z"
        )
        try {
            _ = tls13VerifyClientAuthFlightForCertificateRequest(
                flight,
                encodedRequest,
                unrelatedPolicy,
                transcriptHash,
                clientHsTrafficSecret
            )
            @Fail("required TLS1.3 client auth must reject an untrusted client chain")
        } catch (_: CryptoException) {}

        let tamperedVerify = flight.certificateVerifyHandshake.clone()
        tamperedVerify[tamperedVerify.size - 1] = UInt8(tamperedVerify[tamperedVerify.size - 1]) ^ UInt8(0x01)
        try {
            _ = tls13VerifyClientAuthFlightForCertificateRequest(
                Tls13AuthFlight(
                    Tls13AuthFlightRole.CLIENT,
                    flight.certificateHandshake,
                    tamperedVerify,
                    flight.finishedHandshake
                ),
                encodedRequest,
                policy,
                transcriptHash,
                clientHsTrafficSecret
            )
            @Fail("required TLS1.3 client auth must reject tampered CertificateVerify")
        } catch (_: CryptoException) {}

        try {
            _ = tls13VerifyClientAuthFlightForCertificateRequest(
                flight,
                encodedRequest,
                policy,
                sha256("c198-wrong-client-auth-transcript".toArray()),
                clientHsTrafficSecret
            )
            @Fail("required TLS1.3 client auth must reject a mismatched transcript")
        } catch (_: CryptoException) {}

        let tamperedFinished = flight.finishedHandshake.clone()
        tamperedFinished[tamperedFinished.size - 1] = UInt8(tamperedFinished[tamperedFinished.size - 1]) ^ UInt8(0x01)
        try {
            _ = tls13VerifyClientAuthFlightForCertificateRequest(
                Tls13AuthFlight(
                    Tls13AuthFlightRole.CLIENT,
                    flight.certificateHandshake,
                    flight.certificateVerifyHandshake,
                    tamperedFinished
                ),
                encodedRequest,
                policy,
                transcriptHash,
                clientHsTrafficSecret
            )
            @Fail("required TLS1.3 client auth must reject tampered Finished")
        } catch (_: CryptoException) {}
    }
}

private func readText(path: String): String {
    if (!exists(path)) {
        throw Exception("missing test file: ${path}")
    }
    String.fromUtf8(File.readFrom(path))
}
