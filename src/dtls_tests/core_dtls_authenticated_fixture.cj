package jinguissl_core.dtls_tests

import std.collection.ArrayList
import jinguissl_core.crypto.dtls.*
import jinguissl_core.crypto.x509.{x509CreateSelfSignedEcCertificate, X509SelfSignedConfig}
import jinguissl_core.crypto.ecc.{EcPrivateKey, NamedCurve, ecdsaSign}
import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.digest.{sha256, bytesToHexLower}

// Provider fixture: authenticates a real signature and Finished before testing export cleanup.
func dtlsAuthenticatedFixture(): DtlsHandshakeContext {
    let context = DtlsHandshakeContext(DtlsRole.Client)
    let peer = DtlsHandshakeContext(DtlsRole.Server)
    let key = EcPrivateKey(NamedCurve.P256, BigNum.fromHex("02"))
    let cert = x509CreateSelfSignedEcCertificate(X509SelfSignedConfig("dtls-fixture"), key)
    context.generateClientRandom()
    context.generateServerRandom()
    context.setPeerCertificate(cert.der)
    context.setExpectedFingerprint(bytesToHexLower(sha256(cert.der)))
    context.verifyPeerCertificateFingerprint()
    let params = dtlsBuildServerKeyExchangeEcdhe(peer.keyExchange.publicKey)
    let signed = ArrayList<Byte>()
    for (bytes in [context.clientRandom, context.serverRandom, params]) {
        for (b in bytes) { signed.add(b) }
    }
    let (r, s) = ecdsaSign(key, sha256(signed.toArray()))
    context.verifyServerKeyExchangeSignature(params, r, s)
    context.processPeerKeyExchange(peer.keyExchange.publicKey)
    context.recordHandshakeMessage(DtlsHandshakeType.ServerKeyExchange, UInt16(0), params)
    context.state = DtlsConnectionState.FinishedSent
    context.verifyPeerFinished(context.computeFinishedVerifyData("server finished"), "server finished")
    context.finalizeHandshake()
    context
}
