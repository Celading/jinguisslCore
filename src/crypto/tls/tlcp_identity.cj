package jinguissl_core.crypto.tls

import std.sync.Mutex
import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}
import jinguissl_core.crypto.sm2.{Sm2PrivateKey, sm2PublicKey, sm2PublicKeyToUncompressed}
import jinguissl_core.crypto.utils.constantTimeEquals
import jinguissl_core.crypto.x509.{x509ParseDer, x509ExtractSm2PublicKey,
    X509_KEY_USAGE_DIGITAL_SIGNATURE, X509_KEY_USAGE_CONTENT_COMMITMENT,
    X509_KEY_USAGE_KEY_ENCIPHERMENT, X509_KEY_USAGE_DATA_ENCIPHERMENT, X509_KEY_USAGE_KEY_AGREEMENT}

/** Owned dual-certificate identity. Private scalars never leave this public API.
 * destroy() wipes owned byte buffers and revokes future copies. It cannot erase
 * caller inputs, previously created sessions, or managed BigNum temporaries. */
public class TlcpIdentity {
    private let mutex = Mutex()
    private let signingScalar: Array<Byte>
    private let encryptionScalar: Array<Byte>
    private let certificateMessage: Array<Byte>
    private var destroyed: Bool = false

    public init(signingPrivateScalar: Array<Byte>, encryptionPrivateScalar: Array<Byte>,
        signingCertificateDer: Array<Byte>, encryptionCertificateDer: Array<Byte>,
        intermediateDer!: Array<Array<Byte>> = []) {
        if (signingPrivateScalar.size != 32 || encryptionPrivateScalar.size != 32) {
            throw CryptoException(InvalidArgument, "TLCP identity requires two 32-byte SM2 scalars")
        }
        let signingKey = Sm2PrivateKey(BigNum.fromBytesBE(signingPrivateScalar))
        let encryptionKey = Sm2PrivateKey(BigNum.fromBytesBE(encryptionPrivateScalar))
        let signingCert = x509ParseDer(signingCertificateDer)
        let encryptionCert = x509ParseDer(encryptionCertificateDer)
        tlcpRequireCertificateUsage(signingCert,
            X509_KEY_USAGE_DIGITAL_SIGNATURE | X509_KEY_USAGE_CONTENT_COMMITMENT, "TLCP signing identity")
        tlcpRequireCertificateUsage(encryptionCert, X509_KEY_USAGE_KEY_ENCIPHERMENT |
            X509_KEY_USAGE_DATA_ENCIPHERMENT | X509_KEY_USAGE_KEY_AGREEMENT, "TLCP encryption identity")
        if (!constantTimeEquals(sm2PublicKeyToUncompressed(sm2PublicKey(signingKey)),
            sm2PublicKeyToUncompressed(x509ExtractSm2PublicKey(signingCert))) ||
            !constantTimeEquals(sm2PublicKeyToUncompressed(sm2PublicKey(encryptionKey)),
            sm2PublicKeyToUncompressed(x509ExtractSm2PublicKey(encryptionCert)))) {
            throw CryptoException(InvalidArgument, "TLCP certificate/private key mismatch")
        }
        // n-1 is a valid encryption scalar but cannot sign SM2 messages.
        if (signingKey.scalar.add(BigNum.one()).cmp(BigNum.fromHex(
            "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123")) == 0) {
            throw CryptoException(InvalidArgument, "TLCP signing scalar cannot be n-1")
        }
        this.certificateMessage = tlcpBuildDualCertificateHandshake(signingCertificateDer,
            encryptionCertificateDer, intermediateDer: intermediateDer)
        this.signingScalar = signingPrivateScalar.clone()
        this.encryptionScalar = encryptionPrivateScalar.clone()
    }
    private init(signing: Array<Byte>, encryption: Array<Byte>, message: Array<Byte>) {
        signingScalar = signing.clone(); encryptionScalar = encryption.clone()
        certificateMessage = message.clone()
    }
    public prop isDestroyed: Bool { get() { synchronized(mutex) { destroyed } } }
    public func certificateHandshake(): Array<Byte> { certificateMessage.clone() }
    public func destroy(): Unit {
        synchronized(mutex) {
            destroyed = true
            tlcpWipe(signingScalar); tlcpWipe(encryptionScalar)
        }
    }
    func copyOwned(): TlcpIdentity {
        synchronized(mutex) {
            requireAlive()
            TlcpIdentity(signingScalar, encryptionScalar, certificateMessage)
        }
    }
    func signingKey(): Sm2PrivateKey {
        synchronized(mutex) { requireAlive(); Sm2PrivateKey(BigNum.fromBytesBE(signingScalar)) }
    }
    func encryptionKey(): Sm2PrivateKey {
        synchronized(mutex) { requireAlive(); Sm2PrivateKey(BigNum.fromBytesBE(encryptionScalar)) }
    }
    private func requireAlive(): Unit {
        if (destroyed) { throw CryptoException(InvalidArgument, "TLCP identity destroyed") }
    }
}

func tlcpWipe(bytes: Array<Byte>): Unit {
    for (i in 0..bytes.size) { bytes[i] = 0 }
}
