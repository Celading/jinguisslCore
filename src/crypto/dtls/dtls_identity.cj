package jinguissl_core.crypto.dtls

import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.ecc.{EcPrivateKey, NamedCurve, ecdsaSign, ecPublicFromPrivateKey}
import jinguissl_core.crypto.digest.{sha256, bytesToHexLower}
import jinguissl_core.crypto.utils.csprngBytes
import std.sync.Mutex
import jinguissl_core.crypto.x509.{X509SelfSignedConfig, x509CreateSelfSignedEcCertificate,
    x509ParseEcPrivateKeyPkcs8Pem, x509ParseDer, x509ExtractEcPublicKey}

/** P-256 signing identity. Certificate copies are public; private scalar bytes never leave this object.
 * destroy() revokes future operations; managed BigNum temporaries are not guaranteed erased. */
public class DtlsIdentity {
    private let mutex = Mutex()
    private let scalar: Array<Byte>
    private let certificate: Array<Byte>
    private var destroyed: Bool = false

    public init(privateKeyPem: String, certificateDer: Array<Byte>) {
        let key = x509ParseEcPrivateKeyPkcs8Pem(privateKeyPem)
        dtlsRequire(key.curve == NamedCurve.P256, "DTLS identity requires P-256")
        let publicKey = ecPublicFromPrivateKey(key)
        let certKey = x509ExtractEcPublicKey(x509ParseDer(certificateDer))
        dtlsRequire(certKey.curve == NamedCurve.P256 && publicKey.x.cmp(certKey.x) == 0 &&
            publicKey.y.cmp(certKey.y) == 0, "DTLS certificate does not match private key")
        this.scalar = key.scalar.toBytesBE()
        this.certificate = certificateDer.clone()
    }
    private init(key: EcPrivateKey, certificate: Array<Byte>) {
        this.scalar = key.scalar.toBytesBE()
        this.certificate = certificate.clone()
    }
    public static func generate(commonName: String, notBefore: String, notAfter: String): DtlsIdentity {
        let order = BigNum.fromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
        var raw = csprngBytes(32)
        var scalar = BigNum.fromBytesBE(raw)
        while (scalar.isZero() || scalar.cmp(order) >= 0) {
            for (i in 0..raw.size) { raw[i] = 0 }
            raw = csprngBytes(32)
            scalar = BigNum.fromBytesBE(raw)
        }
        let key = EcPrivateKey(NamedCurve.P256, scalar)
        for (i in 0..raw.size) { raw[i] = 0 }
        let cert = x509CreateSelfSignedEcCertificate(X509SelfSignedConfig(commonName,
            serialNumber: csprngBytes(16), notBefore: notBefore, notAfter: notAfter,
            keyUsageMask: 1), key)
        DtlsIdentity(key, cert.der)
    }
    public func certificateDer(): Array<Byte> { certificate.clone() }
    public func fingerprintSha256(): String { bytesToHexLower(sha256(certificate)) }
    public func destroy(): Unit {
        synchronized(mutex) {
            destroyed = true
            for (i in 0..scalar.size) { scalar[i] = 0 }
        }
    }
    func copyOwned(): DtlsIdentity {
        synchronized(mutex) {
            dtlsRequire(!destroyed, "DTLS identity is destroyed")
            DtlsIdentity(EcPrivateKey(NamedCurve.P256, BigNum.fromBytesBE(scalar)), certificate)
        }
    }
    func sign(digest: Array<Byte>): Array<Byte> {
        synchronized(mutex) {
            dtlsRequire(!destroyed && digest.size == 32, "DTLS identity unavailable or invalid digest")
            let (r, s) = ecdsaSign(EcPrivateKey(NamedCurve.P256, BigNum.fromBytesBE(scalar)), digest)
            let payload = dtlsJoin([dtlsSignatureInteger(r), dtlsSignatureInteger(s)])
            dtlsJoin([[UInt8(0x30), UInt8(payload.size)], payload])
        }
    }
}

private func dtlsSignatureInteger(value: BigNum): Array<Byte> {
    let raw = value.toBytesBE()
    let magnitude = if ((raw[0] & 0x80) != 0) { dtlsJoin([[UInt8(0)], raw]) } else { raw }
    dtlsJoin([[UInt8(2), UInt8(magnitude.size)], magnitude])
}
func dtlsReadSignature(signature: Array<Byte>): (BigNum, BigNum) {
    let r = DtlsReader(signature)
    dtlsRequire(r.u8() == 0x30, "DTLS signature requires DER sequence")
    let content = DtlsReader(r.take(r.u8()))
    r.end()
    let first = dtlsReadSignatureInteger(content)
    let second = dtlsReadSignatureInteger(content)
    content.end()
    (first, second)
}
private func dtlsReadSignatureInteger(r: DtlsReader): BigNum {
    dtlsRequire(r.u8() == 2, "DTLS signature requires DER integer")
    let value = r.take(r.u8())
    dtlsRequire(value.size > 0 && value.size <= 33 && (value[0] & 0x80) == 0,
        "invalid P-256 signature scalar")
    dtlsRequire(value.size == 1 || value[0] != 0 || (value[1] & 0x80) != 0,
        "noncanonical DER signature scalar")
    BigNum.fromBytesBE(value)
}
