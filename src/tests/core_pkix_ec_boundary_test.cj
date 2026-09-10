package jinguissl_core.tests

import std.fs.File
import std.collection.ArrayList
import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.ecc.*
import jinguissl_core.crypto.x509.*
import jinguissl_core.crypto.error.CryptoException

private func readToString(path: String): String {
    String.fromUtf8(File.readFrom(path))
}

private func boundaryCertWithExtensions(cert: X509Certificate, extensions: Array<X509Extension>): X509Certificate {
    X509Certificate(cert.der, cert.tbsDer, cert.serialNumber, cert.signatureAlgorithmOid,
        cert.issuer, cert.subject, cert.notBefore, cert.notAfter,
        cert.subjectPublicKeyInfoDer, extensions, cert.signatureValue)
}

@Test
public class CorePkixEcBoundaryTestSuite {
    @TestCase
    public func testPkcs8InheritsPrivateScalarDomain(): Unit {
        let prefix = BigNum.fromHex("3041020100301306072A8648CE3D020106082A8648CE3D030107042730250201010420").toBytesBE()
        let n = BigNum.fromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
        for (scalar in [n, n.add(BigNum.one())]) {
            let bytes = ArrayList<Byte>()
            for (b in prefix) { bytes.add(b) }
            for (b in scalar.toBytesBE(paddedLen: 32)) { bytes.add(b) }
            try {
                _ = x509ParseEcPrivateKeyPkcs8Der(bytes.toArray())
                @Fail("PKCS8 must reject noncanonical private scalars")
            } catch (_: CryptoException) { () }
        }
        let valid = ArrayList<Byte>()
        for (b in prefix) { valid.add(b) }
        for (b in BigNum.one().toBytesBE(paddedLen: 32)) { valid.add(b) }
        @Assert(x509ParseEcPrivateKeyPkcs8Der(valid.toArray()).scalar.toHex(), BigNum.one().toHex())
    }

    @TestCase
    public func testCriticalEkuRequiresActiveLeafPolicy(): Unit {
        let root = x509ParsePem(readToString("testdata/x509/policy_root.pem"))
        let inter = x509ParsePem(readToString("testdata/x509/policy_intermediate.pem"))
        let leaf = x509ParsePem(readToString("testdata/x509/policy_leaf.pem"))
        let exts = ArrayList<X509Extension>()
        for (ext in leaf.extensions) {
            exts.add(X509Extension(ext.oid, ext.critical || ext.oid == X509_OID_EXTENDED_KEY_USAGE, ext.value))
        }
        let criticalLeaf = boundaryCertWithExtensions(leaf, exts.toArray())
        try {
            _ = x509VerifyCertificateChain(criticalLeaf, X509VerificationPolicy([root], intermediates: [inter]))
            @Fail("critical EKU cannot be ignored by a policy without a purpose")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "PARSE_ERROR")
        }
        _ = x509VerifyCertificateChain(criticalLeaf, X509VerificationPolicy([root],
            intermediates: [inter], requiredLeafExtendedKeyUsages: [X509_OID_EKU_SERVER_AUTH]))
    }

    @TestCase
    public func testRejectNonCanonicalPrivateScalars(): Unit {
        let n = BigNum.fromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")
        for (scalar in [n, n.add(BigNum.one())]) {
            try {
                _ = EcPrivateKey(P256, scalar)
                @Fail("private scalar must be strictly below the group order")
            } catch (e: CryptoException) {
                @Assert(e.code.toString(), "INVALID_ARGUMENT")
            }
        }
        _ = EcPrivateKey(P256, n.sub(BigNum.one()))
    }

    @TestCase
    public func testRejectOutOfFieldPublicCoordinates(): Unit {
        let p = BigNum.fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF")
        let g = ecPublicFromPrivateKey(EcPrivateKey(P256, BigNum.one()))
        for (which in 0..2) {
            try {
                if (which == 0) { _ = EcPublicKey(P256, g.x.add(p), g.y) }
                else { _ = EcPublicKey(P256, g.x, g.y.add(p)) }
                @Fail("coordinates must not be accepted modulo the field")
            } catch (e: CryptoException) {
                @Assert(e.code.toString(), "INVALID_ARGUMENT")
            }
        }
    }

    @TestCase
    public func testCriticalAndDuplicateExtensionsAtEveryChainPosition(): Unit {
        let leaf = x509ParsePem(readToString("testdata/x509/policy_leaf.pem"))
        let inter = x509ParsePem(readToString("testdata/x509/policy_intermediate.pem"))
        let root = x509ParsePem(readToString("testdata/x509/policy_root.pem"))
        for (position in 0..3) {
            for (kind in 0..3) {
                let original = [leaf, inter, root][position]
                let extensions = ArrayList<X509Extension>()
                for (ext in original.extensions) { extensions.add(ext) }
                match (kind) {
                    case 0 => extensions.add(X509Extension("1.2.3.4.5", true, [UInt8(5), 0]))
                    case 1 => extensions.add(X509Extension("2.5.29.30", true, [UInt8(0x30), 0]))
                    case _ => extensions.add(original.extensions[0])
                }
                let changed = boundaryCertWithExtensions(original, extensions.toArray())
                let chain = [leaf, inter, root]
                chain[position] = changed
                try {
                    _ = x509VerifyCertificateChain(chain[0],
                        X509VerificationPolicy([chain[2]], intermediates: [chain[1]]))
                    @Fail("unhandled critical or duplicate extensions must fail at every path position")
                } catch (e: CryptoException) {
                    @Assert(e.code.toString(), "PARSE_ERROR")
                }
            }
        }
    }

    @TestCase
    public func testUnknownNonCriticalAndValidChainRemainUsable(): Unit {
        let leaf = x509ParsePem(readToString("testdata/x509/policy_leaf.pem"))
        let inter = x509ParsePem(readToString("testdata/x509/policy_intermediate.pem"))
        let root = x509ParsePem(readToString("testdata/x509/policy_root.pem"))
        let extensions = ArrayList<X509Extension>()
        for (ext in leaf.extensions) { extensions.add(ext) }
        extensions.add(X509Extension("1.2.3.4.5", false, [UInt8(5), 0]))
        _ = x509VerifyCertificateChain(boundaryCertWithExtensions(leaf, extensions.toArray()),
            X509VerificationPolicy([root], intermediates: [inter]))
    }
}
