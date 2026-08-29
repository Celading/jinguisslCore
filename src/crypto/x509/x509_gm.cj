package jinguissl_core.crypto.x509

import std.collection.ArrayList
import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}
import jinguissl_core.crypto.sm2.{
    Sm2PrivateKey,
    Sm2PublicKey,
    sm2PublicKey,
    sm2PublicKeyFromUncompressed,
    sm2PublicKeyToUncompressed,
    sm2Sign,
    sm2Verify
}

private let GM_DER_BOOLEAN: Int64 = 0x01
private let GM_DER_INTEGER: Int64 = 0x02
private let GM_DER_BIT_STRING: Int64 = 0x03
private let GM_DER_OCTET_STRING: Int64 = 0x04
private let GM_DER_NULL: Int64 = 0x05
private let GM_DER_OID: Int64 = 0x06
private let GM_DER_SEQUENCE: Int64 = 0x30
private let GM_DER_CONTEXT_0: Int64 = 0xa0
private let GM_DER_CONTEXT_1: Int64 = 0xa1
private let GM_DER_CONTEXT_3: Int64 = 0xa3

/** Parsed PKCS#10 request using curveSM2 and SM3-with-SM2. */
public class X509Sm2CertificateRequest {
    public let der: Array<Byte>
    public let certificationRequestInfoDer: Array<Byte>
    public let subject: X509Name
    public let subjectPublicKeyInfoDer: Array<Byte>
    public let signatureAlgorithmOid: String
    public let signatureValue: Array<Byte>

    public init(
        der: Array<Byte>,
        certificationRequestInfoDer: Array<Byte>,
        subject: X509Name,
        subjectPublicKeyInfoDer: Array<Byte>,
        signatureAlgorithmOid: String,
        signatureValue: Array<Byte>
    ) {
        if (
            der.size == 0 || certificationRequestInfoDer.size == 0 ||
            subjectPublicKeyInfoDer.size == 0 || signatureValue.size == 0
        ) {
            throw CryptoException(InvalidArgument, "SM2 certificate request fields must not be empty")
        }
        this.der = der.clone()
        this.certificationRequestInfoDer = certificationRequestInfoDer.clone()
        this.subject = subject
        this.subjectPublicKeyInfoDer = subjectPublicKeyInfoDer.clone()
        this.signatureAlgorithmOid = signatureAlgorithmOid
        this.signatureValue = signatureValue.clone()
    }

    public func toPem(): String { gmDerToPem("CERTIFICATE REQUEST", der) }
}

/** Issuance inputs for a non-self-signed SM2-with-SM3 certificate. */
public class X509Sm2CertificateConfig {
    public let commonName: String
    public let serialNumber: Array<Byte>
    public let notBefore: String
    public let notAfter: String
    public let keyUsageMask: Int64

    public init(
        commonName: String,
        serialNumber!: Array<Byte> = [UInt8(0x01)],
        notBefore!: String = "260101000000Z",
        notAfter!: String = "360101000000Z",
        keyUsageMask!: Int64 = X509_KEY_USAGE_DIGITAL_SIGNATURE
    ) {
        let normalized = commonName.trimAscii()
        if (normalized.size == 0 || serialNumber.size == 0) {
            throw CryptoException(InvalidArgument, "SM2 certificate subject and serial must not be empty")
        }
        if (!isValidX509Time(notBefore) || !isValidX509Time(notAfter)) {
            throw CryptoException(InvalidArgument, "SM2 certificate validity time is invalid")
        }
        if (keyUsageMask < 0) {
            throw CryptoException(InvalidArgument, "SM2 certificate keyUsage must be non-negative")
        }
        this.commonName = normalized
        this.serialNumber = trimLeadingZeroBytes(serialNumber)
        this.notBefore = notBefore
        this.notAfter = notAfter
        this.keyUsageMask = keyUsageMask
    }
}

/** One revoked serial and its revocation time for a generated SM2 CRL. */
public class X509Sm2RevokedCertificate {
    public let serialNumber: Array<Byte>
    public let revocationTime: String

    public init(serialNumber: Array<Byte>, revocationTime: String) {
        if (serialNumber.size == 0) {
            throw CryptoException(InvalidArgument, "SM2 CRL revoked serial must not be empty")
        }
        if (!isValidX509Time(revocationTime)) {
            throw CryptoException(InvalidArgument, "SM2 CRL revocation time is invalid")
        }
        this.serialNumber = trimLeadingZeroBytes(serialNumber)
        this.revocationTime = revocationTime
    }
}

/** Generation inputs for an SM2-with-SM3 CRL. */
public class X509Sm2CrlConfig {
    public let thisUpdate: String
    public let nextUpdate: String
    public let revokedCertificates: Array<X509Sm2RevokedCertificate>

    public init(
        thisUpdate: String,
        nextUpdate!: String = "",
        revokedCertificates!: Array<X509Sm2RevokedCertificate> = []
    ) {
        if (!isValidX509Time(thisUpdate)) {
            throw CryptoException(InvalidArgument, "SM2 CRL thisUpdate is invalid")
        }
        if (nextUpdate.size > 0 && !isValidX509Time(nextUpdate)) {
            throw CryptoException(InvalidArgument, "SM2 CRL nextUpdate is invalid")
        }
        this.thisUpdate = thisUpdate
        this.nextUpdate = nextUpdate
        this.revokedCertificates = revokedCertificates.clone()
    }
}

/** Encode a curveSM2 public key as X.509 SubjectPublicKeyInfo DER. */
public func x509EncodeSm2PublicKeyDer(publicKey: Sm2PublicKey): Array<Byte> {
    encodeSm2SubjectPublicKeyInfo(publicKey)
}

/** Encode a curveSM2 public key as a PUBLIC KEY PEM block. */
public func x509EncodeSm2PublicKeyPem(publicKey: Sm2PublicKey): String {
    gmDerToPem("PUBLIC KEY", x509EncodeSm2PublicKeyDer(publicKey))
}

/** Parse and validate a curveSM2 SubjectPublicKeyInfo DER value. */
public func x509ParseSm2PublicKeyDer(der: Array<Byte>): Sm2PublicKey {
    decodeSm2PublicKeyFromSpki(der)
}

/** Parse and validate one curveSM2 PUBLIC KEY PEM block. */
public func x509ParseSm2PublicKeyPem(pem: String): Sm2PublicKey {
    x509ParseSm2PublicKeyDer(decodeSinglePemBlock(pem, "PUBLIC KEY"))
}

/** Encode a curveSM2 private key as RFC 5915 ECPrivateKey DER. */
public func x509EncodeSm2PrivateKeySec1Der(privateKey: Sm2PrivateKey): Array<Byte> {
    let publicKey = sm2PublicKey(privateKey)
    let parts = ArrayList<Byte>()
    appendBytes(parts, encodeIntegerFromInt(1))
    appendBytes(parts, derWrap(
        GM_DER_OCTET_STRING,
        privateKey.scalar.toBytesBE(paddedLen: 32)
    ))
    appendBytes(parts, derWrap(
        GM_DER_CONTEXT_0,
        derWrap(GM_DER_OID, encodeOid(X509_OID_SM2))
    ))
    appendBytes(parts, derWrap(
        GM_DER_CONTEXT_1,
        encodeBitString(sm2PublicKeyToUncompressed(publicKey))
    ))
    derWrap(GM_DER_SEQUENCE, parts.toArray())
}

/** Encode a curveSM2 private key as an EC PRIVATE KEY PEM block. */
public func x509EncodeSm2PrivateKeySec1Pem(privateKey: Sm2PrivateKey): String {
    gmDerToPem("EC PRIVATE KEY", x509EncodeSm2PrivateKeySec1Der(privateKey))
}

/** Parse and cross-check a curveSM2 RFC 5915 ECPrivateKey. */
public func x509ParseSm2PrivateKeySec1Der(der: Array<Byte>): Sm2PrivateKey {
    gmParseSm2PrivateKeySec1(der, true)
}

/** Parse one curveSM2 EC PRIVATE KEY PEM block. */
public func x509ParseSm2PrivateKeySec1Pem(pem: String): Sm2PrivateKey {
    x509ParseSm2PrivateKeySec1Der(decodeSinglePemBlock(pem, "EC PRIVATE KEY"))
}

/** Encode a curveSM2 private key as unencrypted PKCS#8 PrivateKeyInfo DER. */
public func x509EncodeSm2PrivateKeyPkcs8Der(privateKey: Sm2PrivateKey): Array<Byte> {
    let algorithm = gmSm2PublicKeyAlgorithmIdentifier()
    let parts = ArrayList<Byte>()
    appendBytes(parts, encodeIntegerFromInt(0))
    appendBytes(parts, algorithm)
    appendBytes(parts, derWrap(
        GM_DER_OCTET_STRING,
        x509EncodeSm2PrivateKeySec1Der(privateKey)
    ))
    derWrap(GM_DER_SEQUENCE, parts.toArray())
}

/** Encode a curveSM2 private key as an unencrypted PRIVATE KEY PEM block. */
public func x509EncodeSm2PrivateKeyPkcs8Pem(privateKey: Sm2PrivateKey): String {
    gmDerToPem("PRIVATE KEY", x509EncodeSm2PrivateKeyPkcs8Der(privateKey))
}

/** Parse and validate an unencrypted curveSM2 PKCS#8 PrivateKeyInfo. */
public func x509ParseSm2PrivateKeyPkcs8Der(der: Array<Byte>): Sm2PrivateKey {
    let root = derReadSingleElement(der, "SM2 PKCS8 PrivateKeyInfo")
    if (root.tag != GM_DER_SEQUENCE) {
        throw CryptoException(ParseError, "SM2 PKCS8 PrivateKeyInfo must be SEQUENCE")
    }
    let reader = DerReader(root.value)
    gmRequireIntegerValue(
        reader.readElement("SM2 PKCS8 version", expectedTag: GM_DER_INTEGER),
        UInt8(0x00),
        "SM2 PKCS8 version"
    )
    let algorithm = reader.readElement(
        "SM2 PKCS8 privateKeyAlgorithm", expectedTag: GM_DER_SEQUENCE
    )
    gmRequireSm2AlgorithmIdentifier(algorithm)
    let privateKey = reader.readElement(
        "SM2 PKCS8 privateKey", expectedTag: GM_DER_OCTET_STRING
    )
    while (reader.hasRemaining()) {
        let optional = reader.readElement("SM2 PKCS8 optional field")
        if (!isContextSpecificTag(optional.tag)) {
            throw CryptoException(ParseError, "SM2 PKCS8 optional field must be context-specific")
        }
    }
    gmParseSm2PrivateKeySec1(privateKey.value, false)
}

/** Parse one unencrypted curveSM2 PRIVATE KEY PEM block. */
public func x509ParseSm2PrivateKeyPkcs8Pem(pem: String): Sm2PrivateKey {
    x509ParseSm2PrivateKeyPkcs8Der(decodeSinglePemBlock(pem, "PRIVATE KEY"))
}

/** Create and self-sign a PKCS#10 curveSM2 request. */
public func x509CreateSm2CertificateRequest(
    commonName: String,
    privateKey: Sm2PrivateKey,
    signerIdentity!: Array<Byte> = X509_SM2_DEFAULT_SIGNER_IDENTITY.toArray()
): X509Sm2CertificateRequest {
    let normalized = commonName.trimAscii()
    if (normalized.size == 0 || signerIdentity.size == 0) {
        throw CryptoException(InvalidArgument, "SM2 CSR common name and signer identity must not be empty")
    }
    let infoParts = ArrayList<Byte>()
    appendBytes(infoParts, encodeIntegerFromInt(0))
    appendBytes(infoParts, encodeCommonName(normalized))
    appendBytes(infoParts, encodeSm2SubjectPublicKeyInfo(sm2PublicKey(privateKey)))
    appendBytes(infoParts, derWrap(GM_DER_CONTEXT_0, []))
    let infoDer = derWrap(GM_DER_SEQUENCE, infoParts.toArray())
    let (r, s) = sm2Sign(privateKey, signerIdentity, infoDer)
    let signature = encodeEcdsaSignatureDer(r, s)
    let requestParts = ArrayList<Byte>()
    appendBytes(requestParts, infoDer)
    appendBytes(requestParts, encodeAlgorithmIdentifier(
        X509_OID_SM3_WITH_SM2, withNullParam: false
    ))
    appendBytes(requestParts, encodeBitString(signature))
    let request = x509ParseSm2CertificateRequestDer(
        derWrap(GM_DER_SEQUENCE, requestParts.toArray())
    )
    x509VerifySm2CertificateRequest(request, signerIdentity: signerIdentity)
    request
}

/** Parse one PKCS#10 curveSM2 request from DER. */
public func x509ParseSm2CertificateRequestDer(der: Array<Byte>): X509Sm2CertificateRequest {
    let root = derReadSingleElement(der, "SM2 certificate request")
    if (root.tag != GM_DER_SEQUENCE) {
        throw CryptoException(ParseError, "SM2 certificate request must be SEQUENCE")
    }
    let reader = DerReader(root.value)
    let info = reader.readElement(
        "SM2 certificationRequestInfo", expectedTag: GM_DER_SEQUENCE
    )
    let algorithm = reader.readElement(
        "SM2 CSR signatureAlgorithm", expectedTag: GM_DER_SEQUENCE
    )
    let signature = reader.readElement(
        "SM2 CSR signature", expectedTag: GM_DER_BIT_STRING
    )
    if (reader.hasRemaining()) {
        throw CryptoException(ParseError, "SM2 certificate request contains trailing fields")
    }
    let signatureOid = parseAlgorithmIdentifier(algorithm, "SM2 CSR signatureAlgorithm")
    if (signatureOid != X509_OID_SM3_WITH_SM2) {
        throw CryptoException(Unsupported, "certificate request signature is not SM3-with-SM2")
    }

    let infoReader = DerReader(info.value)
    gmRequireIntegerValue(
        infoReader.readElement("SM2 CSR version", expectedTag: GM_DER_INTEGER),
        UInt8(0x00),
        "SM2 CSR version"
    )
    let subjectElement = infoReader.readElement("SM2 CSR subject", expectedTag: GM_DER_SEQUENCE)
    let publicKeyInfo = infoReader.readElement(
        "SM2 CSR subjectPublicKeyInfo", expectedTag: GM_DER_SEQUENCE
    )
    _ = decodeSm2PublicKeyFromSpki(publicKeyInfo.encoded)
    while (infoReader.hasRemaining()) {
        let attributes = infoReader.readElement("SM2 CSR attributes")
        if (attributes.tag != GM_DER_CONTEXT_0) {
            throw CryptoException(ParseError, "SM2 CSR attributes must use context tag [0]")
        }
    }
    X509Sm2CertificateRequest(
        der,
        info.encoded,
        parseName(subjectElement),
        publicKeyInfo.encoded,
        signatureOid,
        decodeBitStringValue(signature.value, "SM2 CSR signature")
    )
}

/** Parse one PKCS#10 curveSM2 request from PEM. */
public func x509ParseSm2CertificateRequestPem(pem: String): X509Sm2CertificateRequest {
    if (pem.contains("-----BEGIN CERTIFICATE REQUEST-----")) {
        return x509ParseSm2CertificateRequestDer(
            decodeSinglePemBlock(pem, "CERTIFICATE REQUEST")
        )
    }
    x509ParseSm2CertificateRequestDer(decodeSinglePemBlock(pem, "NEW CERTIFICATE REQUEST"))
}

/** Verify the self-signature on a parsed curveSM2 PKCS#10 request. */
public func x509VerifySm2CertificateRequest(
    request: X509Sm2CertificateRequest,
    signerIdentity!: Array<Byte> = X509_SM2_DEFAULT_SIGNER_IDENTITY.toArray()
): Unit {
    if (signerIdentity.size == 0) {
        throw CryptoException(InvalidArgument, "SM2 CSR signer identity must not be empty")
    }
    let publicKey = decodeSm2PublicKeyFromSpki(request.subjectPublicKeyInfoDer)
    let (r, s) = decodeEcdsaSignature(request.signatureValue)
    if (!sm2Verify(publicKey, signerIdentity, request.certificationRequestInfoDer, r, s)) {
        throw CryptoException(ParseError, "SM2 CSR signature verification failed")
    }
}

/** Issue a non-self-signed SM2-with-SM3 certificate from an SM2 issuer. */
public func x509CreateSm2Certificate(
    config: X509Sm2CertificateConfig,
    subjectPublicKey: Sm2PublicKey,
    issuer: X509Certificate,
    issuerPrivateKey: Sm2PrivateKey,
    signerIdentity!: Array<Byte> = X509_SM2_DEFAULT_SIGNER_IDENTITY.toArray()
): X509Certificate {
    if (signerIdentity.size == 0) {
        throw CryptoException(InvalidArgument, "SM2 certificate signer identity must not be empty")
    }
    gmRequireIssuerPrivateKey(issuer, issuerPrivateKey)
    gmRequireIssuerUsage(issuer, X509_KEY_USAGE_KEY_CERT_SIGN, "certificate signing")
    let signatureAlgorithm = encodeAlgorithmIdentifier(
        X509_OID_SM3_WITH_SM2, withNullParam: false
    )
    let tbsParts = ArrayList<Byte>()
    appendBytes(tbsParts, derWrap(GM_DER_CONTEXT_0, encodeIntegerFromInt(2)))
    appendBytes(tbsParts, encodePositiveInteger(config.serialNumber))
    appendBytes(tbsParts, signatureAlgorithm)
    appendBytes(tbsParts, issuer.subject.der)
    appendBytes(tbsParts, encodeValidity(config.notBefore, config.notAfter))
    appendBytes(tbsParts, encodeCommonName(config.commonName))
    appendBytes(tbsParts, encodeSm2SubjectPublicKeyInfo(subjectPublicKey))
    let extensions = encodeExtensionsForSelfSigned(config.keyUsageMask)
    if (extensions.size > 0) {
        appendBytes(tbsParts, derWrap(GM_DER_CONTEXT_3, extensions))
    }
    let tbsDer = derWrap(GM_DER_SEQUENCE, tbsParts.toArray())
    let (r, s) = sm2Sign(issuerPrivateKey, signerIdentity, tbsDer)
    let certParts = ArrayList<Byte>()
    appendBytes(certParts, tbsDer)
    appendBytes(certParts, signatureAlgorithm)
    appendBytes(certParts, encodeBitString(encodeEcdsaSignatureDer(r, s)))
    let certificate = x509ParseDer(derWrap(GM_DER_SEQUENCE, certParts.toArray()))
    x509VerifySm2SignatureWithIssuerIdentity(certificate, issuer, signerIdentity)
    certificate
}

/** Generate and sign an SM2-with-SM3 X.509 v2 CRL. */
public func x509CreateSm2Crl(
    config: X509Sm2CrlConfig,
    issuer: X509Certificate,
    issuerPrivateKey: Sm2PrivateKey,
    signerIdentity!: Array<Byte> = X509_SM2_DEFAULT_SIGNER_IDENTITY.toArray()
): X509Crl {
    if (signerIdentity.size == 0) {
        throw CryptoException(InvalidArgument, "SM2 CRL signer identity must not be empty")
    }
    gmRequireIssuerPrivateKey(issuer, issuerPrivateKey)
    gmRequireIssuerUsage(issuer, X509_KEY_USAGE_CRL_SIGN, "CRL signing")
    let signatureAlgorithm = encodeAlgorithmIdentifier(
        X509_OID_SM3_WITH_SM2, withNullParam: false
    )
    let tbsParts = ArrayList<Byte>()
    appendBytes(tbsParts, encodeIntegerFromInt(1))
    appendBytes(tbsParts, signatureAlgorithm)
    appendBytes(tbsParts, issuer.subject.der)
    appendBytes(tbsParts, encodeTime(config.thisUpdate))
    if (config.nextUpdate.size > 0) {
        appendBytes(tbsParts, encodeTime(config.nextUpdate))
    }
    if (config.revokedCertificates.size > 0) {
        let revoked = ArrayList<Byte>()
        for (entry in config.revokedCertificates) {
            let entryParts = ArrayList<Byte>()
            appendBytes(entryParts, encodePositiveInteger(entry.serialNumber))
            appendBytes(entryParts, encodeTime(entry.revocationTime))
            appendBytes(revoked, derWrap(GM_DER_SEQUENCE, entryParts.toArray()))
        }
        appendBytes(tbsParts, derWrap(GM_DER_SEQUENCE, revoked.toArray()))
    }
    let tbsDer = derWrap(GM_DER_SEQUENCE, tbsParts.toArray())
    let (r, s) = sm2Sign(issuerPrivateKey, signerIdentity, tbsDer)
    let crlParts = ArrayList<Byte>()
    appendBytes(crlParts, tbsDer)
    appendBytes(crlParts, signatureAlgorithm)
    appendBytes(crlParts, encodeBitString(encodeEcdsaSignatureDer(r, s)))
    let crl = x509ParseCrlDer(derWrap(GM_DER_SEQUENCE, crlParts.toArray()))
    x509VerifySm2CrlSignatureWithIssuerIdentity(crl, issuer, signerIdentity)
    crl
}

/** Encode a parsed CRL as an X509 CRL PEM block. */
public func x509CrlToPem(crl: X509Crl): String { gmDerToPem("X509 CRL", crl.der) }

/** Verify an SM2-with-SM3 CRL with an explicit issuer signer identity. */
public func x509VerifySm2CrlSignatureWithIssuerIdentity(
    crl: X509Crl,
    issuer: X509Certificate,
    signerIdentity: Array<Byte>
): Unit {
    if (!x509NameDerEquals(crl.issuer, issuer.subject)) {
        throw CryptoException(ParseError, "CRL issuer does not match issuer certificate subject")
    }
    gmRequireIssuerUsage(issuer, X509_KEY_USAGE_CRL_SIGN, "CRL signing")
    if (crl.signatureAlgorithmOid != X509_OID_SM3_WITH_SM2) {
        throw CryptoException(Unsupported, "CRL signature algorithm is not SM3-with-SM2")
    }
    if (signerIdentity.size == 0) {
        throw CryptoException(InvalidArgument, "SM2 CRL signer identity must not be empty")
    }
    let publicKey = x509ExtractSm2PublicKey(issuer)
    let (r, s) = decodeEcdsaSignature(crl.signatureValue)
    if (!sm2Verify(publicKey, signerIdentity, crl.tbsDer, r, s)) {
        throw CryptoException(ParseError, "X509 CRL SM2-with-SM3 signature verification failed")
    }
}

private func gmParseSm2PrivateKeySec1(der: Array<Byte>, requireCurve: Bool): Sm2PrivateKey {
    let root = derReadSingleElement(der, "SM2 ECPrivateKey")
    if (root.tag != GM_DER_SEQUENCE) {
        throw CryptoException(ParseError, "SM2 ECPrivateKey must be SEQUENCE")
    }
    let reader = DerReader(root.value)
    gmRequireIntegerValue(
        reader.readElement("SM2 ECPrivateKey version", expectedTag: GM_DER_INTEGER),
        UInt8(0x01),
        "SM2 ECPrivateKey version"
    )
    let scalarElement = reader.readElement(
        "SM2 ECPrivateKey privateKey", expectedTag: GM_DER_OCTET_STRING
    )
    if (scalarElement.value.size == 0 || scalarElement.value.size > 32) {
        throw CryptoException(ParseError, "SM2 ECPrivateKey scalar must be 1..32 bytes")
    }
    var hasCurve = false
    var embeddedPublic: ?Array<Byte> = None
    while (reader.hasRemaining()) {
        let tag = reader.peekTag()
        if (tag == GM_DER_CONTEXT_0) {
            if (hasCurve) {
                throw CryptoException(ParseError, "SM2 ECPrivateKey repeats parameters")
            }
            let parameters = reader.readElement(
                "SM2 ECPrivateKey parameters", expectedTag: GM_DER_CONTEXT_0
            )
            let parametersReader = DerReader(parameters.value)
            let oid = parametersReader.readElement(
                "SM2 ECPrivateKey curve OID", expectedTag: GM_DER_OID
            )
            if (decodeOid(oid.value, "SM2 ECPrivateKey curve OID") != X509_OID_SM2) {
                throw CryptoException(Unsupported, "ECPrivateKey curve is not curveSM2")
            }
            if (parametersReader.hasRemaining()) {
                throw CryptoException(ParseError, "SM2 ECPrivateKey parameters contain trailing bytes")
            }
            hasCurve = true
            continue
        }
        if (tag == GM_DER_CONTEXT_1) {
            if (let Some(_) <- embeddedPublic) {
                throw CryptoException(ParseError, "SM2 ECPrivateKey repeats publicKey")
            }
            let publicElement = reader.readElement(
                "SM2 ECPrivateKey publicKey", expectedTag: GM_DER_CONTEXT_1
            )
            let publicReader = DerReader(publicElement.value)
            let bitString = publicReader.readElement(
                "SM2 ECPrivateKey publicKey BIT STRING", expectedTag: GM_DER_BIT_STRING
            )
            if (publicReader.hasRemaining()) {
                throw CryptoException(ParseError, "SM2 ECPrivateKey publicKey contains trailing bytes")
            }
            embeddedPublic = Some(decodeBitStringValue(
                bitString.value, "SM2 ECPrivateKey publicKey"
            ))
            continue
        }
        throw CryptoException(ParseError, "unsupported SM2 ECPrivateKey optional field")
    }
    if (requireCurve && !hasCurve) {
        throw CryptoException(ParseError, "SM2 ECPrivateKey is missing curveSM2 parameters")
    }
    let privateKey = Sm2PrivateKey(BigNum.fromBytesBE(scalarElement.value))
    if (let Some(encodedPublic) <- embeddedPublic) {
        let parsedPublic = sm2PublicKeyFromUncompressed(encodedPublic)
        let expectedPublic = sm2PublicKey(privateKey)
        if (!bytesEqual(
            sm2PublicKeyToUncompressed(parsedPublic),
            sm2PublicKeyToUncompressed(expectedPublic)
        )) {
            throw CryptoException(ParseError, "SM2 ECPrivateKey embedded public key mismatch")
        }
    }
    privateKey
}

private func gmSm2PublicKeyAlgorithmIdentifier(): Array<Byte> {
    let parts = ArrayList<Byte>()
    appendBytes(parts, derWrap(GM_DER_OID, encodeOid(X509_OID_EC_PUBLIC_KEY)))
    appendBytes(parts, derWrap(GM_DER_OID, encodeOid(X509_OID_SM2)))
    derWrap(GM_DER_SEQUENCE, parts.toArray())
}

private func gmRequireSm2AlgorithmIdentifier(element: DerElement): Unit {
    let reader = DerReader(element.value)
    let oidElement = reader.readElement("SM2 algorithm OID", expectedTag: GM_DER_OID)
    let oid = decodeOid(oidElement.value, "SM2 algorithm OID")
    if (oid == X509_OID_EC_PUBLIC_KEY) {
        let curveElement = reader.readElement("SM2 curve OID", expectedTag: GM_DER_OID)
        if (decodeOid(curveElement.value, "SM2 curve OID") != X509_OID_SM2) {
            throw CryptoException(Unsupported, "PKCS8 EC curve is not curveSM2")
        }
    } else if (oid == X509_OID_SM2) {
        if (reader.hasRemaining()) {
            let parameters = reader.readElement("SM2 algorithm parameters")
            if (parameters.tag != GM_DER_NULL && parameters.tag != GM_DER_OID) {
                throw CryptoException(ParseError, "SM2 PKCS8 parameters are invalid")
            }
            if (parameters.tag == GM_DER_OID &&
                decodeOid(parameters.value, "SM2 algorithm parameters") != X509_OID_SM2
            ) {
                throw CryptoException(Unsupported, "SM2 PKCS8 parameters use another curve")
            }
        }
    } else {
        throw CryptoException(Unsupported, "PKCS8 private key algorithm is not SM2")
    }
    if (reader.hasRemaining()) {
        throw CryptoException(ParseError, "SM2 algorithm identifier contains trailing fields")
    }
}

private func gmRequireIntegerValue(element: DerElement, expected: Byte, label: String): Unit {
    let value = parsePositiveInteger(element.value, label)
    if (value.size != 1 || value[0] != expected) {
        throw CryptoException(ParseError, "${label} has an unsupported value")
    }
}

private func gmRequireIssuerPrivateKey(
    issuer: X509Certificate, privateKey: Sm2PrivateKey
): Unit {
    let fromCertificate = x509ExtractSm2PublicKey(issuer)
    let fromPrivate = sm2PublicKey(privateKey)
    if (!bytesEqual(
        sm2PublicKeyToUncompressed(fromCertificate),
        sm2PublicKeyToUncompressed(fromPrivate)
    )) {
        throw CryptoException(InvalidArgument, "SM2 issuer private key does not match certificate")
    }
}

private func gmRequireIssuerUsage(
    issuer: X509Certificate, requiredUsage: Int64, operation: String
): Unit {
    let extension = x509FindExtension(issuer, X509_OID_KEY_USAGE)
    if (let Some(keyUsage) <- extension) {
        if ((x509DecodeKeyUsageFromExtension(keyUsage) & requiredUsage) == 0) {
            throw CryptoException(InvalidArgument, "SM2 issuer keyUsage does not allow ${operation}")
        }
    }
}

private func gmDerToPem(label: String, der: Array<Byte>): String {
    if (der.size == 0) {
        throw CryptoException(InvalidArgument, "PEM DER input must not be empty")
    }
    let encoded = base64Encode(der)
    var output = "-----BEGIN ${label}-----\n"
    var offset: Int64 = 0
    while (offset < encoded.size) {
        let end = minI64(encoded.size, offset + 64)
        output += encoded[offset..end]
        output += "\n"
        offset = end
    }
    output += "-----END ${label}-----\n"
    output
}
