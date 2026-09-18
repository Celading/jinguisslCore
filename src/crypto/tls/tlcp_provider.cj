package jinguissl_core.crypto.tls

import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}

/** Stable local refusal category. alertDescription is a TLCP wire value when
 * applicable, not a promise that a transport delivered an alert. */
public class TlcpProviderException <: Exception {
    public let reason: String
    public let alertDescription: Int64
    public TlcpProviderException(reason: String, message: String, alertDescription!: Int64 = 80) {
        super(message)
        this.reason = reason; this.alertDescription = alertDescription
    }
}

/** Versioned request policy. No auto downgrade, negotiated ALPN, HTTP/2,
 * resumption or regulatory certification is implemented by this provider.
 * HTTP/1.1 use must be explicitly configured by the application out of band. */
public class TlcpProviderPolicy {
    private let suites: Array<TlcpCipherSuite>
    public let handshakeTimeoutMs: Int64
    public let requireClientCertificate: Bool
    public init(cipherSuites!: Array<TlcpCipherSuite> = tlcpDefaultCipherSuites(),
        handshakeTimeoutMs!: Int64 = 30000, requireClientCertificate!: Bool = false,
        alpnProtocols!: Array<String> = [], requireHttp2!: Bool = false,
        requestResumption!: Bool = false, requireCertifiedImplementation!: Bool = false) {
        if (alpnProtocols.size != 0) {
            throw TlcpProviderException("unsupported-alpn", "TLCP provider does not negotiate ALPN")
        }
        if (requireHttp2) {
            throw TlcpProviderException("unsupported-http2", "TLCP provider does not declare HTTP/2 compatibility")
        }
        if (requestResumption) {
            throw TlcpProviderException("unsupported-resumption", "TLCP provider requires a full handshake")
        }
        if (requireCertifiedImplementation) {
            throw TlcpProviderException("unsupported-certification", "No regulatory certification is claimed")
        }
        if (cipherSuites.size == 0 || cipherSuites.size > 4) {
            throw TlcpProviderException("invalid-policy", "TLCP requires 1 to 4 distinct cipher suites")
        }
        for (i in 0..cipherSuites.size) {
            for (j in 0..i) {
                if (cipherSuites[i] == cipherSuites[j]) {
                    throw TlcpProviderException("invalid-policy", "Duplicate TLCP cipher suite")
                }
            }
        }
        if (handshakeTimeoutMs < 1 || handshakeTimeoutMs > 120000) {
            throw TlcpProviderException("invalid-policy", "TLCP handshake timeout must be 1..120000 milliseconds")
        }
        this.suites = cipherSuites.clone()
        this.handshakeTimeoutMs = handshakeTimeoutMs
        this.requireClientCertificate = requireClientCertificate
    }
    public func cipherSuites(): Array<TlcpCipherSuite> { suites.clone() }
}
