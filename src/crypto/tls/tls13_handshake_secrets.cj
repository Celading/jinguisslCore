package jinguissl_core.crypto.tls

import jinguissl_core.crypto.base.SecureBytes
import jinguissl_core.crypto.digest.HashAlgorithm

// Explicit owned-buffer lifecycle; no GC/physical-erasure guarantee.
public class Tls13HandshakeSecrets {
    public let hashAlgorithm: HashAlgorithm
    private let _earlySecret: SecureBytes
    public prop earlySecret: Array<Byte> { get() { _earlySecret.bytes() } }
    private let _handshakeSecret: SecureBytes
    public prop handshakeSecret: Array<Byte> { get() { _handshakeSecret.bytes() } }
    private let _masterSecret: SecureBytes
    public prop masterSecret: Array<Byte> { get() { _masterSecret.bytes() } }

    private let _clientHsTrafficSecret: SecureBytes
    public prop clientHsTrafficSecret: Array<Byte> { get() { _clientHsTrafficSecret.bytes() } }
    private let _serverHsTrafficSecret: SecureBytes
    public prop serverHsTrafficSecret: Array<Byte> { get() { _serverHsTrafficSecret.bytes() } }
    private let _clientAppTrafficSecret: SecureBytes
    public prop clientAppTrafficSecret: Array<Byte> { get() { _clientAppTrafficSecret.bytes() } }
    private let _serverAppTrafficSecret: SecureBytes
    public prop serverAppTrafficSecret: Array<Byte> { get() { _serverAppTrafficSecret.bytes() } }

    private let _clientWriteKey: SecureBytes
    public prop clientWriteKey: Array<Byte> { get() { _clientWriteKey.bytes() } }
    private let _serverWriteKey: SecureBytes
    public prop serverWriteKey: Array<Byte> { get() { _serverWriteKey.bytes() } }
    private let _clientWriteIv: SecureBytes
    public prop clientWriteIv: Array<Byte> { get() { _clientWriteIv.bytes() } }
    private let _serverWriteIv: SecureBytes
    public prop serverWriteIv: Array<Byte> { get() { _serverWriteIv.bytes() } }

    public init(
        earlySecret: Array<Byte>,
        handshakeSecret: Array<Byte>,
        masterSecret: Array<Byte>,
        clientHsTrafficSecret: Array<Byte>,
        serverHsTrafficSecret: Array<Byte>,
        clientAppTrafficSecret: Array<Byte>,
        serverAppTrafficSecret: Array<Byte>,
        clientWriteKey: Array<Byte>,
        serverWriteKey: Array<Byte>,
        clientWriteIv: Array<Byte>,
        serverWriteIv: Array<Byte>,
        hashAlgorithm!: HashAlgorithm = HashAlgorithm.SHA256
    ) {
        this.hashAlgorithm = hashAlgorithm
        this._earlySecret = SecureBytes(earlySecret)
        this._handshakeSecret = SecureBytes(handshakeSecret)
        this._masterSecret = SecureBytes(masterSecret)
        this._clientHsTrafficSecret = SecureBytes(clientHsTrafficSecret)
        this._serverHsTrafficSecret = SecureBytes(serverHsTrafficSecret)
        this._clientAppTrafficSecret = SecureBytes(clientAppTrafficSecret)
        this._serverAppTrafficSecret = SecureBytes(serverAppTrafficSecret)
        this._clientWriteKey = SecureBytes(clientWriteKey)
        this._serverWriteKey = SecureBytes(serverWriteKey)
        this._clientWriteIv = SecureBytes(clientWriteIv)
        this._serverWriteIv = SecureBytes(serverWriteIv)
    }

    public prop isDestroyed: Bool { get() { _earlySecret.isDestroyed } }

    // Serial owner only. Previously exported copies remain the caller's responsibility.
    public func destroy(): Unit {
        _earlySecret.destroy()
        _handshakeSecret.destroy()
        _masterSecret.destroy()
        _clientHsTrafficSecret.destroy()
        _serverHsTrafficSecret.destroy()
        _clientAppTrafficSecret.destroy()
        _serverAppTrafficSecret.destroy()
        _clientWriteKey.destroy()
        _serverWriteKey.destroy()
        _clientWriteIv.destroy()
        _serverWriteIv.destroy()
    }
}
