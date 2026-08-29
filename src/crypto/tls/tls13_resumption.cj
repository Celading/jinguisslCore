package jinguissl_core.crypto.tls

import std.collection.ArrayList
import jinguissl_core.crypto.compliance.TlsVersion
import jinguissl_core.crypto.digest.{HashAlgorithm, hash, hmac, hkdfExtract, hkdfExpand}
import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}
import jinguissl_core.crypto.utils.{constantTimeEquals, randomSeed, secureCopyInto}

public let TLS13_RESUMPTION_MAX_LIFETIME_SECONDS: Int64 = 604_800
public let TLS13_RESUMPTION_DEFAULT_LIFETIME_SECONDS: Int64 = 7_200
public let TLS13_RESUMPTION_DEFAULT_AGE_TOLERANCE_MILLISECONDS: Int64 = 10_000

private let TLS13_RESUMPTION_TICKET_ID_LEN: Int64 = 32
private let TLS13_RESUMPTION_TICKET_NONCE_LEN: Int64 = 8
private let TLS13_RESUMPTION_EXT_PRE_SHARED_KEY: Int64 = 0x0029
private let TLS13_RESUMPTION_EXT_EARLY_DATA: Int64 = 0x002a
private let TLS13_RESUMPTION_EXT_SUPPORTED_VERSIONS: Int64 = 0x002b
private let TLS13_RESUMPTION_EXT_PSK_KEY_EXCHANGE_MODES: Int64 = 0x002d
private let TLS13_RESUMPTION_EXT_KEY_SHARE: Int64 = 0x0033
private let TLS13_RESUMPTION_PSK_MODE_DHE_KE: Int64 = 0x01
private let TLS13_RESUMPTION_UINT32_MODULUS: Int64 = 0x1_0000_0000
private let TLS13_RESUMPTION_UINT32_MASK: Int64 = 0xffff_ffff

/**
 * Secret-bearing local client state for one server-issued opaque ticket.
 * The resumption PSK is never encoded into the wire ticket.
 */
public class Tls13ClientResumptionTicket {
    public let wireTicket: Array<Byte>
    public let resumptionPsk: Array<Byte>
    public let ticketNonce: Array<Byte>
    public let ticketAgeAdd: Int64
    public let ticketLifetimeSeconds: Int64
    public let receivedAtUnixMilliseconds: Int64
    public let serverName: String
    public let alpnProtocol: String
    public let cipherSuite: Int64

    init(
        wireTicket: Array<Byte>,
        resumptionPsk: Array<Byte>,
        ticketNonce: Array<Byte>,
        ticketAgeAdd: Int64,
        ticketLifetimeSeconds: Int64,
        receivedAtUnixMilliseconds: Int64,
        serverName: String,
        alpnProtocol: String,
        cipherSuite: Int64
    ) {
        this.wireTicket = wireTicket.clone()
        this.resumptionPsk = resumptionPsk.clone()
        this.ticketNonce = ticketNonce.clone()
        this.ticketAgeAdd = ticketAgeAdd
        this.ticketLifetimeSeconds = ticketLifetimeSeconds
        this.receivedAtUnixMilliseconds = receivedAtUnixMilliseconds
        this.serverName = serverName
        this.alpnProtocol = alpnProtocol
        this.cipherSuite = cipherSuite
    }
}

/**
 * Server-side result after opaque lookup, context/age validation and binder proof.
 *
 * This is deliberately not a ServerHello or a completed resumed handshake. The
 * caller must still run the selected PSK through the TLS 1.3 PSK+DHE key
 * schedule with the validated ClientHello key_share and the complete transcript.
 */
public class Tls13ValidatedResumption {
    public let resumptionPsk: Array<Byte>
    public let serverName: String
    public let alpnProtocol: String
    public let cipherSuite: Int64

    init(
        resumptionPsk: Array<Byte>,
        serverName: String,
        alpnProtocol: String,
        cipherSuite: Int64
    ) {
        this.resumptionPsk = resumptionPsk.clone()
        this.serverName = serverName
        this.alpnProtocol = alpnProtocol
        this.cipherSuite = cipherSuite
    }
}

private class Tls13ServerResumptionEntry {
    let wireTicket: Array<Byte>
    let resumptionPsk: Array<Byte>
    let ticketNonce: Array<Byte>
    let ticketAgeAdd: Int64
    let issuedAtUnixMilliseconds: Int64
    let expiresAtUnixMilliseconds: Int64
    let serverName: String
    let alpnProtocol: String
    let cipherSuite: Int64
    let generation: Int64

    init(
        wireTicket: Array<Byte>,
        resumptionPsk: Array<Byte>,
        ticketNonce: Array<Byte>,
        ticketAgeAdd: Int64,
        issuedAtUnixMilliseconds: Int64,
        expiresAtUnixMilliseconds: Int64,
        serverName: String,
        alpnProtocol: String,
        cipherSuite: Int64,
        generation: Int64
    ) {
        this.wireTicket = wireTicket.clone()
        this.resumptionPsk = resumptionPsk.clone()
        this.ticketNonce = ticketNonce.clone()
        this.ticketAgeAdd = ticketAgeAdd
        this.issuedAtUnixMilliseconds = issuedAtUnixMilliseconds
        this.expiresAtUnixMilliseconds = expiresAtUnixMilliseconds
        this.serverName = serverName
        this.alpnProtocol = alpnProtocol
        this.cipherSuite = cipherSuite
        this.generation = generation
    }
}

/**
 * Bounded single-process opaque TLS 1.3 ticket owner.
 *
 * The wire ticket is only a CSPRNG lookup label. Rotation clears the current
 * generation, and successful acceptance consumes an entry. This class does
 * not claim cross-process replay coordination; callers must serialize access
 * to one store instance and keep 0-RTT disabled. Binder validation is limited
 * to a first-flight ClientHello; HelloRetryRequest transcript continuation is
 * not accepted by this bounded surface.
 */
public class Tls13OpaqueTicketStore {
    private let _maxEntries: Int64
    private let _entries = ArrayList<Tls13ServerResumptionEntry>()
    private var _rotationGeneration: Int64 = 1

    public init(maxEntries!: Int64 = 1024) {
        if (maxEntries <= 0) {
            throw CryptoException(InvalidArgument, "TLS1.3 opaque ticket store capacity must be positive")
        }
        this._maxEntries = maxEntries
    }

    public prop size: Int64 {
        get() {
            _entries.size
        }
    }

    public prop rotationGeneration: Int64 {
        get() {
            _rotationGeneration
        }
    }

    /**
     * Issues an RFC 9846 NewSessionTicket with an opaque random identity.
     * No early_data extension is emitted.
     */
    public func issueNewSessionTicket(
        resumptionMasterSecret: Array<Byte>,
        serverName: String,
        alpnProtocol: String,
        cipherSuite: Int64,
        nowUnixMilliseconds: Int64,
        ticketLifetimeSeconds!: Int64 = TLS13_RESUMPTION_DEFAULT_LIFETIME_SECONDS
    ): Array<Byte> {
        tls13ResumptionRequireTimestamp(nowUnixMilliseconds, "TLS1.3 ticket issue time")
        tls13ResumptionRequireLifetime(ticketLifetimeSeconds)
        let normalizedServerName = tls13ResumptionNormalizeServerName(serverName)
        let normalizedAlpn = tls13ResumptionNormalizeAlpn(alpnProtocol)
        let hashLen = tls13CipherSuiteHashLen(cipherSuite)
        if (resumptionMasterSecret.size != hashLen) {
            throw CryptoException(
                InvalidArgument,
                "TLS1.3 resumption master secret length must match the ticket cipher hash"
            )
        }

        _ = purgeExpired(nowUnixMilliseconds)
        let wireTicket = newUniqueWireTicket()
        let ticketNonce = randomSeed(size: TLS13_RESUMPTION_TICKET_NONCE_LEN)
        let ticketAgeAdd = tls13ResumptionDecodeUInt32(randomSeed(size: 4), 0)
        let resumptionPsk = tls13DeriveResumptionPsk(
            resumptionMasterSecret,
            ticketNonce,
            cipherSuite
        )
        let expiresAt = nowUnixMilliseconds + ticketLifetimeSeconds * 1000

        _entries.add(
            Tls13ServerResumptionEntry(
                wireTicket,
                resumptionPsk,
                ticketNonce,
                ticketAgeAdd,
                nowUnixMilliseconds,
                expiresAt,
                normalizedServerName,
                normalizedAlpn,
                cipherSuite,
                _rotationGeneration
            )
        )
        trimToCapacity()

        tls13EncodeNewSessionTicketHandshake(
            Tls13NewSessionTicketMessage(
                ticketLifetimeSeconds,
                ticketAgeAdd,
                ticketNonce,
                wireTicket,
                extensions: []
            )
        )
    }

    /**
     * Validates one first-flight, single-identity PSK+DHE ClientHello and
     * consumes its ticket. It does not emit ServerHello or claim that the
     * resumed handshake completed.
     */
    public func validateAndConsumeClientHello(
        encodedClientHello: Array<Byte>,
        nowUnixMilliseconds: Int64,
        ageToleranceMilliseconds!: Int64 = TLS13_RESUMPTION_DEFAULT_AGE_TOLERANCE_MILLISECONDS
    ): Tls13ValidatedResumption {
        tls13ResumptionRequireTimestamp(nowUnixMilliseconds, "TLS1.3 resumption acceptance time")
        if (ageToleranceMilliseconds < 0 || ageToleranceMilliseconds > 60_000) {
            throw CryptoException(
                InvalidArgument,
                "TLS1.3 ticket age tolerance must be between 0 and 60000 milliseconds"
            )
        }
        if (encodedClientHello.size == 0) {
            throw CryptoException(InvalidArgument, "TLS1.3 ClientHello must not be empty")
        }

        _ = purgeExpired(nowUnixMilliseconds)
        let clientHello = tlsDecodeClientHelloHandshake(encodedClientHello)
        tls13ResumptionRequireClientHelloEnvelope(clientHello)
        let pskExtension = tls13ResumptionRequireSinglePskExtension(clientHello.extensions)
        let parsedPsk = tls13ResumptionParseClientPreSharedKey(pskExtension.data)
        if (parsedPsk.identities.size != 1 || parsedPsk.binders.size != 1) {
            throw CryptoException(ParseError, "TLS1.3 opaque ticket backend requires exactly one PSK identity")
        }

        let (entryIndex, foundEntry) = findEntry(parsedPsk.identities[0])
        let entry = match (foundEntry) {
            case Some(value) => value
            case None => throw CryptoException(ParseError, "TLS1.3 opaque ticket is unknown or no longer valid")
        }

        tls13ResumptionRequireEntryContext(entry, clientHello)
        tls13ResumptionRequireTicketAge(
            entry,
            parsedPsk.obfuscatedTicketAges[0],
            nowUnixMilliseconds,
            ageToleranceMilliseconds
        )
        tls13ResumptionRequireBinder(
            encodedClientHello,
            pskExtension.data.size - parsedPsk.identitiesRaw.size,
            parsedPsk.binders[0],
            entry.resumptionPsk,
            entry.cipherSuite
        )

        _entries.remove(at: entryIndex)
        Tls13ValidatedResumption(
            entry.resumptionPsk,
            entry.serverName,
            entry.alpnProtocol,
            entry.cipherSuite
        )
    }

    /** Clears all outstanding tickets and advances the owner generation. */
    public func rotate(): Unit {
        clearEntries()
        if (_rotationGeneration == Int64.Max) {
            _rotationGeneration = 1
        } else {
            _rotationGeneration += 1
        }
    }

    public func purgeExpired(nowUnixMilliseconds: Int64): Int64 {
        tls13ResumptionRequireTimestamp(nowUnixMilliseconds, "TLS1.3 ticket purge time")
        var removed: Int64 = 0
        var i = _entries.size - 1
        while (i >= 0) {
            let entry = _entries[i]
            if (
                entry.generation != _rotationGeneration ||
                nowUnixMilliseconds >= entry.expiresAtUnixMilliseconds
            ) {
                _entries.remove(at: i)
                removed += 1
            }
            i -= 1
        }
        removed
    }

    private func newUniqueWireTicket(): Array<Byte> {
        var attempts: Int64 = 0
        while (attempts < 8) {
            let candidate = randomSeed(size: TLS13_RESUMPTION_TICKET_ID_LEN)
            let (index, _) = findEntry(candidate)
            if (index < 0) {
                return candidate
            }
            attempts += 1
        }
        throw CryptoException(Unsupported, "TLS1.3 CSPRNG produced repeated opaque ticket identities")
    }

    private func findEntry(wireTicket: Array<Byte>): (Int64, ?Tls13ServerResumptionEntry) {
        var i: Int64 = 0
        for (entry in _entries) {
            if (
                entry.wireTicket.size == wireTicket.size &&
                constantTimeEquals(entry.wireTicket, wireTicket)
            ) {
                return (i, Some(entry))
            }
            i += 1
        }
        (-1, None)
    }

    private func trimToCapacity(): Unit {
        while (_entries.size > _maxEntries) {
            _entries.remove(at: 0)
        }
    }

    private func clearEntries(): Unit {
        while (_entries.size > 0) {
            _entries.remove(at: _entries.size - 1)
        }
    }
}

/** RFC 9846 HKDF-Expand-Label(resumption_master_secret, "resumption", nonce, Hash.length). */
public func tls13DeriveResumptionPsk(
    resumptionMasterSecret: Array<Byte>,
    ticketNonce: Array<Byte>,
    cipherSuite: Int64
): Array<Byte> {
    let hashLen = tls13CipherSuiteHashLen(cipherSuite)
    if (resumptionMasterSecret.size != hashLen) {
        throw CryptoException(
            InvalidArgument,
            "TLS1.3 resumption master secret length must match the cipher hash"
        )
    }
    if (ticketNonce.size == 0 || ticketNonce.size > 255) {
        throw CryptoException(InvalidArgument, "TLS1.3 ticket nonce length is invalid")
    }
    tls13ResumptionHkdfExpandLabel(
        tls13CipherSuiteHashAlgorithm(cipherSuite),
        resumptionMasterSecret,
        "resumption",
        ticketNonce,
        hashLen
    )
}

/**
 * Creates local client state from a received NewSessionTicket and the
 * connection's resumption master secret. 0-RTT-bearing tickets are rejected.
 */
public func tls13CreateClientResumptionTicket(
    encodedNewSessionTicket: Array<Byte>,
    resumptionMasterSecret: Array<Byte>,
    serverName: String,
    alpnProtocol: String,
    cipherSuite: Int64,
    receivedAtUnixMilliseconds: Int64
): Tls13ClientResumptionTicket {
    tls13ResumptionRequireTimestamp(receivedAtUnixMilliseconds, "TLS1.3 ticket receipt time")
    let message = tls13DecodeNewSessionTicketHandshake(encodedNewSessionTicket)
    tls13ResumptionRequireLifetime(message.ticketLifetimeSeconds)
    for (extension in message.extensions) {
        if (extension.extType == TLS13_RESUMPTION_EXT_EARLY_DATA) {
            throw CryptoException(Unsupported, "TLS1.3 0-RTT tickets are disabled")
        }
    }
    let resumptionPsk = tls13DeriveResumptionPsk(
        resumptionMasterSecret,
        message.ticketNonce,
        cipherSuite
    )
    Tls13ClientResumptionTicket(
        message.ticket,
        resumptionPsk,
        message.ticketNonce,
        message.ticketAgeAdd,
        message.ticketLifetimeSeconds,
        receivedAtUnixMilliseconds,
        tls13ResumptionNormalizeServerName(serverName),
        tls13ResumptionNormalizeAlpn(alpnProtocol),
        cipherSuite
    )
}

/**
 * Adds one opaque ticket identity and its first-flight binder to an existing
 * PSK+DHE ClientHello. The base ClientHello must already contain one matching
 * cipher, TLS 1.3 supported_versions and a non-empty key_share. This helper
 * does not accept a HelloRetryRequest transcript.
 */
public func tls13BuildClientHelloFromResumptionTicket(
    ticket: Tls13ClientResumptionTicket,
    nowUnixMilliseconds: Int64,
    baseClientHello: Array<Byte>
): Array<Byte> {
    tls13ResumptionRequireTimestamp(nowUnixMilliseconds, "TLS1.3 ClientHello time")
    if (nowUnixMilliseconds < ticket.receivedAtUnixMilliseconds) {
        throw CryptoException(ParseError, "TLS1.3 ticket age cannot move backwards")
    }
    let clientAge = nowUnixMilliseconds - ticket.receivedAtUnixMilliseconds
    if (clientAge >= ticket.ticketLifetimeSeconds * 1000) {
        throw CryptoException(ParseError, "TLS1.3 client ticket is expired")
    }
    let obfuscatedAge = (clientAge + ticket.ticketAgeAdd) & TLS13_RESUMPTION_UINT32_MASK
    let identitiesRaw = tls13ResumptionEncodePskIdentities(ticket.wireTicket, obfuscatedAge)

    let base = tlsDecodeClientHelloHandshake(baseClientHello)
    tls13ResumptionRequireBaseClientHello(ticket, base)
    let algorithm = tls13CipherSuiteHashAlgorithm(ticket.cipherSuite)
    let hashLen = tls13CipherSuiteHashLen(ticket.cipherSuite)
    if (ticket.resumptionPsk.size != hashLen) {
        throw CryptoException(
            InvalidArgument,
            "TLS1.3 client resumption PSK length must match the ticket cipher hash"
        )
    }

    let extensions = ArrayList<TlsExtension>()
    for (extension in base.extensions) {
        if (
            extension.extType == TLS13_RESUMPTION_EXT_PRE_SHARED_KEY ||
            extension.extType == TLS13_RESUMPTION_EXT_PSK_KEY_EXCHANGE_MODES
        ) {
            continue
        }
        extensions.add(extension)
    }
    extensions.add(
        TlsExtension(
            TLS13_RESUMPTION_EXT_PSK_KEY_EXCHANGE_MODES,
            [UInt8(0x01), UInt8(TLS13_RESUMPTION_PSK_MODE_DHE_KE)]
        )
    )
    let placeholderBinderBlock = tls13ResumptionEncodeBinders(
        [Array<Byte>(hashLen, repeat: 0)]
    )
    extensions.add(
        TlsExtension(
            TLS13_RESUMPTION_EXT_PRE_SHARED_KEY,
            tls13ResumptionConcat(identitiesRaw, placeholderBinderBlock)
        )
    )

    let encodedPlaceholderHello = tlsEncodeClientHelloHandshake(
        TlsClientHello(
            base.random,
            base.cipherSuites,
            sessionId: base.sessionId,
            compressionMethods: base.compressionMethods,
            extensions: extensions.toArray(),
            legacyVersion: base.legacyVersion
        )
    )
    let transcriptHash = tls13ResumptionBinderTranscriptHash(
        algorithm,
        encodedPlaceholderHello,
        placeholderBinderBlock.size
    )
    let binder = tls13ResumptionComputeBinder(algorithm, ticket.resumptionPsk, transcriptHash)
    let pskPayload = tls13ResumptionConcat(identitiesRaw, tls13ResumptionEncodeBinders([binder]))
    extensions.remove(at: extensions.size - 1)
    extensions.add(TlsExtension(TLS13_RESUMPTION_EXT_PRE_SHARED_KEY, pskPayload))

    tlsEncodeClientHelloHandshake(
        TlsClientHello(
            base.random,
            base.cipherSuites,
            sessionId: base.sessionId,
            compressionMethods: base.compressionMethods,
            extensions: extensions.toArray(),
            legacyVersion: base.legacyVersion
        )
    )
}

private func tls13ResumptionRequireBaseClientHello(
    ticket: Tls13ClientResumptionTicket,
    clientHello: TlsClientHello
): Unit {
    if (
        clientHello.cipherSuites.size != 1 ||
        clientHello.cipherSuites[0] != ticket.cipherSuite
    ) {
        throw CryptoException(
            InvalidArgument,
            "TLS1.3 resumption base ClientHello must offer exactly the ticket cipher suite"
        )
    }
    if (clientHello.legacyVersion != TLS1_2) {
        throw CryptoException(ParseError, "TLS1.3 resumption base ClientHello legacy version is invalid")
    }
    if (clientHello.compressionMethods != [UInt8(0x00)]) {
        throw CryptoException(ParseError, "TLS1.3 resumption base ClientHello compression is invalid")
    }
    if (let Some(versions) <- tlsFindExtension(
        clientHello.extensions,
        TLS13_RESUMPTION_EXT_SUPPORTED_VERSIONS
    )) {
        if (
            versions.data.size != 3 ||
            UInt8(versions.data[0]) != UInt8(0x02) ||
            UInt8(versions.data[1]) != UInt8(0x03) ||
            UInt8(versions.data[2]) != UInt8(0x04)
        ) {
            throw CryptoException(ParseError, "TLS1.3 resumption base supported_versions is invalid")
        }
    } else {
        throw CryptoException(ParseError, "TLS1.3 resumption base supported_versions is required")
    }
    if (let Some(keyShare) <- tlsFindExtension(
        clientHello.extensions,
        TLS13_RESUMPTION_EXT_KEY_SHARE
    )) {
        if (keyShare.data.size == 0) {
            throw CryptoException(ParseError, "TLS1.3 resumption base key_share is empty")
        }
    } else {
        throw CryptoException(ParseError, "TLS1.3 resumption requires a PSK+DHE key_share")
    }
    for (extension in clientHello.extensions) {
        if (extension.extType == TLS13_RESUMPTION_EXT_EARLY_DATA) {
            throw CryptoException(Unsupported, "TLS1.3 0-RTT ClientHello is disabled")
        }
    }
    if (tls13ResumptionClientHelloServerName(clientHello) != ticket.serverName) {
        throw CryptoException(InvalidArgument, "TLS1.3 resumption base SNI does not match ticket state")
    }
    if (tls13ResumptionClientHelloAlpn(clientHello) != ticket.alpnProtocol) {
        throw CryptoException(InvalidArgument, "TLS1.3 resumption base ALPN does not match ticket state")
    }
}

private class Tls13ResumptionParsedPsk {
    let identitiesRaw: Array<Byte>
    let identities: Array<Array<Byte>>
    let obfuscatedTicketAges: Array<Int64>
    let binders: Array<Array<Byte>>

    init(
        identitiesRaw: Array<Byte>,
        identities: Array<Array<Byte>>,
        obfuscatedTicketAges: Array<Int64>,
        binders: Array<Array<Byte>>
    ) {
        this.identitiesRaw = identitiesRaw.clone()
        this.identities = tls13ResumptionCloneByteArrays(identities)
        this.obfuscatedTicketAges = obfuscatedTicketAges.clone()
        this.binders = tls13ResumptionCloneByteArrays(binders)
    }
}

private func tls13ResumptionRequireClientHelloEnvelope(clientHello: TlsClientHello): Unit {
    if (clientHello.extensions.size == 0) {
        throw CryptoException(ParseError, "TLS1.3 resumption ClientHello has no extensions")
    }
    if (
        clientHello.legacyVersion != TLS1_2 ||
        clientHello.compressionMethods != [UInt8(0x00)]
    ) {
        throw CryptoException(ParseError, "TLS1.3 resumption ClientHello envelope is invalid")
    }
    tls13ResumptionRequireUniqueExtensions(clientHello.extensions)
    let lastExtension = clientHello.extensions[clientHello.extensions.size - 1]
    if (lastExtension.extType != TLS13_RESUMPTION_EXT_PRE_SHARED_KEY) {
        throw CryptoException(ParseError, "TLS1.3 pre_shared_key extension must be last")
    }
    if (clientHello.cipherSuites.size != 1) {
        throw CryptoException(ParseError, "TLS1.3 opaque resumption requires one bound cipher suite")
    }
    for (extension in clientHello.extensions) {
        if (extension.extType == TLS13_RESUMPTION_EXT_EARLY_DATA) {
            throw CryptoException(Unsupported, "TLS1.3 0-RTT ClientHello is disabled")
        }
    }

    if (let Some(versions) <- tlsFindExtension(
        clientHello.extensions,
        TLS13_RESUMPTION_EXT_SUPPORTED_VERSIONS
    )) {
        if (
            versions.data.size != 3 ||
            UInt8(versions.data[0]) != UInt8(0x02) ||
            UInt8(versions.data[1]) != UInt8(0x03) ||
            UInt8(versions.data[2]) != UInt8(0x04)
        ) {
            throw CryptoException(ParseError, "TLS1.3 supported_versions offer is invalid")
        }
    } else {
        throw CryptoException(ParseError, "TLS1.3 supported_versions extension is required")
    }

    if (let Some(modes) <- tlsFindExtension(
        clientHello.extensions,
        TLS13_RESUMPTION_EXT_PSK_KEY_EXCHANGE_MODES
    )) {
        if (
            modes.data.size != 2 ||
            UInt8(modes.data[0]) != UInt8(0x01) ||
            UInt8(modes.data[1]) != UInt8(TLS13_RESUMPTION_PSK_MODE_DHE_KE)
        ) {
            throw CryptoException(ParseError, "TLS1.3 opaque resumption requires psk_dhe_ke mode")
        }
    } else {
        throw CryptoException(ParseError, "TLS1.3 psk_key_exchange_modes extension is required")
    }

    if (let Some(keyShare) <- tlsFindExtension(
        clientHello.extensions,
        TLS13_RESUMPTION_EXT_KEY_SHARE
    )) {
        if (keyShare.data.size == 0) {
            throw CryptoException(ParseError, "TLS1.3 resumption key_share is empty")
        }
    } else {
        throw CryptoException(ParseError, "TLS1.3 resumption requires a PSK+DHE key_share")
    }
}

private func tls13ResumptionRequireUniqueExtensions(extensions: Array<TlsExtension>): Unit {
    var i: Int64 = 0
    while (i < extensions.size) {
        var j = i + 1
        while (j < extensions.size) {
            if (extensions[i].extType == extensions[j].extType) {
                throw CryptoException(ParseError, "TLS1.3 resumption ClientHello has duplicate extensions")
            }
            j += 1
        }
        i += 1
    }
}

private func tls13ResumptionRequireSinglePskExtension(
    extensions: Array<TlsExtension>
): TlsExtension {
    var count: Int64 = 0
    var selected: ?TlsExtension = None
    for (extension in extensions) {
        if (extension.extType == TLS13_RESUMPTION_EXT_PRE_SHARED_KEY) {
            count += 1
            selected = Some(extension)
        }
    }
    if (count != 1) {
        throw CryptoException(ParseError, "TLS1.3 ClientHello must contain exactly one pre_shared_key extension")
    }
    match (selected) {
        case Some(value) => value
        case None => throw CryptoException(ParseError, "TLS1.3 pre_shared_key extension is missing")
    }
}

private func tls13ResumptionRequireEntryContext(
    entry: Tls13ServerResumptionEntry,
    clientHello: TlsClientHello
): Unit {
    if (
        entry.generation <= 0 ||
        clientHello.cipherSuites[0] != entry.cipherSuite
    ) {
        throw CryptoException(ParseError, "TLS1.3 resumption cipher/hash binding mismatch")
    }

    let requestedServerName = tls13ResumptionClientHelloServerName(clientHello)
    if (requestedServerName != entry.serverName) {
        throw CryptoException(ParseError, "TLS1.3 resumption SNI binding mismatch")
    }
    let requestedAlpn = tls13ResumptionClientHelloAlpn(clientHello)
    if (requestedAlpn != entry.alpnProtocol) {
        throw CryptoException(ParseError, "TLS1.3 resumption ALPN binding mismatch")
    }
}

private func tls13ResumptionRequireTicketAge(
    entry: Tls13ServerResumptionEntry,
    obfuscatedTicketAge: Int64,
    nowUnixMilliseconds: Int64,
    toleranceMilliseconds: Int64
): Unit {
    if (nowUnixMilliseconds < entry.issuedAtUnixMilliseconds) {
        throw CryptoException(ParseError, "TLS1.3 server ticket age cannot move backwards")
    }
    let actualAge = nowUnixMilliseconds - entry.issuedAtUnixMilliseconds
    if (actualAge >= entry.expiresAtUnixMilliseconds - entry.issuedAtUnixMilliseconds) {
        throw CryptoException(ParseError, "TLS1.3 server ticket is expired")
    }
    let clientAge = (
        obfuscatedTicketAge - entry.ticketAgeAdd + TLS13_RESUMPTION_UINT32_MODULUS
    ) & TLS13_RESUMPTION_UINT32_MASK
    if (clientAge >= entry.expiresAtUnixMilliseconds - entry.issuedAtUnixMilliseconds) {
        throw CryptoException(ParseError, "TLS1.3 client-reported ticket age exceeds ticket lifetime")
    }
    let difference = if (actualAge >= clientAge) {
        actualAge - clientAge
    } else {
        clientAge - actualAge
    }
    if (difference > toleranceMilliseconds) {
        throw CryptoException(ParseError, "TLS1.3 ticket age is outside the accepted tolerance")
    }
}

private func tls13ResumptionRequireBinder(
    encodedClientHello: Array<Byte>,
    binderBlockLength: Int64,
    providedBinder: Array<Byte>,
    resumptionPsk: Array<Byte>,
    cipherSuite: Int64
): Unit {
    let algorithm = tls13CipherSuiteHashAlgorithm(cipherSuite)
    let transcriptHash = tls13ResumptionBinderTranscriptHash(
        algorithm,
        encodedClientHello,
        binderBlockLength
    )
    let expectedBinder = tls13ResumptionComputeBinder(algorithm, resumptionPsk, transcriptHash)
    if (
        providedBinder.size != expectedBinder.size ||
        !constantTimeEquals(providedBinder, expectedBinder)
    ) {
        throw CryptoException(ParseError, "TLS1.3 resumption PSK binder verification failed")
    }
}

/**
 * RFC 9846 Truncate(ClientHello): remove only the binders vector bytes while
 * retaining the complete-message length fields already encoded on the wire.
 */
private func tls13ResumptionBinderTranscriptHash(
    algorithm: HashAlgorithm,
    encodedClientHello: Array<Byte>,
    binderBlockLength: Int64
): Array<Byte> {
    if (
        binderBlockLength <= 2 ||
        encodedClientHello.size <= binderBlockLength
    ) {
        throw CryptoException(ParseError, "TLS1.3 PSK binder transcript boundary is invalid")
    }
    hash(
        algorithm,
        encodedClientHello[0..(encodedClientHello.size - binderBlockLength)]
    )
}

private func tls13ResumptionClientHelloServerName(clientHello: TlsClientHello): String {
    if (let Some(extension) <- tlsFindExtension(clientHello.extensions, TLS_EXT_SERVER_NAME)) {
        let names = tlsParseServerNameExtension(extension)
        if (names.size != 1) {
            throw CryptoException(ParseError, "TLS1.3 resumption requires exactly one SNI name")
        }
        return tls13ResumptionNormalizeServerName(names[0])
    }
    ""
}

private func tls13ResumptionClientHelloAlpn(clientHello: TlsClientHello): String {
    if (let Some(extension) <- tlsFindExtension(clientHello.extensions, TLS_EXT_ALPN)) {
        let protocols = tlsParseAlpnExtension(extension)
        if (protocols.size != 1) {
            throw CryptoException(ParseError, "TLS1.3 resumption requires exactly one ALPN protocol")
        }
        return tls13ResumptionNormalizeAlpn(protocols[0])
    }
    ""
}

private func tls13ResumptionEncodePskIdentities(
    identity: Array<Byte>,
    obfuscatedTicketAge: Int64
): Array<Byte> {
    if (identity.size == 0 || identity.size > 65535) {
        throw CryptoException(InvalidArgument, "TLS1.3 PSK identity length is invalid")
    }
    let payload = Array<Byte>(2 + identity.size + 4, repeat: 0)
    tls13ResumptionEncodeUInt16Into(identity.size, payload, 0)
    secureCopyInto(identity, payload, dstOffset: 2)
    tls13ResumptionEncodeUInt32Into(obfuscatedTicketAge, payload, 2 + identity.size)
    let out = Array<Byte>(2 + payload.size, repeat: 0)
    tls13ResumptionEncodeUInt16Into(payload.size, out, 0)
    secureCopyInto(payload, out, dstOffset: 2)
    out
}

private func tls13ResumptionEncodeBinders(binders: Array<Array<Byte>>): Array<Byte> {
    if (binders.size == 0) {
        throw CryptoException(InvalidArgument, "TLS1.3 binder list must not be empty")
    }
    var payloadSize: Int64 = 0
    for (binder in binders) {
        if (binder.size == 0 || binder.size > 255) {
            throw CryptoException(InvalidArgument, "TLS1.3 binder length is invalid")
        }
        payloadSize += 1 + binder.size
    }
    let out = Array<Byte>(2 + payloadSize, repeat: 0)
    tls13ResumptionEncodeUInt16Into(payloadSize, out, 0)
    var offset: Int64 = 2
    for (binder in binders) {
        out[offset] = UInt8(binder.size)
        offset += 1
        secureCopyInto(binder, out, dstOffset: offset)
        offset += binder.size
    }
    out
}

private func tls13ResumptionParseClientPreSharedKey(data: Array<Byte>): Tls13ResumptionParsedPsk {
    if (data.size < 4) {
        throw CryptoException(ParseError, "TLS1.3 pre_shared_key extension is too short")
    }
    let identitiesLength = tls13ResumptionDecodeUInt16(data, 0)
    if (identitiesLength <= 0 || identitiesLength + 4 > data.size) {
        throw CryptoException(ParseError, "TLS1.3 PSK identities vector length is invalid")
    }
    let identitiesEnd = 2 + identitiesLength
    let identitiesRaw = data[0..identitiesEnd]
    let identities = ArrayList<Array<Byte>>()
    let ages = ArrayList<Int64>()
    var offset: Int64 = 2
    while (offset < identitiesEnd) {
        if (offset + 2 > identitiesEnd) {
            throw CryptoException(ParseError, "TLS1.3 PSK identity length is truncated")
        }
        let identityLength = tls13ResumptionDecodeUInt16(data, offset)
        offset += 2
        if (identityLength <= 0 || offset + identityLength + 4 > identitiesEnd) {
            throw CryptoException(ParseError, "TLS1.3 PSK identity entry is malformed")
        }
        identities.add(data[offset..(offset + identityLength)])
        offset += identityLength
        ages.add(tls13ResumptionDecodeUInt32(data, offset))
        offset += 4
    }
    if (offset != identitiesEnd) {
        throw CryptoException(ParseError, "TLS1.3 PSK identities vector has trailing bytes")
    }

    let bindersLength = tls13ResumptionDecodeUInt16(data, identitiesEnd)
    if (bindersLength <= 0 || identitiesEnd + 2 + bindersLength != data.size) {
        throw CryptoException(ParseError, "TLS1.3 PSK binders vector length is invalid")
    }
    let bindersEnd = identitiesEnd + 2 + bindersLength
    let binders = ArrayList<Array<Byte>>()
    offset = identitiesEnd + 2
    while (offset < bindersEnd) {
        let binderLength = Int64(UInt8(data[offset]))
        offset += 1
        if (binderLength <= 0 || offset + binderLength > bindersEnd) {
            throw CryptoException(ParseError, "TLS1.3 PSK binder entry is malformed")
        }
        binders.add(data[offset..(offset + binderLength)])
        offset += binderLength
    }
    if (identities.size != binders.size) {
        throw CryptoException(ParseError, "TLS1.3 PSK identity and binder counts differ")
    }
    Tls13ResumptionParsedPsk(
        identitiesRaw,
        identities.toArray(),
        ages.toArray(),
        binders.toArray()
    )
}

private func tls13ResumptionComputeBinder(
    algorithm: HashAlgorithm,
    psk: Array<Byte>,
    transcriptHash: Array<Byte>
): Array<Byte> {
    let hashLen = transcriptHash.size
    let zeros = Array<Byte>(hashLen, repeat: 0)
    let earlySecret = hkdfExtract(algorithm, zeros, psk)
    let binderKey = tls13ResumptionHkdfExpandLabel(
        algorithm,
        earlySecret,
        "res binder",
        hash(algorithm, []),
        hashLen
    )
    let finishedKey = tls13ResumptionHkdfExpandLabel(
        algorithm,
        binderKey,
        "finished",
        [],
        hashLen
    )
    hmac(algorithm, finishedKey, transcriptHash)
}

private func tls13ResumptionHkdfExpandLabel(
    algorithm: HashAlgorithm,
    secret: Array<Byte>,
    label: String,
    context: Array<Byte>,
    outputLen: Int64
): Array<Byte> {
    let fullLabel = "tls13 ${label}".toArray()
    if (fullLabel.size > 255 || context.size > 255) {
        throw CryptoException(OutOfBounds, "TLS1.3 HKDF label or context is too long")
    }
    let info = Array<Byte>(2 + 1 + fullLabel.size + 1 + context.size, repeat: 0)
    tls13ResumptionEncodeUInt16Into(outputLen, info, 0)
    info[2] = UInt8(fullLabel.size)
    secureCopyInto(fullLabel, info, dstOffset: 3)
    info[3 + fullLabel.size] = UInt8(context.size)
    if (context.size > 0) {
        secureCopyInto(context, info, dstOffset: 4 + fullLabel.size)
    }
    hkdfExpand(algorithm, secret, info, outputLen)
}

private func tls13ResumptionRequireLifetime(ticketLifetimeSeconds: Int64): Unit {
    if (
        ticketLifetimeSeconds <= 0 ||
        ticketLifetimeSeconds > TLS13_RESUMPTION_MAX_LIFETIME_SECONDS
    ) {
        throw CryptoException(
            InvalidArgument,
            "TLS1.3 ticket lifetime must be between 1 and 604800 seconds"
        )
    }
}

private func tls13ResumptionRequireTimestamp(value: Int64, label: String): Unit {
    if (value <= 0) {
        throw CryptoException(InvalidArgument, "${label} must be a positive Unix millisecond value")
    }
}

private func tls13ResumptionNormalizeServerName(value: String): String {
    let normalized = value.trimAscii().toAsciiLower()
    if (normalized.size > 65535) {
        throw CryptoException(OutOfBounds, "TLS1.3 resumption server name is too long")
    }
    normalized
}

private func tls13ResumptionNormalizeAlpn(value: String): String {
    let normalized = value.trimAscii()
    if (normalized.size > 255) {
        throw CryptoException(OutOfBounds, "TLS1.3 resumption ALPN value is too long")
    }
    normalized
}

private func tls13ResumptionCloneByteArrays(values: Array<Array<Byte>>): Array<Array<Byte>> {
    if (values.size == 0) {
        return []
    }
    let out = Array<Array<Byte>>(values.size, repeat: values[0].clone())
    var i: Int64 = 0
    while (i < values.size) {
        out[i] = values[i].clone()
        i += 1
    }
    out
}

private func tls13ResumptionConcat(left: Array<Byte>, right: Array<Byte>): Array<Byte> {
    let out = Array<Byte>(left.size + right.size, repeat: 0)
    secureCopyInto(left, out)
    secureCopyInto(right, out, dstOffset: left.size)
    out
}

private func tls13ResumptionEncodeUInt16Into(value: Int64, out: Array<Byte>, offset: Int64): Unit {
    if (value < 0 || value > 65535 || offset < 0 || offset + 2 > out.size) {
        throw CryptoException(OutOfBounds, "TLS1.3 uint16 encode is out of bounds")
    }
    out[offset] = UInt8((value >> 8) & 0xff)
    out[offset + 1] = UInt8(value & 0xff)
}

private func tls13ResumptionDecodeUInt16(value: Array<Byte>, offset: Int64): Int64 {
    if (offset < 0 || offset + 2 > value.size) {
        throw CryptoException(ParseError, "TLS1.3 uint16 decode is out of bounds")
    }
    (Int64(UInt8(value[offset])) << 8) | Int64(UInt8(value[offset + 1]))
}

private func tls13ResumptionEncodeUInt32Into(value: Int64, out: Array<Byte>, offset: Int64): Unit {
    if (
        value < 0 || value > TLS13_RESUMPTION_UINT32_MASK ||
        offset < 0 || offset + 4 > out.size
    ) {
        throw CryptoException(OutOfBounds, "TLS1.3 uint32 encode is out of bounds")
    }
    out[offset] = UInt8((value >> 24) & 0xff)
    out[offset + 1] = UInt8((value >> 16) & 0xff)
    out[offset + 2] = UInt8((value >> 8) & 0xff)
    out[offset + 3] = UInt8(value & 0xff)
}

private func tls13ResumptionDecodeUInt32(value: Array<Byte>, offset: Int64): Int64 {
    if (offset < 0 || offset + 4 > value.size) {
        throw CryptoException(ParseError, "TLS1.3 uint32 decode is out of bounds")
    }
    (Int64(UInt8(value[offset])) << 24) |
        (Int64(UInt8(value[offset + 1])) << 16) |
        (Int64(UInt8(value[offset + 2])) << 8) |
        Int64(UInt8(value[offset + 3]))
}
