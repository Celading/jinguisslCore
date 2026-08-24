package jinguissl_core.tests

import std.collection.ArrayList
import jinguissl_core.crypto.compliance.FipsProfile
import jinguissl_core.crypto.digest.{sha256, sha384}
import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.tls.*
import jinguissl_core.crypto.x25519.x25519PublicFromPrivate

@Test
public class Tls13ResumptionSecurityTestSuite {
    @TestCase
    public func testRfc8448ResumptionPskVector(): Unit {
        let resumptionMasterSecret = resumptionHexToBytes(
            "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c"
        )
        let expectedPsk = resumptionHexToBytes(
            "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3"
        )

        @Assert(
            tls13DeriveResumptionPsk(
                resumptionMasterSecret,
                [UInt8(0x00), UInt8(0x00)],
                TLS13_CIPHER_SUITE_AES_128_GCM_SHA256
            ),
            expectedPsk
        )
    }

    @TestCase
    public func testBinderTranscriptKeepsCompleteClientHelloLengths(): Unit {
        let receivedAt: Int64 = 1_700_300_000_000
        let resumptionMasterSecret = resumptionHexToBytes(
            "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c"
        )
        let encodedTicket = tls13EncodeNewSessionTicketHandshake(
            Tls13NewSessionTicketMessage(
                60,
                0x0102_0304,
                [UInt8(0x00), UInt8(0x00)],
                Array<Byte>(32, repeat: UInt8(0x22)),
                extensions: []
            )
        )
        let ticket = tls13CreateClientResumptionTicket(
            encodedTicket,
            resumptionMasterSecret,
            "vector.example",
            "h2",
            TLS13_CIPHER_SUITE_AES_128_GCM_SHA256,
            receivedAt
        )
        let clientHello = resumptionBuildDeterministicClientHello(ticket, receivedAt + 2500)
        let offer = tls13ExtractClientPskIdentities(clientHello)[0]

        @Assert(resumptionDecodeUInt24(clientHello, 1), clientHello.size - 4)
        @Assert(
            offer.binder,
            resumptionHexToBytes(
                "af3d62c416566a8d66bec4fde4ecc2dcf741a9b4611ccbf14456757ec1a796df"
            )
        )
    }

    @TestCase
    public func testOpaqueTicketIssueResumeConsumeAndRotate(): Unit {
        let issuedAt: Int64 = 1_700_000_000_000
        let store = Tls13OpaqueTicketStore(maxEntries: 4)
        let resumptionMasterSecret = sha256("c198-resumption-master".toArray())
        let encodedTicket = store.issueNewSessionTicket(
            resumptionMasterSecret,
            "api.example.com",
            "h2",
            TLS13_CIPHER_SUITE_AES_128_GCM_SHA256,
            issuedAt,
            ticketLifetimeSeconds: 60
        )
        @Assert(store.size, 1)

        let decodedTicket = tls13DecodeNewSessionTicketHandshake(encodedTicket)
        @Assert(decodedTicket.ticketLifetimeSeconds, 60)
        @Assert(decodedTicket.ticketNonce.size, 8)
        @Assert(decodedTicket.ticket.size, 32)
        @Assert(decodedTicket.extensions.size, 0)

        let clientTicket = tls13CreateClientResumptionTicket(
            encodedTicket,
            resumptionMasterSecret,
            "api.example.com",
            "h2",
            TLS13_CIPHER_SUITE_AES_128_GCM_SHA256,
            issuedAt
        )
        let clientHello = resumptionBuildClientHello(
            clientTicket,
            issuedAt + 2500
        )
        let offer = tls13ExtractClientPskIdentities(clientHello)[0]
        @Assert(offer.identity, decodedTicket.ticket)
        @Assert(offer.obfuscatedTicketAge >= 0, true)

        let accepted = store.validateAndConsumeClientHello(
            clientHello,
            issuedAt + 2500,
            ageToleranceMilliseconds: 1000
        )
        @Assert(accepted.serverName, "api.example.com")
        @Assert(accepted.alpnProtocol, "h2")
        @Assert(accepted.cipherSuite, TLS13_CIPHER_SUITE_AES_128_GCM_SHA256)
        @Assert(accepted.resumptionPsk, clientTicket.resumptionPsk)
        @Assert(store.size, 0)

        try {
            _ = store.validateAndConsumeClientHello(clientHello, issuedAt + 2600)
            @Fail("TLS1.3 opaque ticket must be single-use after successful acceptance")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "PARSE_ERROR")
        }

        let secondTicket = store.issueNewSessionTicket(
            resumptionMasterSecret,
            "api.example.com",
            "h2",
            TLS13_CIPHER_SUITE_AES_128_GCM_SHA256,
            issuedAt + 3000
        )
        let secondClient = tls13CreateClientResumptionTicket(
            secondTicket,
            resumptionMasterSecret,
            "api.example.com",
            "h2",
            TLS13_CIPHER_SUITE_AES_128_GCM_SHA256,
            issuedAt + 3000
        )
        let secondHello = resumptionBuildClientHello(secondClient, issuedAt + 4000)
        let previousGeneration = store.rotationGeneration
        store.rotate()
        @Assert(store.rotationGeneration, previousGeneration + 1)
        @Assert(store.size, 0)
        try {
            _ = store.validateAndConsumeClientHello(secondHello, issuedAt + 4000)
            @Fail("TLS1.3 ticket rotation must invalidate tickets from the previous generation")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "PARSE_ERROR")
        }
    }

    @TestCase
    public func testOpaqueTicketRejectsBindingAgeBinderAndExpiryViolations(): Unit {
        let issuedAt: Int64 = 1_700_100_000_000
        let store = Tls13OpaqueTicketStore(maxEntries: 4)
        let resumptionMasterSecret = sha256("c198-negative-resumption-master".toArray())
        let encodedTicket = store.issueNewSessionTicket(
            resumptionMasterSecret,
            "bound.example.com",
            "h2",
            TLS13_CIPHER_SUITE_AES_128_GCM_SHA256,
            issuedAt,
            ticketLifetimeSeconds: 30
        )

        let wrongSniTicket = tls13CreateClientResumptionTicket(
            encodedTicket,
            resumptionMasterSecret,
            "other.example.com",
            "h2",
            TLS13_CIPHER_SUITE_AES_128_GCM_SHA256,
            issuedAt
        )
        try {
            _ = store.validateAndConsumeClientHello(
                resumptionBuildClientHello(wrongSniTicket, issuedAt + 1000),
                issuedAt + 1000
            )
            @Fail("TLS1.3 resumption must reject a changed SNI")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "PARSE_ERROR")
        }

        let wrongAlpnTicket = tls13CreateClientResumptionTicket(
            encodedTicket,
            resumptionMasterSecret,
            "bound.example.com",
            "http/1.1",
            TLS13_CIPHER_SUITE_AES_128_GCM_SHA256,
            issuedAt
        )
        try {
            _ = store.validateAndConsumeClientHello(
                resumptionBuildClientHello(wrongAlpnTicket, issuedAt + 1000),
                issuedAt + 1000
            )
            @Fail("TLS1.3 resumption must reject a changed ALPN")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "PARSE_ERROR")
        }

        let wrongCipherTicket = tls13CreateClientResumptionTicket(
            encodedTicket,
            resumptionMasterSecret,
            "bound.example.com",
            "h2",
            TLS13_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
            issuedAt
        )
        try {
            _ = store.validateAndConsumeClientHello(
                resumptionBuildClientHello(wrongCipherTicket, issuedAt + 1000),
                issuedAt + 1000
            )
            @Fail("TLS1.3 resumption must reject a changed cipher/hash binding")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "PARSE_ERROR")
        }

        let skewedClientTicket = tls13CreateClientResumptionTicket(
            encodedTicket,
            resumptionMasterSecret,
            "bound.example.com",
            "h2",
            TLS13_CIPHER_SUITE_AES_128_GCM_SHA256,
            issuedAt + 20_000
        )
        try {
            _ = store.validateAndConsumeClientHello(
                resumptionBuildClientHello(skewedClientTicket, issuedAt + 21_000),
                issuedAt + 21_000,
                ageToleranceMilliseconds: 10_000
            )
            @Fail("TLS1.3 resumption must reject ticket age outside the tolerance window")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "PARSE_ERROR")
        }

        let validClientTicket = tls13CreateClientResumptionTicket(
            encodedTicket,
            resumptionMasterSecret,
            "bound.example.com",
            "h2",
            TLS13_CIPHER_SUITE_AES_128_GCM_SHA256,
            issuedAt
        )
        let validHello = resumptionBuildClientHello(validClientTicket, issuedAt + 1000)
        let decodedValidHello = tlsDecodeClientHelloHandshake(validHello)

        let missingKeyShareExtensions = ArrayList<TlsExtension>()
        for (extension in decodedValidHello.extensions) {
            if (extension.extType != 0x0033) {
                missingKeyShareExtensions.add(extension)
            }
        }
        try {
            _ = store.validateAndConsumeClientHello(
                resumptionRebuildClientHello(decodedValidHello, missingKeyShareExtensions.toArray()),
                issuedAt + 1000
            )
            @Fail("TLS1.3 opaque resumption must reject PSK without DHE key_share")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "PARSE_ERROR")
        }

        let earlyDataExtensions = ArrayList<TlsExtension>()
        var extensionIndex: Int64 = 0
        while (extensionIndex < decodedValidHello.extensions.size - 1) {
            earlyDataExtensions.add(decodedValidHello.extensions[extensionIndex])
            extensionIndex += 1
        }
        earlyDataExtensions.add(TlsExtension(0x002a, []))
        earlyDataExtensions.add(decodedValidHello.extensions[decodedValidHello.extensions.size - 1])
        try {
            _ = store.validateAndConsumeClientHello(
                resumptionRebuildClientHello(decodedValidHello, earlyDataExtensions.toArray()),
                issuedAt + 1000
            )
            @Fail("TLS1.3 opaque resumption must reject early_data")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "UNSUPPORTED")
        }

        let duplicateExtensions = ArrayList<TlsExtension>()
        for (extension in decodedValidHello.extensions) {
            if (extension.extType == 0x002b) {
                duplicateExtensions.add(extension)
            }
            duplicateExtensions.add(extension)
        }
        try {
            _ = store.validateAndConsumeClientHello(
                resumptionRebuildClientHello(decodedValidHello, duplicateExtensions.toArray()),
                issuedAt + 1000
            )
            @Fail("TLS1.3 opaque resumption must reject duplicate extensions")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "PARSE_ERROR")
        }

        let tamperedHello = validHello.clone()
        tamperedHello[tamperedHello.size - 1] = UInt8(tamperedHello[tamperedHello.size - 1]) ^ UInt8(0x01)
        try {
            _ = store.validateAndConsumeClientHello(tamperedHello, issuedAt + 1000)
            @Fail("TLS1.3 resumption must reject a tampered PSK binder")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "PARSE_ERROR")
        }
        @Assert(store.size, 1)

        let accepted = store.validateAndConsumeClientHello(
            resumptionBuildClientHello(validClientTicket, issuedAt + 1000),
            issuedAt + 1000
        )
        @Assert(accepted.resumptionPsk, validClientTicket.resumptionPsk)

        let expiringStore = Tls13OpaqueTicketStore()
        let expiringTicketMessage = expiringStore.issueNewSessionTicket(
            resumptionMasterSecret,
            "bound.example.com",
            "h2",
            TLS13_CIPHER_SUITE_AES_128_GCM_SHA256,
            issuedAt,
            ticketLifetimeSeconds: 1
        )
        let expiringTicket = tls13CreateClientResumptionTicket(
            expiringTicketMessage,
            resumptionMasterSecret,
            "bound.example.com",
            "h2",
            TLS13_CIPHER_SUITE_AES_128_GCM_SHA256,
            issuedAt
        )
        try {
            _ = resumptionBuildClientHello(expiringTicket, issuedAt + 1001)
            @Fail("TLS1.3 client must not offer an expired ticket")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "PARSE_ERROR")
        }
    }

    @TestCase
    public func testSha384TicketAndEarlyDataRemainFailClosed(): Unit {
        let issuedAt: Int64 = 1_700_200_000_000
        let store = Tls13OpaqueTicketStore()
        let resumptionMasterSecret = sha384("c198-sha384-resumption-master".toArray())
        let encodedTicket = store.issueNewSessionTicket(
            resumptionMasterSecret,
            "sha384.example.com",
            "h2",
            TLS13_CIPHER_SUITE_AES_256_GCM_SHA384,
            issuedAt,
            ticketLifetimeSeconds: 120
        )
        let decoded = tls13DecodeNewSessionTicketHandshake(encodedTicket)
        @Assert(decoded.extensions.size, 0)

        let clientTicket = tls13CreateClientResumptionTicket(
            encodedTicket,
            resumptionMasterSecret,
            "sha384.example.com",
            "h2",
            TLS13_CIPHER_SUITE_AES_256_GCM_SHA384,
            issuedAt
        )
        let accepted = store.validateAndConsumeClientHello(
            resumptionBuildClientHello(clientTicket, issuedAt + 5000),
            issuedAt + 5000
        )
        @Assert(accepted.cipherSuite, TLS13_CIPHER_SUITE_AES_256_GCM_SHA384)
        @Assert(accepted.resumptionPsk.size, 48)

        let profile = FipsProfile.fromText("TLS1.3\nAES-GCM")
        try {
            tls13HandshakeRequireAllowed(profile, Tls13HandshakeMode.PSK_0RTT_PLACEHOLDER)
            @Fail("TLS1.3 0-RTT placeholder must remain disabled")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "UNSUPPORTED")
        }
    }
}

private func resumptionBuildClientHello(
    ticket: Tls13ClientResumptionTicket,
    nowUnixMilliseconds: Int64
): Array<Byte> {
    let clientPrivate = Array<Byte>(32, repeat: UInt8(0x07))
    let base = tlsDecodeClientHelloHandshake(
        tls13BuildClientHelloX25519WithCipherSuites(
            x25519PublicFromPrivate(clientPrivate),
            [ticket.cipherSuite]
        )
    )
    let extensions = ArrayList<TlsExtension>()
    for (extension in base.extensions) {
        extensions.add(extension)
    }
    if (ticket.serverName.size > 0) {
        extensions.add(tlsBuildServerNameExtension(ticket.serverName))
    }
    if (ticket.alpnProtocol.size > 0) {
        extensions.add(tlsBuildAlpnExtension([ticket.alpnProtocol]))
    }
    let encodedBase = tlsEncodeClientHelloHandshake(
        TlsClientHello(
            base.random,
            base.cipherSuites,
            sessionId: base.sessionId,
            compressionMethods: base.compressionMethods,
            extensions: extensions.toArray(),
            legacyVersion: base.legacyVersion
        )
    )
    tls13BuildClientHelloFromResumptionTicket(ticket, nowUnixMilliseconds, encodedBase)
}

private func resumptionBuildDeterministicClientHello(
    ticket: Tls13ClientResumptionTicket,
    nowUnixMilliseconds: Int64
): Array<Byte> {
    let clientPrivate = Array<Byte>(32, repeat: UInt8(0x07))
    let base = tlsDecodeClientHelloHandshake(
        tls13BuildClientHelloX25519WithCipherSuites(
            x25519PublicFromPrivate(clientPrivate),
            [ticket.cipherSuite]
        )
    )
    let extensions = ArrayList<TlsExtension>()
    for (extension in base.extensions) {
        extensions.add(extension)
    }
    extensions.add(tlsBuildServerNameExtension(ticket.serverName))
    extensions.add(tlsBuildAlpnExtension([ticket.alpnProtocol]))
    let encodedBase = tlsEncodeClientHelloHandshake(
        TlsClientHello(
            Array<Byte>(32, repeat: UInt8(0x11)),
            base.cipherSuites,
            sessionId: [],
            compressionMethods: base.compressionMethods,
            extensions: extensions.toArray(),
            legacyVersion: base.legacyVersion
        )
    )
    tls13BuildClientHelloFromResumptionTicket(ticket, nowUnixMilliseconds, encodedBase)
}

private func resumptionDecodeUInt24(value: Array<Byte>, offset: Int64): Int64 {
    (Int64(UInt8(value[offset])) << 16) |
    (Int64(UInt8(value[offset + 1])) << 8) |
    Int64(UInt8(value[offset + 2]))
}

private func resumptionRebuildClientHello(
    original: TlsClientHello,
    extensions: Array<TlsExtension>
): Array<Byte> {
    tlsEncodeClientHelloHandshake(
        TlsClientHello(
            original.random,
            original.cipherSuites,
            sessionId: original.sessionId,
            compressionMethods: original.compressionMethods,
            extensions: extensions,
            legacyVersion: original.legacyVersion
        )
    )
}

private func resumptionHexToBytes(hex: String): Array<Byte> {
    let clean = hex.trimAscii().replace(" ", "").replace("\n", "").replace("\t", "")
    if ((clean.size % 2) != 0) {
        throw Exception("invalid hex length")
    }
    let out = Array<Byte>(clean.size / 2, repeat: 0)
    var i = 0
    while (i < clean.size) {
        out[i / 2] = UInt8((resumptionHexNibble(clean[i]) << 4) | resumptionHexNibble(clean[i + 1]))
        i += 2
    }
    out
}

private func resumptionHexNibble(ch: Byte): UInt8 {
    if (ch >= b'0' && ch <= b'9') {
        return UInt8(ch - b'0')
    }
    let lower = if (ch >= b'A' && ch <= b'F') { ch + 32 } else { ch }
    if (lower >= b'a' && lower <= b'f') {
        return UInt8(lower - b'a' + 10)
    }
    throw Exception("invalid hex char")
}
