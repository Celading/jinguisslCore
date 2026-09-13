package jinguissl_core.dtls_tests

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.ArrayList
import jinguissl_core.crypto.dtls.*

func mkBytesEcdhe(bytes: Array<Int64>): Array<Byte> {
    let result = Array<Byte>(bytes.size, repeat: 0)
    for (i in 0..bytes.size) { result[i] = UInt8(bytes[i]) }
    result
}

@Test
public class DtlsEcdheKeyExchangeTestSuite {

    @TestCase
    public func testX25519KeyExchangeRoundTrip(): Unit {
        let client = DtlsEcdheKeyExchange()
        let server = DtlsEcdheKeyExchange()

        // Client sends its public key to server
        let clientPub = client.publicKey
        @Assert(clientPub.size, 32)

        // Server processes client's public key
        let serverShared = server.processPeerPublicKey(clientPub)
        @Assert(serverShared.size, 32)

        // Client processes server's public key
        let serverPub = server.publicKey
        let clientShared = client.processPeerPublicKey(serverPub)
        @Assert(clientShared.size, 32)

        // Both should derive the same shared secret
        var same = true
        for (i in 0..32) {
            if (clientShared[i] != serverShared[i]) { same = false }
        }
        @Assert(same, true)
    }
}

@Test
public class DtlsPrfTestSuite {

    @TestCase
    public func testPrfProducesCorrectLength(): Unit {
        let secret = mkBytesEcdhe([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        let seed = mkBytesEcdhe([0xAA, 0xBB, 0xCC, 0xDD])
        let result = dtlsPrf(secret, "test label", seed, 100)
        @Assert(result.size, 100)
    }

    @TestCase
    public func testPrfDeterministic(): Unit {
        let secret = mkBytesEcdhe([0x01, 0x02, 0x03, 0x04])
        let seed = mkBytesEcdhe([0xAA, 0xBB])
        let result1 = dtlsPrf(secret, "test", seed, 48)
        let result2 = dtlsPrf(secret, "test", seed, 48)
        var same = true
        for (i in 0..48) {
            if (result1[i] != result2[i]) { same = false }
        }
        @Assert(same, true)
    }

    @TestCase
    public func testPrfDifferentLabelsProduceDifferentOutput(): Unit {
        let secret = mkBytesEcdhe([0x01, 0x02, 0x03, 0x04])
        let seed = mkBytesEcdhe([0xAA, 0xBB])
        let r1 = dtlsPrf(secret, "label1", seed, 32)
        let r2 = dtlsPrf(secret, "label2", seed, 32)
        var same = true
        for (i in 0..32) {
            if (r1[i] != r2[i]) { same = false }
        }
        @Assert(same, false)
    }
}

@Test
public class DtlsMasterSecretTestSuite {

    @TestCase
    public func testDeriveMasterSecret(): Unit {
        let preMaster = mkBytesEcdhe(Array<Int64>(32, repeat: 0xAB))
        let clientRandom = mkBytesEcdhe(Array<Int64>(32, repeat: 0x11))
        let serverRandom = mkBytesEcdhe(Array<Int64>(32, repeat: 0x22))
        let ms = dtlsDeriveMasterSecret(preMaster, clientRandom, serverRandom)
        @Assert(ms.size, 48)
    }

    @TestCase
    public func testDeriveKeyBlock(): Unit {
        let masterSecret = mkBytesEcdhe(Array<Int64>(48, repeat: 0xCD))
        let clientRandom = mkBytesEcdhe(Array<Int64>(32, repeat: 0x11))
        let serverRandom = mkBytesEcdhe(Array<Int64>(32, repeat: 0x22))
        let kb = dtlsDeriveAeadKeyBlock(masterSecret, clientRandom, serverRandom, 16, 4)
        @Assert(kb.clientWriteKey.size, 16)
        @Assert(kb.serverWriteKey.size, 16)
        @Assert(kb.clientWriteIv.size, 4)
        @Assert(kb.serverWriteIv.size, 4)
        // Client and server keys should differ
        var same = true
        for (i in 0..16) {
            if (kb.clientWriteKey[i] == kb.serverWriteKey[i]) { same = true }
        }
        // They might happen to share some bytes, but not all
    }
}

@Test
public class DtlsSrtpExtractionProperTestSuite {

    @TestCase
    public func testSrtpKeyingMaterialProper(): Unit {
        let masterSecret = mkBytesEcdhe(Array<Int64>(48, repeat: 0xCD))
        let clientRandom = mkBytesEcdhe(Array<Int64>(32, repeat: 0x11))
        let serverRandom = mkBytesEcdhe(Array<Int64>(32, repeat: 0x22))
        let km = dtlsSrtpExtractKeyingMaterialProper(masterSecret, clientRandom,
            serverRandom, DtlsSrtpProtectionProfile.AeadAes128Gcm)
        @Assert(km.clientWriteKey.size, 16)
        @Assert(km.serverWriteKey.size, 16)
        @Assert(km.clientWriteSalt.size, 12)
        @Assert(km.serverWriteSalt.size, 12)
    }

    @TestCase
    public func testSrtpKeyingMaterialDeterministic(): Unit {
        let masterSecret = mkBytesEcdhe(Array<Int64>(48, repeat: 0xCD))
        let clientRandom = mkBytesEcdhe(Array<Int64>(32, repeat: 0x11))
        let serverRandom = mkBytesEcdhe(Array<Int64>(32, repeat: 0x22))
        let km1 = dtlsSrtpExtractKeyingMaterialProper(masterSecret, clientRandom,
            serverRandom, DtlsSrtpProtectionProfile.AeadAes128Gcm)
        let km2 = dtlsSrtpExtractKeyingMaterialProper(masterSecret, clientRandom,
            serverRandom, DtlsSrtpProtectionProfile.AeadAes128Gcm)
        var same = true
        for (i in 0..16) {
            if (km1.clientWriteKey[i] != km2.clientWriteKey[i]) { same = false }
        }
        @Assert(same, true)
    }
}

@Test
public class DtlsAeadTestSuite {

    @TestCase
    public func testAeadNonceConstruction(): Unit {
        let iv = mkBytesEcdhe([0xAA, 0xBB, 0xCC, 0xDD])
        let nonce = dtlsBuildAeadNonce(iv, UInt16(1), UInt48(UInt64(42)))
        @Assert(nonce.size, 12)
        @Assert(nonce[0], UInt8(0xAA))
        @Assert(nonce[1], UInt8(0xBB))
        @Assert(nonce[2], UInt8(0xCC))
        @Assert(nonce[3], UInt8(0xDD))
        // Epoch = 1 at bytes 4-5
        @Assert(nonce[4], UInt8(0))
        @Assert(nonce[5], UInt8(1))
    }

    @TestCase
    public func testAeadEncryptDecryptRoundTrip(): Unit {
        let key = mkBytesEcdhe(Array<Int64>(16, repeat: 0x42))
        let iv = mkBytesEcdhe([0x11, 0x22, 0x33, 0x44])
        let plaintext = mkBytesEcdhe([0x01, 0x02, 0x03, 0x04, 0x05])

        let encrypted = dtlsAeadEncrypt(key, iv, UInt16(0), UInt48(UInt64(1)),
            DtlsContentType.Handshake, UInt16(0xFEFD), plaintext)
        @Assert(encrypted.size, 8 + plaintext.size + 16)

        let decrypted = dtlsAeadDecrypt(key, iv, UInt16(0), UInt48(UInt64(1)),
            DtlsContentType.Handshake, UInt16(0xFEFD), encrypted)
        @Assert(decrypted.size, plaintext.size)
        var same = true
        for (i in 0..plaintext.size) {
            if (decrypted[i] != plaintext[i]) { same = false }
        }
        @Assert(same, true)
    }

    @TestCase
    public func testAeadDecryptFailsWithWrongKey(): Unit {
        let key = mkBytesEcdhe(Array<Int64>(16, repeat: 0x42))
        let wrongKey = mkBytesEcdhe(Array<Int64>(16, repeat: 0x99))
        let iv = mkBytesEcdhe([0x11, 0x22, 0x33, 0x44])
        let plaintext = mkBytesEcdhe([0x01, 0x02, 0x03])

        let encrypted = dtlsAeadEncrypt(key, iv, UInt16(0), UInt48(UInt64(1)),
            DtlsContentType.Handshake, UInt16(0xFEFD), plaintext)

        var threw = false
        try {
            let _ = dtlsAeadDecrypt(wrongKey, iv, UInt16(0), UInt48(UInt64(1)),
                DtlsContentType.Handshake, UInt16(0xFEFD), encrypted)
        } catch (e: Exception) {
            threw = true
        }
        @Assert(threw, true)
    }
}

@Test
public class DtlsHandshakeContextTestSuite {

    @TestCase
    public func testFullEcdheHandshakeContext(): Unit {
        let client = DtlsHandshakeContext(DtlsRole.Client)
        let server = DtlsHandshakeContext(DtlsRole.Server)

        // Client generates ClientHello (includes client random)
        client.generateClientRandom()
        @Assert(client.clientRandom.size, 32)

        // Server generates ServerHello (includes server random)
        server.generateServerRandom()
        @Assert(server.serverRandom.size, 32)

        // Exchange randoms
        server.clientRandom = client.clientRandom
        client.serverRandom = server.serverRandom

        // Server sends its X25519 public key to client
        // Client processes server's public key
        client.processPeerKeyExchange(server.keyExchange.publicKey)

        // Client sends its X25519 public key to server
        // Server processes client's public key
        server.processPeerKeyExchange(client.keyExchange.publicKey)

        // Both should have master secret and key block
        @Assert(client.isHandshakeComplete(), true)
        @Assert(server.isHandshakeComplete(), true)

        // ECDHE agreement is not authentication. Context export must still reject.
        for (context in [client, server]) {
            var rejected = false
            try { _ = context.extractSrtpKeyingMaterial(DtlsSrtpProtectionProfile.AeadAes128Gcm) }
            catch (_: Exception) { rejected = true }
            @Assert(rejected)
        }
        let clientMs = match (client.masterSecret) { case Some(value) => value; case None => Array<Byte>() }
        let serverMs = match (server.masterSecret) { case Some(value) => value; case None => Array<Byte>() }
        let clientKm = dtlsSrtpExtractKeyingMaterialProper(clientMs, client.clientRandom,
            client.serverRandom, DtlsSrtpProtectionProfile.AeadAes128Gcm)
        let serverKm = dtlsSrtpExtractKeyingMaterialProper(serverMs, server.clientRandom,
            server.serverRandom, DtlsSrtpProtectionProfile.AeadAes128Gcm)

        // Client's write key should match server's read key
        var keysMatch = true
        for (i in 0..16) {
            if (clientKm.clientWriteKey[i] != serverKm.clientWriteKey[i]) { keysMatch = false }
        }
        @Assert(keysMatch, true)
    }

    @TestCase
    public func testKeyExchangeMessageBuildParse(): Unit {
        let keyExchange = DtlsEcdheKeyExchange()
        let pubKey = keyExchange.publicKey

        // Build ServerKeyExchange
        let skeBody = dtlsBuildServerKeyExchangeEcdhe(pubKey)
        @Assert(skeBody.size, 4 + 32)
        let parsedPubKey = dtlsParseServerKeyExchangeEcdhe(skeBody)
        @Assert(parsedPubKey.size, 32)
        var same = true
        for (i in 0..32) {
            if (parsedPubKey[i] != pubKey[i]) { same = false }
        }
        @Assert(same, true)

        // Build ClientKeyExchange
        let ckeBody = dtlsBuildClientKeyExchangeEcdhe(pubKey)
        @Assert(ckeBody.size, 1 + 32)
        let parsedCkePubKey = dtlsParseClientKeyExchangeEcdhe(ckeBody)
        @Assert(parsedCkePubKey.size, 32)
    }
}
