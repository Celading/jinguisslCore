package jinguissl_core.tests

import jinguissl_core.crypto.ssh.*
import jinguissl_core.crypto.digest.bytesToHexLower
import jinguissl_core.crypto.error.CryptoException

private func wireBytes(size: Int64, start!: Int64 = 0): Array<Byte> {
    Array<Byte>(size, {i => UInt8((i + start) % 256)})
}

private func checkSshReference(cipher: String, ivLen: Int64, keyLen: Int64,
    first: String, second: String): Unit {
    let material = SshDirectionKeyMaterial(cipher, "none", wireBytes(ivLen), wireBytes(keyLen), [])
    let sender = SshPacketProtectionLayer(material, material)
    let receiver = SshPacketProtectionLayer(material, material)
    for (expected in [first, second]) {
        let sealed = sender.seal("packet".toArray(), randomPadding: wireBytes(32, start: 0xa0))
        @Assert(bytesToHexLower(sealed), expected)
        @Assert(receiver.open(sealed).payload, "packet".toArray())
    }
}

@Test
public class CoreSshWireReferenceTestSuite {
    @TestCase
    public func testSequenceBoundaryRequiresFreshState(): Unit {
        let material = SshDirectionKeyMaterial(SSH_CIPHER_CHACHA20_POLY1305_OPENSSH,
            "none", [], wireBytes(64), [])
        let sender = SshPacketProtectionLayer(material, material,
            initialWriteSequence: SSH_MAX_SEQUENCE_NUMBER)
        let receiver = SshPacketProtectionLayer(material, material,
            initialReadSequence: SSH_MAX_SEQUENCE_NUMBER)
        let finalPacket = sender.seal("last-sequence".toArray())
        @Assert(receiver.open(finalPacket).payload, "last-sequence".toArray())
        try { _ = sender.seal("wrapped".toArray()); @Fail("sequence wrapped") }
        catch (_: CryptoException) {}
        try { _ = receiver.open(finalPacket); @Fail("sequence reused") }
        catch (_: CryptoException) {}
    }

    @TestCase
    public func testKdfMpintAndRawHashReference(): Unit {
        let shared = wireBytes(32)
        shared[0] = 0x80
        let negotiated = SshNegotiatedAlgorithms("curve25519-sha256", "ssh-ed25519",
            SSH_CIPHER_CHACHA20_POLY1305_OPENSSH, SSH_CIPHER_CHACHA20_POLY1305_OPENSSH,
            "none", "none", "none", "none")
        let derived = sshDeriveSessionKeysSha256(shared, wireBytes(32), wireBytes(32, start: 32), negotiated)
        // Independent hashlib SHA256: mpint(K)||raw H||C||raw session_id,
        // then mpint(K)||raw H||all previous key blocks.
        @Assert(bytesToHexLower(derived.clientToServer.encryptionKey),
            "792268cffcbf7682022e9cadc120b7f4a201d0bc65e3ad8a8fce6c85fd9f7523ddcd" +
            "bbdbdb635d6fa1729d49df9a77cf6c4b4ed81858b98eb703c41f38a9a2b3")
    }

    @TestCase
    public func testAeadTamperIsTerminalAndUsedResetRejected(): Unit {
        for (cipher in [SSH_CIPHER_CHACHA20_POLY1305_OPENSSH,
            SSH_CIPHER_AES128_GCM_OPENSSH, SSH_CIPHER_AES256_GCM_OPENSSH]) {
            let isChacha = cipher == SSH_CIPHER_CHACHA20_POLY1305_OPENSSH
            let keyLen = if (isChacha) { 64 } else if (cipher == SSH_CIPHER_AES128_GCM_OPENSSH) { 16 } else { 32 }
            let material = SshDirectionKeyMaterial(cipher, "none",
                wireBytes(if (isChacha) { 0 } else { 12 }), wireBytes(keyLen), [])
            let sender = SshPacketProtectionLayer(material, material)
            sender.reset()
            let sealed = sender.seal("packet".toArray())
            try { sender.reset(); @Fail("used nonce state must not reset") }
            catch (_: CryptoException) {}
            for (index in [0, 4, sealed.size - 1]) {
                let receiver = SshPacketProtectionLayer(material, material)
                let damaged = sealed.clone()
                damaged[index] = damaged[index] ^ UInt8(1)
                try { _ = receiver.open(damaged); @Fail("tamper accepted") }
                catch (_: CryptoException) {}
                try { _ = receiver.open(sealed); @Fail("failed state reused") }
                catch (_: CryptoException) {}
                try { receiver.reset(); @Fail("failed state reset") }
                catch (_: CryptoException) {}
            }
        }
    }

    @TestCase
    public func testGcmCounterExhaustionAndMaterialIsolation(): Unit {
        let iv = Array<Byte>(12, repeat: 0xff)
        let material = SshDirectionKeyMaterial(SSH_CIPHER_AES128_GCM_OPENSSH,
            "none", iv, wireBytes(16), [])
        let sender = SshPacketProtectionLayer(material, material)
        let receiver = SshPacketProtectionLayer(material, material)
        material.iv[0] = 0
        material.encryptionKey[0] = 0xff
        let packet = sender.seal("last".toArray())
        @Assert(receiver.open(packet).payload, "last".toArray())
        try { _ = sender.seal("again".toArray()); @Fail("nonce counter wrapped") }
        catch (_: CryptoException) {}
        try { _ = receiver.open(packet); @Fail("exhausted state reused") }
        catch (_: CryptoException) {}
    }

    @TestCase
    public func testOpenSshChachaTwoKeyReference(): Unit {
        checkSshReference(SSH_CIPHER_CHACHA20_POLY1305_OPENSSH, 0, 64,
            "94450e4911c82352c683d271b2c3ffc50ae5e98f0f62483ede28bfa33ed248acaf9a7a95",
            "c922a7b5602c1dba5a6fccda8cd3dd8b16b2b0ba14be37a39a730bb53a6600404d8f9781")
    }

    @TestCase
    public func testAes128GcmClearLengthReference(): Unit {
        checkSshReference(SSH_CIPHER_AES128_GCM_OPENSSH, 12, 16,
            "000000109a1cc6ad0d7e83f4ea70c22e9305d7a09ba4acbf19298e8ca1fd757707b6fd6a",
            "0000001003622a64cee899e2c63910427f8bdac55a724b1dc51932d3503154edcbe40067")
    }

    @TestCase
    public func testAes256GcmClearLengthReference(): Unit {
        checkSshReference(SSH_CIPHER_AES256_GCM_OPENSSH, 12, 32,
            "000000104e72b778ae80b6bb2ce3342f144fdfc5ab558c828d19e5b63bca0e6189e0cd77",
            "00000010807bf0da28425db124162f2b9dc7ac1eafba0d04131100ad57ad4912e1e55f10")
    }

    @TestCase
    public func testKexDefaultsDoNotAdvertiseUnimplementedFlows(): Unit {
        @Assert(sshBuildDefaultKexInit().kexAlgorithms, ["curve25519-sha256"])
        let unsupported = SshNegotiatedAlgorithms("ecdh-sha2-nistp256", "ssh-ed25519",
            "aes128-ctr", "aes128-ctr", "hmac-sha2-256", "hmac-sha2-256", "none", "none")
        try {
            _ = sshDeriveSessionKeysSha256(wireBytes(32), wireBytes(32), wireBytes(32), unsupported)
            @Fail("unsupported KEX must not reach key derivation")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "UNSUPPORTED")
        }
    }
}
