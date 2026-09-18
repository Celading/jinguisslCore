package jinguissl_core.tests

import jinguissl_core.crypto.ssh.*
import jinguissl_core.crypto.error.CryptoException

@Test
public class CoreSshStreamPrefixTestSuite {
    @TestCase
    public func testPrefixDoesNotAdvanceStateAndUsesConnectionSequence(): Unit {
        for (cipher in ["aes128-ctr","aes256-ctr",SSH_CIPHER_AES128_GCM_OPENSSH,
            SSH_CIPHER_AES256_GCM_OPENSSH,SSH_CIPHER_CHACHA20_POLY1305_OPENSSH]) {
            let chacha = cipher == SSH_CIPHER_CHACHA20_POLY1305_OPENSSH
            let ctr = cipher.endsWith("-ctr")
            let ivLen: Int64 = if (chacha) { 0 } else if (ctr) { 16 } else { 12 }
            let keyLen: Int64 = if (chacha) { 64 } else if (cipher.startsWith("aes128")) { 16 } else { 32 }
            let material = SshDirectionKeyMaterial(cipher,if (ctr) { "hmac-sha2-256" } else { "none" },
                Array<Byte>(ivLen,repeat: 0),Array<Byte>(keyLen,repeat: 7),Array<Byte>(if (ctr) { 32 } else { 0 },repeat: 8))
            let sender = SshPacketProtectionLayer(material,material,initialWriteSequence: 3)
            let reader = SshPacketProtectionLayer(material,material,initialReadSequence: 3)
            for (i in 3..8) {
                let packet = sender.seal([UInt8(i)])
                for (_ in 0..3) { @Assert(reader.encodedPacketSize(packet[..reader.readPrefixLength]),packet.size) }
                @Assert(reader.readSequence,i)
                @Assert(reader.open(packet).payload,[UInt8(i)])
            }
        }
    }
    @TestCase
    public func testOversizedPrefixIsTerminal(): Unit {
        let material = SshDirectionKeyMaterial(SSH_CIPHER_AES128_GCM_OPENSSH,"none",
            Array<Byte>(12,repeat: 0),Array<Byte>(16,repeat: 0),[])
        let reader = SshPacketProtectionLayer(material,material)
        try { _ = reader.encodedPacketSize([UInt8(0),16,0,0]); @Fail("oversized prefix") } catch (_: CryptoException) {}
        try { _ = reader.encodedPacketSize([UInt8(0),0,0,16]); @Fail("terminal reader reused") } catch (_: CryptoException) {}
    }
}
