package jinguissl_core.tests

import jinguissl_core.crypto.tls.Tls13HandshakeSecrets
import jinguissl_core.crypto.error.CryptoException

@Test
public class CoreTlsSecretLifecycleTestSuite {
    @TestCase
    public func testSecretsAreOwnedSnapshotsAndDestroyIsTerminal(): Unit {
        let input = Array<Byte>(32, repeat: 0x42)
        let keys = Tls13HandshakeSecrets(input, input, input, input, input,
            input, input, input, input, input, input)
        input[0] = 0
        let exported = keys.clientWriteKey
        @Assert(exported[0], UInt8(0x42))
        exported[0] = 0x17
        @Assert(keys.clientWriteKey[0], UInt8(0x42))
        keys.destroy()
        keys.destroy()
        @Assert(keys.isDestroyed, true)
        @Assert(exported[0], UInt8(0x17))
        try { _ = keys.clientWriteKey; @Fail("destroyed key exported") }
        catch (_: CryptoException) {}
        try { _ = keys.serverHsTrafficSecret; @Fail("destroyed handshake secret exported") }
        catch (_: CryptoException) {}
        try { _ = keys.masterSecret; @Fail("destroyed master secret exported") }
        catch (_: CryptoException) {}
    }
}
