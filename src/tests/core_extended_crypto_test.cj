package jinguissl_core.tests

import jinguissl_core.crypto.digest.{blake2s, Blake2sContext, bytesToHexLower}
import jinguissl_core.crypto.chacha20.{hchacha20, xchacha20Poly1305Encrypt, xchacha20Poly1305Decrypt}
import jinguissl_core.crypto.error.CryptoException

@Test
public class CoreExtendedCryptoTestSuite {
    @TestCase
    public func testBlake2sIndependentVectorsAndStreaming(): Unit {
        // Python hashlib (independent RFC 7693 implementation), incremental bytes.
        let vectors: Array<(Int64, Int64, Int64, String)> = [
            (0,0,32,"69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"),
            (3,0,32,"e8f91c6ef232a041452ab0e149070cdd7dd1769e75b3a5921be37876c45c9900"),
            (63,32,32,"c65382513f07460da39833cb666c5ed82e61b9e998f4b0c4287cee56c3cc9bcd"),
            (64,32,32,"8975b0577fd35566d750b362b0897a26c399136df07bababbde6203ff2954ed4"),
            (65,32,32,"21fe0ceb0052be7fb0f004187cacd7de67fa6eb0938d927677f2398c132317a8"),
            (128,16,16,"24548ecbf479d44b545512c39a847b95"),
            (129,0,1,"fa"), (0,32,16,"9536f9b267655743dee97b8a670f9f53"),
            (1024,32,32,"9ad228e0f38ae8e2f5ab6b1c668d6cd863e3e27244e6d52d4f14e3038aecf426")]
        for ((n,k,d,expected) in vectors) {
            let input = Array<Byte>(n, {i => UInt8(i % 256)})
            let key = Array<Byte>(k, {i => UInt8(i)})
            @Assert(bytesToHexLower(blake2s(input, key: key, digestLength: d)), expected)
            let stream = Blake2sContext(key: key, digestLength: d)
            for (b in input) { stream.update([b]); stream.update([]) }
            @Assert(bytesToHexLower(stream.finalDigest()), expected)
            try { stream.update([]); @Fail("finalized context reused") } catch (_: CryptoException) {}
            stream.destroy()
        }
        @Assert(bytesToHexLower(blake2s("abc".toArray())),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
    }

    @TestCase
    public func testBlake2sInvalidParametersAndKeyIsolation(): Unit {
        for (n in [0,33]) {
            try { _ = Blake2sContext(digestLength: n); @Fail("bad digest length") } catch (_: CryptoException) {}
        }
        try { _ = Blake2sContext(key: Array<Byte>(33, repeat: 0)); @Fail("bad key") } catch (_: CryptoException) {}
        let key = Array<Byte>(32, {i => UInt8(i)})
        let context = Blake2sContext(key: key, digestLength: 16)
        key[0] = 255
        @Assert(bytesToHexLower(context.finalDigest()), "9536f9b267655743dee97b8a670f9f53")
        try { _ = context.finalDigest(); @Fail("second final") } catch (_: CryptoException) {}
        let destroyed = Blake2sContext()
        destroyed.destroy()
        try { _ = destroyed.finalDigest(); @Fail("destroyed final") } catch (_: CryptoException) {}
    }

    @TestCase
    public func testHchachaDraftVector(): Unit {
        @Assert(bytesToHexLower(hchacha20(Array<Byte>(32, {i => UInt8(i)}),
            [0,0,0,9,0,0,0,0x4a,0,0,0,0,0x31,0x41,0x59,0x27])),
            "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
    }

    @TestCase
    public func testXchachaDraftVectorAndTamper(): Unit {
        let key = Array<Byte>(32, {i => UInt8(128+i)})
        let nonce = Array<Byte>(24, {i => UInt8(64+i)})
        let aad: Array<Byte> = [0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7]
        let plain = ("Ladies and Gentlemen of the class of '99: " +
            "If I could offer you only one tip for the future, sunscreen would be it.").toArray()
        let (cipher, tag) = xchacha20Poly1305Encrypt(key, nonce, plain, aad: aad)
        @Assert(bytesToHexLower(cipher), "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
            "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
            "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
            "21f9664c97637da9768812f615c68b13b52e")
        @Assert(bytesToHexLower(tag), "c0875924c1c7987947deafd8780acf49")
        @Assert(xchacha20Poly1305Decrypt(key, nonce, cipher, tag, aad: aad), plain)
        for (field in [key,nonce,cipher,tag,aad]) {
            field[0] = field[0] ^ UInt8(1)
            try { _ = xchacha20Poly1305Decrypt(key, nonce, cipher, tag, aad: aad); @Fail("tamper accepted") }
            catch (_: CryptoException) {}
            field[0] = field[0] ^ UInt8(1)
        }
    }

    @TestCase
    public func testXchachaEmptyAndInvalidLengths(): Unit {
        let key = Array<Byte>(32, repeat: 0)
        let nonce = Array<Byte>(24, repeat: 0)
        let (cipher, tag) = xchacha20Poly1305Encrypt(key, nonce, [])
        @Assert(xchacha20Poly1305Decrypt(key, nonce, cipher, tag).size, 0)
        for (n in [0,12,16,23,25]) {
            try { _ = xchacha20Poly1305Encrypt(key, Array<Byte>(n, repeat: 0), []); @Fail("bad nonce") }
            catch (_: CryptoException) {}
        }
        try { _ = hchacha20([], Array<Byte>(16, repeat: 0)); @Fail("bad key") } catch (_: CryptoException) {}
        try { _ = hchacha20(key, []); @Fail("bad H nonce") } catch (_: CryptoException) {}
        try { _ = xchacha20Poly1305Decrypt(key, nonce, cipher, []); @Fail("bad tag") } catch (_: CryptoException) {}
    }
}
