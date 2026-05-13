package jinguissl_core.jinguissl.tests

import jinguissl_core.jinguissl.crypto.digest.*

@Test
public class CoreDigestTestSuite {
    @TestCase
    public func testHashAlgorithmEnumShape(): Unit {
        @Assert(HashAlgorithm.MD5.toString(), "MD5")
        @Assert(HashAlgorithm.SHA1.toString(), "SHA-1")
        @Assert(HashAlgorithm.SHA256.toString(), "SHA-256")
        @Assert(HashAlgorithm.SHA384.toString(), "SHA-384")
        @Assert(HashAlgorithm.SHA512.toString(), "SHA-512")

        @Assert(HashAlgorithm.MD5.ordinalValue(), 0)
        @Assert(HashAlgorithm.SHA1.ordinalValue(), 1)
        @Assert(HashAlgorithm.SHA256.ordinalValue(), 2)
        @Assert(HashAlgorithm.SHA384.ordinalValue(), 3)
        @Assert(HashAlgorithm.SHA512.ordinalValue(), 4)
    }

    @TestCase
    public func testHashAlgorithmEquality(): Unit {
        @Assert(HashAlgorithm.MD5 == HashAlgorithm.MD5, true)
        @Assert(HashAlgorithm.MD5 != HashAlgorithm.SHA1, true)
        @Assert(HashAlgorithm.SHA256 == HashAlgorithm.SHA256, true)
        @Assert(HashAlgorithm.SHA256 != HashAlgorithm.SHA512, true)
    }

    @TestCase
    public func testMd5EmptyStringKnownVector(): Unit {
        let empty: Array<Byte> = []
        let digest = md5(empty)
        let hex = bytesToHexLower(digest)
        @Assert(hex, "d41d8cd98f00b204e9800998ecf8427e")
    }

    @TestCase
    public func testSha1EmptyStringKnownVector(): Unit {
        let empty: Array<Byte> = []
        let digest = sha1(empty)
        let hex = bytesToHexLower(digest)
        @Assert(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709")
    }

    @TestCase
    public func testSha256EmptyStringKnownVector(): Unit {
        let empty: Array<Byte> = []
        let digest = sha256(empty)
        let hex = bytesToHexLower(digest)
        @Assert(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    @TestCase
    public func testSha384EmptyStringKnownVector(): Unit {
        let empty: Array<Byte> = []
        let digest = sha384(empty)
        let hex = bytesToHexLower(digest)
        @Assert(hex, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")
    }

    @TestCase
    public func testSha512EmptyStringKnownVector(): Unit {
        let empty: Array<Byte> = []
        let digest = sha512(empty)
        let hex = bytesToHexLower(digest)
        @Assert(hex, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
    }

    @TestCase
    public func testHashDispatcherRoutesCorrectly(): Unit {
        let empty: Array<Byte> = []
        @Assert(bytesToHexLower(hash(HashAlgorithm.MD5, empty)), "d41d8cd98f00b204e9800998ecf8427e")
        @Assert(bytesToHexLower(hash(HashAlgorithm.SHA1, empty)), "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        @Assert(bytesToHexLower(hash(HashAlgorithm.SHA256, empty)), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        @Assert(bytesToHexLower(hash(HashAlgorithm.SHA384, empty)), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b")
        @Assert(bytesToHexLower(hash(HashAlgorithm.SHA512, empty)), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
    }

    @TestCase
    public func testMd5KnownDataVector(): Unit {
        let data: Array<Byte> = [0x61, 0x62, 0x63] // "abc"
        let digest = md5(data)
        let hex = bytesToHexLower(digest)
        @Assert(hex, "900150983cd24fb0d6963f7d28e17f72")
    }

    @TestCase
    public func testSha256KnownDataVector(): Unit {
        let data: Array<Byte> = [0x61, 0x62, 0x63] // "abc"
        let digest = sha256(data)
        let hex = bytesToHexLower(digest)
        @Assert(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    @TestCase
    public func testBytesToHexLowerEdgeCases(): Unit {
        @Assert(bytesToHexLower([]), "")
        @Assert(bytesToHexLower([0x00]), "00")
        @Assert(bytesToHexLower([0xff]), "ff")
        @Assert(bytesToHexLower([0xab, 0xcd, 0xef]), "abcdef")
        @Assert(bytesToHexLower([0x12, 0x34, 0x56]), "123456")
    }

    @TestCase
    public func testHashAlgorithmAllValuesCovered(): Unit {
        @Assert(hash(HashAlgorithm.MD5, [0x00]).size, 16)
        @Assert(hash(HashAlgorithm.SHA1, [0x00]).size, 20)
        @Assert(hash(HashAlgorithm.SHA256, [0x00]).size, 32)
        @Assert(hash(HashAlgorithm.SHA384, [0x00]).size, 48)
        @Assert(hash(HashAlgorithm.SHA512, [0x00]).size, 64)
    }
}
