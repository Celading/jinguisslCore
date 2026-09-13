package jinguissl_core.crypto.dtls

import std.collection.ArrayList
import jinguissl_core.crypto.digest.{hmac, HashAlgorithm}
import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}
import jinguissl_core.crypto.utils.csprngBytes

public let DTLS_RANDOM_LEN: Int64 = 32
public let DTLS_RANDOM_BYTES_LEN: Int64 = 28
public let DTLS_CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256: UInt16 = 0xc02b
public let DTLS_CIPHER_SUITE_ECDHE_RSA_AES128_GCM_SHA256: UInt16 = 0xc02f
public let DTLS_CIPHER_SUITE_ECDHE_ECDSA_AES256_GCM_SHA384: UInt16 = 0xc02c
public let DTLS_EXT_USE_SRTP: UInt16 = 14
public let DTLS_EXT_SUPPORTED_GROUPS: UInt16 = 10
public let DTLS_EXT_EC_POINT_FORMATS: UInt16 = 11
public let DTLS_EXT_SIGNATURE_ALGORITHMS: UInt16 = 13

func dtlsRequire(ok: Bool, message: String): Unit {
    if (!ok) { throw CryptoException(CryptoErrorCode.InvalidArgument, message) }
}
func dtlsJoin(parts: Array<Array<Byte>>): Array<Byte> {
    let result = ArrayList<Byte>()
    for (part in parts) { for (b in part) { result.add(b) } }
    result.toArray()
}
func dtlsU16(value: Int64): Array<Byte> {
    dtlsRequire(value >= 0 && value <= 65535, "DTLS uint16 out of range")
    [UInt8(value >> 8), UInt8(value & 255)]
}
func dtlsU24(value: Int64): Array<Byte> {
    dtlsRequire(value >= 0 && value <= 0xffffff, "DTLS uint24 out of range")
    [UInt8(value >> 16), UInt8((value >> 8) & 255), UInt8(value & 255)]
}
class DtlsReader {
    let data: Array<Byte>
    var offset: Int64 = 0
    init(data: Array<Byte>) { this.data = data }
    prop remaining: Int64 { get() { data.size - offset } }
    func take(count: Int64): Array<Byte> {
        dtlsRequire(count >= 0 && count <= remaining, "truncated DTLS vector")
        let value = data[offset..(offset + count)].clone()
        offset += count
        value
    }
    func u8(): Int64 { Int64(take(1)[0]) }
    func u16(): Int64 { let b = take(2); (Int64(b[0]) << 8) | Int64(b[1]) }
    func u24(): Int64 { let b = take(3); (Int64(b[0]) << 16) | (Int64(b[1]) << 8) | Int64(b[2]) }
    func end(): Unit { dtlsRequire(remaining == 0, "trailing DTLS vector bytes") }
}

public class DtlsRandom {
    public let gmtUnixTime: UInt32
    public let randomBytes: Array<Byte>
    public init(gmtUnixTime: UInt32, randomBytes: Array<Byte>) {
        dtlsRequire(randomBytes.size == 28, "DTLS random requires 28 trailing bytes")
        this.gmtUnixTime = gmtUnixTime
        this.randomBytes = randomBytes.clone()
    }
    public func encode(): Array<Byte> {
        dtlsJoin([[UInt8(gmtUnixTime >> 24), UInt8((gmtUnixTime >> 16) & 255),
            UInt8((gmtUnixTime >> 8) & 255), UInt8(gmtUnixTime & 255)], randomBytes])
    }
    public static func decode(data: Array<Byte>): DtlsRandom { decodeFrom(data, 0) }
    public static func decodeFrom(data: Array<Byte>, offset: Int64): DtlsRandom {
        dtlsRequire(offset >= 0 && offset <= data.size && data.size - offset >= 32, "truncated DTLS random")
        let b = data[offset..(offset + 32)]
        DtlsRandom((UInt32(b[0]) << 24) | (UInt32(b[1]) << 16) |
            (UInt32(b[2]) << 8) | UInt32(b[3]), b[4..])
    }
    public static func generate(): DtlsRandom { DtlsRandom(UInt32(0), csprngBytes(28)) }
}

public class DtlsExtension {
    public let kind: UInt16
    public let data: Array<Byte>
    public init(kind: UInt16, data: Array<Byte>) {
        dtlsRequire(data.size <= 65535, "DTLS extension exceeds uint16")
        this.kind = kind
        this.data = data.clone()
    }
}
func dtlsEncodeExtensions(extensions: Array<DtlsExtension>): Array<Byte> {
    let parts = ArrayList<Array<Byte>>()
    let seen = ArrayList<UInt16>()
    for (ext in extensions) {
        dtlsRequire(!seen.contains(ext.kind), "duplicate DTLS extension")
        seen.add(ext.kind)
        parts.add(dtlsJoin([dtlsU16(Int64(ext.kind)), dtlsU16(ext.data.size), ext.data]))
    }
    let data = dtlsJoin(parts.toArray())
    dtlsJoin([dtlsU16(data.size), data])
}
func dtlsReadExtensions(reader: DtlsReader): Array<DtlsExtension> {
    if (reader.remaining == 0) { return [] }
    let extReader = DtlsReader(reader.take(reader.u16()))
    reader.end()
    let result = ArrayList<DtlsExtension>()
    let seen = ArrayList<UInt16>()
    while (extReader.remaining > 0) {
        let kind = UInt16(extReader.u16())
        dtlsRequire(!seen.contains(kind), "duplicate DTLS extension")
        seen.add(kind)
        result.add(DtlsExtension(kind, extReader.take(extReader.u16())))
    }
    result.toArray()
}
func dtlsProfileExtension(profiles: Array<UInt16>): DtlsExtension {
    let parts = ArrayList<Array<Byte>>()
    for (profile in profiles) { parts.add(dtlsU16(Int64(profile))) }
    let data = dtlsJoin(parts.toArray())
    DtlsExtension(UInt16(14), dtlsJoin([dtlsU16(data.size), data, [UInt8(0)]]))
}
func dtlsReadProfiles(ext: DtlsExtension, server: Bool): Array<UInt16> {
    let reader = DtlsReader(ext.data)
    let count = reader.u16()
    dtlsRequire(count > 0 && count % 2 == 0 && (!server || count == 2), "invalid DTLS SRTP profiles")
    let list = DtlsReader(reader.take(count))
    let profiles = ArrayList<UInt16>()
    while (list.remaining > 0) { profiles.add(UInt16(list.u16())) }
    let mki = reader.u8()
    dtlsRequire(mki == 0, "nonempty SRTP MKI is unsupported")
    reader.end()
    profiles.toArray()
}

public class DtlsClientHello {
    public let version: UInt16
    public let random: DtlsRandom
    public let sessionId: Array<Byte>
    public let cookie: Array<Byte>
    public let cipherSuites: Array<UInt16>
    public let compressionMethods: Array<Byte>
    public let srtpProfiles: Array<UInt16>
    public let extensions: Array<DtlsExtension>
    public init(version: UInt16, random: DtlsRandom, sessionId: Array<Byte>, cookie: Array<Byte>,
        cipherSuites: Array<UInt16>, compressionMethods: Array<Byte>, srtpProfiles: Array<UInt16>,
        extensions!: Array<DtlsExtension> = []) {
        dtlsRequire(sessionId.size <= 32 && cookie.size <= 255, "invalid DTLS session/cookie size")
        dtlsRequire(cipherSuites.size > 0 && cipherSuites.size <= 32767, "invalid DTLS cipher list")
        dtlsRequire(compressionMethods.size > 0 && compressionMethods.size <= 255, "invalid compression list")
        this.version = version; this.random = random; this.sessionId = sessionId.clone()
        this.cookie = cookie.clone(); this.cipherSuites = cipherSuites.clone()
        this.compressionMethods = compressionMethods.clone(); this.srtpProfiles = srtpProfiles.clone()
        this.extensions = extensions.clone()
    }
    public func encode(): Array<Byte> {
        let suites = ArrayList<Array<Byte>>()
        for (suite in cipherSuites) { suites.add(dtlsU16(Int64(suite))) }
        let suiteBytes = dtlsJoin(suites.toArray())
        let ext = ArrayList<DtlsExtension>()
        for (item in extensions) { ext.add(item) }
        if (srtpProfiles.size > 0) { ext.add(dtlsProfileExtension(srtpProfiles)) }
        dtlsJoin([dtlsU16(Int64(version)), random.encode(), [UInt8(sessionId.size)], sessionId,
            [UInt8(cookie.size)], cookie, dtlsU16(suiteBytes.size), suiteBytes,
            [UInt8(compressionMethods.size)], compressionMethods, dtlsEncodeExtensions(ext.toArray())])
    }
    public static func decode(data: Array<Byte>): DtlsClientHello {
        let r = DtlsReader(data)
        let version = UInt16(r.u16())
        let random = DtlsRandom.decode(r.take(32))
        let session = r.take(r.u8())
        let cookie = r.take(r.u8())
        let suiteReader = DtlsReader(r.take(r.u16()))
        let suites = ArrayList<UInt16>()
        while (suiteReader.remaining > 0) { suites.add(UInt16(suiteReader.u16())) }
        let compression = r.take(r.u8())
        let ext = ArrayList<DtlsExtension>()
        var profiles: Array<UInt16> = []
        for (item in dtlsReadExtensions(r)) {
            if (item.kind == DTLS_EXT_USE_SRTP) { profiles = dtlsReadProfiles(item, false) }
            else { ext.add(item) }
        }
        DtlsClientHello(version, random, session, cookie, suites.toArray(), compression, profiles,
            extensions: ext.toArray())
    }
}

public class DtlsServerHello {
    public let version: UInt16
    public let random: DtlsRandom
    public let sessionId: Array<Byte>
    public let cipherSuite: UInt16
    public let compressionMethod: Byte
    public let srtpProfile: ?UInt16
    public let extensions: Array<DtlsExtension>
    public init(version: UInt16, random: DtlsRandom, sessionId: Array<Byte>, cipherSuite: UInt16,
        compressionMethod: Byte, srtpProfile: ?UInt16, extensions!: Array<DtlsExtension> = []) {
        dtlsRequire(sessionId.size <= 32, "invalid DTLS server session size")
        this.version = version; this.random = random; this.sessionId = sessionId.clone()
        this.cipherSuite = cipherSuite; this.compressionMethod = compressionMethod
        this.srtpProfile = srtpProfile; this.extensions = extensions.clone()
    }
    public func encode(): Array<Byte> {
        let ext = ArrayList<DtlsExtension>()
        for (item in extensions) { ext.add(item) }
        match (srtpProfile) { case Some(profile) => ext.add(dtlsProfileExtension([profile])); case None => () }
        dtlsJoin([dtlsU16(Int64(version)), random.encode(), [UInt8(sessionId.size)], sessionId,
            dtlsU16(Int64(cipherSuite)), [compressionMethod], dtlsEncodeExtensions(ext.toArray())])
    }
    public static func decode(data: Array<Byte>): DtlsServerHello {
        let r = DtlsReader(data)
        let version = UInt16(r.u16())
        let random = DtlsRandom.decode(r.take(32))
        let session = r.take(r.u8())
        let suite = UInt16(r.u16())
        let compression = UInt8(r.u8())
        var profile: ?UInt16 = None
        let ext = ArrayList<DtlsExtension>()
        for (item in dtlsReadExtensions(r)) {
            if (item.kind == DTLS_EXT_USE_SRTP) { profile = dtlsReadProfiles(item, true)[0] }
            else { ext.add(item) }
        }
        DtlsServerHello(version, random, session, suite, compression, profile, extensions: ext.toArray())
    }
}

public class DtlsHelloVerifyRequest {
    public let version: UInt16
    public let cookie: Array<Byte>
    public init(version: UInt16, cookie: Array<Byte>) {
        dtlsRequire(cookie.size <= 255, "invalid DTLS cookie size")
        this.version = version; this.cookie = cookie.clone()
    }
    public func encode(): Array<Byte> {
        dtlsJoin([dtlsU16(Int64(version)), [UInt8(cookie.size)], cookie])
    }
    public static func decode(data: Array<Byte>): DtlsHelloVerifyRequest {
        let r = DtlsReader(data)
        let version = UInt16(r.u16())
        let cookie = r.take(r.u8())
        r.end()
        DtlsHelloVerifyRequest(version, cookie)
    }
}

/** Low-level cookie MAC. The first argument must be a private server secret,
 * never a transmitted ServerHello random. Prefer DtlsCookieManager. */
public func dtlsGenerateCookie(serverSecret: Array<Byte>, clientRandom: Array<Byte>, version: UInt16): Array<Byte> {
    dtlsRequire(serverSecret.size >= 16 && clientRandom.size == 32, "invalid cookie secret/random")
    hmac(HashAlgorithm.SHA256, serverSecret, dtlsJoin([dtlsU16(Int64(version)), clientRandom]))
}
