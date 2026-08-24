package jinguissl_core.crypto.sm3

import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}

private let SM3_IV: Array<UInt32> = [
    UInt32(0x7380166F), UInt32(0x4914B2B9), UInt32(0x172442D7), UInt32(0xDA8A0600),
    UInt32(0xA96F30BC), UInt32(0x163138AA), UInt32(0xE38DEE4D), UInt32(0xB0FB0E4E)
]

private let SM3_BLOCK_SIZE: Int64 = 64
private let SM3_DIGEST_SIZE: Int64 = 32

/**
 * Incremental SM3 digest context.
 *
 * A context accepts any number of chunks and may be reused after `reset`.
 * Calling `update` or `finish` after a digest has been finalized is rejected.
 */
public class Sm3Context {
    private var state: Array<UInt32> = SM3_IV.clone()
    private var buffer: Array<Byte> = Array<Byte>(SM3_BLOCK_SIZE, repeat: UInt8(0))
    private var buffered: Int64 = 0
    private var totalBytes: UInt64 = 0
    private var finalized: Bool = false

    public init() {}

    /** Add a chunk to this digest. */
    public func update(data: Array<Byte>): Unit {
        if (finalized) {
            throw CryptoException(InvalidArgument, "SM3 context is already finalized")
        }
        if (UInt64(data.size) > UInt64(0x1FFF_FFFF_FFFF_FFFF) - totalBytes) {
            throw CryptoException(InvalidArgument, "SM3 bit length overflow")
        }
        totalBytes += UInt64(data.size)

        var offset: Int64 = 0
        while (offset < data.size) {
            let take = minInt64(SM3_BLOCK_SIZE - buffered, data.size - offset)
            var i: Int64 = 0
            while (i < take) {
                buffer[buffered + i] = data[offset + i]
                i += 1
            }
            buffered += take
            offset += take

            if (buffered == SM3_BLOCK_SIZE) {
                sm3Compress(state, buffer)
                buffered = 0
            }
        }
    }

    /** Finalize and return the 32-byte digest. */
    public func finish(): Array<Byte> {
        if (finalized) {
            throw CryptoException(InvalidArgument, "SM3 context is already finalized")
        }
        if (totalBytes > UInt64(0x1FFF_FFFF_FFFF_FFFF)) {
            throw CryptoException(InvalidArgument, "SM3 bit length overflow")
        }

        let bitLength = totalBytes * 8
        buffer[buffered] = UInt8(0x80)
        buffered += 1

        if (buffered > 56) {
            while (buffered < SM3_BLOCK_SIZE) {
                buffer[buffered] = UInt8(0)
                buffered += 1
            }
            sm3Compress(state, buffer)
            buffered = 0
        }
        while (buffered < 56) {
            buffer[buffered] = UInt8(0)
            buffered += 1
        }
        var i: Int64 = 0
        while (i < 8) {
            buffer[56 + i] = UInt8((bitLength >> UInt64(56 - i * 8)) & UInt64(0xFF))
            i += 1
        }
        sm3Compress(state, buffer)
        finalized = true
        stateToDigest(state)
    }

    /** Reset this context to the SM3 initial state. */
    public func reset(): Unit {
        state = SM3_IV.clone()
        buffer = Array<Byte>(SM3_BLOCK_SIZE, repeat: UInt8(0))
        buffered = 0
        totalBytes = 0
        finalized = false
    }
}

/**
 * SM3 cryptographic hash function (GM/T 0004-2012).
 *
 * Computes a 256-bit (32-byte) hash of the input data.
 *
 * @param data Input bytes.
 * @return 32-byte SM3 digest.
 */
public func sm3(data: Array<Byte>): Array<Byte> {
    let context = Sm3Context()
    context.update(data)
    context.finish()
}

/** Compute HMAC-SM3. */
public func hmacSm3(key: Array<Byte>, data: Array<Byte>): Array<Byte> {
    let normalized = if (key.size > SM3_BLOCK_SIZE) { sm3(key) } else { key }
    let innerPad = Array<Byte>(SM3_BLOCK_SIZE, repeat: UInt8(0x36))
    let outerPad = Array<Byte>(SM3_BLOCK_SIZE, repeat: UInt8(0x5C))
    var i: Int64 = 0
    while (i < normalized.size) {
        innerPad[i] ^= normalized[i]
        outerPad[i] ^= normalized[i]
        i += 1
    }

    let inner = Sm3Context()
    inner.update(innerPad)
    inner.update(data)
    let innerDigest = inner.finish()

    let outer = Sm3Context()
    outer.update(outerPad)
    outer.update(innerDigest)
    outer.finish()
}

/**
 * SM3 counter-mode key derivation function used by SM2.
 *
 * The counter starts at one and is encoded as a four-byte big-endian value.
 */
public func sm3Kdf(input: Array<Byte>, outputLen: Int64): Array<Byte> {
    if (outputLen < 0) {
        throw CryptoException(InvalidArgument, "SM3 KDF output length must not be negative")
    }
    if (outputLen == 0) {
        return []
    }
    if (outputLen > Int64(UInt32(0xFFFF_FFFF)) * SM3_DIGEST_SIZE) {
        throw CryptoException(InvalidArgument, "SM3 KDF output length is too large")
    }
    let blocks = (outputLen + SM3_DIGEST_SIZE - 1) / SM3_DIGEST_SIZE

    let output = Array<Byte>(outputLen, repeat: UInt8(0))
    var counter: UInt32 = 1
    var offset: Int64 = 0
    while (offset < outputLen) {
        let context = Sm3Context()
        context.update(input)
        context.update([
            UInt8((counter >> 24) & UInt32(0xFF)),
            UInt8((counter >> 16) & UInt32(0xFF)),
            UInt8((counter >> 8) & UInt32(0xFF)),
            UInt8(counter & UInt32(0xFF))
        ])
        let digest = context.finish()
        let take = minInt64(SM3_DIGEST_SIZE, outputLen - offset)
        var i: Int64 = 0
        while (i < take) {
            output[offset + i] = digest[i]
            i += 1
        }
        offset += take
        if (offset < outputLen) {
            counter += 1
        }
    }
    output
}

private func minInt64(a: Int64, b: Int64): Int64 {
    if (a < b) { a } else { b }
}

private func stateToDigest(state: Array<UInt32>): Array<Byte> {
    let result = Array<Byte>(SM3_DIGEST_SIZE, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < 8) {
        result[i * 4] = UInt8((state[i] >> 24) & UInt32(0xFF))
        result[i * 4 + 1] = UInt8((state[i] >> 16) & UInt32(0xFF))
        result[i * 4 + 2] = UInt8((state[i] >> 8) & UInt32(0xFF))
        result[i * 4 + 3] = UInt8(state[i] & UInt32(0xFF))
        i += 1
    }
    result
}

/* ─── SM3 compression helpers (private) ─── */

private func rotl32(v: UInt32, bits: Int64): UInt32 {
    let n = bits & 31
    (v << UInt32(n)) | (v >> UInt32((32 - n) & 31))
}

private func P0(x: UInt32): UInt32 {
    x ^ rotl32(x, 9) ^ rotl32(x, 17)
}

private func P1(x: UInt32): UInt32 {
    x ^ rotl32(x, 15) ^ rotl32(x, 23)
}

private func FF0(x: UInt32, y: UInt32, z: UInt32): UInt32 {
    x ^ y ^ z
}

private func FF1(x: UInt32, y: UInt32, z: UInt32): UInt32 {
    (x & y) | (x & z) | (y & z)
}

private func GG0(x: UInt32, y: UInt32, z: UInt32): UInt32 {
    x ^ y ^ z
}

private func GG1(x: UInt32, y: UInt32, z: UInt32): UInt32 {
    (x & y) | ((UInt32(0xFFFFFFFF) ^ x) & z)
}

/* Wrapping 32-bit addition (mod 2^32, matching SM3 spec) */
private func add32(a: UInt32, b: UInt32): UInt32 {
    UInt32((UInt64(a) + UInt64(b)) & UInt64(0xFFFF_FFFF))
}

private func add32(a: UInt32, b: UInt32, c: UInt32): UInt32 {
    UInt32((UInt64(a) + UInt64(b) + UInt64(c)) & UInt64(0xFFFF_FFFF))
}
private func sm3Compress(state: Array<UInt32>, block: Array<Byte>): Unit {
    /* Message expansion: W[0..15] from block, W[16..67] derived */
    var w = Array<UInt32>(68, repeat: UInt32(0))

    var i = 0
    while (i < 16) {
        w[i] = (UInt32(block[i * 4]) << 24) |
               (UInt32(block[i * 4 + 1]) << 16) |
               (UInt32(block[i * 4 + 2]) << 8) |
               UInt32(block[i * 4 + 3])
        i += 1
    }

    i = 16
    while (i < 68) {
        w[i] = P1(w[i - 16] ^ w[i - 9] ^ rotl32(w[i - 3], 15)) ^
               rotl32(w[i - 13], 7) ^
               w[i - 6]
        i += 1
    }

    /* Working variables */
    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    var f = state[5]
    var g = state[6]
    var h = state[7]

    /* 64 rounds */
    i = 0
    while (i < 64) {
        /* Round constant: Tj rotated left by j */
        let Tj = if (i < 16) { UInt32(0x79CC4519) } else { UInt32(0x7A879D8A) }
        let Kj = rotl32(Tj, i)

        let a12 = rotl32(a, 12)
        let SS1 = rotl32(add32(add32(a12, e), Kj), 7)
        let SS2 = SS1 ^ a12

        let Wj = w[i]
        let Wi = w[i] ^ w[i + 4]

        let (FF, GG) = if (i < 16) { (FF0, GG0) } else { (FF1, GG1) }

        let TT1 = add32(add32(add32(FF(a, b, c), d), SS2), Wi)
        let TT2 = add32(add32(add32(GG(e, f, g), h), SS1), Wj)

        d = c
        c = rotl32(b, 9)
        b = a
        a = TT1

        h = g
        g = rotl32(f, 19)
        f = e
        e = P0(TT2)

        i += 1
    }

    /* Update state */
    state[0] ^= a
    state[1] ^= b
    state[2] ^= c
    state[3] ^= d
    state[4] ^= e
    state[5] ^= f
    state[6] ^= g
    state[7] ^= h
}
