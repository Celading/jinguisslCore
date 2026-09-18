package jinguissl_core.crypto.digest

import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}

private let B2S_IV: Array<UInt32> = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
private let B2S_SIGMA: Array<Array<Int64>> = [
    [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
    [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
    [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],
    [7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
    [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],
    [2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
    [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],
    [13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
    [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],
    [10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0]]

/// RFC 7693 sequential BLAKE2s. Caller-serialized, single-finalization owner.
/// digestLength is a parameter, not truncation of a 32-byte digest.
public class Blake2sContext {
    private let state: Array<UInt32> = B2S_IV.clone()
    private let block: Array<Byte> = Array<Byte>(64, repeat: 0)
    private let digestLength: Int64
    private var buffered: Int64 = 0
    private var count: UInt64 = 0
    private var closed: Bool = false

    public init(key!: Array<Byte> = [], digestLength!: Int64 = 32) {
        if (key.size > 32 || digestLength < 1 || digestLength > 32) {
            throw CryptoException(InvalidArgument, "BLAKE2s requires key length 0..32 and digest length 1..32")
        }
        this.digestLength = digestLength
        state[0] = state[0] ^ (UInt32(0x01010000) | (UInt32(key.size) << 8) | UInt32(digestLength))
        if (key.size > 0) {
            for (i in 0..key.size) { block[i] = key[i] }
            buffered = 64
        }
    }

    private func requireOpen(): Unit {
        if (closed) { throw CryptoException(InvalidArgument, "BLAKE2s context is finalized or destroyed") }
    }

    public func update(input: Array<Byte>): Unit {
        requireOpen()
        if (UInt64(input.size) > UInt64.Max - count - UInt64(buffered)) {
            throw CryptoException(OutOfBounds, "BLAKE2s byte counter exhausted")
        }
        var offset: Int64 = 0
        while (offset < input.size) {
            if (buffered == 64) {
                count += 64
                compress(false)
                buffered = 0
            }
            let take = if (input.size - offset < 64 - buffered) { input.size - offset } else { 64 - buffered }
            for (i in 0..take) { block[buffered + i] = input[offset + i] }
            buffered += take
            offset += take
        }
    }

    public func finalDigest(): Array<Byte> {
        requireOpen()
        count += UInt64(buffered)
        for (i in buffered..64) { block[i] = 0 }
        compress(true)
        let result = Array<Byte>(digestLength, {i => UInt8((state[i / 4] >> (8 * (i % 4))) & 0xff)})
        destroy()
        result
    }

    /// Clears owned mutable state; no guarantee about managed-runtime copies.
    public func destroy(): Unit {
        for (i in 0..state.size) { state[i] = 0 }
        for (i in 0..block.size) { block[i] = 0 }
        count = 0
        buffered = 0
        closed = true
    }

    private func compress(last: Bool): Unit {
        let words = Array<UInt32>(16, {i =>
            UInt32(block[4*i]) | (UInt32(block[4*i+1]) << 8) |
            (UInt32(block[4*i+2]) << 16) | (UInt32(block[4*i+3]) << 24)})
        let v = Array<UInt32>(16, {i => if (i < 8) { state[i] } else { B2S_IV[i-8] }})
        v[12] = v[12] ^ UInt32(count & 0xffffffff)
        v[13] = v[13] ^ UInt32(count >> 32)
        if (last) { v[14] = v[14] ^ UInt32.Max }
        for (round in 0..10) {
            let s = B2S_SIGMA[round]
            b2sMix(v, 0,4,8,12, words[s[0]],words[s[1]])
            b2sMix(v, 1,5,9,13, words[s[2]],words[s[3]])
            b2sMix(v, 2,6,10,14, words[s[4]],words[s[5]])
            b2sMix(v, 3,7,11,15, words[s[6]],words[s[7]])
            b2sMix(v, 0,5,10,15, words[s[8]],words[s[9]])
            b2sMix(v, 1,6,11,12, words[s[10]],words[s[11]])
            b2sMix(v, 2,7,8,13, words[s[12]],words[s[13]])
            b2sMix(v, 3,4,9,14, words[s[14]],words[s[15]])
        }
        for (i in 0..8) { state[i] = state[i] ^ v[i] ^ v[i+8] }
        for (i in 0..16) { words[i] = 0; v[i] = 0 }
    }
}

@OverflowWrapping
private func b2sMix(v: Array<UInt32>, a: Int64, b: Int64, c: Int64, d: Int64, x: UInt32, y: UInt32): Unit {
    v[a] = v[a] + v[b] + x
    v[d] = b2sRotate(v[d] ^ v[a], 16)
    v[c] = v[c] + v[d]
    v[b] = b2sRotate(v[b] ^ v[c], 12)
    v[a] = v[a] + v[b] + y
    v[d] = b2sRotate(v[d] ^ v[a], 8)
    v[c] = v[c] + v[d]
    v[b] = b2sRotate(v[b] ^ v[c], 7)
}

private func b2sRotate(x: UInt32, n: Int64): UInt32 { (x >> n) | (x << (32-n)) }

public func blake2s(input: Array<Byte>, key!: Array<Byte> = [], digestLength!: Int64 = 32): Array<Byte> {
    let context = Blake2sContext(key: key, digestLength: digestLength)
    try { context.update(input); context.finalDigest() } finally { context.destroy() }
}
