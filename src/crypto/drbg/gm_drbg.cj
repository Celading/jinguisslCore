package jinguissl_core.crypto.drbg

import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}
import jinguissl_core.crypto.sm3.{Sm3Context, sm3}
import jinguissl_core.crypto.sm4.Sm4Context
import jinguissl_core.crypto.utils.csprngBytes

private let GM_DRBG_RESEED_INTERVAL: UInt64 = 1024
private let SM3_HASH_DRBG_SEED_LEN: Int64 = 55
private let SM3_HASH_DRBG_MAX_REQUEST: Int64 = 32
private let SM4_CTR_DRBG_SEED_LEN: Int64 = 32
private let SM4_CTR_DRBG_MAX_REQUEST: Int64 = 16
private let GM_DRBG_MIN_ENTROPY: Int64 = 32
private let GM_DRBG_MIN_NONCE: Int64 = 16

/**
 * SM3 Hash-DRBG with the GM request and reseed limits used by the comparison
 * provider. A context is mutable and intentionally not thread-safe.
 */
public class Sm3HashDrbg {
    private var v: Array<Byte> = Array<Byte>(SM3_HASH_DRBG_SEED_LEN, repeat: UInt8(0))
    private var c: Array<Byte> = Array<Byte>(SM3_HASH_DRBG_SEED_LEN, repeat: UInt8(0))
    private var counter: UInt64 = 0
    private var active: Bool = false

    public init(
        entropy: Array<Byte>,
        nonce: Array<Byte>,
        personalization!: Array<Byte> = []
    ) {
        gmDrbgRequireSeed(entropy, nonce, personalization)
        v = sm3HashDf([entropy, nonce, personalization], SM3_HASH_DRBG_SEED_LEN)
        c = sm3HashDf([[UInt8(0)], v], SM3_HASH_DRBG_SEED_LEN)
        counter = 1
        active = true
    }

    /** Generate one GM-bounded request (at most 32 bytes). */
    public func generate(
        outputLen: Int64,
        additionalInput!: Array<Byte> = []
    ): Array<Byte> {
        requireGenerate(outputLen, SM3_HASH_DRBG_MAX_REQUEST, "SM3 Hash-DRBG")
        if (additionalInput.size > 0) {
            let context = Sm3Context()
            context.update([UInt8(0x02)])
            context.update(v)
            context.update(additionalInput)
            gmDrbgAddBigEndian(v, context.finish())
        }

        let output = sm3Hashgen(v, outputLen)
        let context = Sm3Context()
        context.update([UInt8(0x03)])
        context.update(v)
        gmDrbgAddBigEndian(v, context.finish())
        gmDrbgAddBigEndian(v, c)
        gmDrbgAddBigEndian(v, gmDrbgCounterBytes(counter))
        counter += UInt64(1)
        output
    }

    /** Generate any positive length by issuing multiple bounded requests. */
    public func generateBytes(
        outputLen: Int64,
        additionalInput!: Array<Byte> = []
    ): Array<Byte> {
        gmDrbgRequirePositiveLength(outputLen, "SM3 Hash-DRBG")
        let output = Array<Byte>(outputLen, repeat: UInt8(0))
        var offset: Int64 = 0
        var first = true
        while (offset < outputLen) {
            let take = gmDrbgMin(SM3_HASH_DRBG_MAX_REQUEST, outputLen - offset)
            let part = generate(take, additionalInput: if (first) { additionalInput } else { [] })
            gmDrbgCopy(part, output, offset)
            first = false
            offset += take
        }
        output
    }

    /**
     * Reseed using the GM compatibility ordering 0x01 || entropy || V || input.
     */
    public func reseed(
        entropy: Array<Byte>,
        additionalInput!: Array<Byte> = []
    ): Unit {
        gmDrbgRequireInstantiated(active, "SM3 Hash-DRBG")
        if (entropy.size < GM_DRBG_MIN_ENTROPY) {
            throw CryptoException(InvalidArgument, "SM3 Hash-DRBG reseed entropy must be at least 32 bytes")
        }
        v = sm3HashDf(
            [[UInt8(0x01)], entropy, v, additionalInput],
            SM3_HASH_DRBG_SEED_LEN
        )
        c = sm3HashDf([[UInt8(0)], v], SM3_HASH_DRBG_SEED_LEN)
        counter = 1
    }

    /** Reseed from the runtime's fail-closed system CSPRNG boundary. */
    public func reseedFromSystem(additionalInput!: Array<Byte> = []): Unit {
        reseed(csprngBytes(GM_DRBG_MIN_ENTROPY), additionalInput: additionalInput)
    }

    public func reseedCounter(): UInt64 { counter }

    /** Clear the state and permanently deactivate this context. */
    public func uninstantiate(): Unit {
        gmDrbgClear(v)
        gmDrbgClear(c)
        counter = 0
        active = false
    }

    private func requireGenerate(outputLen: Int64, limit: Int64, label: String): Unit {
        gmDrbgRequireActive(active, counter, label)
        gmDrbgRequirePositiveLength(outputLen, label)
        if (outputLen > limit) {
            throw CryptoException(InvalidArgument, "${label} request exceeds ${limit} bytes")
        }
    }
}

/**
 * SM4-CTR-DRBG with the block-cipher derivation function, GM request limit and
 * explicit entropy ownership. A context is mutable and not thread-safe.
 */
public class Sm4CtrDrbg {
    private var key: Array<Byte> = Array<Byte>(16, repeat: UInt8(0))
    private var v: Array<Byte> = Array<Byte>(16, repeat: UInt8(0))
    private var counter: UInt64 = 0
    private var active: Bool = false

    public init(
        entropy: Array<Byte>,
        nonce: Array<Byte>,
        personalization!: Array<Byte> = []
    ) {
        gmDrbgRequireSeed(entropy, nonce, personalization)
        let seed = sm4BlockCipherDf([entropy, nonce, personalization])
        sm4CtrUpdate(seed)
        counter = 1
        active = true
    }

    /** Generate one GM-bounded request (at most 16 bytes). */
    public func generate(
        outputLen: Int64,
        additionalInput!: Array<Byte> = []
    ): Array<Byte> {
        gmDrbgRequireActive(active, counter, "SM4-CTR-DRBG")
        gmDrbgRequirePositiveLength(outputLen, "SM4-CTR-DRBG")
        if (outputLen > SM4_CTR_DRBG_MAX_REQUEST) {
            throw CryptoException(InvalidArgument, "SM4-CTR-DRBG request exceeds 16 bytes")
        }
        let provided = if (additionalInput.size > 0) {
            sm4BlockCipherDf([additionalInput])
        } else {
            Array<Byte>(SM4_CTR_DRBG_SEED_LEN, repeat: UInt8(0))
        }
        if (additionalInput.size > 0) {
            sm4CtrUpdate(provided)
        }

        let context = Sm4Context(key)
        gmDrbgIncrement(v)
        let output = context.encryptBlock(v)[..outputLen]
        sm4CtrUpdate(provided)
        counter += UInt64(1)
        output
    }

    /** Generate any positive length by issuing multiple bounded requests. */
    public func generateBytes(
        outputLen: Int64,
        additionalInput!: Array<Byte> = []
    ): Array<Byte> {
        gmDrbgRequirePositiveLength(outputLen, "SM4-CTR-DRBG")
        let output = Array<Byte>(outputLen, repeat: UInt8(0))
        var offset: Int64 = 0
        var first = true
        while (offset < outputLen) {
            let take = gmDrbgMin(SM4_CTR_DRBG_MAX_REQUEST, outputLen - offset)
            let part = generate(take, additionalInput: if (first) { additionalInput } else { [] })
            gmDrbgCopy(part, output, offset)
            first = false
            offset += take
        }
        output
    }

    /** Reseed with entropy and optional additional input through Block_Cipher_df. */
    public func reseed(
        entropy: Array<Byte>,
        additionalInput!: Array<Byte> = []
    ): Unit {
        gmDrbgRequireInstantiated(active, "SM4-CTR-DRBG")
        if (entropy.size < GM_DRBG_MIN_ENTROPY) {
            throw CryptoException(InvalidArgument, "SM4-CTR-DRBG reseed entropy must be at least 32 bytes")
        }
        sm4CtrUpdate(sm4BlockCipherDf([entropy, additionalInput]))
        counter = 1
    }

    /** Reseed from the runtime's fail-closed system CSPRNG boundary. */
    public func reseedFromSystem(additionalInput!: Array<Byte> = []): Unit {
        reseed(csprngBytes(GM_DRBG_MIN_ENTROPY), additionalInput: additionalInput)
    }

    public func reseedCounter(): UInt64 { counter }

    /** Clear the state and permanently deactivate this context. */
    public func uninstantiate(): Unit {
        gmDrbgClear(key)
        gmDrbgClear(v)
        counter = 0
        active = false
    }

    private func sm4CtrUpdate(provided: Array<Byte>): Unit {
        let context = Sm4Context(key)
        let temp = Array<Byte>(SM4_CTR_DRBG_SEED_LEN, repeat: UInt8(0))
        var offset: Int64 = 0
        while (offset < SM4_CTR_DRBG_SEED_LEN) {
            gmDrbgIncrement(v)
            gmDrbgCopy(context.encryptBlock(v), temp, offset)
            offset += 16
        }
        var i: Int64 = 0
        while (i < SM4_CTR_DRBG_SEED_LEN) {
            temp[i] ^= provided[i]
            i += 1
        }
        key = temp[..16]
        v = temp[16..]
    }
}

/** Instantiate SM3 Hash-DRBG from the runtime system CSPRNG. */
public func sm3HashDrbgFromSystem(personalization!: Array<Byte> = []): Sm3HashDrbg {
    Sm3HashDrbg(
        csprngBytes(GM_DRBG_MIN_ENTROPY),
        csprngBytes(GM_DRBG_MIN_NONCE),
        personalization: personalization
    )
}

/** Instantiate SM4-CTR-DRBG from the runtime system CSPRNG. */
public func sm4CtrDrbgFromSystem(personalization!: Array<Byte> = []): Sm4CtrDrbg {
    Sm4CtrDrbg(
        csprngBytes(GM_DRBG_MIN_ENTROPY),
        csprngBytes(GM_DRBG_MIN_NONCE),
        personalization: personalization
    )
}

private func sm3HashDf(inputs: Array<Array<Byte>>, outputLen: Int64): Array<Byte> {
    let output = Array<Byte>(outputLen, repeat: UInt8(0))
    let outputBits = UInt32(outputLen * 8)
    var counter: UInt8 = 1
    var offset: Int64 = 0
    while (offset < outputLen) {
        let context = Sm3Context()
        context.update([
            counter,
            UInt8((outputBits >> 24) & UInt32(0xFF)),
            UInt8((outputBits >> 16) & UInt32(0xFF)),
            UInt8((outputBits >> 8) & UInt32(0xFF)),
            UInt8(outputBits & UInt32(0xFF))
        ])
        for (input in inputs) {
            context.update(input)
        }
        let digest = context.finish()
        let take = gmDrbgMin(digest.size, outputLen - offset)
        gmDrbgCopyRange(digest, 0, output, offset, take)
        offset += take
        counter += UInt8(1)
    }
    output
}

private func sm3Hashgen(seed: Array<Byte>, outputLen: Int64): Array<Byte> {
    let data = seed.clone()
    let output = Array<Byte>(outputLen, repeat: UInt8(0))
    var offset: Int64 = 0
    while (offset < outputLen) {
        let digest = sm3(data)
        let take = gmDrbgMin(digest.size, outputLen - offset)
        gmDrbgCopyRange(digest, 0, output, offset, take)
        offset += take
        if (offset < outputLen) {
            gmDrbgIncrement(data)
        }
    }
    output
}

private func sm4BlockCipherDf(inputs: Array<Array<Byte>>): Array<Byte> {
    var inputLen: Int64 = 0
    for (input in inputs) {
        inputLen += input.size
    }
    if (inputLen > Int64(UInt32.Max)) {
        throw CryptoException(InvalidArgument, "SM4-CTR-DRBG derivation input is too large")
    }
    let unpaddedLen = 8 + inputLen + 1
    let paddedLen = ((unpaddedLen + 15) / 16) * 16
    let s = Array<Byte>(paddedLen, repeat: UInt8(0))
    gmDrbgPutUInt32Be(UInt32(inputLen), s, 0)
    gmDrbgPutUInt32Be(UInt32(SM4_CTR_DRBG_SEED_LEN), s, 4)
    var position: Int64 = 8
    for (input in inputs) {
        gmDrbgCopy(input, s, position)
        position += input.size
    }
    s[position] = UInt8(0x80)

    let derivationKey = Array<Byte>(16, {index => UInt8(index)})
    let bccOutput = Array<Byte>(SM4_CTR_DRBG_SEED_LEN, repeat: UInt8(0))
    var blockIndex: UInt32 = 0
    var offset: Int64 = 0
    while (offset < SM4_CTR_DRBG_SEED_LEN) {
        let iv = Array<Byte>(16, repeat: UInt8(0))
        gmDrbgPutUInt32Be(blockIndex, iv, 0)
        let bccInput = Array<Byte>(iv.size + s.size, repeat: UInt8(0))
        gmDrbgCopy(iv, bccInput, 0)
        gmDrbgCopy(s, bccInput, iv.size)
        gmDrbgCopy(sm4DrbgBcc(derivationKey, bccInput), bccOutput, offset)
        blockIndex += UInt32(1)
        offset += 16
    }

    let output = Array<Byte>(SM4_CTR_DRBG_SEED_LEN, repeat: UInt8(0))
    let context = Sm4Context(bccOutput[..16])
    var x = bccOutput[16..]
    offset = 0
    while (offset < output.size) {
        x = context.encryptBlock(x)
        gmDrbgCopy(x, output, offset)
        offset += 16
    }
    output
}

private func sm4DrbgBcc(key: Array<Byte>, input: Array<Byte>): Array<Byte> {
    let context = Sm4Context(key)
    let state = Array<Byte>(16, repeat: UInt8(0))
    var offset: Int64 = 0
    while (offset < input.size) {
        var i: Int64 = 0
        while (i < 16) {
            state[i] ^= input[offset + i]
            i += 1
        }
        gmDrbgCopy(context.encryptBlock(state), state, 0)
        offset += 16
    }
    state
}

private func gmDrbgRequireSeed(
    entropy: Array<Byte>,
    nonce: Array<Byte>,
    personalization: Array<Byte>
): Unit {
    if (entropy.size < GM_DRBG_MIN_ENTROPY) {
        throw CryptoException(InvalidArgument, "GM-DRBG entropy must be at least 32 bytes")
    }
    if (nonce.size < GM_DRBG_MIN_NONCE) {
        throw CryptoException(InvalidArgument, "GM-DRBG nonce must be at least 16 bytes")
    }
    if (personalization.size > Int64(UInt32.Max)) {
        throw CryptoException(InvalidArgument, "GM-DRBG personalization is too large")
    }
}

private func gmDrbgRequireActive(active: Bool, counter: UInt64, label: String): Unit {
    gmDrbgRequireInstantiated(active, label)
    if (counter > GM_DRBG_RESEED_INTERVAL) {
        throw CryptoException(InvalidArgument, "${label} requires reseeding")
    }
}

private func gmDrbgRequireInstantiated(active: Bool, label: String): Unit {
    if (!active) {
        throw CryptoException(InvalidArgument, "${label} is uninstantiated")
    }
}

private func gmDrbgRequirePositiveLength(value: Int64, label: String): Unit {
    if (value <= 0) {
        throw CryptoException(InvalidArgument, "${label} output length must be positive")
    }
}

private func gmDrbgAddBigEndian(target: Array<Byte>, value: Array<Byte>): Unit {
    var targetIndex = target.size - 1
    var valueIndex = value.size - 1
    var carry: UInt16 = 0
    while (valueIndex >= 0) {
        let sum = UInt16(target[targetIndex]) + UInt16(value[valueIndex]) + carry
        target[targetIndex] = UInt8(sum & UInt16(0xFF))
        carry = if (sum > UInt16(0xFF)) { UInt16(1) } else { UInt16(0) }
        targetIndex -= 1
        valueIndex -= 1
    }
    while (targetIndex >= 0 && carry != 0) {
        let sum = UInt16(target[targetIndex]) + carry
        target[targetIndex] = UInt8(sum & UInt16(0xFF))
        carry = if (sum > UInt16(0xFF)) { UInt16(1) } else { UInt16(0) }
        targetIndex -= 1
    }
}

private func gmDrbgIncrement(value: Array<Byte>): Unit {
    var i = value.size - 1
    while (i >= 0) {
        if (value[i] == UInt8(0xFF)) {
            value[i] = UInt8(0)
        } else {
            value[i] += UInt8(1)
            return
        }
        i -= 1
    }
}

private func gmDrbgCounterBytes(value: UInt64): Array<Byte> {
    let output = Array<Byte>(4, repeat: UInt8(0))
    let narrowed = UInt32(value)
    gmDrbgPutUInt32Be(narrowed, output, 0)
    output
}

private func gmDrbgPutUInt32Be(value: UInt32, output: Array<Byte>, offset: Int64): Unit {
    output[offset] = UInt8((value >> 24) & UInt32(0xFF))
    output[offset + 1] = UInt8((value >> 16) & UInt32(0xFF))
    output[offset + 2] = UInt8((value >> 8) & UInt32(0xFF))
    output[offset + 3] = UInt8(value & UInt32(0xFF))
}

private func gmDrbgCopy(input: Array<Byte>, output: Array<Byte>, offset: Int64): Unit {
    gmDrbgCopyRange(input, 0, output, offset, input.size)
}

private func gmDrbgCopyRange(
    input: Array<Byte>,
    inputOffset: Int64,
    output: Array<Byte>,
    outputOffset: Int64,
    length: Int64
): Unit {
    var i: Int64 = 0
    while (i < length) {
        output[outputOffset + i] = input[inputOffset + i]
        i += 1
    }
}

private func gmDrbgClear(value: Array<Byte>): Unit {
    var i: Int64 = 0
    while (i < value.size) {
        value[i] = UInt8(0)
        i += 1
    }
}

private func gmDrbgMin(left: Int64, right: Int64): Int64 {
    if (left < right) { left } else { right }
}
