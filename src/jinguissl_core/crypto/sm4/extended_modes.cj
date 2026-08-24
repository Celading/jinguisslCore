package jinguissl_core.crypto.sm4

import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}

private let SM4_EXT_BLOCK_SIZE: Int64 = 16
private let SM4_XTS_MAX_DATA_UNIT_BYTES: Int64 = 16 * 1024 * 1024

/** SM4-CFB128 encryption. The final segment may be shorter than one block. */
public func sm4CfbEncrypt(
    key: Array<Byte>,
    iv: Array<Byte>,
    plaintext: Array<Byte>
): Array<Byte> {
    sm4ExtRequireBlock(iv, "SM4-CFB iv")
    let context = Sm4Context(key)
    let feedback = iv.clone()
    let stream = Array<Byte>(SM4_EXT_BLOCK_SIZE, repeat: UInt8(0))
    let output = Array<Byte>(plaintext.size, repeat: UInt8(0))
    var offset: Int64 = 0
    while (offset < plaintext.size) {
        let position = offset % SM4_EXT_BLOCK_SIZE
        if (position == 0) {
            sm4ExtCopy(context.encryptBlock(feedback), stream, 0)
        }
        let value = plaintext[offset] ^ stream[position]
        output[offset] = value
        feedback[position] = value
        offset += 1
    }
    output
}

/** SM4-CFB128 decryption. Ciphertext, rather than plaintext, feeds the shift register. */
public func sm4CfbDecrypt(
    key: Array<Byte>,
    iv: Array<Byte>,
    ciphertext: Array<Byte>
): Array<Byte> {
    sm4ExtRequireBlock(iv, "SM4-CFB iv")
    let context = Sm4Context(key)
    let feedback = iv.clone()
    let stream = Array<Byte>(SM4_EXT_BLOCK_SIZE, repeat: UInt8(0))
    let output = Array<Byte>(ciphertext.size, repeat: UInt8(0))
    var offset: Int64 = 0
    while (offset < ciphertext.size) {
        let position = offset % SM4_EXT_BLOCK_SIZE
        if (position == 0) {
            sm4ExtCopy(context.encryptBlock(feedback), stream, 0)
        }
        let value = ciphertext[offset]
        output[offset] = value ^ stream[position]
        feedback[position] = value
        offset += 1
    }
    output
}

/** SM4-OFB encryption/decryption. */
public func sm4OfbCrypt(
    key: Array<Byte>,
    iv: Array<Byte>,
    input: Array<Byte>
): Array<Byte> {
    sm4ExtRequireBlock(iv, "SM4-OFB iv")
    let context = Sm4Context(key)
    let feedback = iv.clone()
    let output = Array<Byte>(input.size, repeat: UInt8(0))
    var offset: Int64 = 0
    while (offset < input.size) {
        let next = context.encryptBlock(feedback)
        sm4ExtCopy(next, feedback, 0)
        let take = sm4ExtMin(SM4_EXT_BLOCK_SIZE, input.size - offset)
        var i: Int64 = 0
        while (i < take) {
            output[offset + i] = input[offset + i] ^ feedback[i]
            i += 1
        }
        offset += take
    }
    output
}

/**
 * SM4-XTS encryption with ciphertext stealing for a final partial block.
 *
 * `key` is K1 || K2 (32 bytes); equal halves are rejected. XTS provides
 * confidentiality only and must not be used as an authentication mechanism.
 */
public func sm4XtsEncrypt(
    key: Array<Byte>,
    dataUnitTweak: Array<Byte>,
    plaintext: Array<Byte>
): Array<Byte> {
    let (dataContext, tweak) = sm4XtsPrepare(key, dataUnitTweak, plaintext.size)
    sm4XtsCrypt(dataContext, tweak, plaintext, true)
}

/** SM4-XTS decryption with ciphertext stealing for a final partial block. */
public func sm4XtsDecrypt(
    key: Array<Byte>,
    dataUnitTweak: Array<Byte>,
    ciphertext: Array<Byte>
): Array<Byte> {
    let (dataContext, tweak) = sm4XtsPrepare(key, dataUnitTweak, ciphertext.size)
    sm4XtsCrypt(dataContext, tweak, ciphertext, false)
}

/**
 * HCTR wide-block encryption compatible with the pinned openHiTLS SM4 profile.
 *
 * HCTR is length preserving and requires a 32-byte K1 || hash-key plus a
 * 16-byte tweak. This compatibility primitive is not an authenticated mode.
 */
public func sm4HctrEncrypt(
    key: Array<Byte>,
    tweak: Array<Byte>,
    plaintext: Array<Byte>
): Array<Byte> {
    sm4HctrCrypt(key, tweak, plaintext, true)
}

/** HCTR wide-block decryption compatible with the pinned openHiTLS SM4 profile. */
public func sm4HctrDecrypt(
    key: Array<Byte>,
    tweak: Array<Byte>,
    ciphertext: Array<Byte>
): Array<Byte> {
    sm4HctrCrypt(key, tweak, ciphertext, false)
}

/** SM4-CMAC with a 4..16-byte left-truncated tag. */
public func sm4Cmac(
    key: Array<Byte>,
    message: Array<Byte>,
    tagLen!: Int64 = 16
): Array<Byte> {
    sm4RequireMacTagLength(tagLen, "SM4-CMAC")
    let context = Sm4Context(key)
    let zero = Array<Byte>(SM4_EXT_BLOCK_SIZE, repeat: UInt8(0))
    let firstSubkey = sm4CmacDouble(context.encryptBlock(zero))
    let secondSubkey = sm4CmacDouble(firstSubkey)
    let complete = message.size > 0 && (message.size % SM4_EXT_BLOCK_SIZE) == 0
    let blockCount = if (message.size == 0) {
        Int64(1)
    } else {
        (message.size + SM4_EXT_BLOCK_SIZE - 1) / SM4_EXT_BLOCK_SIZE
    }

    let state = Array<Byte>(SM4_EXT_BLOCK_SIZE, repeat: UInt8(0))
    var blockIndex: Int64 = 0
    while (blockIndex + 1 < blockCount) {
        let block = sm4ExtBlockAt(message, blockIndex * SM4_EXT_BLOCK_SIZE)
        sm4ExtXorInPlace(block, state)
        sm4ExtCopy(context.encryptBlock(block), state, 0)
        blockIndex += 1
    }

    let last = Array<Byte>(SM4_EXT_BLOCK_SIZE, repeat: UInt8(0))
    if (complete) {
        sm4ExtCopyRange(message, (blockCount - 1) * SM4_EXT_BLOCK_SIZE, last, 0, SM4_EXT_BLOCK_SIZE)
        sm4ExtXorInPlace(last, firstSubkey)
    } else {
        let used = message.size - (blockCount - 1) * SM4_EXT_BLOCK_SIZE
        if (used > 0) {
            sm4ExtCopyRange(message, (blockCount - 1) * SM4_EXT_BLOCK_SIZE, last, 0, used)
        }
        last[used] = UInt8(0x80)
        sm4ExtXorInPlace(last, secondSubkey)
    }
    sm4ExtXorInPlace(last, state)
    context.encryptBlock(last)[..tagLen]
}

/**
 * SM4 CBC-MAC with zero padding and a 4..16-byte left-truncated tag.
 *
 * Plain CBC-MAC is safe only when the caller fixes or domain-separates message
 * lengths. Use SM4-CMAC for general variable-length messages.
 */
public func sm4CbcMac(
    key: Array<Byte>,
    message: Array<Byte>,
    tagLen!: Int64 = 16
): Array<Byte> {
    sm4RequireMacTagLength(tagLen, "SM4-CBC-MAC")
    let context = Sm4Context(key)
    let blockCount = if (message.size == 0) {
        Int64(1)
    } else {
        (message.size + SM4_EXT_BLOCK_SIZE - 1) / SM4_EXT_BLOCK_SIZE
    }
    let state = Array<Byte>(SM4_EXT_BLOCK_SIZE, repeat: UInt8(0))
    var blockIndex: Int64 = 0
    while (blockIndex < blockCount) {
        let block = sm4ExtPartialBlockAt(message, blockIndex * SM4_EXT_BLOCK_SIZE)
        sm4ExtXorInPlace(block, state)
        sm4ExtCopy(context.encryptBlock(block), state, 0)
        blockIndex += 1
    }
    state[..tagLen]
}

private func sm4XtsPrepare(
    key: Array<Byte>,
    dataUnitTweak: Array<Byte>,
    dataLen: Int64
): (Sm4Context, Array<Byte>) {
    if (key.size != 32) {
        throw CryptoException(InvalidArgument, "SM4-XTS key must be 32 bytes")
    }
    sm4ExtRequireBlock(dataUnitTweak, "SM4-XTS data-unit tweak")
    if (dataLen < SM4_EXT_BLOCK_SIZE) {
        throw CryptoException(InvalidArgument, "SM4-XTS data unit must be at least 16 bytes")
    }
    if (dataLen > SM4_XTS_MAX_DATA_UNIT_BYTES) {
        throw CryptoException(InvalidArgument, "SM4-XTS data unit exceeds 2^20 blocks")
    }
    let key1 = key[..SM4_EXT_BLOCK_SIZE]
    let key2 = key[SM4_EXT_BLOCK_SIZE..]
    if (sm4ExtArraysEqual(key1, key2)) {
        throw CryptoException(InvalidArgument, "SM4-XTS key halves must differ")
    }
    (Sm4Context(key1), Sm4Context(key2).encryptBlock(dataUnitTweak))
}

private func sm4XtsCrypt(
    context: Sm4Context,
    initialTweak: Array<Byte>,
    input: Array<Byte>,
    encrypt: Bool
): Array<Byte> {
    let output = Array<Byte>(input.size, repeat: UInt8(0))
    let tweak = initialTweak.clone()
    let fullBlocks = input.size / SM4_EXT_BLOCK_SIZE
    let partial = input.size % SM4_EXT_BLOCK_SIZE
    let ordinaryBlocks = if (partial == 0) { fullBlocks } else { fullBlocks - 1 }

    var blockIndex: Int64 = 0
    while (blockIndex < ordinaryBlocks) {
        let offset = blockIndex * SM4_EXT_BLOCK_SIZE
        let transformed = sm4XtsBlock(context, sm4ExtBlockAt(input, offset), tweak, encrypt)
        sm4ExtCopy(transformed, output, offset)
        sm4XtsMultiplyTweak(tweak)
        blockIndex += 1
    }
    if (partial == 0) {
        return output
    }

    let penultimateOffset = ordinaryBlocks * SM4_EXT_BLOCK_SIZE
    let partialOffset = penultimateOffset + SM4_EXT_BLOCK_SIZE
    if (encrypt) {
        let stolenSource = sm4XtsBlock(
            context,
            sm4ExtBlockAt(input, penultimateOffset),
            tweak,
            true
        )
        sm4ExtCopyRange(stolenSource, 0, output, partialOffset, partial)
        let mixed = Array<Byte>(SM4_EXT_BLOCK_SIZE, repeat: UInt8(0))
        sm4ExtCopyRange(input, partialOffset, mixed, 0, partial)
        sm4ExtCopyRange(stolenSource, partial, mixed, partial, SM4_EXT_BLOCK_SIZE - partial)
        sm4XtsMultiplyTweak(tweak)
        sm4ExtCopy(sm4XtsBlock(context, mixed, tweak, true), output, penultimateOffset)
    } else {
        let nextTweak = tweak.clone()
        sm4XtsMultiplyTweak(nextTweak)
        let mixed = sm4XtsBlock(
            context,
            sm4ExtBlockAt(input, penultimateOffset),
            nextTweak,
            false
        )
        sm4ExtCopyRange(mixed, 0, output, partialOffset, partial)
        let stolenSource = Array<Byte>(SM4_EXT_BLOCK_SIZE, repeat: UInt8(0))
        sm4ExtCopyRange(input, partialOffset, stolenSource, 0, partial)
        sm4ExtCopyRange(mixed, partial, stolenSource, partial, SM4_EXT_BLOCK_SIZE - partial)
        sm4ExtCopy(sm4XtsBlock(context, stolenSource, tweak, false), output, penultimateOffset)
    }
    output
}

private func sm4XtsBlock(
    context: Sm4Context,
    block: Array<Byte>,
    tweak: Array<Byte>,
    encrypt: Bool
): Array<Byte> {
    sm4ExtXorInPlace(block, tweak)
    let transformed = if (encrypt) { context.encryptBlock(block) } else { context.decryptBlock(block) }
    sm4ExtXorInPlace(transformed, tweak)
    transformed
}

/* SM4-XTS uses the GM bit ordering exposed by the comparison provider. */
private func sm4XtsMultiplyTweak(tweak: Array<Byte>): Unit {
    var carry: UInt8 = 0
    var i: Int64 = 0
    while (i < SM4_EXT_BLOCK_SIZE) {
        let nextCarry = (tweak[i] & UInt8(1)) << UInt8(7)
        tweak[i] = (tweak[i] >> UInt8(1)) | carry
        carry = nextCarry
        i += 1
    }
    if (carry != 0) {
        tweak[0] ^= UInt8(0xE1)
    }
}

private func sm4HctrCrypt(
    key: Array<Byte>,
    tweak: Array<Byte>,
    input: Array<Byte>,
    encrypt: Bool
): Array<Byte> {
    if (key.size != 32) {
        throw CryptoException(InvalidArgument, "SM4-HCTR key must be 32 bytes")
    }
    sm4ExtRequireBlock(tweak, "SM4-HCTR tweak")
    if (input.size < SM4_EXT_BLOCK_SIZE) {
        throw CryptoException(InvalidArgument, "SM4-HCTR input must be at least 16 bytes")
    }
    let context = Sm4Context(key[..SM4_EXT_BLOCK_SIZE])
    let hashKey = key[SM4_EXT_BLOCK_SIZE..]
    let first = sm4ExtBlockAt(input, 0)
    let rest = input[SM4_EXT_BLOCK_SIZE..]
    let output = Array<Byte>(input.size, repeat: UInt8(0))

    if (encrypt) {
        let z1 = first
        sm4ExtXorInPlace(z1, sm4HctrHash(hashKey, rest, tweak))
        let z2 = context.encryptBlock(z1)
        let counterBase = z1.clone()
        sm4ExtXorInPlace(counterBase, z2)
        let transformedRest = sm4HctrCounterCrypt(context, counterBase, rest)
        let outputFirst = z2
        sm4ExtXorInPlace(outputFirst, sm4HctrHash(hashKey, transformedRest, tweak))
        sm4ExtCopy(outputFirst, output, 0)
        sm4ExtCopy(transformedRest, output, SM4_EXT_BLOCK_SIZE)
    } else {
        let z2 = first
        sm4ExtXorInPlace(z2, sm4HctrHash(hashKey, rest, tweak))
        let z1 = context.decryptBlock(z2)
        let counterBase = z1.clone()
        sm4ExtXorInPlace(counterBase, z2)
        let transformedRest = sm4HctrCounterCrypt(context, counterBase, rest)
        let outputFirst = z1
        sm4ExtXorInPlace(outputFirst, sm4HctrHash(hashKey, transformedRest, tweak))
        sm4ExtCopy(outputFirst, output, 0)
        sm4ExtCopy(transformedRest, output, SM4_EXT_BLOCK_SIZE)
    }
    output
}

private func sm4HctrHash(
    hashKey: Array<Byte>,
    data: Array<Byte>,
    tweak: Array<Byte>
): Array<Byte> {
    let effective = Array<Byte>(data.size + tweak.size, repeat: UInt8(0))
    sm4ExtCopy(data, effective, 0)
    sm4ExtCopy(tweak, effective, data.size)
    let blockCount = (effective.size + SM4_EXT_BLOCK_SIZE - 1) / SM4_EXT_BLOCK_SIZE
    let hash = Array<Byte>(SM4_EXT_BLOCK_SIZE, repeat: UInt8(0))
    var blockIndex: Int64 = 0
    while (blockIndex < blockCount) {
        let block = sm4ExtPartialBlockAt(effective, blockIndex * SM4_EXT_BLOCK_SIZE)
        sm4ExtXorInPlace(hash, block)
        sm4ExtCopy(sm4HctrFieldMultiply(hash, hashKey), hash, 0)
        blockIndex += 1
    }
    sm4ExtCopy(sm4HctrFieldMultiply(hash, hashKey), hash, 0)
    let lengthBlock = Array<Byte>(SM4_EXT_BLOCK_SIZE, repeat: UInt8(0))
    sm4ExtPutUInt64Be(UInt64(effective.size) * UInt64(8), lengthBlock, 8)
    sm4ExtXorInPlace(hash, sm4HctrFieldMultiply(lengthBlock, hashKey))
    hash
}

private func sm4HctrFieldMultiply(left: Array<Byte>, right: Array<Byte>): Array<Byte> {
    let result = Array<Byte>(SM4_EXT_BLOCK_SIZE, repeat: UInt8(0))
    let value = left.clone()
    var bit: Int64 = 0
    while (bit < 128) {
        if (((right[bit / 8] >> UInt8(7 - (bit % 8))) & UInt8(1)) != 0) {
            sm4ExtXorInPlace(result, value)
        }
        let lowBit = value[15] & UInt8(1)
        var carry: UInt8 = 0
        var i: Int64 = 0
        while (i < SM4_EXT_BLOCK_SIZE) {
            let nextCarry = value[i] & UInt8(1)
            value[i] = (value[i] >> UInt8(1)) | (carry << UInt8(7))
            carry = nextCarry
            i += 1
        }
        if (lowBit != 0) {
            value[0] ^= UInt8(0xE1)
        }
        bit += 1
    }
    result
}

private func sm4HctrCounterCrypt(
    context: Sm4Context,
    counterBase: Array<Byte>,
    input: Array<Byte>
): Array<Byte> {
    let output = Array<Byte>(input.size, repeat: UInt8(0))
    var counter: UInt64 = 1
    var offset: Int64 = 0
    while (offset < input.size) {
        let counterBlock = counterBase.clone()
        var i: Int64 = 0
        while (i < 8) {
            counterBlock[15 - i] ^= UInt8((counter >> UInt64(i * 8)) & UInt64(0xFF))
            i += 1
        }
        let stream = context.encryptBlock(counterBlock)
        let take = sm4ExtMin(SM4_EXT_BLOCK_SIZE, input.size - offset)
        i = 0
        while (i < take) {
            output[offset + i] = input[offset + i] ^ stream[i]
            i += 1
        }
        counter += UInt64(1)
        offset += take
    }
    output
}

private func sm4CmacDouble(input: Array<Byte>): Array<Byte> {
    let output = Array<Byte>(SM4_EXT_BLOCK_SIZE, repeat: UInt8(0))
    var carry: UInt8 = 0
    var i: Int64 = SM4_EXT_BLOCK_SIZE - 1
    while (i >= 0) {
        let nextCarry = (input[i] >> UInt8(7)) & UInt8(1)
        output[i] = (input[i] << UInt8(1)) | carry
        carry = nextCarry
        i -= 1
    }
    if (carry != 0) {
        output[15] ^= UInt8(0x87)
    }
    output
}

private func sm4RequireMacTagLength(tagLen: Int64, label: String): Unit {
    if (tagLen < 4 || tagLen > SM4_EXT_BLOCK_SIZE) {
        throw CryptoException(InvalidArgument, "${label} tag length must be between 4 and 16 bytes")
    }
}

private func sm4ExtRequireBlock(value: Array<Byte>, label: String): Unit {
    if (value.size != SM4_EXT_BLOCK_SIZE) {
        throw CryptoException(InvalidArgument, "${label} must be 16 bytes")
    }
}

private func sm4ExtBlockAt(input: Array<Byte>, offset: Int64): Array<Byte> {
    let block = Array<Byte>(SM4_EXT_BLOCK_SIZE, repeat: UInt8(0))
    sm4ExtCopyRange(input, offset, block, 0, SM4_EXT_BLOCK_SIZE)
    block
}

private func sm4ExtPartialBlockAt(input: Array<Byte>, offset: Int64): Array<Byte> {
    let block = Array<Byte>(SM4_EXT_BLOCK_SIZE, repeat: UInt8(0))
    if (offset < input.size) {
        sm4ExtCopyRange(input, offset, block, 0, sm4ExtMin(SM4_EXT_BLOCK_SIZE, input.size - offset))
    }
    block
}

private func sm4ExtCopy(input: Array<Byte>, output: Array<Byte>, offset: Int64): Unit {
    sm4ExtCopyRange(input, 0, output, offset, input.size)
}

private func sm4ExtCopyRange(
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

private func sm4ExtXorInPlace(left: Array<Byte>, right: Array<Byte>): Unit {
    var i: Int64 = 0
    while (i < SM4_EXT_BLOCK_SIZE) {
        left[i] ^= right[i]
        i += 1
    }
}

private func sm4ExtPutUInt64Be(value: UInt64, output: Array<Byte>, offset: Int64): Unit {
    var i: Int64 = 0
    while (i < 8) {
        output[offset + 7 - i] = UInt8((value >> UInt64(i * 8)) & UInt64(0xFF))
        i += 1
    }
}

private func sm4ExtArraysEqual(left: Array<Byte>, right: Array<Byte>): Bool {
    if (left.size != right.size) {
        return false
    }
    var difference: UInt8 = 0
    var i: Int64 = 0
    while (i < left.size) {
        difference |= left[i] ^ right[i]
        i += 1
    }
    difference == 0
}

private func sm4ExtMin(left: Int64, right: Int64): Int64 {
    if (left < right) { left } else { right }
}
