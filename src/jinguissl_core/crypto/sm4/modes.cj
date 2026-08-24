package jinguissl_core.crypto.sm4

import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}
import jinguissl_core.crypto.utils.constantTimeEquals

private let SM4_BLOCK_SIZE: Int64 = 16

/** SM4-ECB with optional PKCS#7 padding. */
public func sm4EcbEncrypt(key: Array<Byte>, plaintext: Array<Byte>, pkcs7!: Bool = false): Array<Byte> {
    let input = if (pkcs7) {
        sm4Pad(plaintext)
    } else {
        requireAligned(plaintext, "SM4-ECB plaintext")
        plaintext
    }
    let context = Sm4Context(key)
    cryptEcb(context, input, true)
}

/** SM4-ECB decryption with optional strict PKCS#7 removal. */
public func sm4EcbDecrypt(key: Array<Byte>, ciphertext: Array<Byte>, pkcs7!: Bool = false): Array<Byte> {
    requireAligned(ciphertext, "SM4-ECB ciphertext")
    let context = Sm4Context(key)
    let plaintext = cryptEcb(context, ciphertext, false)
    if (pkcs7) { sm4Unpad(plaintext) } else { plaintext }
}

/** SM4-CBC with optional PKCS#7 padding. */
public func sm4CbcEncrypt(
    key: Array<Byte>,
    iv: Array<Byte>,
    plaintext: Array<Byte>,
    pkcs7!: Bool = false
): Array<Byte> {
    requireBlock(iv, "SM4-CBC iv")
    let input = if (pkcs7) {
        sm4Pad(plaintext)
    } else {
        requireAligned(plaintext, "SM4-CBC plaintext")
        plaintext
    }
    let context = Sm4Context(key)
    let output = Array<Byte>(input.size, repeat: UInt8(0))
    var previous = iv.clone()
    var offset: Int64 = 0
    while (offset < input.size) {
        let block = copyBlock(input, offset)
        xorBlockInPlace(block, previous)
        let encrypted = context.encryptBlock(block)
        copyInto(encrypted, output, offset)
        previous = encrypted
        offset += SM4_BLOCK_SIZE
    }
    output
}

/** SM4-CBC decryption with optional strict PKCS#7 removal. */
public func sm4CbcDecrypt(
    key: Array<Byte>,
    iv: Array<Byte>,
    ciphertext: Array<Byte>,
    pkcs7!: Bool = false
): Array<Byte> {
    requireBlock(iv, "SM4-CBC iv")
    requireAligned(ciphertext, "SM4-CBC ciphertext")
    let context = Sm4Context(key)
    let output = Array<Byte>(ciphertext.size, repeat: UInt8(0))
    var previous = iv.clone()
    var offset: Int64 = 0
    while (offset < ciphertext.size) {
        let block = copyBlock(ciphertext, offset)
        let decrypted = context.decryptBlock(block)
        xorBlockInPlace(decrypted, previous)
        copyInto(decrypted, output, offset)
        previous = block
        offset += SM4_BLOCK_SIZE
    }
    if (pkcs7) { sm4Unpad(output) } else { output }
}

/** SM4-CTR encryption/decryption using a big-endian 128-bit counter. */
public func sm4CtrCrypt(key: Array<Byte>, counterBlock: Array<Byte>, input: Array<Byte>): Array<Byte> {
    requireBlock(counterBlock, "SM4-CTR counter")
    let context = Sm4Context(key)
    let counter = counterBlock.clone()
    let output = Array<Byte>(input.size, repeat: UInt8(0))
    var offset: Int64 = 0
    while (offset < input.size) {
        let stream = context.encryptBlock(counter)
        let take = min64(SM4_BLOCK_SIZE, input.size - offset)
        var i: Int64 = 0
        while (i < take) {
            output[offset + i] = input[offset + i] ^ stream[i]
            i += 1
        }
        incrementCounter128(counter)
        offset += take
    }
    output
}

/** SM4-GCM authenticated encryption. */
public func sm4GcmEncrypt(
    key: Array<Byte>,
    iv: Array<Byte>,
    plaintext: Array<Byte>,
    aad!: Array<Byte> = [],
    tagLen!: Int64 = 16
): (Array<Byte>, Array<Byte>) {
    requireGcmInputs(iv, plaintext.size, aad.size, tagLen)
    let context = Sm4Context(key)
    let hashSubkey = context.encryptBlock(Array<Byte>(SM4_BLOCK_SIZE, repeat: UInt8(0)))
    let j0 = gcmInitialCounter(hashSubkey, iv)
    let ciphertext = gcmCtrCrypt(context, j0, plaintext)
    let authentication = ghashAuthenticated(hashSubkey, aad, ciphertext)
    let mask = context.encryptBlock(j0)
    let tag = Array<Byte>(tagLen, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < tagLen) {
        tag[i] = mask[i] ^ authentication[i]
        i += 1
    }
    (ciphertext, tag)
}

/** SM4-GCM authenticated decryption; plaintext is returned only after tag verification. */
public func sm4GcmDecrypt(
    key: Array<Byte>,
    iv: Array<Byte>,
    ciphertext: Array<Byte>,
    tag: Array<Byte>,
    aad!: Array<Byte> = []
): Array<Byte> {
    requireGcmInputs(iv, ciphertext.size, aad.size, tag.size)
    let context = Sm4Context(key)
    let hashSubkey = context.encryptBlock(Array<Byte>(SM4_BLOCK_SIZE, repeat: UInt8(0)))
    let j0 = gcmInitialCounter(hashSubkey, iv)
    let authentication = ghashAuthenticated(hashSubkey, aad, ciphertext)
    let mask = context.encryptBlock(j0)
    let expected = Array<Byte>(tag.size, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < tag.size) {
        expected[i] = mask[i] ^ authentication[i]
        i += 1
    }
    if (!constantTimeEquals(expected, tag)) {
        throw CryptoException(InvalidArgument, "SM4-GCM authentication tag mismatch")
    }
    gcmCtrCrypt(context, j0, ciphertext)
}

/** SM4-CCM authenticated encryption. Nonces from 7 through 13 bytes are supported. */
public func sm4CcmEncrypt(
    key: Array<Byte>,
    nonce: Array<Byte>,
    plaintext: Array<Byte>,
    aad!: Array<Byte> = [],
    tagLen!: Int64 = 16
): (Array<Byte>, Array<Byte>) {
    let q = requireCcmInputs(nonce, plaintext.size, tagLen)
    let context = Sm4Context(key)
    let mac = ccmMac(context, nonce, q, plaintext, aad, tagLen)
    let s0 = context.encryptBlock(ccmCounterBlock(nonce, q, 0))
    let ciphertext = ccmCtrCrypt(context, nonce, q, plaintext)
    let tag = Array<Byte>(tagLen, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < tagLen) {
        tag[i] = mac[i] ^ s0[i]
        i += 1
    }
    (ciphertext, tag)
}

/** SM4-CCM authenticated decryption with fail-closed tag verification. */
public func sm4CcmDecrypt(
    key: Array<Byte>,
    nonce: Array<Byte>,
    ciphertext: Array<Byte>,
    tag: Array<Byte>,
    aad!: Array<Byte> = []
): Array<Byte> {
    let q = requireCcmInputs(nonce, ciphertext.size, tag.size)
    let context = Sm4Context(key)
    let plaintext = ccmCtrCrypt(context, nonce, q, ciphertext)
    let mac = ccmMac(context, nonce, q, plaintext, aad, tag.size)
    let s0 = context.encryptBlock(ccmCounterBlock(nonce, q, 0))
    let expected = Array<Byte>(tag.size, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < tag.size) {
        expected[i] = mac[i] ^ s0[i]
        i += 1
    }
    if (!constantTimeEquals(expected, tag)) {
        throw CryptoException(InvalidArgument, "SM4-CCM authentication tag mismatch")
    }
    plaintext
}

private func cryptEcb(context: Sm4Context, input: Array<Byte>, encrypt: Bool): Array<Byte> {
    let output = Array<Byte>(input.size, repeat: UInt8(0))
    var offset: Int64 = 0
    while (offset < input.size) {
        let block = copyBlock(input, offset)
        let transformed = if (encrypt) { context.encryptBlock(block) } else { context.decryptBlock(block) }
        copyInto(transformed, output, offset)
        offset += SM4_BLOCK_SIZE
    }
    output
}

private func sm4Pad(input: Array<Byte>): Array<Byte> {
    let padding = SM4_BLOCK_SIZE - (input.size % SM4_BLOCK_SIZE)
    let output = Array<Byte>(input.size + padding, repeat: UInt8(padding))
    copyInto(input, output, 0)
    output
}

private func sm4Unpad(input: Array<Byte>): Array<Byte> {
    if (input.size == 0 || (input.size % SM4_BLOCK_SIZE) != 0) {
        throw CryptoException(ParseError, "invalid SM4 PKCS#7 length")
    }
    let padding = Int64(input[input.size - 1])
    if (padding <= 0 || padding > SM4_BLOCK_SIZE || padding > input.size) {
        throw CryptoException(ParseError, "invalid SM4 PKCS#7 padding")
    }
    var mismatch: UInt8 = 0
    var i: Int64 = 0
    while (i < SM4_BLOCK_SIZE) {
        let inPadding = if (i < padding) { UInt8(0xFF) } else { UInt8(0) }
        mismatch |= (input[input.size - 1 - i] ^ UInt8(padding)) & inPadding
        i += 1
    }
    if (mismatch != 0) {
        throw CryptoException(ParseError, "invalid SM4 PKCS#7 padding")
    }
    input[..input.size - padding]
}

private func requireBlock(value: Array<Byte>, label: String): Unit {
    if (value.size != SM4_BLOCK_SIZE) {
        throw CryptoException(InvalidArgument, "${label} must be 16 bytes")
    }
}

private func requireAligned(value: Array<Byte>, label: String): Unit {
    if ((value.size % SM4_BLOCK_SIZE) != 0) {
        throw CryptoException(InvalidArgument, "${label} must be block aligned")
    }
}

private func requireGcmInputs(
    iv: Array<Byte>, messageLen: Int64, aadLen: Int64, tagLen: Int64
): Unit {
    if (iv.size == 0) {
        throw CryptoException(InvalidArgument, "SM4-GCM iv must not be empty")
    }
    if (tagLen < 12 || tagLen > 16) {
        throw CryptoException(InvalidArgument, "SM4-GCM tag length must be between 12 and 16 bytes")
    }
    if (iv.size > 0x1FFF_FFFF_FFFF_FFFF || aadLen > 0x1FFF_FFFF_FFFF_FFFF) {
        throw CryptoException(InvalidArgument, "SM4-GCM iv or AAD bit length is too large")
    }
    if (messageLen > 0x0F_FFFF_FFE0) {
        throw CryptoException(InvalidArgument, "SM4-GCM message exceeds the 32-bit counter limit")
    }
}

private func gcmInitialCounter(hashSubkey: Array<Byte>, iv: Array<Byte>): Array<Byte> {
    if (iv.size == 12) {
        let j0 = Array<Byte>(SM4_BLOCK_SIZE, repeat: UInt8(0))
        copyInto(iv, j0, 0)
        j0[15] = UInt8(1)
        return j0
    }
    let state = Array<Byte>(SM4_BLOCK_SIZE, repeat: UInt8(0))
    ghashData(state, hashSubkey, iv)
    let lengths = Array<Byte>(SM4_BLOCK_SIZE, repeat: UInt8(0))
    putUInt64Be(UInt64(iv.size) * 8, lengths, 8)
    ghashBlock(state, hashSubkey, lengths)
    state
}

private func gcmCtrCrypt(context: Sm4Context, j0: Array<Byte>, input: Array<Byte>): Array<Byte> {
    let counter = j0.clone()
    let output = Array<Byte>(input.size, repeat: UInt8(0))
    var offset: Int64 = 0
    while (offset < input.size) {
        incrementCounter32(counter)
        let stream = context.encryptBlock(counter)
        let take = min64(SM4_BLOCK_SIZE, input.size - offset)
        var i: Int64 = 0
        while (i < take) {
            output[offset + i] = input[offset + i] ^ stream[i]
            i += 1
        }
        offset += take
    }
    output
}

private func ghashAuthenticated(hashSubkey: Array<Byte>, aad: Array<Byte>, ciphertext: Array<Byte>): Array<Byte> {
    let state = Array<Byte>(SM4_BLOCK_SIZE, repeat: UInt8(0))
    ghashData(state, hashSubkey, aad)
    ghashData(state, hashSubkey, ciphertext)
    let lengths = Array<Byte>(SM4_BLOCK_SIZE, repeat: UInt8(0))
    putUInt64Be(UInt64(aad.size) * 8, lengths, 0)
    putUInt64Be(UInt64(ciphertext.size) * 8, lengths, 8)
    ghashBlock(state, hashSubkey, lengths)
    state
}

private func ghashData(state: Array<Byte>, hashSubkey: Array<Byte>, data: Array<Byte>): Unit {
    var offset: Int64 = 0
    while (offset < data.size) {
        let block = copyPartialBlock(data, offset)
        ghashBlock(state, hashSubkey, block)
        offset += SM4_BLOCK_SIZE
    }
}

private func ghashBlock(state: Array<Byte>, hashSubkey: Array<Byte>, block: Array<Byte>): Unit {
    xorBlockInPlace(state, block)
    let product = galoisMultiply(state, hashSubkey)
    copyInto(product, state, 0)
}

private func galoisMultiply(x: Array<Byte>, y: Array<Byte>): Array<Byte> {
    let z = Array<Byte>(SM4_BLOCK_SIZE, repeat: UInt8(0))
    let v = y.clone()
    var bit: Int64 = 0
    while (bit < 128) {
        if (((x[bit / 8] >> UInt8(7 - (bit % 8))) & UInt8(1)) != 0) {
            xorBlockInPlace(z, v)
        }
        let lowBit = v[15] & UInt8(1)
        var carry: UInt8 = 0
        var i: Int64 = 0
        while (i < SM4_BLOCK_SIZE) {
            let nextCarry = v[i] & UInt8(1)
            v[i] = (v[i] >> UInt8(1)) | (carry << UInt8(7))
            carry = nextCarry
            i += 1
        }
        if (lowBit != 0) {
            v[0] ^= UInt8(0xE1)
        }
        bit += 1
    }
    z
}

private func requireCcmInputs(nonce: Array<Byte>, messageLen: Int64, tagLen: Int64): Int64 {
    if (nonce.size < 7 || nonce.size > 13) {
        throw CryptoException(InvalidArgument, "SM4-CCM nonce length must be between 7 and 13 bytes")
    }
    if (tagLen < 4 || tagLen > 16 || (tagLen % 2) != 0) {
        throw CryptoException(InvalidArgument, "SM4-CCM tag length must be an even value from 4 through 16")
    }
    let q = 15 - nonce.size
    if (q < 8) {
        let limit = UInt64(1) << UInt64(q * 8)
        if (UInt64(messageLen) >= limit) {
            throw CryptoException(InvalidArgument, "SM4-CCM message is too long for nonce length")
        }
    }
    q
}

private func ccmMac(
    context: Sm4Context,
    nonce: Array<Byte>,
    q: Int64,
    plaintext: Array<Byte>,
    aad: Array<Byte>,
    tagLen: Int64
): Array<Byte> {
    if (aad.size > Int64(UInt32(0xFFFF_FFFF))) {
        throw CryptoException(InvalidArgument, "SM4-CCM AAD is too long")
    }
    let b0 = Array<Byte>(SM4_BLOCK_SIZE, repeat: UInt8(0))
    let aadFlag = if (aad.size > 0) { UInt8(0x40) } else { UInt8(0) }
    b0[0] = aadFlag | (UInt8((tagLen - 2) / 2) << UInt8(3)) | UInt8(q - 1)
    copyInto(nonce, b0, 1)
    putLength(UInt64(plaintext.size), b0, SM4_BLOCK_SIZE - q, q)

    var mac = context.encryptBlock(b0)
    if (aad.size > 0) {
        let prefixLen = if (aad.size < 0xFF00) { Int64(2) } else { Int64(6) }
        let encodedLen = prefixLen + aad.size
        let paddedLen = roundUpBlock(encodedLen)
        let encoded = Array<Byte>(paddedLen, repeat: UInt8(0))
        if (prefixLen == 2) {
            encoded[0] = UInt8((UInt64(aad.size) >> 8) & UInt64(0xFF))
            encoded[1] = UInt8(UInt64(aad.size) & UInt64(0xFF))
        } else {
            encoded[0] = UInt8(0xFF)
            encoded[1] = UInt8(0xFE)
            encoded[2] = UInt8((UInt64(aad.size) >> 24) & UInt64(0xFF))
            encoded[3] = UInt8((UInt64(aad.size) >> 16) & UInt64(0xFF))
            encoded[4] = UInt8((UInt64(aad.size) >> 8) & UInt64(0xFF))
            encoded[5] = UInt8(UInt64(aad.size) & UInt64(0xFF))
        }
        copyInto(aad, encoded, prefixLen)
        mac = cbcMacBlocks(context, mac, encoded)
    }
    if (plaintext.size > 0) {
        let padded = Array<Byte>(roundUpBlock(plaintext.size), repeat: UInt8(0))
        copyInto(plaintext, padded, 0)
        mac = cbcMacBlocks(context, mac, padded)
    }
    mac
}

private func cbcMacBlocks(context: Sm4Context, initial: Array<Byte>, data: Array<Byte>): Array<Byte> {
    var mac = initial
    var offset: Int64 = 0
    while (offset < data.size) {
        let block = copyBlock(data, offset)
        xorBlockInPlace(block, mac)
        mac = context.encryptBlock(block)
        offset += SM4_BLOCK_SIZE
    }
    mac
}

private func ccmCtrCrypt(
    context: Sm4Context,
    nonce: Array<Byte>,
    q: Int64,
    input: Array<Byte>
): Array<Byte> {
    let output = Array<Byte>(input.size, repeat: UInt8(0))
    var counter: UInt64 = 1
    var offset: Int64 = 0
    while (offset < input.size) {
        let stream = context.encryptBlock(ccmCounterBlock(nonce, q, counter))
        let take = min64(SM4_BLOCK_SIZE, input.size - offset)
        var i: Int64 = 0
        while (i < take) {
            output[offset + i] = input[offset + i] ^ stream[i]
            i += 1
        }
        counter += 1
        offset += take
    }
    output
}

private func ccmCounterBlock(nonce: Array<Byte>, q: Int64, counter: UInt64): Array<Byte> {
    let block = Array<Byte>(SM4_BLOCK_SIZE, repeat: UInt8(0))
    block[0] = UInt8(q - 1)
    copyInto(nonce, block, 1)
    putLength(counter, block, SM4_BLOCK_SIZE - q, q)
    block
}

private func putLength(value: UInt64, output: Array<Byte>, offset: Int64, length: Int64): Unit {
    var i: Int64 = 0
    while (i < length) {
        output[offset + length - 1 - i] = UInt8((value >> UInt64(i * 8)) & UInt64(0xFF))
        i += 1
    }
}

private func putUInt64Be(value: UInt64, output: Array<Byte>, offset: Int64): Unit {
    putLength(value, output, offset, 8)
}

private func incrementCounter128(counter: Array<Byte>): Unit {
    var i: Int64 = 15
    while (i >= 0) {
        if (counter[i] == UInt8(0xFF)) {
            counter[i] = UInt8(0)
        } else {
            counter[i] += UInt8(1)
            return
        }
        i -= 1
    }
}

private func incrementCounter32(counter: Array<Byte>): Unit {
    var i: Int64 = 15
    while (i >= 12) {
        if (counter[i] == UInt8(0xFF)) {
            counter[i] = UInt8(0)
        } else {
            counter[i] += UInt8(1)
            return
        }
        i -= 1
    }
}

private func copyBlock(input: Array<Byte>, offset: Int64): Array<Byte> {
    let block = Array<Byte>(SM4_BLOCK_SIZE, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < SM4_BLOCK_SIZE) {
        block[i] = input[offset + i]
        i += 1
    }
    block
}

private func copyPartialBlock(input: Array<Byte>, offset: Int64): Array<Byte> {
    let block = Array<Byte>(SM4_BLOCK_SIZE, repeat: UInt8(0))
    let take = min64(SM4_BLOCK_SIZE, input.size - offset)
    var i: Int64 = 0
    while (i < take) {
        block[i] = input[offset + i]
        i += 1
    }
    block
}

private func copyInto(input: Array<Byte>, output: Array<Byte>, offset: Int64): Unit {
    var i: Int64 = 0
    while (i < input.size) {
        output[offset + i] = input[i]
        i += 1
    }
}

private func xorBlockInPlace(left: Array<Byte>, right: Array<Byte>): Unit {
    var i: Int64 = 0
    while (i < SM4_BLOCK_SIZE) {
        left[i] ^= right[i]
        i += 1
    }
}

private func roundUpBlock(length: Int64): Int64 {
    ((length + SM4_BLOCK_SIZE - 1) / SM4_BLOCK_SIZE) * SM4_BLOCK_SIZE
}

private func min64(a: Int64, b: Int64): Int64 {
    if (a < b) { a } else { b }
}
