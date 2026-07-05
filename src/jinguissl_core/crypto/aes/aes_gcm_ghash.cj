package jinguissl_core.crypto.aes

import jinguissl_core.crypto.error.{CryptoException, CryptoErrorCode}
import jinguissl_core.crypto.utils.secureCopyInto

let GHASH_TABLE_BYTES: Int64 = 16
let GHASH_TABLE_STRIDE: Int64 = 256
let GHASH_TABLE_SIZE: Int64 = GHASH_TABLE_BYTES * GHASH_TABLE_STRIDE

func gcmJ0(h: Array<Byte>, iv: Array<Byte>): Array<Byte> {
    if (iv.size == 12) {
        let out = Array<Byte>(16, repeat: 0)
        secureCopyInto(iv, out)
        out[15] = UInt8(1)
        return out
    }

    ghash(h, [], iv)
}

func gcmJ0WithPair(hHi: UInt64, hLo: UInt64, iv: Array<Byte>): Array<Byte> {
    if (iv.size == 12) {
        let out = Array<Byte>(16, repeat: 0)
        secureCopyInto(iv, out)
        out[15] = UInt8(1)
        return out
    }

    ghashWithPair(hHi, hLo, [], iv)
}

func gcmJ0WithTable(tableHi: Array<UInt64>, tableLo: Array<UInt64>, iv: Array<Byte>): Array<Byte> {
    if (iv.size == 12) {
        let out = Array<Byte>(16, repeat: 0)
        secureCopyInto(iv, out)
        out[15] = UInt8(1)
        return out
    }

    ghashWithTable(tableHi, tableLo, [], iv)
}

func ghash(h: Array<Byte>, aad: Array<Byte>, cipher: Array<Byte>): Array<Byte> {
    requireBlock(h, "GHASH key")
    let (hHi, hLo) = readU64PairBE(h)
    ghashWithPair(hHi, hLo, aad, cipher)
}

func ghashWithPair(hHi: UInt64, hLo: UInt64, aad: Array<Byte>, cipher: Array<Byte>): Array<Byte> {
    var x = zeroBlock()
    ghashUpdateWithPairInPlace(x, hHi, hLo, aad)
    ghashUpdateWithPairInPlace(x, hHi, hLo, cipher)
    ghashFinalizeWithPairInPlace(x, hHi, hLo, aad.size, cipher.size)
    x
}

func ghashWithTable(tableHi: Array<UInt64>, tableLo: Array<UInt64>, aad: Array<Byte>, cipher: Array<Byte>): Array<Byte> {
    var x = zeroBlock()
    ghashUpdateWithTableInPlace(x, tableHi, tableLo, aad)
    ghashUpdateWithTableInPlace(x, tableHi, tableLo, cipher)
    ghashFinalizeWithTableInPlace(x, tableHi, tableLo, aad.size, cipher.size)
    x
}

@OverflowWrapping
func ghashUpdatePairWithTableUnchecked(
    zHiInput: UInt64,
    zLoInput: UInt64,
    tableHi: Array<UInt64>,
    tableLo: Array<UInt64>,
    input: Array<Byte>
): (UInt64, UInt64) {
    var zHi = zHiInput
    var zLo = zLoInput
    var offset = 0
    let fullLimit = input.size - (input.size % AES_BLOCK_SIZE)

    while (offset < fullLimit) {
        zHi = zHi ^ decodeUInt64BE(input, offset)
        zLo = zLo ^ decodeUInt64BE(input, offset + 8)
        let (nextHi, nextLo) = gfMul128PairWithTableUnchecked(zHi, zLo, tableHi, tableLo)
        zHi = nextHi
        zLo = nextLo
        offset += AES_BLOCK_SIZE
    }

    if (offset < input.size) {
        var tailHi: UInt64 = 0
        var tailLo: UInt64 = 0
        let take = input.size - offset
        var i = 0
        var hiShift = Int64(56)
        var loShift = Int64(56)
        while (i < take) {
            let value = UInt64(UInt8(input[offset + i]))
            if (i < 8) {
                tailHi = tailHi ^ (value << hiShift)
                hiShift -= 8
            } else {
                tailLo = tailLo ^ (value << loShift)
                loShift -= 8
            }
            i += 1
        }
        zHi = zHi ^ tailHi
        zLo = zLo ^ tailLo
        let (nextHi, nextLo) = gfMul128PairWithTableUnchecked(zHi, zLo, tableHi, tableLo)
        zHi = nextHi
        zLo = nextLo
    }

    (zHi, zLo)
}

func ghashUpdateInPlace(acc: Array<Byte>, h: Array<Byte>, input: Array<Byte>): Unit {
    requireBlock(h, "GHASH key")
    let (hHi, hLo) = readU64PairBE(h)
    ghashUpdateWithPairInPlace(acc, hHi, hLo, input)
}

func ghashUpdateWithPairInPlace(acc: Array<Byte>, hHi: UInt64, hLo: UInt64, input: Array<Byte>): Unit {
    requireBlock(acc, "GHASH accumulator")
    var (zHi, zLo) = readU64PairBE(acc)
    var offset = 0

    while ((offset + AES_BLOCK_SIZE) <= input.size) {
        zHi = zHi ^ decodeUInt64BE(input, offset)
        zLo = zLo ^ decodeUInt64BE(input, offset + 8)
        let (nextHi, nextLo) = gfMul128Pair(zHi, zLo, hHi, hLo)
        zHi = nextHi
        zLo = nextLo
        offset += AES_BLOCK_SIZE
    }

    writeU64PairBE(acc, zHi, zLo)

    if (offset < input.size) {
        let take = input.size - offset
        var i = 0
        while (i < take) {
            acc[i] = UInt8(acc[i]) ^ UInt8(input[offset + i])
            i += 1
        }
        let (tailHi, tailLo) = readU64PairBE(acc)
        let (nextHi, nextLo) = gfMul128Pair(tailHi, tailLo, hHi, hLo)
        writeU64PairBE(acc, nextHi, nextLo)
    }
}

func ghashUpdateWithTableInPlace(
    acc: Array<Byte>,
    tableHi: Array<UInt64>,
    tableLo: Array<UInt64>,
    input: Array<Byte>
): Unit {
    requireBlock(acc, "GHASH accumulator")
    requireGhashTable(tableHi, tableLo)

    var (zHi, zLo) = readU64PairBE(acc)
    var offset = 0

    while ((offset + AES_BLOCK_SIZE) <= input.size) {
        zHi = zHi ^ decodeUInt64BE(input, offset)
        zLo = zLo ^ decodeUInt64BE(input, offset + 8)
        let (nextHi, nextLo) = gfMul128PairWithTableUnchecked(zHi, zLo, tableHi, tableLo)
        zHi = nextHi
        zLo = nextLo
        offset += AES_BLOCK_SIZE
    }

    writeU64PairBE(acc, zHi, zLo)

    if (offset < input.size) {
        let take = input.size - offset
        var i = 0
        while (i < take) {
            acc[i] = UInt8(acc[i]) ^ UInt8(input[offset + i])
            i += 1
        }
        let (tailHi, tailLo) = readU64PairBE(acc)
        let (nextHi, nextLo) = gfMul128PairWithTableUnchecked(tailHi, tailLo, tableHi, tableLo)
        writeU64PairBE(acc, nextHi, nextLo)
    }
}

func ghashFinalizeInPlace(acc: Array<Byte>, h: Array<Byte>, aadLen: Int64, cipherLen: Int64): Unit {
    requireBlock(h, "GHASH key")
    let (hHi, hLo) = readU64PairBE(h)
    ghashFinalizeWithPairInPlace(acc, hHi, hLo, aadLen, cipherLen)
}

func ghashFinalizeWithPairInPlace(acc: Array<Byte>, hHi: UInt64, hLo: UInt64, aadLen: Int64, cipherLen: Int64): Unit {
    requireBlock(acc, "GHASH accumulator")
    let (zHi, zLo) = readU64PairBE(acc)
    let (nextHi, nextLo) = ghashFinalizePair(zHi, zLo, aadLen, cipherLen, hHi, hLo)
    writeU64PairBE(acc, nextHi, nextLo)
}

func ghashFinalizeWithTableInPlace(
    acc: Array<Byte>,
    tableHi: Array<UInt64>,
    tableLo: Array<UInt64>,
    aadLen: Int64,
    cipherLen: Int64
): Unit {
    requireBlock(acc, "GHASH accumulator")
    let (zHi, zLo) = readU64PairBE(acc)
    let (nextHi, nextLo) = ghashFinalizePairWithTable(zHi, zLo, aadLen, cipherLen, tableHi, tableLo)
    writeU64PairBE(acc, nextHi, nextLo)
}

@OverflowWrapping
func ghashFinalizePair(
    zHi: UInt64,
    zLo: UInt64,
    aadLen: Int64,
    cipherLen: Int64,
    hHi: UInt64,
    hLo: UInt64
): (UInt64, UInt64) {
    let aadBits = UInt64(aadLen) * UInt64(8)
    let cipherBits = UInt64(cipherLen) * UInt64(8)
    gfMul128Pair(zHi ^ aadBits, zLo ^ cipherBits, hHi, hLo)
}

@OverflowWrapping
func ghashFinalizePairWithTable(
    zHi: UInt64,
    zLo: UInt64,
    aadLen: Int64,
    cipherLen: Int64,
    tableHi: Array<UInt64>,
    tableLo: Array<UInt64>
): (UInt64, UInt64) {
    let aadBits = UInt64(aadLen) * UInt64(8)
    let cipherBits = UInt64(cipherLen) * UInt64(8)
    gfMul128PairWithTableUnchecked(zHi ^ aadBits, zLo ^ cipherBits, tableHi, tableLo)
}

@OverflowWrapping
func shiftForByteIndex(index: Int64): Int64 {
    56 - (index * 8)
}

func xorFullBlockFromOffsetInPlace(dst: Array<Byte>, src: Array<Byte>, offset: Int64): Unit {
    if (dst.size != AES_BLOCK_SIZE) {
        throw CryptoException(InvalidArgument, "AES block length must be 16 bytes")
    }
    if (offset < 0 || (offset + AES_BLOCK_SIZE) > src.size) {
        throw CryptoException(OutOfBounds, "source block offset out of bounds")
    }
    xorFullBlockFromOffsetInPlaceUnchecked(dst, src, offset)
}

func xorFullBlockFromOffsetInPlaceUnchecked(dst: Array<Byte>, src: Array<Byte>, offset: Int64): Unit {
    var i = 0
    while (i < AES_BLOCK_SIZE) {
        dst[i] = UInt8(dst[i]) ^ UInt8(src[offset + i])
        i += 1
    }
}

@OverflowWrapping
func constantTimeTagEqualsPair(tag: Array<Byte>, hi: UInt64, lo: UInt64): Bool {
    var diff = UInt8(0)
    var i = 0
    while (i < tag.size) {
        let expected = if (i < 8) {
            UInt8((hi >> shiftForByteIndex(i)) & UInt64(0xff))
        } else {
            UInt8((lo >> shiftForByteIndex(i - 8)) & UInt64(0xff))
        }
        diff = diff | (UInt8(tag[i]) ^ expected)
        i += 1
    }
    diff == UInt8(0)
}

@OverflowWrapping
func writeTagPrefixFromPair(out: Array<Byte>, hi: UInt64, lo: UInt64): Unit {
    var i = 0
    while (i < out.size) {
        out[i] = if (i < 8) {
            UInt8((hi >> shiftForByteIndex(i)) & UInt64(0xff))
        } else {
            UInt8((lo >> shiftForByteIndex(i - 8)) & UInt64(0xff))
        }
        i += 1
    }
}

func encodeUInt64BE(out: Array<Byte>, offset: Int64, value: UInt64): Unit {
    out[offset] = UInt8((value >> 56) & UInt64(0xff))
    out[offset + 1] = UInt8((value >> 48) & UInt64(0xff))
    out[offset + 2] = UInt8((value >> 40) & UInt64(0xff))
    out[offset + 3] = UInt8((value >> 32) & UInt64(0xff))
    out[offset + 4] = UInt8((value >> 24) & UInt64(0xff))
    out[offset + 5] = UInt8((value >> 16) & UInt64(0xff))
    out[offset + 6] = UInt8((value >> 8) & UInt64(0xff))
    out[offset + 7] = UInt8(value & UInt64(0xff))
}

@OverflowWrapping
func buildGhashTable(hHi: UInt64, hLo: UInt64): (Array<UInt64>, Array<UInt64>) {
    let tableHi = Array<UInt64>(GHASH_TABLE_SIZE, repeat: UInt64(0))
    let tableLo = Array<UInt64>(GHASH_TABLE_SIZE, repeat: UInt64(0))

    var byteIndex = 0
    while (byteIndex < GHASH_TABLE_BYTES) {
        let base = byteIndex * GHASH_TABLE_STRIDE
        var byteValue = 1
        while (byteValue < GHASH_TABLE_STRIDE) {
            var xHi: UInt64 = 0
            var xLo: UInt64 = 0
            if (byteIndex < 8) {
                xHi = UInt64(byteValue) << shiftForByteIndex(byteIndex)
            } else {
                xLo = UInt64(byteValue) << shiftForByteIndex(byteIndex - 8)
            }
            let (entryHi, entryLo) = gfMul128Pair(xHi, xLo, hHi, hLo)
            let index = base + byteValue
            tableHi[index] = entryHi
            tableLo[index] = entryLo
            byteValue += 1
        }
        byteIndex += 1
    }

    (tableHi, tableLo)
}

func requireGhashTable(tableHi: Array<UInt64>, tableLo: Array<UInt64>): Unit {
    if (tableHi.size != GHASH_TABLE_SIZE || tableLo.size != GHASH_TABLE_SIZE) {
        throw CryptoException(InvalidArgument, "GHASH table length mismatch")
    }
}

@OverflowWrapping
func gfMul128PairWithTable(
    xHi: UInt64,
    xLo: UInt64,
    tableHi: Array<UInt64>,
    tableLo: Array<UInt64>
): (UInt64, UInt64) {
    requireGhashTable(tableHi, tableLo)
    gfMul128PairWithTableUnchecked(xHi, xLo, tableHi, tableLo)
}

@OverflowWrapping
func gfMul128PairWithTableUnchecked(
    xHi: UInt64,
    xLo: UInt64,
    tableHi: Array<UInt64>,
    tableLo: Array<UInt64>
): (UInt64, UInt64) {
    var zHi: UInt64 = 0
    var zLo: UInt64 = 0

    var tableIndex = Int64((xHi >> 56) & UInt64(0xff))
    zHi = zHi ^ tableHi[tableIndex]
    zLo = zLo ^ tableLo[tableIndex]
    tableIndex = GHASH_TABLE_STRIDE + Int64((xHi >> 48) & UInt64(0xff))
    zHi = zHi ^ tableHi[tableIndex]
    zLo = zLo ^ tableLo[tableIndex]
    tableIndex = 2 * GHASH_TABLE_STRIDE + Int64((xHi >> 40) & UInt64(0xff))
    zHi = zHi ^ tableHi[tableIndex]
    zLo = zLo ^ tableLo[tableIndex]
    tableIndex = 3 * GHASH_TABLE_STRIDE + Int64((xHi >> 32) & UInt64(0xff))
    zHi = zHi ^ tableHi[tableIndex]
    zLo = zLo ^ tableLo[tableIndex]
    tableIndex = 4 * GHASH_TABLE_STRIDE + Int64((xHi >> 24) & UInt64(0xff))
    zHi = zHi ^ tableHi[tableIndex]
    zLo = zLo ^ tableLo[tableIndex]
    tableIndex = 5 * GHASH_TABLE_STRIDE + Int64((xHi >> 16) & UInt64(0xff))
    zHi = zHi ^ tableHi[tableIndex]
    zLo = zLo ^ tableLo[tableIndex]
    tableIndex = 6 * GHASH_TABLE_STRIDE + Int64((xHi >> 8) & UInt64(0xff))
    zHi = zHi ^ tableHi[tableIndex]
    zLo = zLo ^ tableLo[tableIndex]
    tableIndex = 7 * GHASH_TABLE_STRIDE + Int64(xHi & UInt64(0xff))
    zHi = zHi ^ tableHi[tableIndex]
    zLo = zLo ^ tableLo[tableIndex]

    tableIndex = 8 * GHASH_TABLE_STRIDE + Int64((xLo >> 56) & UInt64(0xff))
    zHi = zHi ^ tableHi[tableIndex]
    zLo = zLo ^ tableLo[tableIndex]
    tableIndex = 9 * GHASH_TABLE_STRIDE + Int64((xLo >> 48) & UInt64(0xff))
    zHi = zHi ^ tableHi[tableIndex]
    zLo = zLo ^ tableLo[tableIndex]
    tableIndex = 10 * GHASH_TABLE_STRIDE + Int64((xLo >> 40) & UInt64(0xff))
    zHi = zHi ^ tableHi[tableIndex]
    zLo = zLo ^ tableLo[tableIndex]
    tableIndex = 11 * GHASH_TABLE_STRIDE + Int64((xLo >> 32) & UInt64(0xff))
    zHi = zHi ^ tableHi[tableIndex]
    zLo = zLo ^ tableLo[tableIndex]
    tableIndex = 12 * GHASH_TABLE_STRIDE + Int64((xLo >> 24) & UInt64(0xff))
    zHi = zHi ^ tableHi[tableIndex]
    zLo = zLo ^ tableLo[tableIndex]
    tableIndex = 13 * GHASH_TABLE_STRIDE + Int64((xLo >> 16) & UInt64(0xff))
    zHi = zHi ^ tableHi[tableIndex]
    zLo = zLo ^ tableLo[tableIndex]
    tableIndex = 14 * GHASH_TABLE_STRIDE + Int64((xLo >> 8) & UInt64(0xff))
    zHi = zHi ^ tableHi[tableIndex]
    zLo = zLo ^ tableLo[tableIndex]
    tableIndex = 15 * GHASH_TABLE_STRIDE + Int64(xLo & UInt64(0xff))
    zHi = zHi ^ tableHi[tableIndex]
    zLo = zLo ^ tableLo[tableIndex]

    (zHi, zLo)
}

@OverflowWrapping
func gfMul128InPlace(x: Array<Byte>, y: Array<Byte>): Unit {
    requireBlock(x, "GF input")
    requireBlock(y, "GF input")
    let (vHi, vLo) = readU64PairBE(y)
    gfMul128WithPairInPlace(x, vHi, vLo)
}

@OverflowWrapping
func gfMul128WithPairInPlace(x: Array<Byte>, yHi: UInt64, yLo: UInt64): Unit {
    requireBlock(x, "GF input")
    let (xHi, xLo) = readU64PairBE(x)
    let (zHi, zLo) = gfMul128Pair(xHi, xLo, yHi, yLo)
    writeU64PairBE(x, zHi, zLo)
}

@OverflowWrapping
func gfMul128Pair(xHiInput: UInt64, xLoInput: UInt64, yHi: UInt64, yLo: UInt64): (UInt64, UInt64) {
    var xHi = xHiInput
    var xLo = xLoInput
    var vHi = yHi
    var vLo = yLo
    var zHi: UInt64 = 0
    var zLo: UInt64 = 0
    let reductionPoly = UInt64(0xe1) << 56

    var i = 0
    while (i < 128) {
        let bit = xHi >> 63
        let bitMask = UInt64(0) - bit
        zHi = zHi ^ (vHi & bitMask)
        zLo = zLo ^ (vLo & bitMask)

        let lsb = vLo & UInt64(0x01)
        vLo = (vLo >> 1) | (vHi << 63)
        vHi = vHi >> 1
        let lsbMask = UInt64(0) - lsb
        vHi = vHi ^ (reductionPoly & lsbMask)

        xHi = (xHi << 1) | (xLo >> 63)
        xLo = xLo << 1
        i += 1
    }

    (zHi, zLo)
}

@OverflowWrapping
func readU64PairBE(block: Array<Byte>): (UInt64, UInt64) {
    (decodeUInt64BE(block, 0), decodeUInt64BE(block, 8))
}

@OverflowWrapping
func writeU64PairBE(block: Array<Byte>, hi: UInt64, lo: UInt64): Unit {
    encodeUInt64BE(block, 0, hi)
    encodeUInt64BE(block, 8, lo)
}

@OverflowWrapping
func decodeUInt64BE(input: Array<Byte>, offset: Int64): UInt64 {
    (UInt64(UInt8(input[offset])) << 56) |
    (UInt64(UInt8(input[offset + 1])) << 48) |
    (UInt64(UInt8(input[offset + 2])) << 40) |
    (UInt64(UInt8(input[offset + 3])) << 32) |
    (UInt64(UInt8(input[offset + 4])) << 24) |
    (UInt64(UInt8(input[offset + 5])) << 16) |
    (UInt64(UInt8(input[offset + 6])) << 8) |
    UInt64(UInt8(input[offset + 7]))
}
