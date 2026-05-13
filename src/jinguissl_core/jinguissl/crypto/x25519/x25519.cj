package jinguissl_core.jinguissl.crypto.x25519

import jinguissl_core.jinguissl.crypto.bignum.BigNum
import jinguissl_core.jinguissl.crypto.error.*
import jinguissl_core.jinguissl.crypto.utils.csprngBytes

public let X25519_KEY_LEN: Int64 = 32
public let X25519_SHARED_SECRET_LEN: Int64 = 32

private let X25519_A24: BigNum = BigNum.fromHex("1db41")
private let X25519_BASEPOINT_U: Array<Byte> = [
    UInt8(0x09), UInt8(0x00), UInt8(0x00), UInt8(0x00),
    UInt8(0x00), UInt8(0x00), UInt8(0x00), UInt8(0x00),
    UInt8(0x00), UInt8(0x00), UInt8(0x00), UInt8(0x00),
    UInt8(0x00), UInt8(0x00), UInt8(0x00), UInt8(0x00),
    UInt8(0x00), UInt8(0x00), UInt8(0x00), UInt8(0x00),
    UInt8(0x00), UInt8(0x00), UInt8(0x00), UInt8(0x00),
    UInt8(0x00), UInt8(0x00), UInt8(0x00), UInt8(0x00),
    UInt8(0x00), UInt8(0x00), UInt8(0x00), UInt8(0x00)
]
private let X25519_P: BigNum = BigNum.fromHex(
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
)

public func x25519GeneratePrivateKey(): Array<Byte> {
    x25519ClampPrivateKey(csprngBytes(X25519_KEY_LEN))
}

public func x25519ClampPrivateKey(privateKey: Array<Byte>): Array<Byte> {
    x25519RequireKeyLength(privateKey, "X25519 private key")
    let clamped = privateKey.clone()
    clamped[0] = UInt8(UInt8(clamped[0]) & UInt8(0xf8))
    clamped[31] = UInt8(UInt8(clamped[31]) & UInt8(0x7f))
    clamped[31] = UInt8(UInt8(clamped[31]) | UInt8(0x40))
    clamped
}

public func x25519ValidatePublicKey(publicKey: Array<Byte>): Unit {
    x25519RequireKeyLength(publicKey, "X25519 public key")
}

public func x25519PublicFromPrivate(privateKey: Array<Byte>): Array<Byte> {
    x25519ScalarMult(privateKey, X25519_BASEPOINT_U)
}

public func x25519DeriveSharedSecret(privateKey: Array<Byte>, peerPublicKey: Array<Byte>): Array<Byte> {
    x25519ValidatePublicKey(peerPublicKey)
    let shared = x25519ScalarMult(privateKey, peerPublicKey)
    if (isAllZero(shared)) {
        throw CryptoException(InvalidArgument, "X25519 shared secret resolves to all-zero")
    }
    shared
}

public func x25519ScalarMult(privateKey: Array<Byte>, uCoordinate: Array<Byte>): Array<Byte> {
    x25519RequireKeyLength(privateKey, "X25519 private key")
    x25519RequireKeyLength(uCoordinate, "X25519 u-coordinate")

    let scalar = x25519ClampPrivateKey(privateKey)
    let x1 = decodeLittleEndian(modReduceUCoordinate(uCoordinate))
    var x2 = BigNum.one()
    var z2 = BigNum.zero()
    var x3 = x1
    var z3 = BigNum.one()
    var swapBit: Int64 = 0

    var bit = Int64(254)
    while (bit >= 0) {
        let kBit = scalarBit(scalar, bit)
        let shouldSwap = swapBit ^ kBit
        if (shouldSwap != 0) {
            let tx = x2
            x2 = x3
            x3 = tx
            let tz = z2
            z2 = z3
            z3 = tz
        }
        swapBit = kBit

        let a = modP(x2.add(z2))
        let aa = modP(a.mul(a))
        let b = modP(x2.sub(z2))
        let bb = modP(b.mul(b))
        let e = modP(aa.sub(bb))
        let c = modP(x3.add(z3))
        let d = modP(x3.sub(z3))
        let da = modP(d.mul(a))
        let cb = modP(c.mul(b))
        let daPlusCb = modP(da.add(cb))
        let daMinusCb = modP(da.sub(cb))

        x3 = modP(daPlusCb.mul(daPlusCb))
        z3 = modP(x1.mul(modP(daMinusCb.mul(daMinusCb))))
        x2 = modP(aa.mul(bb))
        z2 = modP(e.mul(modP(aa.add(modP(X25519_A24.mul(e))))))
        bit -= 1
    }

    if (swapBit != 0) {
        let tx = x2
        x2 = x3
        x3 = tx
        let tz = z2
        z2 = z3
        z3 = tz
    }

    let inv = try {
        z2.modInverse(X25519_P)
    } catch (_: CryptoException) {
        throw CryptoException(ParseError, "X25519 scalar multiplication result is not invertible")
    }
    encodeLittleEndian(modP(x2.mul(inv)), X25519_SHARED_SECRET_LEN)
}

private func modReduceUCoordinate(value: Array<Byte>): Array<Byte> {
    let out = value.clone()
    out[31] = UInt8(UInt8(out[31]) & UInt8(0x7f))
    out
}

private func x25519RequireKeyLength(key: Array<Byte>, label: String): Unit {
    if (key.size != X25519_KEY_LEN) {
        throw CryptoException(InvalidArgument, "${label} must be 32 bytes")
    }
}

private func scalarBit(scalar: Array<Byte>, bitIndex: Int64): Int64 {
    let byteIndex = bitIndex / 8
    let bitOffset = bitIndex % 8
    Int64((UInt8(scalar[byteIndex]) >> UInt8(bitOffset)) & UInt8(0x01))
}

private func modP(value: BigNum): BigNum {
    value.mod(X25519_P)
}

private func decodeLittleEndian(bytes: Array<Byte>): BigNum {
    BigNum.fromBytesBE(reverseBytes(bytes))
}

private func encodeLittleEndian(value: BigNum, size: Int64): Array<Byte> {
    reverseBytes(value.toBytesBE(paddedLen: size))
}

private func reverseBytes(bytes: Array<Byte>): Array<Byte> {
    let out = Array<Byte>(bytes.size, repeat: 0)
    var i = 0
    while (i < bytes.size) {
        out[bytes.size - 1 - i] = bytes[i]
        i += 1
    }
    out
}

private func isAllZero(bytes: Array<Byte>): Bool {
    var acc: UInt8 = 0
    var i = 0
    while (i < bytes.size) {
        acc = acc | UInt8(bytes[i])
        i += 1
    }
    acc == UInt8(0)
}
